use super::models::*;
use crate::sqx::models::HttpResponse;
use crate::sqx::session::SessionManager;
use anyhow::Result;
use reqwest::Client;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tracing::{debug, info};

pub struct TargetProber {
    client: Client,
    timeout: Duration,
    user_agent: String,
    session: Option<Arc<SessionManager>>,
}

impl TargetProber {
    pub fn new(client: Client, timeout: Duration, user_agent: String) -> Self {
        Self {
            client,
            timeout,
            user_agent,
            session: None,
        }
    }

    pub fn with_session(mut self, session: Arc<SessionManager>) -> Self {
        self.session = Some(session);
        self
    }

    /// Build a complete target profile. Sends ~10-15 benign requests.
    pub async fn profile(&self, url: &str) -> Result<TargetProfile> {
        info!("Starting behavioral fingerprinting for: {}", url);

        // 1. Baseline: send the exact original request 3 times, measure timing
        let timing = self.measure_timing(url, 3).await?;

        // 2. Behavior probing: test how target responds to modifications
        let behavior = self.probe_behavior(url).await?;

        // 3. WAF detection: send known-bad inputs, analyze block behavior
        let waf = self.detect_waf(url).await?;

        // 4. Parameter analysis: which params influence output?
        let parameters = self.analyze_parameters(url).await?;

        // 5. DBMS hint: from error messages, headers, behavior
        let dbms_hint = self.detect_dbms_hint(url, &behavior).await?;

        // 6. Build strategy from all observations
        let strategy = Self::build_strategy(&timing, &behavior, &waf, &dbms_hint);

        let probe_count = 3 + 4 + 3 + parameters.len() + 2; // approximate

        Ok(TargetProfile {
            url: url.to_string(),
            dbms_hint,
            waf,
            behavior,
            timing,
            strategy,
            parameters,
            probe_count,
        })
    }

    /// Measure baseline timing (standalone version).
    async fn measure_timing(&self, url: &str, samples: usize) -> Result<TimingProfile> {
        let mut durations = Vec::with_capacity(samples);

        for _ in 0..samples {
            let start = Instant::now();
            let _ = self.get(url).await?;
            durations.push(start.elapsed());
            tokio::time::sleep(Duration::from_millis(100)).await;
        }

        let mean_nanos =
            durations.iter().map(|d| d.as_nanos() as f64).sum::<f64>() / samples as f64;
        let variance = durations
            .iter()
            .map(|d| {
                let diff = d.as_nanos() as f64 - mean_nanos;
                diff * diff
            })
            .sum::<f64>()
            / samples as f64;
        let stddev_nanos = variance.sqrt();

        let mean = Duration::from_nanos(mean_nanos as u64);
        let stddev = Duration::from_nanos(stddev_nanos as u64);

        Ok(TimingProfile {
            mean_response: mean,
            stddev_response: stddev,
            time_threshold: mean + stddev * 2,
            samples,
        })
    }

    /// Generate a random probe parameter name to avoid fingerprinting.
    fn random_probe_param(&self) -> String {
        use rand::Rng;
        let mut rng = rand::thread_rng();
        let chars: Vec<char> = (0..10)
            .map(|_| rng.sample(rand::distributions::Alphanumeric) as char)
            .collect();
        format!("_x{}", chars.into_iter().collect::<String>())
    }

    /// Probe target behavior with benign modified inputs.
    async fn probe_behavior(&self, url: &str) -> Result<TargetBehavior> {
        // Request 1: Normal request (baseline)
        let normal = self.get(url).await?;

        // Request 2: Add a garbage parameter with random name — verifies
        // parameter handling behavior (response intentionally discarded)
        // Using random param name to avoid tool fingerprinting
        let probe_param = self.random_probe_param();
        let _garbage_url = if url.contains('?') {
            format!("{}&{}=1", url, probe_param)
        } else {
            format!("{}?{}=1", url, probe_param)
        };
        let _ = self.get(&_garbage_url).await;

        // Request 3: Modify an existing parameter value to obviously invalid
        let invalid_resp = self
            .send_modified_param(url, |v| format!("{}AAAA", v))
            .await;

        // Request 4: Send a single quote as param value
        let quote_resp = self.send_modified_param(url, |_| "'".to_string()).await;

        let reflects_errors = quote_resp
            .as_ref()
            .map(|r| {
                let body_lower = r.body.to_lowercase();
                body_lower.contains("sql")
                    || body_lower.contains("syntax")
                    || body_lower.contains("error")
                    || body_lower.contains("exception")
                    || body_lower.contains("warning")
            })
            .unwrap_or(false);

        let reflects_input = invalid_resp
            .as_ref()
            .map(|r| r.body.contains("AAAA"))
            .unwrap_or(false);

        let invalid_status = invalid_resp
            .as_ref()
            .map(|r| r.status)
            .unwrap_or(normal.status);

        let redirects_on_error = invalid_resp
            .as_ref()
            .map(|r| r.status == 301 || r.status == 302 || r.status == 307)
            .unwrap_or(false);

        let content_varies = invalid_resp
            .as_ref()
            .map(|r| {
                let len_diff = (normal.body.len() as i64 - r.body.len() as i64).abs();
                len_diff > 50 || normal.status != r.status
            })
            .unwrap_or(false);

        let custom_error_pages = quote_resp
            .as_ref()
            .map(|r| {
                r.body.len() > 500
                    && !r.body.contains("Traceback")
                    && !r.body.contains("at java.")
                    && !r.body.contains("stack trace")
            })
            .unwrap_or(false);

        let content_type = normal
            .headers
            .get("content-type")
            .cloned()
            .unwrap_or_else(|| "text/html".to_string());

        Ok(TargetBehavior {
            content_varies,
            reflects_errors,
            custom_error_pages,
            redirects_on_error,
            error_redirect_url: None, // TODO: extract from Location header
            normal_status: normal.status,
            invalid_input_status: invalid_status,
            reflects_input,
            content_type,
            normal_body_size: normal.body.len(),
        })
    }

    /// Detect WAF presence and type.
    async fn detect_waf(&self, url: &str) -> Result<Option<WafFingerprint>> {
        let probe_payloads = [
            "' OR 1=1--",
            "<script>alert(1)</script>",
            "../../../etc/passwd",
        ];

        for payload in &probe_payloads {
            let probe_url = self.inject_first_param(url, payload);
            match self.get(&probe_url).await {
                Ok(resp) => {
                    if let Some(waf) = self.identify_waf_from_response(&resp) {
                        return Ok(Some(waf));
                    }
                }
                Err(_) => {
                    debug!("Connection failed on WAF probe — possible network-level WAF");
                }
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }

        Ok(None)
    }

    /// Identify WAF from response characteristics.
    fn identify_waf_from_response(&self, resp: &HttpResponse) -> Option<WafFingerprint> {
        let body = &resp.body;
        let status = resp.status;

        // Define WAF signatures: (body_pattern, waf_name, recommended_tampers)
        let signatures: Vec<(&str, &str, Vec<&str>)> = vec![
            // Cloudflare
            (
                "cloudflare",
                "Cloudflare",
                vec!["randomcase", "urlencode", "space_to_comment"],
            ),
            (
                "cf-ray",
                "Cloudflare",
                vec!["randomcase", "urlencode", "space_to_comment"],
            ),
            (
                "__cfduid",
                "Cloudflare",
                vec!["randomcase", "urlencode", "space_to_comment"],
            ),
            // Akamai
            (
                "akamaighost",
                "Akamai",
                vec!["double_urlencode", "randomcase", "mysql_version_comment"],
            ),
            (
                "akamai",
                "Akamai",
                vec!["double_urlencode", "randomcase", "mysql_version_comment"],
            ),
            (
                "kona site defender",
                "Akamai (Kona)",
                vec!["double_urlencode", "randomcase", "mysql_version_comment"],
            ),
            // AWS WAF
            (
                "awswaf",
                "AWS WAF",
                vec!["urlencode", "space_to_tab", "inline_comment"],
            ),
            (
                "request blocked",
                "AWS WAF",
                vec!["urlencode", "space_to_tab", "inline_comment"],
            ),
            // ModSecurity
            (
                "modsecurity",
                "ModSecurity",
                vec!["space_to_comment", "randomcase", "hex_encode"],
            ),
            (
                "mod_security",
                "ModSecurity",
                vec!["space_to_comment", "randomcase", "hex_encode"],
            ),
            // Imperva/Incapsula
            (
                "incapsula",
                "Imperva",
                vec!["double_urlencode", "unicode_escape", "space_to_newline"],
            ),
            (
                "imperva",
                "Imperva",
                vec!["double_urlencode", "unicode_escape", "space_to_newline"],
            ),
            (
                "_incap_",
                "Imperva",
                vec!["double_urlencode", "unicode_escape", "space_to_newline"],
            ),
            // Sucuri
            (
                "sucuri",
                "Sucuri",
                vec!["randomcase", "space_to_comment", "urlencode"],
            ),
            (
                "x-sucuri-id",
                "Sucuri",
                vec!["randomcase", "space_to_comment", "urlencode"],
            ),
            // F5 BIG-IP ASM
            (
                "big-ip",
                "F5 BIG-IP",
                vec!["double_urlencode", "space_to_tab", "null_byte"],
            ),
            (
                "f5 networks",
                "F5 BIG-IP",
                vec!["double_urlencode", "space_to_tab", "null_byte"],
            ),
            // Barracuda
            (
                "barracuda",
                "Barracuda",
                vec!["urlencode", "space_to_comment", "randomcase"],
            ),
            // Fortinet/FortiWeb
            (
                "fortigate",
                "FortiWeb",
                vec!["urlencode", "randomcase", "inline_comment"],
            ),
            (
                "fortiweb",
                "FortiWeb",
                vec!["urlencode", "randomcase", "inline_comment"],
            ),
            // DenyAll
            (
                "denyall",
                "DenyAll",
                vec!["double_urlencode", "space_to_comment"],
            ),
            // Citrix NetScaler
            (
                "netscaler",
                "Citrix NetScaler",
                vec!["urlencode", "randomcase"],
            ),
            ("ns_af", "Citrix NetScaler", vec!["urlencode", "randomcase"]),
        ];

        let body_lower = body.to_lowercase();

        for (pattern, name, tampers) in &signatures {
            if body_lower.contains(pattern) {
                return Some(WafFingerprint {
                    name: name.to_string(),
                    confidence: 0.85,
                    block_status: status,
                    block_signature: Some(pattern.to_string()),
                    recommended_tampers: tampers.iter().map(|s| s.to_string()).collect(),
                });
            }
        }

        // Generic detection: blocked with 403/406/429 but no specific WAF identified
        if status == 403 || status == 406 || status == 429 {
            return Some(WafFingerprint {
                name: "Unknown WAF".to_string(),
                confidence: 0.5,
                block_status: status,
                block_signature: None,
                recommended_tampers: vec![
                    "randomcase".to_string(),
                    "urlencode".to_string(),
                    "space_to_comment".to_string(),
                ],
            });
        }

        None
    }

    /// Build scan strategy from all collected intelligence.
    fn build_strategy(
        timing: &TimingProfile,
        behavior: &TargetBehavior,
        waf: &Option<WafFingerprint>,
        dbms_hint: &Option<String>,
    ) -> ScanStrategy {
        let mut technique_order = Vec::new();
        let mut tamper_chain = Vec::new();
        let waf_bypass_required = waf.is_some();

        // If target reflects errors → error-based first (fastest, most reliable)
        if behavior.reflects_errors {
            technique_order.push("ErrorBased".to_string());
        }

        // If content varies with input → boolean blind is viable
        if behavior.content_varies {
            technique_order.push("BooleanBlind".to_string());
        }

        // Union-based works when input is reflected and no WAF blocking SELECT
        if behavior.reflects_input {
            technique_order.push("UnionBased".to_string());
        }

        // Time-based as fallback — skip if timing jitter is too high
        let skip_time_based = timing.stddev_response > Duration::from_millis(2000);
        if !skip_time_based {
            technique_order.push("TimeBased".to_string());
        }

        // Stacked queries — depends on DBMS
        match dbms_hint.as_deref() {
            Some("MSSQL") | Some("PostgreSQL") => {
                technique_order.push("StackedQueries".to_string());
            }
            _ => {} // MySQL rarely supports stacked queries in web contexts
        }

        // OOB always last (requires external infrastructure)
        technique_order.push("OutOfBand".to_string());

        // If no techniques were prioritized, use default order
        if technique_order.len() <= 1 {
            technique_order = vec![
                "ErrorBased".to_string(),
                "BooleanBlind".to_string(),
                "UnionBased".to_string(),
                "TimeBased".to_string(),
                "StackedQueries".to_string(),
                "OutOfBand".to_string(),
            ];
        }

        // WAF evasion strategy
        if let Some(waf) = waf {
            tamper_chain = waf.recommended_tampers.clone();
        }

        // Delay recommendation
        let recommended_delay_ms = if waf.is_some() {
            500 // Slow down against WAF
        } else if timing.mean_response > Duration::from_millis(1000) {
            200 // Target is slow, don't overwhelm
        } else {
            50 // Fast target, can be more aggressive
        };

        // Parallelism recommendation
        let parallel_safe = waf.is_none(); // Don't parallelize against WAF
        let max_concurrent = if waf.is_some() {
            1
        } else if timing.mean_response > Duration::from_millis(500) {
            3
        } else {
            5
        };

        ScanStrategy {
            technique_order,
            waf_bypass_required,
            tamper_chain,
            recommended_delay_ms,
            parallel_safe,
            max_concurrent,
            skip_time_based,
            use_content_length: behavior.content_varies,
            use_body_hash: !behavior.content_varies,
        }
    }

    /// Detect DBMS from probing (error messages, headers, behavior).
    async fn detect_dbms_hint(
        &self,
        url: &str,
        behavior: &TargetBehavior,
    ) -> Result<Option<String>> {
        if !behavior.reflects_errors {
            return Ok(None);
        }

        // Send a single quote to trigger error
        let probe_url = self.inject_first_param(url, "'");
        match self.get(&probe_url).await {
            Ok(resp) => {
                let body_lower = resp.body.to_lowercase();
                if body_lower.contains("mysql") || body_lower.contains("mariadb") {
                    return Ok(Some("MySQL".to_string()));
                }
                if body_lower.contains("postgresql") || body_lower.contains("pg_") {
                    return Ok(Some("PostgreSQL".to_string()));
                }
                if body_lower.contains("microsoft sql")
                    || body_lower.contains("mssql")
                    || body_lower.contains("sqlserver")
                {
                    return Ok(Some("MSSQL".to_string()));
                }
                if body_lower.contains("ora-") || body_lower.contains("oracle") {
                    return Ok(Some("Oracle".to_string()));
                }
                if body_lower.contains("sqlite") {
                    return Ok(Some("SQLite".to_string()));
                }
                Ok(None)
            }
            Err(_) => Ok(None),
        }
    }

    /// Analyze URL parameters.
    async fn analyze_parameters(&self, url: &str) -> Result<Vec<ParameterProfile>> {
        let parsed = reqwest::Url::parse(url)?;
        let params: Vec<(String, String)> = parsed
            .query_pairs()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();

        let mut profiles = Vec::new();

        // Get baseline
        let baseline = self.get(url).await?;

        for (name, value) in &params {
            let is_numeric = value.parse::<i64>().is_ok();

            // Test if modifying this parameter changes output
            let test_value = if is_numeric {
                format!("{}", value.parse::<i64>().unwrap_or(0) + 99999)
            } else {
                format!("{}sqxprobe", value)
            };

            let modified_url = self.replace_param(url, name, &test_value);
            let modified_resp = self.get(&modified_url).await.ok();

            let influences_output = modified_resp
                .as_ref()
                .map(|r| {
                    let size_diff = (baseline.body.len() as i64 - r.body.len() as i64).abs();
                    size_diff > 50 || baseline.status != r.status
                })
                .unwrap_or(false);

            // Heuristic: numeric params that change output are likely DB-backed
            let likely_db_param = is_numeric && influences_output;

            profiles.push(ParameterProfile {
                name: name.clone(),
                original_value: value.clone(),
                is_numeric,
                influences_output,
                likely_db_param,
            });
        }

        Ok(profiles)
    }

    // ── HTTP helpers ──

    async fn get(&self, url: &str) -> Result<HttpResponse> {
        let start = Instant::now();
        let mut builder = self
            .client
            .get(url)
            .header("User-Agent", &self.user_agent)
            .timeout(self.timeout);

        if let Some(ref session) = self.session {
            builder = session.apply(builder).await;
        }

        let resp = builder.send().await?;

        if let Some(ref session) = self.session {
            session.update_from_response(&resp).await;
        }

        let status = resp.status().as_u16();
        let headers: std::collections::HashMap<String, String> = resp
            .headers()
            .iter()
            .filter_map(|(k, v)| {
                v.to_str()
                    .ok()
                    .map(|vs| (k.as_str().to_lowercase(), vs.to_string()))
            })
            .collect();
        let body = resp.text().await.unwrap_or_default();
        Ok(HttpResponse {
            status,
            body,
            duration: start.elapsed(),
            headers,
        })
    }

    /// Send request with first parameter modified by transform function.
    async fn send_modified_param(
        &self,
        url: &str,
        transform: impl Fn(&str) -> String,
    ) -> Option<HttpResponse> {
        let parsed = reqwest::Url::parse(url).ok()?;
        let params: Vec<(String, String)> = parsed
            .query_pairs()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        if params.is_empty() {
            return None;
        }

        let modified_url = self.replace_param(url, &params[0].0, &transform(&params[0].1));
        self.get(&modified_url).await.ok()
    }

    /// Inject payload into first parameter.
    fn inject_first_param(&self, url: &str, payload: &str) -> String {
        let Ok(parsed) = reqwest::Url::parse(url) else {
            return url.to_string();
        };
        let params: Vec<(String, String)> = parsed
            .query_pairs()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        if params.is_empty() {
            return url.to_string();
        }
        self.replace_param(url, &params[0].0, payload)
    }

    /// Replace a parameter value in URL.
    fn replace_param(&self, url: &str, param: &str, new_value: &str) -> String {
        let Ok(mut parsed) = reqwest::Url::parse(url) else {
            return url.to_string();
        };
        let pairs: Vec<(String, String)> = parsed
            .query_pairs()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        parsed.set_query(None);
        {
            let mut ser = parsed.query_pairs_mut();
            for (k, v) in &pairs {
                if k == param {
                    ser.append_pair(k, new_value);
                } else {
                    ser.append_pair(k, v);
                }
            }
        }
        parsed.to_string()
    }
}
