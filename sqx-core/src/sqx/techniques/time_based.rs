//! Time-based blind SQL injection technique.

use std::time::{Duration, Instant};
use tokio::time::timeout;
use tracing::{debug, info, warn};

use crate::sqx::{
    detector::SqliDetector,
    evasion::tamper_chain::TamperChain,
    models::{SqliTechnique, SqliTestResult},
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
        debug!(
            "Testing time-based blind SQL injection on parameter: {}",
            param
        );

        // Timeout tracking
        let start_time = Instant::now();
        let max_duration = Duration::from_secs(5); // 5 second timeout for time-based tests
        let mut tested_count = 0;

        // Statistical baseline: 2 samples for speed
        let (baseline_mean, baseline_stddev) = self.measure_baseline_timing(url, 2).await.ok()?;
        let sleep_secs = self.compute_adaptive_sleep(baseline_mean, baseline_stddev).min(2); // Cap at 2 seconds
        self.set_adaptive_sleep(sleep_secs);
        let threshold = baseline_mean + baseline_stddev * 2;

        // 1. Built-in dialects path (limited to first 3 most common dialects)
        let dialects: Vec<_> = crate::sqx::dbms::all_dialects().into_iter().take(3).collect();
        for dialect in dialects {
            // Check timeout
            if start_time.elapsed() > max_duration {
                debug!("Time-based test timeout reached");
                break;
            }

            let suffix = dialect.time_based_payload(sleep_secs);
            if suffix.is_empty() {
                continue;
            }

            let sleep_fn = dialect.sleep_function(sleep_secs);
            let cond_sleep = dialect.conditional_sleep("1=1", sleep_secs);
            // Reduced candidates - only most effective patterns
            let candidates = [
                format!("{} AND {}-- ", original_value, cond_sleep),
                format!("{} OR {}-- ", original_value, cond_sleep),
            ];

            for payload in &candidates {
                if let Some(res) = self
                    .try_time_payload_fast(
                        url,
                        param,
                        original_value,
                        payload,
                        tamper,
                        sleep_secs,
                        threshold,
                        Some(dialect.name()),
                        None,
                    )
                    .await
                {
                    return Some(res);
                }
            }
            tested_count += 1;
        }

        // 2. Dynamic sqlmap payloads path (stype=5) - very limited for speed
        if start_time.elapsed() < max_duration {
            let dynamic = crate::sqx::payloads::PayloadDatabase::load();
            let tests: Vec<_> = dynamic.dynamic.tests.iter().filter(|t| t.stype == 5).take(5).collect();

            for test in tests {
                if start_time.elapsed() > max_duration {
                    debug!("Time-based dynamic test timeout");
                    break;
                }

                if test.level > 2 {
                    continue;
                }

                // Limit to 1 boundary per test
                for boundary in dynamic.dynamic.boundaries.iter().take(1) {
                    if !test.clause.is_empty() && !boundary.clause.is_empty() {
                        if !test.clause.iter().any(|tc| boundary.clause.contains(tc)) {
                            continue;
                        }
                    }

                    let where_bit = if test.where_clause.is_empty() || boundary.where_clause.is_empty()
                    {
                        1u8
                    } else {
                        boundary
                            .where_clause
                            .iter()
                            .find(|bw| test.where_clause.contains(bw))
                            .copied()
                            .unwrap_or(1)
                    };

                    let payload = self.apply_sqlmap_boundary_time(
                        original_value,
                        &test.request_payload,
                        boundary,
                        where_bit,
                        sleep_secs,
                    );

                    if let Some(res) = self
                        .try_time_payload_fast(
                            url,
                            param,
                            original_value,
                            &payload,
                            tamper,
                            sleep_secs,
                            threshold,
                            None,
                            Some(&test.title),
                        )
                        .await
                    {
                        return Some(res);
                    }
                }
            }
        }

        debug!("Time-based test complete: {} dialects tested in {:?}", tested_count, start_time.elapsed());
        None
    }

    /// Apply sqlmap boundary for time-based tests respecting <where> semantics.
    fn apply_sqlmap_boundary_time(
        &self,
        original: &str,
        payload_template: &str,
        boundary: &crate::sqx::payloads::SqlmapBoundary,
        where_bit: u8,
        sleep_secs: u64,
    ) -> String {

        let prefix = crate::sqx::payloads::resolve_placeholders(
            &boundary.prefix,
            42,
            "sqx",
            original,
            "1=1",
            sleep_secs,
        );
        let suffix = crate::sqx::payloads::resolve_placeholders(
            &boundary.suffix,
            42,
            "sqx",
            original,
            "1=1",
            sleep_secs,
        );
        let payload = crate::sqx::payloads::resolve_placeholders(
            payload_template,
            42,
            "sqx",
            original,
            "1=1",
            sleep_secs,
        );

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
        )
        .await
        {
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
        tokio::time::sleep(crate::sqx::stealth::jittered_delay(
            self.config.delay_ms,
            self.config.stealth.jitter_pct,
        ))
        .await;
        None
    }

    /// Fast version of try_time_payload without delay between requests
    async fn try_time_payload_fast(
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
            Duration::from_secs(5 + sleep_secs), // Shorter timeout for fast test
            self.send_request(&test_url),
        )
        .await
        {
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
        // No delay for fast version
        None
    }
}
