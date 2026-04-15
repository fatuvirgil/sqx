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

        let sleep_secs = self.config.sleep_duration_secs;

        // Statistical baseline: 3 samples → mean + 2σ threshold
        let (baseline_mean, baseline_stddev) = self.measure_baseline_timing(url, 3).await.ok()?;
        let threshold = baseline_mean + baseline_stddev * 2;

        for dialect in crate::sqx::dbms::all_dialects() {
            let payload = dialect.time_based_payload(sleep_secs);
            if payload.is_empty() {
                continue;
            }

            let effective = tamper.map(|t| t.apply(&payload)).unwrap_or_else(|| payload.clone());
            let test_url = self.build_test_url(url, param, original_value, &effective);

            let start = Instant::now();
            match timeout(Duration::from_secs(10 + sleep_secs), self.send_request(&test_url)).await {
                Ok(Ok(_)) => {
                    let duration = start.elapsed();
                    // Use half the sleep duration as headroom
                    let detection_threshold = threshold + Duration::from_secs(sleep_secs / 2);
                    if duration > detection_threshold {
                        info!("Time-based blind SQL injection found! DBMS: {}", dialect.name());
                        return Some(SqliTestResult {
                            parameter: param.to_string(),
                            technique: SqliTechnique::TimeBased,
                            confidence: 0.9,
                            payload: effective.clone(),
                            evidence: format!(
                                "Response time: {:?} (threshold: {:?})",
                                duration, detection_threshold
                            ),
                            dbms_hint: Some(dialect.name().to_string()),
                        });
                    }
                }
                Ok(Err(e)) => {
                    warn!("Request failed for time-based test: {}", e);
                }
                Err(_) => {
                    info!("Time-based blind SQL injection found (timeout)! DBMS: {}", dialect.name());
                    return Some(SqliTestResult {
                        parameter: param.to_string(),
                        technique: SqliTechnique::TimeBased,
                        confidence: 0.85,
                        payload: effective.clone(),
                        evidence: "Request timed out (likely due to SLEEP function)".to_string(),
                        dbms_hint: Some(dialect.name().to_string()),
                    });
                }
            }

            tokio::time::sleep(Duration::from_millis(self.config.delay_ms)).await;
        }

        None
    }
}
