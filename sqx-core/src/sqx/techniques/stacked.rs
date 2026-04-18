//! Stacked queries SQL injection technique.

use std::time::Duration;
use tokio::time::timeout;
use tracing::{debug, info};

use crate::sqx::{
    detector::SqliDetector,
    evasion::tamper_chain::TamperChain,
    models::{SqliTechnique, SqliTestResult},
};

impl SqliDetector {
    /// Test for stacked queries SQL injection
    pub(crate) async fn test_stacked_queries(
        &self,
        url: &str,
        param: &str,
        original_value: &str,
        tamper: Option<&TamperChain>,
    ) -> Option<SqliTestResult> {
        debug!("Testing stacked queries on parameter: {}", param);

        // Statistical baseline: 3 samples → mean + 2σ threshold
        let (baseline_mean, baseline_stddev) = self.measure_baseline_timing(url, 3).await.ok()?;
        let sleep_secs = self.compute_adaptive_sleep(baseline_mean, baseline_stddev);
        self.set_adaptive_sleep(sleep_secs);
        let threshold = baseline_mean + baseline_stddev * 2;

        let dialects = crate::sqx::dbms::all_dialects();

        for dialect in &dialects {
            let payload = dialect.stacked_sleep_payload(original_value, sleep_secs);
            if payload.is_empty() {
                continue;
            }

            let effective = tamper
                .map(|t| t.apply(&payload))
                .unwrap_or_else(|| payload.clone());
            let test_url = self.build_test_url(url, param, original_value, &effective);

            let start = std::time::Instant::now();
            match timeout(
                Duration::from_secs(10 + sleep_secs),
                self.send_request(&test_url),
            )
            .await
            {
                Ok(Ok(_)) => {
                    let duration = start.elapsed();
                    // Use half the sleep duration as headroom
                    let detection_threshold = threshold + Duration::from_secs(sleep_secs / 2);
                    if duration > detection_threshold {
                        info!(
                            "Stacked queries SQL injection found! DBMS: {}",
                            dialect.name()
                        );
                        return Some(SqliTestResult {
                            parameter: param.to_string(),
                            technique: SqliTechnique::StackedQueries,
                            confidence: 0.85,
                            payload: effective.clone(),
                            evidence: format!(
                                "Time delay detected ({:?}) using stacked query",
                                duration
                            ),
                            dbms_hint: Some(dialect.name().to_string()),
                            injection_context: None,
                            payload_id: None,
                        });
                    }
                }
                Ok(Err(_)) => {}
                Err(_) => {
                    return Some(SqliTestResult {
                        parameter: param.to_string(),
                        technique: SqliTechnique::StackedQueries,
                        confidence: 0.82,
                        payload: effective.clone(),
                        evidence: "Request timeout (stacked query executed)".to_string(),
                        dbms_hint: Some(dialect.name().to_string()),
                        injection_context: None,
                        payload_id: None,
                    });
                }
            }

            tokio::time::sleep(crate::sqx::stealth::jittered_delay(
                self.config.delay_ms,
                self.config.stealth.jitter_pct,
            ))
            .await;
        }

        None
    }
}
