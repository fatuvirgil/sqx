//! Error-based SQL injection technique.

use std::time::Duration;
use tracing::{debug, info, warn};

use crate::sqx::{
    detector::SqliDetector,
    evasion::tamper_chain::TamperChain,
    models::{HttpResponse, SqliTestResult, SqliTechnique},
    similarity::detect_sql_error,
};

impl SqliDetector {
    /// Test for error-based SQL injection
    pub(crate) async fn test_error_based(
        &self,
        url: &str,
        param: &str,
        original_value: &str,
        _baseline: &HttpResponse,
        tamper: Option<&TamperChain>,
    ) -> Option<SqliTestResult> {
        debug!("Testing error-based SQL injection on parameter: {}", param);

        let error_payloads = [
            ("'", "Single quote"),
            ("\"", "Double quote"),
            ("\\", "Backslash"),
            ("' -- ", "Comment"),
            ("' OR '1'='1", "OR condition"),
        ];

        for (payload, desc) in error_payloads {
            let effective = tamper.map(|t| t.apply(payload)).unwrap_or_else(|| payload.to_string());
            let test_url = self.build_test_url(url, param, original_value, &effective);

            match self.send_request(&test_url).await {
                Ok(response) => {
                    if let Some(dbms) = detect_sql_error(&response.body) {
                        info!("Error-based SQL injection found! DBMS: {:?}", dbms);
                        return Some(SqliTestResult {
                            parameter: param.to_string(),
                            technique: SqliTechnique::ErrorBased,
                            confidence: 0.95,
                            payload: effective,
                            evidence: format!("SQL error found in response (DBMS: {})", dbms),
                            dbms_hint: Some(dbms.to_string()),
                            injection_context: None,
                            payload_id: None,
                        });

                    }
                }
                Err(e) => {
                    warn!("Request failed for payload {}: {}", desc, e);
                }
            }

            tokio::time::sleep(crate::sqx::stealth::jittered_delay(self.config.delay_ms, self.config.stealth.jitter_pct)).await;
        }

        None
    }
}
