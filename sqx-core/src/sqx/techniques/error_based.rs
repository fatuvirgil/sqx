//! Error-based SQL injection technique.

use tracing::{debug, info, warn};

use crate::sqx::{
    dbms::all_dialects,
    detector::SqliDetector,
    evasion::tamper_chain::TamperChain,
    models::{HttpResponse, SqliTechnique, SqliTestResult},
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
        use std::time::Instant;
        let start = Instant::now();
        let max_duration = std::time::Duration::from_secs(3); // 3 second timeout
        
        debug!("Testing error-based SQL injection on parameter: {}", param);

        // Phase 1: Generic error probes (limited to 3 most effective)
        let error_payloads = [
            ("'", "Single quote"),
            ("\"", "Double quote"),
            ("\\", "Backslash"),
        ];

        for (payload, desc) in error_payloads {
            // Check timeout
            if start.elapsed() > max_duration {
                debug!("Error-based test timeout reached");
                break;
            }
            
            let effective = tamper
                .map(|t| t.apply(payload))
                .unwrap_or_else(|| payload.to_string());
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

            // Minimal delay between requests
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }

        // Phase 2: DBMS-specific error-based payloads (limited to first 3 dialects)
        debug!("Testing DBMS-specific error-based payloads");
        let dialects: Vec<_> = all_dialects().into_iter().take(3).collect();
        
        for dialect in dialects {
            // Check timeout
            if start.elapsed() > max_duration {
                debug!("Error-based DBMS test timeout reached");
                break;
            }
            
            let payloads = dialect.error_based_payloads();
            if payloads.is_empty() {
                continue;
            }

            // Limit to first 2 payloads per dialect
            for (payload_template, desc) in payloads.iter().take(2) {
                let expression = "1";
                let payload = payload_template.replace("%s", expression);
                
                let effective = tamper
                    .map(|t| t.apply(&payload))
                    .unwrap_or(payload);
                let test_url = self.build_test_url(url, param, original_value, &effective);

                match self.send_request(&test_url).await {
                    Ok(response) => {
                        if let Some(dbms) = detect_sql_error(&response.body) {
                            info!(
                                "DBMS-specific error-based injection found! DBMS: {:?}, Technique: {}",
                                dbms, desc
                            );
                            return Some(SqliTestResult {
                                parameter: param.to_string(),
                                technique: SqliTechnique::ErrorBased,
                                confidence: 0.98,
                                payload: effective,
                                evidence: format!("SQL error ({}): {}", desc, dbms),
                                dbms_hint: Some(dbms.to_string()),
                                injection_context: Some(desc.to_string()),
                                payload_id: None,
                            });
                        }
                    }
                    Err(e) => {
                        warn!("Request failed for {} error payload: {}", dialect.name(), e);
                    }
                }

                // Minimal delay between requests
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        }

        debug!("Error-based test complete in {:?}", start.elapsed());
        None
    }
}
