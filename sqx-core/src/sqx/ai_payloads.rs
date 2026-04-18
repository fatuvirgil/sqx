use crate::sqx::{
    ai_advisor::AiSuggestedPayload,
    detector::SqliDetector,
    evasion::tamper_chain::TamperChain,
    models::{HttpResponse, SqliTechnique, SqliTestResult},
    similarity::detect_sql_error,
};

impl SqliDetector {
    /// Test AI-suggested payloads against the target parameter.
    /// Returns the first hit found, or None if no payload triggered a detection.
    pub(crate) async fn test_ai_payloads(
        &self,
        url: &str,
        param: &str,
        original_value: &str,
        suggestions: &[AiSuggestedPayload],
        technique: SqliTechnique,
        baseline: Option<&HttpResponse>,
        tamper: Option<&TamperChain>,
    ) -> Option<SqliTestResult> {
        let sleep_threshold = if technique == SqliTechnique::TimeBased {
            if let Some(base) = baseline {
                let estimated_stddev =
                    std::time::Duration::from_millis(base.duration.as_millis() as u64 / 4);
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
                            evidence: format!(
                                "[AI] Response delayed {}ms (threshold {}s)",
                                elapsed.as_millis(),
                                sleep_threshold
                            ),
                            dbms_hint: None,
                            injection_context: None,
                            payload_id: None,
                        });
                    }
                }
                SqliTechnique::BooleanBlind
                | SqliTechnique::UnionBased
                | SqliTechnique::StackedQueries => {
                    if let Some(base) = baseline {
                        let len_diff = (base.body.len() as i64 - resp.body.len() as i64).abs();
                        if len_diff > 50 && base.status == resp.status {
                            return Some(SqliTestResult {
                                parameter: param.to_string(),
                                technique,
                                confidence: 0.70,
                                payload: payload.clone(),
                                evidence: format!(
                                    "[AI] Response length changed: {} → {}",
                                    base.body.len(),
                                    resp.body.len()
                                ),
                                dbms_hint: None,
                                injection_context: None,
                                payload_id: None,
                            });
                        }
                    }
                }
                SqliTechnique::OutOfBand | SqliTechnique::SecondOrder => {}
                SqliTechnique::CodeInjection => {}
            }
        }

        None
    }
}
