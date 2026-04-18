use anyhow::Result;
use std::collections::HashSet;
use std::time::Duration;
use tracing::{debug, info};

use crate::sqx::{
    ai_advisor::{AiAdvisor, TargetContext},
    detector::SqliDetector,
    evasion::tamper_chain::TamperChain,
    fingerprint::{ParameterProfile, TargetProber, TargetProfile},
    models::{HttpResponse, SqliTechnique, SqliTestResult},
};

impl SqliDetector {
    /// Scan with behavioral fingerprinting (recommended entry point).
    /// Phase 1: Fingerprint the target (~10-15 benign probes).
    /// Phase 2: Run injection tests using the strategy derived from the profile.
    pub async fn scan_smart(&self, url: &str) -> Result<(TargetProfile, Vec<SqliTestResult>)> {
        self.scan_smart_with_optional_tamper(url, None).await
    }

    /// Smart scan with an explicit user-supplied tamper chain.
    pub async fn scan_smart_with_tamper(
        &self,
        url: &str,
        tamper: &TamperChain,
    ) -> Result<(TargetProfile, Vec<SqliTestResult>)> {
        self.scan_smart_with_optional_tamper(url, Some(tamper))
            .await
    }

    async fn scan_smart_with_optional_tamper(
        &self,
        url: &str,
        user_tamper: Option<&TamperChain>,
    ) -> Result<(TargetProfile, Vec<SqliTestResult>)> {
        let mut prober = TargetProber::new(
            self.client.clone(),
            Duration::from_secs(self.config.timeout_secs),
            self.config.user_agent.clone(),
        );
        if let Some(ref session) = self.session {
            prober = prober.with_session(session.clone());
        }
        let profile = prober.profile(url).await?;

        info!(
            "Target profile: WAF={:?}, DBMS={:?}, strategy={:?}",
            profile.waf.as_ref().map(|w| &w.name),
            profile.dbms_hint,
            profile.strategy.technique_order
        );

        let results = self.scan_with_strategy(url, &profile, user_tamper).await?;
        Ok((profile, results))
    }

    /// Detect if a response looks like a WAF block rather than a normal "not vulnerable" response.
    fn is_waf_blocked(resp: &HttpResponse, waf_block_status: Option<u16>) -> bool {
        if matches!(resp.status, 403 | 406 | 429 | 503) {
            return true;
        }
        if let Some(expected) = waf_block_status {
            if expected != 0 && resp.status == expected {
                return true;
            }
        }
        let body_lower = resp.body.to_lowercase();
        let waf_signatures = [
            "access denied",
            "blocked",
            "forbidden",
            "not acceptable",
            "security violation",
            "attack detected",
            "cloudflare",
            "request rejected",
            "waf",
            "web application firewall",
            "incapsula",
            "imperva",
            "akamai",
            "sucuri",
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
    async fn scan_with_strategy(
        &self,
        url: &str,
        profile: &TargetProfile,
        user_tamper: Option<&TamperChain>,
    ) -> Result<Vec<SqliTestResult>> {
        let mut results = Vec::new();

        let target_params: Vec<&ParameterProfile> = profile
            .parameters
            .iter()
            .filter(|p| p.likely_db_param || p.influences_output)
            .collect();

        let params_to_test: Vec<&ParameterProfile> = if target_params.is_empty() {
            profile.parameters.iter().collect()
        } else {
            target_params
        };

        let mut base_tamper_names: Vec<String> = user_tamper
            .map(|chain| chain.names().into_iter().map(str::to_string).collect())
            .unwrap_or_default();
        for name in &profile.strategy.tamper_chain {
            if !base_tamper_names.iter().any(|existing| existing == name) {
                base_tamper_names.push(name.clone());
            }
        }
        let tamper = if !base_tamper_names.is_empty() {
            let names: Vec<&str> = base_tamper_names.iter().map(|s| s.as_str()).collect();
            Some(TamperChain::from_names(&names))
        } else {
            None
        };
        let tamper_ref = tamper.as_ref();

        let advisor = AiAdvisor::new(self.config.ai_advisor.clone());
        let waf_block_status = profile.waf.as_ref().map(|w| w.block_status);

        let waf_name = profile.waf.as_ref().map(|w| w.name.as_str());
        let waf_recommended: Vec<String> = profile
            .waf
            .as_ref()
            .map(|w| w.recommended_tampers.clone())
            .unwrap_or_default();
        let escalation_list: Vec<Vec<String>> =
            super::evasion::waf_bypass::build_escalation_list(waf_name, &waf_recommended);

        for param in &params_to_test {
            if self.is_scan_cancelled() {
                break;
            }

            let mut tried_tampers: HashSet<String> = base_tamper_names.iter().cloned().collect();

            'technique: for technique_name in &profile.strategy.technique_order {
                let technique = match technique_name.as_str() {
                    "ErrorBased" => SqliTechnique::ErrorBased,
                    "BooleanBlind" => SqliTechnique::BooleanBlind,
                    "TimeBased" => SqliTechnique::TimeBased,
                    "UnionBased" => SqliTechnique::UnionBased,
                    "StackedQueries" => SqliTechnique::StackedQueries,
                    "OutOfBand" => SqliTechnique::OutOfBand,
                    _ => continue,
                };

                if self.config.ai_advisor.enabled && technique != SqliTechnique::OutOfBand {
                    let ctx = TargetContext {
                        parameter: param.name.clone(),
                        param_type: if param.is_numeric {
                            "numeric".to_string()
                        } else {
                            "string".to_string()
                        },
                        dbms_hint: profile.dbms_hint.clone(),
                        waf_name: profile.waf.as_ref().map(|w| w.name.clone()),
                        error_snippet: None,
                        reflects_errors: profile.behavior.reflects_errors,
                        reflects_input: profile.behavior.reflects_input,
                        technique: technique_name
                            .to_lowercase()
                            .replace("based", "")
                            .replace("blind", "")
                            .trim()
                            .to_string(),
                    };
                    let suggestions = advisor.suggest(&ctx).await;
                    if !suggestions.is_empty() {
                        let baseline = self.send_request(url).await.ok();
                        if let Some(r) = self
                            .test_ai_payloads(
                                url,
                                &param.name,
                                &param.original_value,
                                &suggestions,
                                technique,
                                baseline.as_ref(),
                                tamper_ref,
                            )
                            .await
                        {
                            results.push(r);
                            continue 'technique;
                        }
                    }
                }

                let result = self
                    .run_technique(
                        url,
                        param,
                        technique,
                        tamper_ref,
                        profile.dbms_hint.as_deref(),
                    )
                    .await;
                if let Some(r) = result {
                    results.push(r);
                    continue 'technique;
                }

                if profile.waf.is_some() {
                    let blocked = self
                        .probe_is_blocked(
                            url,
                            &param.name,
                            &param.original_value,
                            tamper_ref,
                            waf_block_status,
                        )
                        .await;

                    if blocked {
                        debug!(
                            "WAF blocking param={} technique={} — starting tamper escalation",
                            param.name, technique_name
                        );
                        for chain in &escalation_list {
                            let chain_key = chain.join(",");
                            if tried_tampers.contains(&chain_key) {
                                continue;
                            }
                            tried_tampers.insert(chain_key.clone());

                            let names: Vec<&str> = chain.iter().map(|s| s.as_str()).collect();
                            let escalated = TamperChain::from_names(&names);
                            let esc_ref = &escalated;

                            let esc_result = self
                                .run_technique(
                                    url,
                                    param,
                                    technique,
                                    Some(esc_ref),
                                    profile.dbms_hint.as_deref(),
                                )
                                .await;

                            if let Some(mut r) = esc_result {
                                r.evidence = format!("[tamper:{}] {}", chain_key, r.evidence);
                                results.push(r);
                                continue 'technique;
                            }

                            let still_blocked = self
                                .probe_is_blocked(
                                    url,
                                    &param.name,
                                    &param.original_value,
                                    Some(esc_ref),
                                    waf_block_status,
                                )
                                .await;
                            if !still_blocked {
                                debug!(
                                    "Tamper chain '{}' bypassed WAF but no vuln found — stopping escalation",
                                    chain_key
                                );
                                break;
                            }
                        }
                    }
                }
            }
        }

        Ok(results)
    }
}
