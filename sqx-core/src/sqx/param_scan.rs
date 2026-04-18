use anyhow::Result;
use tracing::{debug, info, warn};

use crate::sqx::detector::SqliDetector;
use crate::sqx::evasion::tamper_chain::TamperChain;
use crate::sqx::models::{SqliTechnique, SqliTestResult};
use crate::sqx::similarity::{detect_php_error, detect_sql_error};

impl SqliDetector {
    /// Test a parameter for server-side code injection (PHP eval, create_function, etc.)
    /// Must run before SQLi tests to avoid false positives from PHP error responses.
    pub(crate) async fn test_code_injection(
        &self,
        url: &str,
        param: &str,
        original_value: &str,
    ) -> Option<SqliTestResult> {
        // A single quote breaks out of PHP string context — if we get a PHP error
        // but no SQL error, this is code injection, not SQLi.
        let probe = format!("{}'", original_value);
        let test_url = self.build_test_url(url, param, original_value, &probe);
        let resp = self.send_request(&test_url).await.ok()?;

        if detect_php_error(&resp.body) && detect_sql_error(&resp.body).is_none() {
            info!("PHP code injection detected on param={}", param);
            // Extract the specific PHP error for evidence
            let evidence_snippet = [
                "ParseError",
                "Parse error:",
                "Fatal error:",
                "syntax error, unexpected",
                "create_function",
                "eval()'d code",
                "runtime-created function",
            ]
            .iter()
            .find(|p| resp.body.contains(*p))
            .copied()
            .unwrap_or("PHP error in response");

            return Some(SqliTestResult {
                parameter: param.to_string(),
                technique: SqliTechnique::CodeInjection,
                confidence: 0.90,
                payload: probe,
                evidence: format!(
                    "PHP code injection — server eval'd user input. Indicator: '{}'. \
                     Not SQL injection. Check for eval(), create_function(), or similar constructs.",
                    evidence_snippet
                ),
                dbms_hint: None,
                injection_context: None,
                payload_id: None,
            });
        }
        None
    }

    /// Test a specific parameter for SQL injection using all configured techniques
    pub(crate) async fn test_parameter(
        &self,
        url: &str,
        param: &str,
        original_value: &str,
    ) -> Result<Vec<SqliTestResult>> {
        self.test_parameter_with_tamper(url, param, original_value, None)
            .await
    }

    pub(crate) async fn test_parameter_with_tamper(
        &self,
        url: &str,
        param: &str,
        original_value: &str,
        tamper: Option<&TamperChain>,
    ) -> Result<Vec<SqliTestResult>> {
        debug!("Testing parameter: {} = {}", param, original_value);
        let mut results = Vec::new();

        // Code injection check first — prevents false positive SQLi reports
        // when the server uses PHP eval/create_function on user input.
        if let Some(result) = self.test_code_injection(url, param, original_value).await {
            results.push(result);
            return Ok(results);
        }

        let baseline = self.send_request(url).await?;

        if self.config.techniques.contains(&SqliTechnique::ErrorBased)
            && let Some(result) = self
                .test_error_based(url, param, original_value, &baseline, tamper)
                .await
        {
            results.push(result);
            return Ok(results);
        }

        if self.config.techniques.contains(&SqliTechnique::BooleanBlind)
            && let Some(result) = self
                .test_boolean_blind(url, param, original_value, &baseline, tamper)
                .await
        {
            results.push(result);
            return Ok(results);
        }

        if self.config.techniques.contains(&SqliTechnique::TimeBased)
            && let Some(result) = self
                .test_time_based(url, param, original_value, tamper)
                .await
        {
            results.push(result);
            return Ok(results);
        }

        if self.config.techniques.contains(&SqliTechnique::UnionBased)
            && let Some(result) = self
                .test_union_based(url, param, original_value, &baseline, tamper)
                .await
        {
            results.push(result);
            return Ok(results);
        }

        if self
            .config
            .techniques
            .contains(&SqliTechnique::StackedQueries)
            && let Some(result) = self
                .test_stacked_queries(url, param, original_value, tamper)
                .await
        {
            results.push(result);
            return Ok(results);
        }

        // Note: Out-of-band detection is a Pro feature
        // It requires the OOB server which is only available in SQX Pro
        if self.config.techniques.contains(&SqliTechnique::OutOfBand) {
            warn!("Out-of-band detection is a Pro feature. Upgrade to SQX Pro for OOB support.");
        }

        Ok(results)
    }
}
