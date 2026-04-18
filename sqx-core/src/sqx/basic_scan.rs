use anyhow::Result;
use tracing::{info, warn};

use crate::sqx::detector::SqliDetector;
use crate::sqx::evasion::tamper_chain::TamperChain;
use crate::sqx::models::SqliTestResult;

impl SqliDetector {
    /// Test a single URL for SQL injection vulnerabilities
    pub async fn test_url(&self, url: &str) -> Result<Vec<SqliTestResult>> {
        self.test_url_with_optional_tamper(url, None).await
    }

    /// Test a single URL for SQL injection vulnerabilities with an explicit tamper chain.
    pub async fn test_url_with_tamper(
        &self,
        url: &str,
        tamper: &TamperChain,
    ) -> Result<Vec<SqliTestResult>> {
        self.test_url_with_optional_tamper(url, Some(tamper)).await
    }

    async fn test_url_with_optional_tamper(
        &self,
        url: &str,
        tamper: Option<&TamperChain>,
    ) -> Result<Vec<SqliTestResult>> {
        info!("Starting SQL injection scan against: {}", url);
        let mut results = Vec::new();

        let parsed_url = reqwest::Url::parse(url)?;
        let params: Vec<(String, String)> = parsed_url
            .query_pairs()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();

        if params.is_empty() {
            warn!("No parameters found in URL: {}", url);
            let common_params: Vec<&str> = self
                .config
                .param_wordlist
                .iter()
                .map(|s| s.as_str())
                .collect();
            for param in common_params {
                if self.is_scan_cancelled() {
                    break;
                }
                let test_url = format!("{}?{}=1", url, param);
                if let Ok(param_results) = self
                    .test_parameter_with_tamper(&test_url, param, "1", tamper)
                    .await
                {
                    results.extend(param_results);
                }
                tokio::time::sleep(crate::sqx::stealth::jittered_delay(
                    self.config.delay_ms,
                    self.config.stealth.jitter_pct,
                ))
                .await;
            }
        } else {
            for (param, value) in &params {
                if self.is_scan_cancelled() {
                    break;
                }
                if let Ok(param_results) = self
                    .test_parameter_with_tamper(url, param, value, tamper)
                    .await
                {
                    results.extend(param_results);
                }
                tokio::time::sleep(crate::sqx::stealth::jittered_delay(
                    self.config.delay_ms,
                    self.config.stealth.jitter_pct,
                ))
                .await;
            }
        }

        // Also probe injectable HTTP headers — many back-ends log X-Forwarded-For,
        // User-Agent, Referer, Cookie directly into DB tables without sanitization.
        let header_results = match tamper {
            Some(chain) => self.test_headers_with_tamper(url, chain).await,
            None => self.test_headers(url).await,
        };
        results.extend(header_results);

        info!(
            "SQL injection scan complete. Found {} vulnerabilities",
            results.len()
        );
        Ok(results)
    }
}
