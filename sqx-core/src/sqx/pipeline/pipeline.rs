//! Pipeline — thin orchestration layer over SqliDetector.
//!
//! Wraps a scan run with timing, request counting, and profile enrichment,
//! then returns a [`PipelineResult`] suitable for report generators.

use std::time::Instant;

use anyhow::Result;
use tracing::warn;

use crate::sqx::detector::SqliDetector;

use super::models::PipelineResult;

/// Pipeline configuration (currently a placeholder; extend as needed).
#[derive(Debug, Clone, Default)]
pub struct PipelineConfig {
    /// If true, run `scan_smart` (fingerprint first).
    /// If false, run `test_url` (no fingerprinting).
    pub smart_scan: bool,
}

/// Orchestrates a single-target scan and produces a [`PipelineResult`].
pub struct Pipeline {
    detector: SqliDetector,
    config: PipelineConfig,
}

impl Pipeline {
    pub fn new(detector: SqliDetector, config: PipelineConfig) -> Self {
        Self { detector, config }
    }

    /// Run a full scan against `url`.
    ///
    /// - `post_body`: if `Some`, run a POST scan (`test_url_post`).
    /// - `content_type`: POST content-type (`"form"`, `"json"`, `"xml"`). Defaults to `"form"`.
    pub async fn run(
        &self,
        url: &str,
        post_body: Option<&str>,
        content_type: Option<&str>,
    ) -> Result<PipelineResult> {
        let start = Instant::now();

        if let Some(body) = post_body {
            let ct = content_type.unwrap_or("form");
            let findings = self.detector.test_url_post(url, body, ct).await?;
            let elapsed = start.elapsed().as_secs_f64();
            let params_tested = findings
                .iter()
                .map(|f| f.parameter.as_str())
                .collect::<std::collections::HashSet<_>>()
                .len()
                .max(1);

            return Ok(PipelineResult::new(
                findings,
                None,
                params_tested,
                self.detector.request_count(),
                elapsed,
            ));
        }

        if self.config.smart_scan {
            match self.detector.scan_smart(url).await {
                Ok((profile, findings)) => {
                    let elapsed = start.elapsed().as_secs_f64();
                    let params_tested = profile.parameters.len().max(1);
                    let total_requests = profile.probe_count + self.detector.request_count();
                    return Ok(PipelineResult::new(
                        findings,
                        Some(profile),
                        params_tested,
                        total_requests,
                        elapsed,
                    ));
                }
                Err(e) => {
                    warn!("scan_smart failed, falling back to test_url: {}", e);
                }
            }
        }

        // Fallback: plain URL scan
        let findings = self.detector.test_url(url).await?;
        let elapsed = start.elapsed().as_secs_f64();
        let params_tested = findings
            .iter()
            .map(|f| f.parameter.as_str())
            .collect::<std::collections::HashSet<_>>()
            .len()
            .max(1);

        Ok(PipelineResult::new(
            findings,
            None,
            params_tested,
            self.detector.request_count(),
            elapsed,
        ))
    }
}
