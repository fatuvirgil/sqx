//! SQX — SQL Injection Detection & Exploitation Engine
//! Re-exports all public types from sub-modules.

pub mod models;
pub mod http;
pub mod similarity;
pub mod detector;
pub mod techniques;
pub mod extraction;
pub mod evasion;
pub mod payloads;
pub mod dbms;
pub mod fingerprint;
pub mod session;
pub mod pipeline;
pub mod reporting;
pub mod crawler;
pub mod ai_advisor;

// ── Public re-exports ────────────────────────────────────────────────────────
#[allow(unused_imports)]
pub use models::{
    SqliTestResult, SqliTechnique, SqliConfig, SqliInfoExtraction,
    BlindExtractionResult, BlindExtractionProgress, ExtractionState, ExtractionStatus,
    CancellationToken, BlindExtractionConfig, BlindTechnique,
    SchemaEnumerationConfig, SchemaEnumerationProgress,
    UnionExtractedData, HttpResponse,
};
#[allow(unused_imports)]
pub use detector::SqliDetector;
#[allow(unused_imports)]
pub use evasion::tamper::TamperScript;
#[allow(unused_imports)]
pub use evasion::tamper_chain::TamperChain;
#[allow(unused_imports)]
pub use payloads::PayloadDatabase;
#[allow(unused_imports)]
pub use extraction::file_read::{FileReadPayload, FileReadResult, FileReadPayloads};
#[allow(unused_imports)]
pub use extraction::os_exec::{OsExecPayload, OsExecResult, OsCommandPayloads};
#[allow(unused_imports)]
pub use dbms::{DbmsDialect, all_dialects, dialect_by_name};
#[allow(unused_imports)]
pub use fingerprint::{
    TargetProfile, WafFingerprint, ScanStrategy, TargetBehavior,
    TimingProfile, ParameterProfile, TargetProber,
};
#[allow(unused_imports)]
pub use session::{SessionConfig, CsrfConfig, AuthConfig, SessionManager};

use anyhow::Result;
use tracing::{info, warn};

/// Simple scan function for Tauri command
#[allow(dead_code)]
pub async fn scan_sql_injection(url: &str) -> Result<Vec<SqliTestResult>> {
    let detector = SqliDetector::new()?;
    detector.test_url(url).await
}

/// Full automatic scan: crawl → fingerprint → scan each injection point → collect results.
///
/// # Arguments
/// * `start_url`        — Entry point for the crawler.
/// * `detector`         — Pre-configured `SqliDetector` (reused for every injection point).
/// * `crawler_config`   — Crawler settings; `None` uses sane defaults (50 pages, depth 3).
/// * `pipeline_config`  — Pipeline settings; `None` uses defaults (plain `test_url`).
pub async fn auto_scan(
    start_url: &str,
    detector: SqliDetector,
    crawler_config: Option<crawler::CrawlerConfig>,
    pipeline_config: Option<pipeline::PipelineConfig>,
) -> Result<Vec<pipeline::PipelineResult>> {
    let crawler_config = crawler_config.unwrap_or_default();
    let pipeline_config = pipeline_config.unwrap_or_default();

    // Phase 1: Crawl
    let spider = crawler::Spider::new(
        detector.client.clone(),
        crawler_config,
        detector.config.user_agent.clone(),
    );
    let injection_points = spider.crawl(start_url).await?;
    info!("Discovered {} injection points", injection_points.len());

    // Phase 2: Scan each injection point
    let mut all_results: Vec<pipeline::PipelineResult> = Vec::new();

    for point in &injection_points {
        let pipe = pipeline::Pipeline::new(detector.clone(), pipeline_config.clone());
        match point.method {
            crawler::HttpMethod::Get => {
                match pipe.run(&point.url, None, None).await {
                    Ok(result) => all_results.push(result),
                    Err(e) => warn!("GET scan failed for {}: {}", point.url, e),
                }
            }
            crawler::HttpMethod::Post => {
                // Reconstruct a form-encoded body from discovered params
                let body: String = point
                    .parameters
                    .iter()
                    .map(|p| {
                        format!(
                            "{}={}",
                            urlencoding::encode(&p.name),
                            urlencoding::encode(p.default_value.as_deref().unwrap_or("1"))
                        )
                    })
                    .collect::<Vec<_>>()
                    .join("&");
                let ct = point
                    .content_type
                    .as_deref()
                    .unwrap_or("application/x-www-form-urlencoded");
                let ct_short = if ct.contains("json") { "json" } else { "form" };
                match pipe.run(&point.url, Some(&body), Some(ct_short)).await {
                    Ok(result) => all_results.push(result),
                    Err(e) => warn!("POST scan failed for {}: {}", point.url, e),
                }
            }
        }
    }

    Ok(all_results)
}
