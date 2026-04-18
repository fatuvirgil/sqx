//! SQX — SQL Injection Detection & Exploitation Engine
//! Re-exports all public types from sub-modules.

pub mod ai_advisor;
pub mod ai_payloads;
pub mod basic_scan;
pub mod crawler;
pub mod dbms;
pub mod detector;
pub mod evasion;
pub mod extraction;
pub mod findings;
pub mod fingerprint;
pub mod http;
pub mod info;
pub mod models;
pub mod param_scan;
pub mod payloads;
pub mod request;
pub mod pipeline;
pub mod post_scan;
pub mod reporting;
// Note: Second-order detection moved to sqx-pro
// pub mod second_order;
pub mod session;
pub mod similarity;
pub mod smart_scan;
pub mod stealth;
pub mod shell;
pub mod takeover;
pub mod techniques;
pub mod url_utils;

// ── Public re-exports ────────────────────────────────────────────────────────
#[allow(unused_imports)]
pub use dbms::{DbmsDialect, all_dialects, dialect_by_name};
#[allow(unused_imports)]
pub use detector::{OobServer, SqliDetector};
#[allow(unused_imports)]
pub use evasion::tamper::TamperScript;
#[allow(unused_imports)]
pub use evasion::tamper_chain::TamperChain;
#[allow(unused_imports)]
pub use fingerprint::{
    ParameterProfile, ScanStrategy, TargetBehavior, TargetProber, TargetProfile, TimingProfile,
    WafFingerprint,
};
#[allow(unused_imports)]
pub use models::{
    BlindExtractionConfig, BlindExtractionProgress, BlindExtractionResult, BlindTechnique,
    CancellationToken, ExtractionState, ExtractionStatus, HttpResponse, SchemaEnumerationConfig,
    SchemaEnumerationProgress, SqliConfig, SqliInfoExtraction, SqliTechnique, SqliTestResult,
    UnionExtractedData,
};
#[allow(unused_imports)]
pub use payloads::PayloadDatabase;
#[allow(unused_imports)]
pub use session::{AuthConfig, CsrfConfig, SessionConfig, SessionManager};
#[allow(unused_imports)]
pub use shell::{
    detect_os_shell_methods, OsShell, OsShellMethod, ShellConfig, ShellHistoryEntry,
    ShellResult, ShellSession, ShellTechnique, SqlShell,
};
pub use takeover::{
    CustomSqlRequest, CustomSqlResult, FileReadPayload, FileReadPayloads, FileReadResult,
    FileWritePayload, FileWritePayloads, FileWriteResult, OsCommandPayloads, OsExecPayload,
    OsExecResult,
};

use anyhow::Result;
use std::sync::Arc;
use tracing::{debug, info, warn};

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

    // Phase 1: Crawl using regex-based spider
    let spider = crawler::Spider::new(
        detector.client.clone(),
        crawler_config,
        detector.config.user_agent.clone(),
    );
    let spider = if let Some(ref session) = detector.session {
        spider.with_session(session.clone())
    } else {
        spider
    };
    let crawl = spider.crawl(start_url).await?;
    info!(
        "Discovered {} injection points across {} pages",
        crawl.injection_points.len(),
        crawl.visited_pages.len()
    );

    // Phase 2+: Run scan phases
    run_scan_phases(detector, crawl, pipeline_config).await
}

/// Full automatic scan using headless browser for SPA support.
///
/// This variant uses Chrome/CDP to execute JavaScript and discover
/// injection points in dynamic SPAs (React, Vue, Angular, etc.).
///
/// Falls back to regex-based spider if Chrome is not available.
///
/// # Arguments
/// * `start_url`        — Entry point for the crawler.
/// * `detector`         — Pre-configured `SqliDetector`.
/// * `crawler_config`   — Crawler settings including headless config.
/// * `pipeline_config`  — Pipeline settings.
pub async fn auto_scan_headless(
    start_url: &str,
    detector: SqliDetector,
    crawler_config: Option<crawler::CrawlerConfig>,
    pipeline_config: Option<pipeline::PipelineConfig>,
) -> Result<Vec<pipeline::PipelineResult>> {
    let crawler_config = crawler_config.unwrap_or_default();
    let pipeline_config = pipeline_config.unwrap_or_default();

    // Note: Headless crawler is Pro-only feature
    // In Core, we always use the regex-based spider
    if crawler_config.headless {
        warn!("Headless crawler is a Pro feature. Using regex-based crawler. Upgrade to SQX Pro for SPA support.");
    }
    
    let crawl_result = {
        let spider = crawler::Spider::new(
            detector.client.clone(),
            crawler_config,
            detector.config.user_agent.clone(),
        );
        let spider = if let Some(ref session) = detector.session {
            spider.with_session(session.clone())
        } else {
            spider
        };
        spider.crawl(start_url).await?
    };

    info!(
        "Discovered {} injection points across {} pages",
        crawl_result.injection_points.len(),
        crawl_result.visited_pages.len()
    );

    // Phase 2+: Same as regular auto_scan
    run_scan_phases(detector, crawl_result, pipeline_config).await
}

/// Run scan phases (Phase 2, 3, 4) after crawling.
/// Extracted to avoid code duplication between auto_scan and auto_scan_headless.
async fn run_scan_phases(
    detector: SqliDetector,
    crawl: crawler::CrawlResult,
    pipeline_config: pipeline::PipelineConfig,
) -> Result<Vec<pipeline::PipelineResult>> {
    // Phase 2: Scan each injection point
    let mut all_results: Vec<pipeline::PipelineResult> = Vec::new();

    for point in &crawl.injection_points {
        let pipe = pipeline::Pipeline::new(detector.clone(), pipeline_config.clone());
        match point.method {
            crawler::HttpMethod::Get => match pipe.run(&point.url, None, None).await {
                Ok(result) => all_results.push(result),
                Err(e) => warn!("GET scan failed for {}: {}", point.url, e),
            },
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

    // Phase 3: scan visited pages that have no explicit injection points.
    let covered: std::collections::HashSet<String> = crawl
        .injection_points
        .iter()
        .map(|p| {
            reqwest::Url::parse(&p.url)
                .map(|mut u| {
                    u.set_query(None);
                    u.to_string()
                })
                .unwrap_or_else(|_| p.url.clone())
        })
        .collect();

    let phase3_detector = {
        let mut cfg = detector.config.clone();
        cfg.techniques = vec![
            crate::sqx::models::SqliTechnique::ErrorBased,
            crate::sqx::models::SqliTechnique::BooleanBlind,
        ];
        let mut phase3 = crate::sqx::detector::SqliDetector::with_config(cfg)
            .unwrap_or_else(|_| detector.clone());
        if let Some(ref session) = detector.session {
            phase3 = phase3.with_session(session.clone());
        }
        // Pass OOB server to phase 3 detector if configured (Pro feature)
        if let Some(ref oob_server) = detector.oob_server {
            phase3 = phase3.with_oob_dyn(oob_server.clone());
        }
        if let Some(ref token) = detector.cancel_token {
            phase3 = phase3.with_cancel_token(token.clone());
        }
        phase3
    };

    for page_url in &crawl.visited_pages {
        if covered.contains(page_url) {
            continue;
        }
        debug!(
            "Phase 3: fuzzing common params on parameterless page {}",
            page_url
        );
        let pipe = pipeline::Pipeline::new(phase3_detector.clone(), pipeline_config.clone());
        match pipe.run(page_url, None, None).await {
            Ok(result) => {
                if !result.findings.is_empty() {
                    all_results.push(result);
                }
            }
            Err(e) => warn!("Param-fuzz scan failed for {}: {}", page_url, e),
        }
    }

    // Note: Second-order detection is a Pro feature
    // In Core, we focus on direct SQL injection detection
    
    Ok(all_results)
}
