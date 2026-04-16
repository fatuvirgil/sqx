//! SQX — SQL Injection Detection & Exploitation Engine
//! Re-exports all public types from sub-modules.

pub mod models;
pub mod http;
pub mod similarity;
pub mod stealth;
pub mod payload_fetcher;
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

    // Phase 1: Crawl
    let spider = crawler::Spider::new(
        detector.client.clone(),
        crawler_config,
        detector.config.user_agent.clone(),
    );
    let crawl = spider.crawl(start_url).await?;
    info!(
        "Discovered {} injection points across {} pages",
        crawl.injection_points.len(),
        crawl.visited_pages.len()
    );

    // Phase 2: Scan each injection point
    let mut all_results: Vec<pipeline::PipelineResult> = Vec::new();

    for point in &crawl.injection_points {
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

    // Phase 3: scan visited pages that have no explicit injection points.
    //
    // Many apps (e.g. sqli-labs) respond to common GET params like ?id=1 but
    // don't embed those params in any HTML form or link — the crawler finds the
    // page URLs but produces zero injection points for them.  `test_url` already
    // contains a common-param fuzzing fallback for parameterless URLs, so we just
    // need to call it on each such page.
    let covered: std::collections::HashSet<String> = crawl
        .injection_points
        .iter()
        .map(|p| {
            reqwest::Url::parse(&p.url)
                .map(|mut u| { u.set_query(None); u.to_string() })
                .unwrap_or_else(|_| p.url.clone())
        })
        .collect();

    // Phase 3 uses a lightweight detector — only error-based + boolean-blind.
    // UNION and time-based are too slow for discovery on hundreds of param×page
    // combinations; they run in full scans once a vuln is confirmed.
    let phase3_detector = {
        let mut cfg = detector.config.clone();
        cfg.techniques = vec![
            crate::sqx::models::SqliTechnique::ErrorBased,
            crate::sqx::models::SqliTechnique::BooleanBlind,
        ];
        crate::sqx::detector::SqliDetector::with_config(cfg)
            .unwrap_or_else(|_| detector.clone())
    };

    for page_url in &crawl.visited_pages {
        if covered.contains(page_url) {
            continue;
        }
        debug!("Phase 3: fuzzing common params on parameterless page {}", page_url);
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

    // Phase 4: Second-order detection & Auto-provisioning
    info!("Phase 4: Second-order SQL injection discovery");
    
    // 1. Find registration forms
    let reg_forms: Vec<_> = crawl.injection_points.iter()
        .filter(|p| p.form_type == Some(models::FormType::Registration))
        .collect();

    for reg_point in reg_forms {
        // 2. Auto-provision test user
        if let Ok(provision) = detector.auto_provision(reg_point).await {
            if provision.success {
                // 3. Configure session with these credentials for subsequent discovery
                let mut auth_config = session::AuthConfig {
                    login_url: String::new(),
                    method: "form".to_string(),
                    credentials: std::collections::HashMap::new(),
                    basic_username: None,
                    basic_password: None,
                    bearer_token: None,
                    success_indicator: None,
                };
                
                // Find a login form to use these credentials
                let login_point = crawl.injection_points.iter()
                    .find(|p| p.form_type == Some(models::FormType::Login));
                
                if let Some(lp) = login_point {
                    auth_config.login_url = lp.url.clone();
                    for param in &lp.parameters {
                        let val = match param.name.to_lowercase().as_str() {
                            "username" | "user" | "login" => Some(provision.username.clone()),
                            "password" | "pass" | "pwd" => Some(provision.password.clone()),
                            _ => None,
                        };
                        if let Some(v) = val {
                            auth_config.credentials.insert(param.name.clone(), v);
                        }
                    }

                    // Attach session to a dedicated discovery detector
                    let sess_mgr = Arc::new(session::SessionManager::new(session::SessionConfig {
                        auth: Some(auth_config),
                        ..Default::default()
                    }));
                    
                    let discovery_detector = detector.clone().with_session(sess_mgr);
                    if let Ok(_) = discovery_detector.ensure_authenticated().await {
                        // 4. Discover candidates
                        let candidates = discovery_detector.discover_second_order_candidates(&crawl, &provision).await;
                        for candidate in candidates {
                            // 5. Test each candidate
                            let second_order_results = discovery_detector.test_second_order(&candidate).await;
                            if !second_order_results.is_empty() {
                                all_results.push(pipeline::PipelineResult::new(
                                    second_order_results,
                                    None,
                                    1,
                                    discovery_detector.request_count(),
                                    0.0,
                                ));
                            }
                        }
                    }
                }
            }
        }
    }

    Ok(all_results)
}
