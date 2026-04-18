use std::sync::Arc;

use sqx_core::sqx::{
    SqliConfig, SqliDetector, SqliTechnique, TamperChain, ai_advisor::AiAdvisorConfig,
    crawler::CrawlerConfig, pipeline::PipelineConfig, session::SessionManager,
};

// Note: OOB server is Pro-only
// use sqx_core::oob::{OobServer, OobServerConfig};

use crate::commands::reporting::print_or_write_findings;

// Note: OOB server is Pro-only
// async fn build_oob_server(domain: Option<String>, port: u16) -> Option<Arc<OobServer>> {
//     ...
// }

async fn build_oob_server(_domain: Option<String>, _port: u16) -> Option<Arc<()>> {
    eprintln!("[!] OOB server is a Pro feature. Upgrade to SQX Pro for OOB support.");
    None
}

fn parse_techniques(tech: Option<Vec<String>>) -> Vec<SqliTechnique> {
    match tech {
        None => vec![
            SqliTechnique::ErrorBased,
            SqliTechnique::BooleanBlind,
            SqliTechnique::UnionBased,
            SqliTechnique::TimeBased,
            SqliTechnique::StackedQueries,
        ],
        Some(list) => list
            .iter()
            .filter_map(|t| match t.to_lowercase().as_str() {
                "error" => Some(SqliTechnique::ErrorBased),
                "blind" => Some(SqliTechnique::BooleanBlind),
                "union" => Some(SqliTechnique::UnionBased),
                "time" => Some(SqliTechnique::TimeBased),
                "stacked" => Some(SqliTechnique::StackedQueries),
                "oob" => Some(SqliTechnique::OutOfBand),
                _ => None,
            })
            .collect(),
    }
}

fn build_detector(
    techniques: Vec<SqliTechnique>,
    delay: u64,
    timeout: u64,
    // oob_server: Option<Arc<OobServer>>,  // Pro-only
    ai_advisor: Option<AiAdvisorConfig>,
    param_wordlist: Option<Vec<String>>,
    proxy: Option<String>,
    session: Option<Arc<SessionManager>>,
) -> SqliDetector {
    let config = SqliConfig {
        techniques,
        delay_ms: delay,
        timeout_secs: timeout,
        ai_advisor: ai_advisor.unwrap_or_default(),
        param_wordlist: param_wordlist.unwrap_or_else(|| SqliConfig::default().param_wordlist),
        proxy,
        ..SqliConfig::default()
    };
    let mut detector = SqliDetector::with_config(config).expect("Failed to build HTTP client");
    // OOB server is Pro-only
    // if let Some(srv) = oob_server {
    //     detector = detector.with_oob_server(srv);
    // }
    if let Some(sess) = session {
        detector = detector.with_session(sess);
    }
    detector
}

pub(crate) fn build_user_tamper_chain(tamper: Option<Vec<String>>) -> Option<TamperChain> {
    let names: Vec<String> = tamper
        .unwrap_or_default()
        .into_iter()
        .map(|name| name.trim().to_string())
        .filter(|name| !name.is_empty())
        .collect();
    if names.is_empty() {
        return None;
    }
    let refs: Vec<&str> = names.iter().map(|s| s.as_str()).collect();
    let chain = TamperChain::from_names(&refs);
    if chain.is_empty() { None } else { Some(chain) }
}

pub(crate) fn auto_techniques(oob: bool) -> Vec<SqliTechnique> {
    let mut techniques = vec![
        SqliTechnique::ErrorBased,
        SqliTechnique::BooleanBlind,
        SqliTechnique::UnionBased,
        SqliTechnique::TimeBased,
        SqliTechnique::StackedQueries,
    ];
    if oob {
        techniques.push(SqliTechnique::OutOfBand);
    }
    techniques
}

fn read_wordlist(path: Option<String>) -> Option<Vec<String>> {
    path.map(|path| {
        std::fs::read_to_string(&path)
            .map(|s| {
                s.lines()
                    .map(|l| l.trim().to_string())
                    .filter(|l| !l.is_empty())
                    .collect()
            })
            .unwrap_or_else(|e| {
                eprintln!("[!] Failed to read wordlist '{}': {}", path, e);
                Vec::new()
            })
    })
}

async fn ensure_auth_if_configured(detector: &SqliDetector, context: Option<&str>) {
    match detector.ensure_authenticated().await {
        Ok(()) => {
            if detector.has_auth_session() {
                match context {
                    Some(label) => eprintln!("[+] [{}] Login successful", label),
                    None => eprintln!("[+] Login successful"),
                }
            }
        }
        Err(e) => match context {
            Some(label) => eprintln!(
                "⚠ [{}] Login failed — scanning unauthenticated: {}",
                label, e
            ),
            None => eprintln!("⚠ Login failed — scanning unauthenticated: {}", e),
        },
    }
}

pub(crate) async fn run_scan(
    url: String,
    smart: bool,
    tech: Option<Vec<String>>,
    tamper: Option<Vec<String>>,
    oob: bool,
    oob_domain: Option<String>,
    oob_port: u16,
    output: String,
    out_file: Option<String>,
    delay: u64,
    timeout: u64,
    post_body: Option<String>,
    post_ct: Option<String>,
    param_wordlist: Option<String>,
    proxy: Option<String>,
    session: Option<Arc<SessionManager>>,
    ai_cfg: Option<AiAdvisorConfig>,
) {
    let oob_server = if oob {
        build_oob_server(oob_domain, oob_port).await
    } else {
        None
    };

    let mut techniques = parse_techniques(tech);
    if oob && !techniques.contains(&SqliTechnique::OutOfBand) {
        techniques.push(SqliTechnique::OutOfBand);
    }
    let tamper_chain = build_user_tamper_chain(tamper);

    let wordlist = read_wordlist(param_wordlist);
    let detector = build_detector(
        techniques, delay, timeout, /* oob_server, */ ai_cfg, wordlist, proxy, session,
    );

    ensure_auth_if_configured(&detector, None).await;

    let findings = if smart {
        let result = match tamper_chain.as_ref() {
            Some(chain) => detector.scan_smart_with_tamper(&url, chain).await,
            None => detector.scan_smart(&url).await,
        };
        match result {
            Ok((profile, results)) => {
                if let Some(waf) = &profile.waf {
                    eprintln!(
                        "[*] WAF detected: {} (confidence {:.0}%)",
                        waf.name,
                        waf.confidence * 100.0
                    );
                }
                if let Some(dbms) = &profile.dbms_hint {
                    eprintln!("[*] DBMS hint: {}", dbms);
                }
                results
            }
            Err(e) => {
                eprintln!("[!] Scan error: {}", e);
                return;
            }
        }
    } else if let Some(body) = post_body {
        let ct = post_ct.as_deref().unwrap_or("form");
        let result = match tamper_chain.as_ref() {
            Some(chain) => {
                detector
                    .test_url_post_with_tamper(&url, &body, ct, chain)
                    .await
            }
            None => detector.test_url_post(&url, &body, ct).await,
        };
        match result {
            Ok(r) => r,
            Err(e) => {
                eprintln!("[!] POST scan error: {}", e);
                return;
            }
        }
    } else {
        let result = match tamper_chain.as_ref() {
            Some(chain) => detector.test_url_with_tamper(&url, chain).await,
            None => detector.test_url(&url).await,
        };
        match result {
            Ok(r) => r,
            Err(e) => {
                eprintln!("[!] Scan error: {}", e);
                return;
            }
        }
    };

    print_or_write_findings(&findings, &output, out_file.as_deref(), Some(&url));
}

pub(crate) async fn run_auto(
    url: String,
    smart: bool,
    oob: bool,
    oob_domain: Option<String>,
    max_pages: usize,
    max_depth: usize,
    output: String,
    out_file: Option<String>,
    param_wordlist: Option<String>,
    proxy: Option<String>,
    session: Option<Arc<SessionManager>>,
    ai_cfg: Option<AiAdvisorConfig>,
    headless: bool,
    chrome_path: Option<String>,
    render_wait: u64,
) {
    let oob_server = if oob {
        build_oob_server(oob_domain, 8080).await
    } else {
        None
    };

    let wordlist = read_wordlist(param_wordlist);
    let detector = build_detector(
        auto_techniques(oob),
        100,
        30,
        /* oob_server, */
        ai_cfg,
        wordlist,
        proxy,
        session,
    );

    ensure_auth_if_configured(&detector, None).await;

    // Note: Headless crawler is Pro-only
    if headless {
        eprintln!("[!] Headless crawler is a Pro feature. Using regex-based crawler.");
        eprintln!("    Upgrade to SQX Pro for SPA/React/Vue/Angular support.");
    }

    let crawler_config = CrawlerConfig {
        max_pages,
        max_depth,
        headless: false,  // Pro-only
        ..CrawlerConfig::default()
    };
    let pipeline_config = PipelineConfig { smart_scan: smart };

    eprintln!(
        "[*] Starting auto scan: {} (max_pages={}, max_depth={}, headless={})",
        url, max_pages, max_depth, false
    );

    // Note: Headless scan is Pro-only
    let scan_result = sqx_core::sqx::auto_scan(&url, detector, Some(crawler_config), Some(pipeline_config)).await;

    match scan_result
    {
        Ok(results) => {
            let total_findings: usize = results.iter().map(|r| r.findings.len()).sum();
            eprintln!(
                "[+] Scan complete: {} injection points found",
                total_findings
            );

            match output.as_str() {
                "json" | "sarif" | "markdown" => {
                    let all_findings: Vec<sqx_core::sqx::SqliTestResult> =
                        results.iter().flat_map(|r| r.findings.clone()).collect();
                    if !all_findings.is_empty() {
                        print_or_write_findings(
                            &all_findings,
                            &output,
                            out_file.as_deref(),
                            Some(&url),
                        );
                    }
                }
                _ => {
                    for (i, result) in results.iter().enumerate() {
                        if !result.findings.is_empty() {
                            let result_url = result
                                .profile
                                .as_ref()
                                .map(|p| p.url.as_str())
                                .unwrap_or(&url);
                            eprintln!(
                                "  [{}] {} findings — {:.1}s",
                                i + 1,
                                result.findings.len(),
                                result.elapsed_secs
                            );
                            print_or_write_findings(
                                &result.findings,
                                &output,
                                None,
                                Some(result_url),
                            );
                        }
                    }
                }
            }
        }
        Err(e) => eprintln!("[!] Auto scan error: {}", e),
    }
}

pub(crate) async fn run_batch(
    targets_file: String,
    concurrency: usize,
    smart: bool,
    tech: Option<Vec<String>>,
    tamper: Option<Vec<String>>,
    delay: u64,
    timeout: u64,
    output: String,
    out_file: Option<String>,
    param_wordlist: Option<String>,
    proxy: Option<String>,
    session: Option<Arc<SessionManager>>,
) {
    let raw = match std::fs::read_to_string(&targets_file) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("[!] Cannot read targets file '{}': {}", targets_file, e);
            return;
        }
    };

    let urls: Vec<String> = raw
        .lines()
        .map(|l| l.trim())
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(|l| l.to_string())
        .collect();

    if urls.is_empty() {
        eprintln!("[-] No targets found in '{}'", targets_file);
        return;
    }

    // Core limitation: max 5 concurrent batch scans (Pro has unlimited)
    const MAX_CORE_CONCURRENCY: usize = 5;
    let actual_concurrency = concurrency.min(MAX_CORE_CONCURRENCY);
    
    if concurrency > MAX_CORE_CONCURRENCY {
        eprintln!(
            "[!] Concurrency limited to {} in Core (requested: {}). Upgrade to Pro for unlimited.",
            MAX_CORE_CONCURRENCY,
            concurrency
        );
    }
    
    eprintln!(
        "[*] Batch scan: {} target(s), concurrency={}",
        urls.len(),
        actual_concurrency
    );

    let techniques = parse_techniques(tech);
    let wordlist = read_wordlist(param_wordlist);
    let tamper_chain = Arc::new(build_user_tamper_chain(tamper));

    let sem = Arc::new(tokio::sync::Semaphore::new(actual_concurrency));
    let mut join_set: tokio::task::JoinSet<(String, Vec<sqx_core::sqx::SqliTestResult>)> =
        tokio::task::JoinSet::new();

    for url in urls {
        let permit = sem.clone().acquire_owned().await.unwrap();
        let url_clone = url.clone();
        let techniques_clone = techniques.clone();
        let delay_clone = delay;
        let timeout_clone = timeout;
        let smart_clone = smart;
        let wordlist_clone = wordlist.clone();
        let proxy_clone = proxy.clone();
        let session_clone = session.clone();
        let tamper_chain_clone = tamper_chain.clone();

        join_set.spawn(async move {
            let _permit = permit;

            let config = SqliConfig {
                techniques: techniques_clone,
                delay_ms: delay_clone,
                timeout_secs: timeout_clone,
                param_wordlist: wordlist_clone
                    .unwrap_or_else(|| SqliConfig::default().param_wordlist),
                proxy: proxy_clone,
                ..SqliConfig::default()
            };

            let mut detector = match SqliDetector::with_config(config) {
                Ok(d) => d,
                Err(e) => {
                    eprintln!("[!] {} — detector error: {}", url_clone, e);
                    return (url_clone, vec![]);
                }
            };

            if let Some(ref sess) = session_clone {
                detector = detector.with_session(sess.clone());
            }

            ensure_auth_if_configured(&detector, Some(&url_clone)).await;

            let findings = if smart_clone {
                let result = match tamper_chain_clone.as_ref().as_ref() {
                    Some(chain) => detector.scan_smart_with_tamper(&url_clone, chain).await,
                    None => detector.scan_smart(&url_clone).await,
                };
                match result {
                    Ok((_, r)) => r,
                    Err(e) => {
                        eprintln!("[!] {} — {}", url_clone, e);
                        vec![]
                    }
                }
            } else {
                let result = match tamper_chain_clone.as_ref().as_ref() {
                    Some(chain) => detector.test_url_with_tamper(&url_clone, chain).await,
                    None => detector.test_url(&url_clone).await,
                };
                match result {
                    Ok(r) => r,
                    Err(e) => {
                        eprintln!("[!] {} — {}", url_clone, e);
                        vec![]
                    }
                }
            };

            if !findings.is_empty() {
                eprintln!("[VULN] {} — {} finding(s)", url_clone, findings.len());
            } else {
                eprintln!("[ ok ] {}", url_clone);
            }

            (url_clone, findings)
        });
    }

    let mut all_findings: Vec<(String, Vec<sqx_core::sqx::SqliTestResult>)> = Vec::new();
    while let Some(res) = join_set.join_next().await {
        if let Ok(entry) = res {
            all_findings.push(entry);
        }
    }

    let total_vulns: usize = all_findings.iter().map(|(_, f)| f.len()).sum();
    let vuln_count = all_findings.iter().filter(|(_, f)| !f.is_empty()).count();
    eprintln!(
        "[+] Batch complete — {}/{} targets vulnerable, {} total findings",
        vuln_count,
        all_findings.len(),
        total_vulns
    );

    let content = match output.as_str() {
        "json" => {
            let map: std::collections::HashMap<&str, &Vec<sqx_core::sqx::SqliTestResult>> =
                all_findings.iter().map(|(u, f)| (u.as_str(), f)).collect();
            serde_json::to_string_pretty(&map).unwrap_or_default()
        }
        "sarif" => serde_json::to_string_pretty(
            &sqx_core::sqx::reporting::SarifReport::from_batch(&all_findings),
        )
        .unwrap_or_default(),
        "markdown" => {
            eprintln!("[!] Markdown output is a Pro feature. Use 'json' or 'text', or upgrade to SQX Pro.");
            std::process::exit(1);
        }
        _ => {
            let mut out = String::new();
            for (url, findings) in &all_findings {
                if findings.is_empty() {
                    continue;
                }
                out.push_str(&format!("=== {} ===\n", url));
                for f in findings {
                    out.push_str(&format!(
                        "  [VULN] param={} technique={} confidence={:.0}%\n  payload: {}\n  evidence: {}\n",
                        f.parameter, f.technique, f.confidence * 100.0, f.payload, f.evidence,
                    ));
                }
            }
            if out.is_empty() {
                out.push_str("[-] No SQL injection found in any target.\n");
            }
            out
        }
    };

    match out_file.as_deref() {
        Some(path) => {
            if let Err(e) = std::fs::write(path, &content) {
                eprintln!("[!] Failed to write output: {}", e);
            } else {
                eprintln!("[+] Output written to {}", path);
            }
        }
        None => print!("{}", content),
    }
}
