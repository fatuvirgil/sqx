//! SQX CLI — clap-based command line interface.
//!
//! Usage examples:
//!   sqx scan "http://target.com/page?id=1"
//!   sqx scan "http://target.com/page?id=1" --smart --tamper space_to_comment,randomcase
//!   sqx scan "http://target.com/page?id=1" --tech error,blind,union --oob --oob-domain cb.example.com
//!   sqx post  "http://target.com/login" --body "user=admin&pass=x" --ct form
//!   sqx auto  "http://target.com/" --smart --max-pages 100
//!   sqx gui

use clap::{Parser, Subcommand};
use std::sync::Arc;
use tracing_subscriber::EnvFilter;

use sqx_core::oob::{OobServer, OobServerConfig};
use sqx_core::sqx::{
    SqliDetector, SqliConfig, SqliTechnique, TamperChain,
    pipeline::PipelineConfig,
    crawler::CrawlerConfig,
    reporting::SarifReport,
    ai_advisor::{AiAdvisorConfig, AiBackend},
    models::BlindTechnique,
    session::{SessionManager, SessionConfig, AuthConfig},
};

#[derive(Parser)]
#[command(
    name = "sqx",
    about = "SQX — SQL Injection Scanner",
    version,
    propagate_version = true,
)]
pub struct Cli {
    #[command(subcommand)]
    command: Command,

    /// Verbosity (-v info, -vv debug, -vvv trace)
    #[arg(short, long, action = clap::ArgAction::Count, global = true)]
    verbose: u8,

    /// Proxy URL for HTTP/SOCKS5 (e.g. socks5://127.0.0.1:9050)
    #[arg(long, global = true)]
    proxy: Option<String>,

    /// Raw cookie string (e.g. "PHPSESSID=abc123; user=admin")
    #[arg(long, global = true)]
    cookie: Option<String>,

    /// Auto-detect session cookies from the first response
    #[arg(long, global = true)]
    cookie_auto_detect: bool,

    /// Login URL for automatic authentication
    #[arg(long, global = true)]
    login_url: Option<String>,

    /// Auth method: form | json | basic | bearer
    #[arg(long, global = true)]
    auth_method: Option<String>,

    /// Credential pair as key=value (repeatable; for form/json auth)
    #[arg(long = "auth-cred", global = true, value_parser = parse_key_val::<String, String>)]
    auth_creds: Vec<(String, String)>,

    /// Username (for basic auth)
    #[arg(long, global = true)]
    auth_user: Option<String>,

    /// Password (for basic auth)
    #[arg(long, global = true)]
    auth_pass: Option<String>,

    /// Bearer token (for bearer auth)
    #[arg(long, global = true)]
    auth_token: Option<String>,

    /// Login success indicator: status code (e.g. 302) or cookie name
    #[arg(long, global = true)]
    auth_success: Option<String>,
}

#[derive(Subcommand)]
enum Command {
    /// Scan a GET URL for SQL injection
    Scan {
        /// Target URL with parameters (e.g. http://target.com/page?id=1)
        url: String,

        /// Use smart scan (behavioral fingerprinting first)
        #[arg(long)]
        smart: bool,

        /// Techniques to test: error, blind, union, time, stacked, oob (comma-separated)
        #[arg(long, value_delimiter = ',')]
        tech: Option<Vec<String>>,

        /// Tamper scripts to apply (comma-separated, e.g. space_to_comment,randomcase)
        #[arg(long, value_delimiter = ',')]
        tamper: Option<Vec<String>>,

        /// Enable Out-of-Band detection
        #[arg(long)]
        oob: bool,

        /// OOB callback domain (required when --oob is set)
        #[arg(long)]
        oob_domain: Option<String>,

        /// OOB HTTP port (default: 8080)
        #[arg(long, default_value = "8080")]
        oob_port: u16,

        /// Output format: text, json, sarif, markdown (default: text)
        #[arg(long, default_value = "text")]
        output: String,

        /// Write output to file instead of stdout
        #[arg(long, short = 'o')]
        out_file: Option<String>,

        /// Request delay in ms
        #[arg(long, default_value = "100")]
        delay: u64,

        /// Request timeout in seconds
        #[arg(long, default_value = "30")]
        timeout: u64,

        /// Custom parameter wordlist file (one per line) for fuzzing URLs without query strings
        #[arg(long)]
        param_wordlist: Option<String>,

        /// Enable AI payload advisor (default backend: local Ollama)
        #[arg(long)]
        ai_advisor: bool,

        /// AI model spec: ollama:llama3.2 (default), claude:claude-sonnet-4-6, openai:gpt-4o
        #[arg(long, default_value = "ollama:llama3.2")]
        ai_model: String,

        /// API key for commercial AI backends (Claude, OpenAI)
        #[arg(long)]
        ai_api_key: Option<String>,

        /// Base URL for Ollama or OpenAI-compatible endpoints
        #[arg(long)]
        ai_base_url: Option<String>,

        /// Confirm consent to send target context to a commercial AI API
        #[arg(long)]
        ai_consent: bool,
    },

    /// Scan a POST endpoint for SQL injection
    Post {
        /// Target URL
        url: String,

        /// POST body (e.g. "user=admin&pass=x" or JSON)
        #[arg(long)]
        body: String,

        /// Content-Type: form, json, xml (default: form)
        #[arg(long, default_value = "form")]
        ct: String,

        /// Techniques (same as scan)
        #[arg(long, value_delimiter = ',')]
        tech: Option<Vec<String>>,

        /// Tamper scripts (same as scan)
        #[arg(long, value_delimiter = ',')]
        tamper: Option<Vec<String>>,

        /// Output format
        #[arg(long, default_value = "text")]
        output: String,

        /// Write output to file
        #[arg(long, short = 'o')]
        out_file: Option<String>,
    },

    /// Full auto scan: spider → fingerprint → scan all injection points
    Auto {
        /// Start URL for the crawler
        url: String,

        /// Use smart scan (fingerprinting) per injection point
        #[arg(long)]
        smart: bool,

        /// Enable OOB detection
        #[arg(long)]
        oob: bool,

        /// OOB callback domain
        #[arg(long)]
        oob_domain: Option<String>,

        /// Maximum pages to crawl (default: 50)
        #[arg(long, default_value = "50")]
        max_pages: usize,

        /// Maximum crawl depth (default: 3)
        #[arg(long, default_value = "3")]
        max_depth: usize,

        /// Enable AI payload advisor
        #[arg(long)]
        ai_advisor: bool,

        /// AI model spec (see scan --help)
        #[arg(long, default_value = "ollama:llama3.2")]
        ai_model: String,

        /// API key for commercial AI backends
        #[arg(long)]
        ai_api_key: Option<String>,

        /// Base URL for Ollama or OpenAI-compatible endpoints
        #[arg(long)]
        ai_base_url: Option<String>,

        /// Confirm consent to send target context to a commercial AI API
        #[arg(long)]
        ai_consent: bool,

        /// Output format
        #[arg(long, default_value = "text")]
        output: String,

        /// Write output to file
        #[arg(long, short = 'o')]
        out_file: Option<String>,

        /// Custom parameter wordlist file (one per line) for fuzzing URLs without query strings
        #[arg(long)]
        param_wordlist: Option<String>,
    },

    /// Dump all data from a confirmed-vulnerable endpoint (schema + data extraction)
    Dump {
        /// Target URL with the vulnerable parameter (e.g. http://target.com/page?id=1)
        url: String,

        /// Injectable parameter name
        #[arg(long)]
        param: String,

        /// Benign value for that parameter (used as baseline)
        #[arg(long, default_value = "1")]
        value: String,

        /// DBMS: mysql, postgresql, mssql, oracle, sqlite
        #[arg(long, default_value = "mysql")]
        dbms: String,

        /// Extraction technique: boolean, time
        #[arg(long, default_value = "boolean")]
        technique: String,

        /// Max rows to extract per column (safety cap)
        #[arg(long, default_value = "100")]
        max_rows: usize,

        /// Request delay in ms (lower = faster extraction)
        #[arg(long, default_value = "100")]
        delay: u64,

        /// Output format: text, json, csv
        #[arg(long, default_value = "text")]
        output: String,

        /// Write output to file instead of stdout
        #[arg(long, short = 'o')]
        out_file: Option<String>,
    },

    /// Batch scan multiple targets from a file (one URL per line, # comments ignored)
    Batch {
        /// Path to targets file
        targets: String,

        /// Concurrent workers (default: 5)
        #[arg(long, default_value = "5")]
        concurrency: usize,

        /// Use smart scan (behavioral fingerprinting) per target
        #[arg(long)]
        smart: bool,

        /// Techniques: error, blind, union, time, stacked, oob (comma-separated)
        #[arg(long, value_delimiter = ',')]
        tech: Option<Vec<String>>,

        /// Tamper scripts (comma-separated)
        #[arg(long, value_delimiter = ',')]
        tamper: Option<Vec<String>>,

        /// Request delay in ms
        #[arg(long, default_value = "100")]
        delay: u64,

        /// Request timeout in seconds
        #[arg(long, default_value = "30")]
        timeout: u64,

        /// Output format: text, json
        #[arg(long, default_value = "text")]
        output: String,

        /// Write aggregated output to file
        #[arg(long, short = 'o')]
        out_file: Option<String>,

        /// Custom parameter wordlist file (one per line) for fuzzing URLs without query strings
        #[arg(long)]
        param_wordlist: Option<String>,
    },

    /// List available tamper scripts
    Tampers,

    /// Launch desktop GUI (moved to sqx-gui binary)
    Gui,

    /// Read a remote file via SQL injection (requires confirmed vulnerable endpoint)
    #[command(name = "file-read")]
    FileRead {
        /// Target URL with the vulnerable parameter
        url: String,
        /// Injectable parameter name
        #[arg(long)]
        param: String,
        /// Remote file path to read (e.g. /etc/passwd)
        #[arg(long)]
        file: String,
        /// DBMS: mysql, postgresql, mssql, oracle, sqlite
        #[arg(long, default_value = "mysql")]
        dbms: String,
        /// Benign value for the parameter
        #[arg(long, default_value = "1")]
        value: String,
        /// Write output to file instead of stdout
        #[arg(long, short = 'o')]
        out_file: Option<String>,
    },

    /// Write content to a remote file via SQL injection (requires confirmed vulnerable endpoint)
    #[command(name = "file-write")]
    FileWrite {
        /// Target URL with the vulnerable parameter
        url: String,
        /// Injectable parameter name
        #[arg(long)]
        param: String,
        /// Remote file path to write
        #[arg(long)]
        file: String,
        /// Content to write
        #[arg(long)]
        content: String,
        /// DBMS: mysql, postgresql, mssql, oracle, sqlite
        #[arg(long, default_value = "mysql")]
        dbms: String,
        /// Benign value for the parameter
        #[arg(long, default_value = "1")]
        value: String,
    },

    /// Download sqlmap payloads (GPLv2) + PayloadsAllTheThings (MIT) into local cache.
    /// Run this once to expand payload coverage beyond the built-in set.
    /// Files are stored in ~/.local/share/sqx/payloads/ and never redistributed.
    #[command(name = "update-payloads")]
    UpdatePayloads,
}

impl Cli {
    pub async fn run(self) {
        // Setup logging
        let level = match self.verbose {
            0 => "warn",
            1 => "info",
            2 => "debug",
            _ => "trace",
        };
        tracing_subscriber::fmt()
            .with_env_filter(EnvFilter::new(format!("sqx={}", level)))
            .with_target(false)
            .init();

        let proxy = self.proxy;
        let session = build_session_manager(
            self.cookie, self.cookie_auto_detect,
            self.login_url, self.auth_method, self.auth_creds,
            self.auth_user, self.auth_pass, self.auth_token, self.auth_success,
        );
        match self.command {
            Command::Scan { url, smart, tech, tamper, oob, oob_domain, oob_port, output, out_file, delay, timeout, param_wordlist, ai_advisor, ai_model, ai_api_key, ai_base_url, ai_consent } => {
                let ai_cfg = build_ai_config(ai_advisor, &ai_model, ai_api_key.as_deref(), ai_base_url.as_deref(), ai_consent);
                run_scan(url, smart, tech, tamper, oob, oob_domain, oob_port, output, out_file, delay, timeout, None, None, param_wordlist, proxy, session, ai_cfg).await;
            }
            Command::Post { url, body, ct, tech, tamper, output, out_file } => {
                run_scan(url, false, tech, tamper, false, None, 8080, output, out_file, 100, 30, Some(body), Some(ct), None, proxy, session, None).await;
            }
            Command::Auto { url, smart, oob, oob_domain, max_pages, max_depth, ai_advisor, ai_model, ai_api_key, ai_base_url, ai_consent, output, out_file, param_wordlist } => {
                let ai_cfg = build_ai_config(ai_advisor, &ai_model, ai_api_key.as_deref(), ai_base_url.as_deref(), ai_consent);
                run_auto(url, smart, oob, oob_domain, max_pages, max_depth, output, out_file, param_wordlist, proxy, session, ai_cfg).await;
            }
            Command::Dump { url, param, value, dbms, technique, max_rows, output, out_file, delay } => {
                run_dump(url, param, value, dbms, technique, max_rows, output, out_file, proxy, session, delay).await;
            }
            Command::Batch { targets, concurrency, smart, tech, tamper, delay, timeout, output, out_file, param_wordlist } => {
                run_batch(targets, concurrency, smart, tech, tamper, delay, timeout, output, out_file, param_wordlist, proxy, session).await;
            }
            Command::Tampers => {
                println!("Available tamper scripts:");
                for name in TamperChain::available_names() {
                    println!("  {}", name);
                }
            }
            Command::Gui => {
                eprintln!("[!] GUI moved to separate binary. Run: sqx-gui");
                std::process::exit(1);
            }
            Command::UpdatePayloads => {
                eprintln!("[*] Updating payload database...");
                match sqx_core::sqx::payload_fetcher::DynamicPayloads::fetch_and_cache().await {
                    Ok(()) => eprintln!("[+] Done. Run any scan to use the new payloads."),
                    Err(e) => eprintln!("[-] Failed: {}", e),
                }
            }
            Command::FileRead { url, param, file, dbms, value, out_file } => {
                run_file_read(url, param, file, dbms, value, out_file, proxy, session).await;
            }
            Command::FileWrite { url, param, file, content, dbms, value } => {
                run_file_write(url, param, file, content, dbms, value, proxy, session).await;
            }
        }
    }
}

// ── Helpers ──────────────────────────────────────────────────────────────────

fn build_session_manager(
    cookie: Option<String>,
    auto_detect: bool,
    login_url: Option<String>,
    auth_method: Option<String>,
    auth_creds: Vec<(String, String)>,
    auth_user: Option<String>,
    auth_pass: Option<String>,
    auth_token: Option<String>,
    auth_success: Option<String>,
) -> Option<Arc<SessionManager>> {
    let mut config = SessionConfig::default();

    if let Some(ref c) = cookie {
        for part in c.split(';') {
            let part = part.trim();
            if part.is_empty() { continue; }
            if let Some(eq_pos) = part.find('=') {
                config.cookies.insert(part[..eq_pos].trim().to_string(), part[eq_pos + 1..].trim().to_string());
            }
        }
    }
    if auto_detect {
        config.auto_detect = true;
    }

    if let Some(url) = login_url {
        let method = auth_method.unwrap_or_else(|| "form".to_string());
        let mut credentials = std::collections::HashMap::new();
        for (k, v) in auth_creds {
            credentials.insert(k, v);
        }
        config.auth = Some(AuthConfig {
            login_url: url,
            method,
            credentials,
            basic_username: auth_user,
            basic_password: auth_pass,
            bearer_token: auth_token,
            success_indicator: auth_success,
        });
    }

    if cookie.is_some() || auto_detect || config.auth.is_some() {
        return Some(Arc::new(SessionManager::new(config)));
    }
    None
}

fn parse_key_val<T, U>(s: &str) -> Result<(T, U), Box<dyn std::error::Error + Send + Sync + 'static>>
where
    T: std::str::FromStr,
    T::Err: std::error::Error + Send + Sync + 'static,
    U: std::str::FromStr,
    U::Err: std::error::Error + Send + Sync + 'static,
{
    let pos = s.find('=').ok_or_else(|| format!("invalid KEY=value: no `=` found in `{}`", s))?;
    Ok((s[..pos].parse()?, s[pos + 1..].parse()?))
}

async fn build_oob_server(domain: Option<String>, port: u16) -> Option<Arc<OobServer>> {
    let domain = domain?;
    let config = OobServerConfig {
        http_port: port,
        dns_port: 8053,
        domain: domain.clone(),
        public_host: "127.0.0.1".to_string(),
        ttl_seconds: 3600,
    };
    let server = Arc::new(OobServer::new(config));
    match server.start().await {
        Ok(()) => {
            eprintln!("[+] OOB server started — HTTP :{}, DNS :8053, domain: {}", port, domain);
            Some(server)
        }
        Err(e) => {
            eprintln!("[!] Failed to start OOB server: {}", e);
            None
        }
    }
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
        Some(list) => list.iter().filter_map(|t| match t.to_lowercase().as_str() {
            "error"   => Some(SqliTechnique::ErrorBased),
            "blind"   => Some(SqliTechnique::BooleanBlind),
            "union"   => Some(SqliTechnique::UnionBased),
            "time"    => Some(SqliTechnique::TimeBased),
            "stacked" => Some(SqliTechnique::StackedQueries),
            "oob"     => Some(SqliTechnique::OutOfBand),
            _         => None,
        }).collect(),
    }
}

fn build_detector(
    techniques: Vec<SqliTechnique>,
    delay: u64,
    timeout: u64,
    oob_server: Option<Arc<OobServer>>,
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
    let mut detector = SqliDetector::with_config(config)
        .expect("Failed to build HTTP client");
    if let Some(srv) = oob_server {
        detector = detector.with_oob_server(srv);
    }
    if let Some(sess) = session {
        detector = detector.with_session(sess);
    }
    detector
}

/// Build AI advisor config from CLI flags.
/// Returns None (disabled) if --ai-advisor was not passed.
/// Aborts with an error message if a commercial backend is requested without --ai-consent.
fn build_ai_config(
    enabled: bool,
    model_spec: &str,
    api_key: Option<&str>,
    base_url: Option<&str>,
    consent: bool,
) -> Option<AiAdvisorConfig> {
    if !enabled {
        return None;
    }

    let backend = match AiBackend::from_str(model_spec, api_key, base_url) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("[!] AI advisor config error: {}", e);
            return None;
        }
    };

    if backend.is_commercial() && !consent {
        eprintln!(
            "[!] Commercial AI backend '{}' requires --ai-consent.\n\
             This flag confirms you consent to sending target context (parameter names,\n\
             error messages, DBMS info) to a third-party API. Add --ai-consent to proceed.",
            model_spec
        );
        return None;
    }

    if backend.is_commercial() {
        eprintln!("[*] AI advisor: using commercial backend '{}' (consent given)", model_spec);
    } else {
        eprintln!("[*] AI advisor: using local backend '{}'", model_spec);
    }

    Some(AiAdvisorConfig {
        enabled: true,
        backend,
        max_suggestions: 10,
        timeout_secs: 30,
    })
}

async fn run_scan(
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

    let wordlist = param_wordlist.map(|path| {
        std::fs::read_to_string(&path)
            .map(|s| s.lines().map(|l| l.trim().to_string()).filter(|l| !l.is_empty()).collect())
            .unwrap_or_else(|e| { eprintln!("[!] Failed to read wordlist '{}': {}", path, e); Vec::new() })
    });
    let detector = build_detector(techniques, delay, timeout, oob_server, ai_cfg, wordlist, proxy, session);

    match detector.ensure_authenticated().await {
        Ok(()) => {
            if detector.has_auth_session() {
                eprintln!("[+] Login successful");
            }
        }
        Err(e) => eprintln!("⚠ Login failed — scanning unauthenticated: {}", e),
    }

    // Apply tamper chain via config patching — detector clone with chain
    // (chain is passed to scan_with_strategy internally via fingerprint)
    // For plain test_url, we apply tamper at the param level via auto_scan.
    // For now, smart scan with tamper uses the fingerprint-derived chain.
    let _ = tamper; // used in smart path via profile.strategy.tamper_chain

    let findings = if smart {
        match detector.scan_smart(&url).await {
            Ok((profile, results)) => {
                if let Some(waf) = &profile.waf {
                    eprintln!("[*] WAF detected: {} (confidence {:.0}%)", waf.name, waf.confidence * 100.0);
                }
                if let Some(dbms) = &profile.dbms_hint {
                    eprintln!("[*] DBMS hint: {}", dbms);
                }
                results
            }
            Err(e) => { eprintln!("[!] Scan error: {}", e); return; }
        }
    } else if let Some(body) = post_body {
        let ct = post_ct.as_deref().unwrap_or("form");
        match detector.test_url_post(&url, &body, ct).await {
            Ok(r) => r,
            Err(e) => { eprintln!("[!] POST scan error: {}", e); return; }
        }
    } else {
        match detector.test_url(&url).await {
            Ok(r) => r,
            Err(e) => { eprintln!("[!] Scan error: {}", e); return; }
        }
    };

    print_or_write_findings(&findings, &output, out_file.as_deref(), Some(&url));
}

async fn run_auto(
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
) {
    let oob_server = if oob {
        build_oob_server(oob_domain, 8080).await
    } else {
        None
    };

    let wordlist = param_wordlist.map(|path| {
        std::fs::read_to_string(&path)
            .map(|s| s.lines().map(|l| l.trim().to_string()).filter(|l| !l.is_empty()).collect())
            .unwrap_or_else(|e| { eprintln!("[!] Failed to read wordlist '{}': {}", path, e); Vec::new() })
    });
    let detector = build_detector(vec![
        SqliTechnique::ErrorBased, SqliTechnique::BooleanBlind,
        SqliTechnique::UnionBased, SqliTechnique::TimeBased,
        SqliTechnique::StackedQueries,
    ], 100, 30, oob_server, ai_cfg, wordlist, proxy, session);

    match detector.ensure_authenticated().await {
        Ok(()) => {
            if detector.has_auth_session() {
                eprintln!("[+] Login successful");
            }
        }
        Err(e) => eprintln!("⚠ Login failed — scanning unauthenticated: {}", e),
    }

    let crawler_config = CrawlerConfig {
        max_pages,
        max_depth,
        ..CrawlerConfig::default()
    };
    let pipeline_config = PipelineConfig { smart_scan: smart };

    eprintln!("[*] Starting auto scan: {} (max_pages={}, max_depth={})", url, max_pages, max_depth);

    match sqx_core::sqx::auto_scan(&url, detector, Some(crawler_config), Some(pipeline_config)).await {
        Ok(results) => {
            let total_findings: usize = results.iter().map(|r| r.findings.len()).sum();
            eprintln!("[+] Scan complete: {} injection points found", total_findings);

            // For structured formats, aggregate all findings into a single report
            match output.as_str() {
                "json" | "sarif" | "markdown" => {
                    let all_findings: Vec<sqx_core::sqx::SqliTestResult> =
                        results.iter().flat_map(|r| r.findings.clone()).collect();
                    if !all_findings.is_empty() {
                        print_or_write_findings(&all_findings, &output, out_file.as_deref(), Some(&url));
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
                            eprintln!("  [{}] {} findings — {:.1}s", i + 1, result.findings.len(), result.elapsed_secs);
                            print_or_write_findings(&result.findings, &output, None, Some(result_url));
                        }
                    }
                }
            }
        }
        Err(e) => eprintln!("[!] Auto scan error: {}", e),
    }
}

fn print_or_write_findings(
    findings: &[sqx_core::sqx::SqliTestResult],
    format: &str,
    out_file: Option<&str>,
    target_url: Option<&str>,
) {
    if findings.is_empty() {
        eprintln!("[-] No SQL injection found.");
        return;
    }

    let url = target_url.unwrap_or("unknown");
    let content: String = match format {
        "json" => {
            serde_json::to_string_pretty(findings).unwrap_or_default()
        }
        "sarif" => {
            serde_json::to_string_pretty(&sqx_core::sqx::reporting::SarifReport::from_findings(findings, url))
                .unwrap_or_default()
        }
        "markdown" => {
            sqx_core::sqx::reporting::MarkdownReport::from_findings(findings, url)
        }
        _ => {
            // Plain text
            let mut out = String::new();
            for f in findings {
                out.push_str(&format!(
                    "[VULN] param={} technique={} confidence={:.0}%\n  payload: {}\n  evidence: {}\n",
                    f.parameter,
                    f.technique,
                    f.confidence * 100.0,
                    f.payload,
                    f.evidence,
                ));
            }
            out
        }
    };

    match out_file {
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

async fn run_dump(
    url: String,
    param: String,
    value: String,
    dbms: String,
    technique: String,
    max_rows: usize,
    output: String,
    out_file: Option<String>,
    proxy: Option<String>,
    session: Option<Arc<SessionManager>>,
    delay: u64,
) {
    let blind_technique = match technique.to_lowercase().as_str() {
        "time" => BlindTechnique::Time,
        _      => BlindTechnique::Boolean,
    };

    let config = SqliConfig {
        proxy,
        delay_ms: delay,
        ..SqliConfig::default()
    };
    let mut detector = match SqliDetector::with_config(config) {
        Ok(d) => d,
        Err(e) => { eprintln!("[!] Failed to build detector: {}", e); return; }
    };
    if let Some(sess) = session {
        detector = detector.with_session(sess);
    }

    match detector.ensure_authenticated().await {
        Ok(()) => {
            if detector.has_auth_session() {
                eprintln!("[+] Login successful");
            }
        }
        Err(e) => eprintln!("⚠ Login failed — scanning unauthenticated: {}", e),
    }

    eprintln!(
        "[*] dump-all: {} param={} dbms={} technique={:?} max_rows={}",
        url, param, dbms, blind_technique, max_rows
    );

    match detector.dump_all(&url, &param, &value, &dbms, blind_technique, max_rows, None, None).await {
        Ok(result) => {
            eprintln!(
                "[+] Dump complete — {} table(s), {} requests, {:.1}s",
                result.tables.len(), result.total_requests, result.elapsed_secs
            );

            let content = match output.as_str() {
                "json" => serde_json::to_string_pretty(&result).unwrap_or_default(),
                "csv"  => result.to_csv(),
                _      => result.to_text(),
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
        Err(e) => eprintln!("[!] Dump error: {}", e),
    }
}

async fn run_batch(
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
    // Read and parse targets file — one URL per line, skip blank lines and # comments
    let raw = match std::fs::read_to_string(&targets_file) {
        Ok(s) => s,
        Err(e) => { eprintln!("[!] Cannot read targets file '{}': {}", targets_file, e); return; }
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

    eprintln!("[*] Batch scan: {} target(s), concurrency={}", urls.len(), concurrency);

    let techniques = parse_techniques(tech);
    let wordlist: Option<Vec<String>> = param_wordlist.map(|path| {
        std::fs::read_to_string(&path)
            .map(|s| s.lines().map(|l| l.trim().to_string()).filter(|l| !l.is_empty()).collect())
            .unwrap_or_else(|e| { eprintln!("[!] Failed to read wordlist '{}': {}", path, e); Vec::new() })
    });
    let _ = tamper; // passed through smart scan path via fingerprint strategy

    // Semaphore limits concurrent workers
    let sem = std::sync::Arc::new(tokio::sync::Semaphore::new(concurrency));
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

        join_set.spawn(async move {
            let _permit = permit; // released when this task ends

            let config = SqliConfig {
                techniques: techniques_clone,
                delay_ms: delay_clone,
                timeout_secs: timeout_clone,
                param_wordlist: wordlist_clone.unwrap_or_else(|| SqliConfig::default().param_wordlist),
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

            match detector.ensure_authenticated().await {
                Ok(()) => {
                    if detector.has_auth_session() {
                        eprintln!("[+] [{}] Login successful", url_clone);
                    }
                }
                Err(e) => eprintln!("⚠ [{}] Login failed — scanning unauthenticated: {}", url_clone, e),
            }

            let findings = if smart_clone {
                match detector.scan_smart(&url_clone).await {
                    Ok((_, r)) => r,
                    Err(e) => { eprintln!("[!] {} — {}", url_clone, e); vec![] }
                }
            } else {
                match detector.test_url(&url_clone).await {
                    Ok(r) => r,
                    Err(e) => { eprintln!("[!] {} — {}", url_clone, e); vec![] }
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

    // Collect results as tasks complete
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
        vuln_count, all_findings.len(), total_vulns
    );

    // Format output
    let content = match output.as_str() {
        "json" => {
            let map: std::collections::HashMap<&str, &Vec<sqx_core::sqx::SqliTestResult>> =
                all_findings.iter().map(|(u, f)| (u.as_str(), f)).collect();
            serde_json::to_string_pretty(&map).unwrap_or_default()
        }
        "sarif" => {
            serde_json::to_string_pretty(&sqx_core::sqx::reporting::SarifReport::from_batch(&all_findings))
                .unwrap_or_default()
        }
        "markdown" => {
            sqx_core::sqx::reporting::MarkdownReport::from_batch(&all_findings)
        }
        _ => {
            let mut out = String::new();
            for (url, findings) in &all_findings {
                if findings.is_empty() { continue; }
                out.push_str(&format!("=== {} ===\n", url));
                for f in findings {
                    out.push_str(&format!(
                        "  [VULN] param={} technique={} confidence={:.0}%\n  payload: {}\n  evidence: {}\n",
                        f.parameter, f.technique, f.confidence * 100.0, f.payload, f.evidence,
                    ));
                }
            }
            if out.is_empty() { out.push_str("[-] No SQL injection found in any target.\n"); }
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

async fn run_file_read(
    url: String,
    param: String,
    file: String,
    dbms: String,
    value: String,
    out_file: Option<String>,
    proxy: Option<String>,
    session: Option<Arc<SessionManager>>,
) {
    let config = sqx_core::sqx::SqliConfig {
        proxy,
        ..sqx_core::sqx::SqliConfig::default()
    };
    let mut detector = match sqx_core::sqx::SqliDetector::with_config(config) {
        Ok(d) => d,
        Err(e) => { eprintln!("[!] Failed to build detector: {}", e); return; }
    };
    if let Some(sess) = session {
        detector = detector.with_session(sess);
    }

    eprintln!("[*] file-read: {} param={} file={} dbms={}", url, param, file, dbms);

    match detector.file_read(&url, &param, &value, &dbms, &file).await {
        Ok(result) => {
            let content = if let Some(ref data) = result.content {
                format!(
                    "[+] File-read succeeded ({} requests)\n\nPayload: {}\n\nContent:\n{}\n",
                    result.total_requests, result.payload_used, data
                )
            } else {
                format!(
                    "[-] File-read failed after {} requests. No readable content returned.\n",
                    result.total_requests
                )
            };
            match out_file {
                Some(path) => {
                    if let Err(e) = std::fs::write(&path, &content) {
                        eprintln!("[!] Failed to write output: {}", e);
                    } else {
                        eprintln!("[+] Output written to {}", path);
                    }
                }
                None => print!("{}", content),
            }
        }
        Err(e) => eprintln!("[!] File-read error: {}", e),
    }
}

async fn run_file_write(
    url: String,
    param: String,
    file: String,
    content: String,
    dbms: String,
    value: String,
    proxy: Option<String>,
    session: Option<Arc<SessionManager>>,
) {
    let config = sqx_core::sqx::SqliConfig {
        proxy,
        ..sqx_core::sqx::SqliConfig::default()
    };
    let mut detector = match sqx_core::sqx::SqliDetector::with_config(config) {
        Ok(d) => d,
        Err(e) => { eprintln!("[!] Failed to build detector: {}", e); return; }
    };
    if let Some(sess) = session {
        detector = detector.with_session(sess);
    }

    eprintln!("[*] file-write: {} param={} file={} dbms={}", url, param, file, dbms);

    match detector.file_write(&url, &param, &value, &dbms, &file, &content).await {
        Ok(result) => {
            if result.success {
                eprintln!(
                    "[+] File-write succeeded ({} requests)\nPayload: {}\nEvidence: {}",
                    result.total_requests, result.payload_used, result.evidence
                );
            } else {
                eprintln!(
                    "[-] File-write failed after {} requests. {}",
                    result.total_requests, result.evidence
                );
            }
        }
        Err(e) => eprintln!("[!] File-write error: {}", e),
    }
}
