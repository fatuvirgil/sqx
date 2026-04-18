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

use crate::commands::extraction::run_dump;
use crate::commands::intel::run_intel;
use crate::commands::scanning::{
    auto_techniques, build_user_tamper_chain, run_auto, run_batch, run_scan,
};
use crate::commands::takeover::{run_custom_sql, run_file_read, run_file_write};
use crate::commands::validate::run_validate;
use sqx_core::sqx::{
    SqliTechnique, TamperChain,
    ai_advisor::{AiAdvisorConfig, AiBackend},
    session::{AuthConfig, SessionConfig, SessionManager},
};

#[derive(Parser)]
#[command(
    name = "sqx",
    about = "SQX — SQL Injection Scanner",
    version,
    propagate_version = true
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

        /// Output format: text, json, sarif (markdown is Pro-only)
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

        /// Use headless browser for crawling (SPA support, requires Chrome)
        #[arg(long)]
        headless: bool,

        /// Chrome/Chromium binary path (default: auto-detect)
        #[arg(long)]
        chrome_path: Option<String>,

        /// Wait time for JS rendering in milliseconds (default: 2000)
        #[arg(long, default_value = "2000")]
        render_wait: u64,
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

        /// Concurrent workers (default: 5, max 5 in Core, unlimited in Pro)
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

    /// Execute a custom scalar SQL query/expression via blind extraction
    #[command(name = "sql")]
    Sql {
        /// Target URL with the vulnerable parameter
        url: String,

        /// Injectable parameter name
        #[arg(long)]
        param: String,

        /// SQL scalar query or expression returning one cell
        #[arg(long)]
        query: String,

        /// Benign value for the parameter
        #[arg(long, default_value = "1")]
        value: String,

        /// DBMS: mysql, postgresql, mssql, oracle, sqlite
        #[arg(long, default_value = "mysql")]
        dbms: String,

        /// Extraction technique: boolean, time
        #[arg(long, default_value = "boolean")]
        technique: String,

        /// Maximum extracted value length
        #[arg(long, default_value = "256")]
        max_length: usize,

        /// Optional boundary hint from the payload database
        #[arg(long)]
        boundary: Option<String>,

        /// Optional payload id/title for vector reuse
        #[arg(long)]
        payload_id: Option<String>,

        /// Request delay in ms
        #[arg(long, default_value = "100")]
        delay: u64,

        /// Output format: text, json
        #[arg(long, default_value = "text")]
        output: String,

        /// Write output to file instead of stdout
        #[arg(long, short = 'o')]
        out_file: Option<String>,
    },

    /// Interactive SQL shell via blind injection.
    /// Opens a REPL that executes SQL queries against the target database.
    #[command(name = "sql-shell")]
    SqlShell {
        /// Target URL with the vulnerable parameter
        url: String,

        /// Injectable parameter name
        #[arg(long)]
        param: String,

        /// Benign value for the parameter
        #[arg(long, default_value = "1")]
        value: String,

        /// DBMS: mysql, postgresql, mssql, oracle, sqlite
        #[arg(long, default_value = "mysql")]
        dbms: String,

        /// Extraction technique: boolean, time
        #[arg(long, default_value = "boolean")]
        technique: String,

        /// Maximum output length per query
        #[arg(long, default_value = "4096")]
        max_length: usize,

        /// Request delay in ms
        #[arg(long, default_value = "100")]
        delay: u64,
    },

    /// Interactive OS shell via SQL injection command execution.
    /// Opens a REPL that executes OS commands on the target server.
    #[command(name = "os-shell")]
    OsShell {
        /// Target URL with the vulnerable parameter
        url: String,

        /// Injectable parameter name
        #[arg(long)]
        param: String,

        /// Benign value for the parameter
        #[arg(long, default_value = "1")]
        value: String,

        /// DBMS: mysql, postgresql, mssql, oracle, sqlite
        #[arg(long, default_value = "mysql")]
        dbms: String,

        /// Extraction technique: boolean, time
        #[arg(long, default_value = "boolean")]
        technique: String,

        /// Maximum output length per command
        #[arg(long, default_value = "4096")]
        max_length: usize,

        /// Request delay in ms
        #[arg(long, default_value = "100")]
        delay: u64,
    },

    /// Replay a request from a file or raw text.
    /// Supports raw HTTP format and curl commands.
    Replay {
        /// Path to request file, or "-" to read from stdin
        file: String,
        
        /// Output format: text, json
        #[arg(long, default_value = "text")]
        output: String,
        
        /// Write output to file
        #[arg(long, short = 'o')]
        out_file: Option<String>,
        
        /// Request timeout in seconds
        #[arg(long, default_value = "30")]
        timeout: u64,
    },

    /// Run benchmark against a test matrix (requires sqli-labs or similar).
    /// Compares SQX detection rate and performance.
    Bench {
        /// Base URL of the test target (e.g., http://localhost:8080)
        #[arg(long, default_value = "http://localhost:8080")]
        target: String,
        
        /// Output file for JSON results
        #[arg(long, short = 'o')]
        out_file: Option<String>,
    },

    /// Collect intelligence for a target domain (CVEs, assets, advisories).
    Intel {
        /// Target domain to analyze (e.g., example.com)
        domain: String,
        
        /// Output format: text, json
        #[arg(long, default_value = "text")]
        output: String,
        
        /// Write output to file
        #[arg(long, short = 'o')]
        out_file: Option<String>,
        
        /// KB path for caching
        #[arg(long, default_value = "./data/intel.kb")]
        kb_path: String,
    },

    /// Validate a SQL payload against syntax and semantic rules.
    Validate {
        /// SQL payload to validate
        payload: String,
        
        /// Target database dialect: mysql, postgres, mssql, sqlite, oracle
        #[arg(long, default_value = "mysql")]
        dialect: String,
        
        /// Check against known SQLi techniques
        #[arg(long)]
        check_technique: bool,
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
            self.cookie,
            self.cookie_auto_detect,
            self.login_url,
            self.auth_method,
            self.auth_creds,
            self.auth_user,
            self.auth_pass,
            self.auth_token,
            self.auth_success,
        );
        match self.command {
            Command::Scan {
                url,
                smart,
                tech,
                tamper,
                oob,
                oob_domain,
                oob_port,
                output,
                out_file,
                delay,
                timeout,
                param_wordlist,
                ai_advisor,
                ai_model,
                ai_api_key,
                ai_base_url,
                ai_consent,
            } => {
                let ai_cfg = build_ai_config(
                    ai_advisor,
                    &ai_model,
                    ai_api_key.as_deref(),
                    ai_base_url.as_deref(),
                    ai_consent,
                );
                run_scan(
                    url,
                    smart,
                    tech,
                    tamper,
                    oob,
                    oob_domain,
                    oob_port,
                    output,
                    out_file,
                    delay,
                    timeout,
                    None,
                    None,
                    param_wordlist,
                    proxy,
                    session,
                    ai_cfg,
                )
                .await;
            }
            Command::Post {
                url,
                body,
                ct,
                tech,
                tamper,
                output,
                out_file,
            } => {
                run_scan(
                    url,
                    false,
                    tech,
                    tamper,
                    false,
                    None,
                    8080,
                    output,
                    out_file,
                    100,
                    30,
                    Some(body),
                    Some(ct),
                    None,
                    proxy,
                    session,
                    None,
                )
                .await;
            }
            Command::Auto {
                url,
                smart,
                oob,
                oob_domain,
                max_pages,
                max_depth,
                ai_advisor,
                ai_model,
                ai_api_key,
                ai_base_url,
                ai_consent,
                output,
                out_file,
                param_wordlist,
                headless,
                chrome_path,
                render_wait,
            } => {
                let ai_cfg = build_ai_config(
                    ai_advisor,
                    &ai_model,
                    ai_api_key.as_deref(),
                    ai_base_url.as_deref(),
                    ai_consent,
                );
                run_auto(
                    url,
                    smart,
                    oob,
                    oob_domain,
                    max_pages,
                    max_depth,
                    output,
                    out_file,
                    param_wordlist,
                    proxy,
                    session,
                    ai_cfg,
                    headless,
                    chrome_path,
                    render_wait,
                )
                .await;
            }
            Command::Dump {
                url,
                param,
                value,
                dbms,
                technique,
                max_rows,
                output,
                out_file,
                delay,
            } => {
                run_dump(
                    url, param, value, dbms, technique, max_rows, output, out_file, proxy, session,
                    delay,
                )
                .await;
            }
            Command::Batch {
                targets,
                concurrency,
                smart,
                tech,
                tamper,
                delay,
                timeout,
                output,
                out_file,
                param_wordlist,
            } => {
                run_batch(
                    targets,
                    concurrency,
                    smart,
                    tech,
                    tamper,
                    delay,
                    timeout,
                    output,
                    out_file,
                    param_wordlist,
                    proxy,
                    session,
                )
                .await;
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
            Command::Replay {
                file,
                output,
                out_file,
                timeout,
            } => {
                crate::commands::replay::run_replay(file, output, out_file, timeout, proxy).await;
            }
            Command::Bench { target, out_file } => {
                crate::commands::bench::run_bench(target, out_file).await;
            }
            Command::Intel { domain, output, out_file, kb_path } => {
                run_intel(domain, output, out_file, kb_path).await;
            }
            Command::Validate { payload, dialect, check_technique } => {
                run_validate(payload, dialect, check_technique);
            }
            Command::UpdatePayloads => {
                eprintln!("[*] Updating payload database...");
                match sqx_core::sqx::payloads::PayloadDatabase::fetch_and_cache().await {
                    Ok(()) => eprintln!("[+] Done. Run any scan to use the new payloads."),
                    Err(e) => eprintln!("[-] Failed: {}", e),
                }
            }
            Command::FileRead {
                url,
                param,
                file,
                dbms,
                value,
                out_file,
            } => {
                run_file_read(url, param, file, dbms, value, out_file, proxy, session).await;
            }
            Command::FileWrite {
                url,
                param,
                file,
                content,
                dbms,
                value,
            } => {
                run_file_write(url, param, file, content, dbms, value, proxy, session).await;
            }
            Command::Sql {
                url,
                param,
                query,
                value,
                dbms,
                technique,
                max_length,
                boundary,
                payload_id,
                delay,
                output,
                out_file,
            } => {
                run_custom_sql(
                    url, param, query, value, dbms, technique, max_length, boundary, payload_id,
                    delay, output, out_file, proxy, session,
                )
                .await;
            }
            Command::SqlShell {
                url,
                param,
                value,
                dbms,
                technique,
                max_length,
                delay,
            } => {
                crate::commands::shell::run_sql_shell(
                    url, param, value, dbms, technique, max_length, delay, proxy, session,
                )
                .await;
            }
            Command::OsShell {
                url,
                param,
                value,
                dbms,
                technique,
                max_length,
                delay,
            } => {
                crate::commands::shell::run_os_shell(
                    url, param, value, dbms, technique, max_length, delay, proxy, session,
                )
                .await;
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
            if part.is_empty() {
                continue;
            }
            if let Some(eq_pos) = part.find('=') {
                config.cookies.insert(
                    part[..eq_pos].trim().to_string(),
                    part[eq_pos + 1..].trim().to_string(),
                );
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
    } else if let Some(method) = auth_method {
        let method = method.to_ascii_lowercase();
        if matches!(method.as_str(), "basic" | "bearer") {
            config.auth = Some(AuthConfig {
                login_url: String::new(),
                method,
                credentials: std::collections::HashMap::new(),
                basic_username: auth_user,
                basic_password: auth_pass,
                bearer_token: auth_token,
                success_indicator: auth_success,
            });
        }
    }

    if cookie.is_some() || auto_detect || config.auth.is_some() || !config.headers.is_empty() {
        return Some(Arc::new(SessionManager::new(config)));
    }
    None
}

fn parse_key_val<T, U>(
    s: &str,
) -> Result<(T, U), Box<dyn std::error::Error + Send + Sync + 'static>>
where
    T: std::str::FromStr,
    T::Err: std::error::Error + Send + Sync + 'static,
    U: std::str::FromStr,
    U::Err: std::error::Error + Send + Sync + 'static,
{
    let pos = s
        .find('=')
        .ok_or_else(|| format!("invalid KEY=value: no `=` found in `{}`", s))?;
    Ok((s[..pos].parse()?, s[pos + 1..].parse()?))
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
        eprintln!(
            "[*] AI advisor: using commercial backend '{}' (consent given)",
            model_spec
        );
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn user_tamper_chain_is_built_from_cli_values() {
        let chain = build_user_tamper_chain(Some(vec![
            "space_to_comment".to_string(),
            "randomcase".to_string(),
        ]))
        .expect("tamper chain");
        assert_eq!(chain.names(), vec!["space_to_comment", "randomcase"]);
    }

    #[test]
    fn auto_oob_enables_out_of_band_technique() {
        let techniques = auto_techniques(true);
        assert!(techniques.contains(&SqliTechnique::OutOfBand));
    }

    #[test]
    fn bearer_auth_without_login_url_sets_authorization_header() {
        let session = build_session_manager(
            None,
            false,
            None,
            Some("bearer".to_string()),
            vec![],
            None,
            None,
            Some("sekret".to_string()),
            None,
        )
        .expect("session");

        assert!(session.has_auth());
    }

    #[test]
    fn basic_auth_without_login_url_sets_authorization_header() {
        let session = build_session_manager(
            None,
            false,
            None,
            Some("basic".to_string()),
            vec![],
            Some("alice".to_string()),
            Some("wonder".to_string()),
            None,
            None,
        )
        .expect("session");

        assert!(session.has_auth());
    }

    #[test]
    fn sql_subcommand_parses_custom_query_flags() {
        let cli = Cli::parse_from([
            "sqx",
            "sql",
            "http://target.local/item?id=1",
            "--param",
            "id",
            "--query",
            "SELECT version()",
            "--dbms",
            "mysql",
            "--technique",
            "time",
        ]);

        match cli.command {
            Command::Sql {
                url,
                param,
                query,
                dbms,
                technique,
                ..
            } => {
                assert_eq!(url, "http://target.local/item?id=1");
                assert_eq!(param, "id");
                assert_eq!(query, "SELECT version()");
                assert_eq!(dbms, "mysql");
                assert_eq!(technique, "time");
            }
            _ => panic!("expected sql subcommand"),
        }
    }
}
