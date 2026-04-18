//! Core types for interactive shells via SQL injection.

use serde::{Deserialize, Serialize};

/// Result of a single shell command execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShellResult {
    /// The command that was executed
    pub command: String,
    /// Output from the command (stdout equivalent)
    pub output: String,
    /// Whether the command executed successfully
    pub success: bool,
    /// Total HTTP requests made for this command
    pub requests: usize,
    /// Execution time in milliseconds
    pub duration_ms: u64,
}

/// Shell execution configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShellConfig {
    /// Maximum output length per command
    pub max_output_length: usize,
    /// Extraction technique: boolean or time
    pub technique: ShellTechnique,
    /// Request delay in milliseconds
    pub delay_ms: u64,
    /// Auto-detect DBMS capabilities
    pub auto_detect: bool,
}

impl Default for ShellConfig {
    fn default() -> Self {
        Self {
            max_output_length: 4096,
            technique: ShellTechnique::Boolean,
            delay_ms: 100,
            auto_detect: true,
        }
    }
}

/// Extraction technique for shell commands.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum ShellTechnique {
    Boolean,
    Time,
}

impl std::fmt::Display for ShellTechnique {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ShellTechnique::Boolean => write!(f, "boolean"),
            ShellTechnique::Time => write!(f, "time"),
        }
    }
}

/// History entry for shell sessions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShellHistoryEntry {
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub command: String,
    pub output: String,
    pub success: bool,
}

/// Shell session state.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ShellSession {
    pub history: Vec<ShellHistoryEntry>,
    pub total_requests: usize,
    pub start_time: Option<chrono::DateTime<chrono::Utc>>,
}

impl ShellSession {
    pub fn new() -> Self {
        Self {
            history: Vec::new(),
            total_requests: 0,
            start_time: Some(chrono::Utc::now()),
        }
    }

    pub fn add_entry(&mut self, command: String, output: String, success: bool) {
        self.history.push(ShellHistoryEntry {
            timestamp: chrono::Utc::now(),
            command,
            output,
            success,
        });
    }

    pub fn add_requests(&mut self, count: usize) {
        self.total_requests += count;
    }
}

/// OS shell execution method for different DBMS types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OsShellMethod {
    /// xp_cmdshell (MSSQL)
    XpCmdshell,
    /// UTL_FILE + DBMS_SCHEDULER (Oracle)
    UtlFileScheduler,
    /// COPY TO PROGRAM (PostgreSQL)
    CopyToProgram,
    /// INTO OUTFILE + UDF (MySQL)
    IntoOutfileUdf,
    /// System command via SQLite load_extension
    SqliteLoadExtension,
}

impl OsShellMethod {
    /// Get human-readable description.
    pub fn description(&self) -> &'static str {
        match self {
            OsShellMethod::XpCmdshell => "MSSQL xp_cmdshell",
            OsShellMethod::UtlFileScheduler => "Oracle UTL_FILE + DBMS_SCHEDULER",
            OsShellMethod::CopyToProgram => "PostgreSQL COPY ... TO PROGRAM",
            OsShellMethod::IntoOutfileUdf => "MySQL INTO OUTFILE + UDF",
            OsShellMethod::SqliteLoadExtension => "SQLite load_extension",
        }
    }

    /// Check if this method is available for the given DBMS.
    pub fn available_for_dbms(&self, dbms: &str) -> bool {
        let dbms = dbms.to_lowercase();
        match self {
            OsShellMethod::XpCmdshell => dbms == "mssql" || dbms == "sqlserver",
            OsShellMethod::UtlFileScheduler => dbms == "oracle",
            OsShellMethod::CopyToProgram => dbms == "postgresql" || dbms == "postgres",
            OsShellMethod::IntoOutfileUdf => dbms == "mysql" || dbms == "mariadb",
            OsShellMethod::SqliteLoadExtension => dbms == "sqlite",
        }
    }
}

/// Detect available OS shell methods for a DBMS.
pub fn detect_os_shell_methods(dbms: &str) -> Vec<OsShellMethod> {
    let methods = vec![
        OsShellMethod::XpCmdshell,
        OsShellMethod::UtlFileScheduler,
        OsShellMethod::CopyToProgram,
        OsShellMethod::IntoOutfileUdf,
        OsShellMethod::SqliteLoadExtension,
    ];
    
    methods
        .into_iter()
        .filter(|m| m.available_for_dbms(dbms))
        .collect()
}
