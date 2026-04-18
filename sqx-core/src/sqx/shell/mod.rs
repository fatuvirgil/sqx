//! Interactive shells via SQL injection.
//!
//! This module provides REPL-style interfaces for executing SQL queries
//! and OS commands through a confirmed SQL injection vulnerability.
//!
//! # Example: SQL Shell
//!
//! ```rust,ignore
//! use sqx_core::sqx::shell::{SqlShell, ShellConfig};
//!
//! let config = ShellConfig::default();
//! let mut shell = SqlShell::new(&detector, url, param, value, "mysql", config).await?;
//! shell.run_repl().await?;
//! ```

pub mod fast_extract;
pub mod os_shell;
pub mod sql_shell;
pub mod types;

pub use fast_extract::{
    fast_extract_sql, AdaptiveExtractor, FastExtractionResult, FastTechnique,
};
pub use os_shell::OsShell;
pub use sql_shell::SqlShell;
pub use types::{
    detect_os_shell_methods, OsShellMethod, ShellConfig, ShellHistoryEntry, ShellResult,
    ShellSession, ShellTechnique,
};
