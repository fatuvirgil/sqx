//! Post-exploitation and operator-driven takeover workflows.
//!
//! This module is the public entry point for capabilities that go beyond
//! detection and raw extraction primitives: file operations, command execution,
//! and custom SQL execution.

pub mod custom_sql;
pub mod file_read;
pub mod file_write;
pub mod os_exec;

pub use custom_sql::{CustomSqlRequest, CustomSqlResult};
pub use file_read::{FileReadPayload, FileReadPayloads, FileReadResult};
pub use file_write::{FileWritePayload, FileWritePayloads, FileWriteResult};
pub use os_exec::{OsCommandPayloads, OsExecPayload, OsExecResult};
