//! Semantic Consistency Checker.
//!
//! Validates that payloads are semantically appropriate for the target database.

use super::types::{DbDialect, ValidationResult};
use crate::intel::types::TargetProfile;
use tracing::{debug, instrument};

/// Semantic consistency checker.
pub struct SemanticChecker;

impl SemanticChecker {
    /// Check payload semantic consistency against target profile.
    #[instrument(skip(payload, profile))]
    pub fn check(payload: &str, profile: &TargetProfile) -> ValidationResult {
        let dialect = profile.get_dialect();
        debug!("Checking semantics for dialect: {:?}", dialect);

        // 1. Dialect function match
        if let Err(e) = Self::check_dialect_functions(payload, &dialect) {
            return ValidationResult::SemanticError(e);
        }

        // 2. Comment style check
        if let Err(e) = Self::check_comment_style(payload, &dialect) {
            return ValidationResult::SemanticError(e);
        }

        // 3. Data type compatibility
        if let Err(e) = Self::check_data_types(payload, &dialect) {
            return ValidationResult::SemanticError(e);
        }

        ValidationResult::Valid
    }

    /// Check that functions match the target dialect.
    fn check_dialect_functions(payload: &str, dialect: &DbDialect) -> Result<(), String> {
        let payload_lower = payload.to_lowercase();

        // PostgreSQL functions in MySQL target
        if matches!(dialect, DbDialect::MySQL) {
            if payload_lower.contains("pg_sleep") {
                return Err("PostgreSQL function 'pg_sleep' in MySQL target".to_string());
            }
            if payload_lower.contains("pg_read_file") {
                return Err("PostgreSQL function 'pg_read_file' in MySQL target".to_string());
            }
            if payload_lower.contains("copy (") {
                return Err("PostgreSQL COPY syntax in MySQL target".to_string());
            }
        }

        // MySQL functions in PostgreSQL target
        if matches!(dialect, DbDialect::Postgres) {
            if payload_lower.contains("sleep(") && !payload_lower.contains("pg_sleep") {
                return Err("MySQL function 'sleep' in PostgreSQL target".to_string());
            }
            if payload_lower.contains("benchmark(") {
                return Err("MySQL function 'benchmark' in PostgreSQL target".to_string());
            }
            if payload_lower.contains("extractvalue") {
                return Err("MySQL function 'extractvalue' in PostgreSQL target".to_string());
            }
        }

        // MSSQL functions in other targets
        if !matches!(dialect, DbDialect::MSSQL) {
            if payload_lower.contains("waitfor delay") {
                return Err("MSSQL 'waitfor delay' in non-MSSQL target".to_string());
            }
            if payload_lower.contains("xp_cmdshell") {
                return Err("MSSQL 'xp_cmdshell' in non-MSSQL target".to_string());
            }
            if payload_lower.contains("openrowset") {
                return Err("MSSQL 'openrowset' in non-MSSQL target".to_string());
            }
        }

        // Oracle functions in other targets
        if !matches!(dialect, DbDialect::Oracle) {
            if payload_lower.contains("dbms_pipe.receive_message") {
                return Err("Oracle 'dbms_pipe' in non-Oracle target".to_string());
            }
            if payload_lower.contains("utl_http.request") {
                return Err("Oracle 'utl_http' in non-Oracle target".to_string());
            }
        }

        // SQLite functions in other targets
        if !matches!(dialect, DbDialect::SQLite) {
            if payload_lower.contains("sqlite_version") {
                return Err("SQLite function in non-SQLite target".to_string());
            }
            if payload_lower.contains("load_extension") {
                return Err("SQLite extension loading in non-SQLite target".to_string());
            }
        }

        Ok(())
    }

    /// Check comment style matches dialect.
    fn check_comment_style(payload: &str, dialect: &DbDialect) -> Result<(), String> {
        let payload_lower = payload.to_lowercase();

        // MySQL-specific comment styles
        if matches!(dialect, DbDialect::MSSQL) || matches!(dialect, DbDialect::Postgres) {
            if payload_lower.contains("# ") || payload_lower.ends_with('#') {
                return Err("MySQL-style hash comment in non-MySQL target".to_string());
            }
        }

        // Check for proper comment termination
        if payload_lower.contains("--") && !payload_lower.contains("-- ") {
            // '--' without space might be okay in some contexts but warn
        }

        Ok(())
    }

    /// Check data type compatibility.
    fn check_data_types(payload: &str, dialect: &DbDialect) -> Result<(), String> {
        let payload_lower = payload.to_lowercase();

        // MySQL type casting
        if matches!(dialect, DbDialect::Postgres) {
            // PostgreSQL uses :: syntax
            if payload_lower.contains("cast(") && payload_lower.contains(" as int)") {
                // MySQL style CAST
                return Err("MySQL CAST syntax in PostgreSQL target".to_string());
            }
        }

        // String concatenation
        if matches!(dialect, DbDialect::MSSQL) {
            if payload_lower.contains("concat(") {
                // MSSQL prefers + for concatenation in older versions
            }
        }

        Ok(())
    }

    /// Extract detected functions from payload.
    pub fn extract_functions(payload: &str) -> Vec<String> {
        let patterns = [
            r"(?i)(\w+)\s*\(",           // function calls
            r"(?i)(@@\w+)",              // MSSQL variables
        ];

        let mut functions = Vec::new();
        for pattern in &patterns {
            if let Ok(regex) = regex::Regex::new(pattern) {
                for cap in regex.captures_iter(payload) {
                    if let Some(m) = cap.get(1) {
                        functions.push(m.as_str().to_lowercase());
                    }
                }
            }
        }

        functions.sort();
        functions.dedup();
        functions
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::intel::types::TechStack;

    fn create_profile(db: &str) -> TargetProfile {
        TargetProfile {
            domain: "test.com".to_string(),
            tech_stack: TechStack {
                db: db.to_string(),
                ..Default::default()
            },
            ..Default::default()
        }
    }

    #[test]
    fn test_postgres_function_in_mysql() {
        let profile = create_profile("MySQL 8.0");
        let result = SemanticChecker::check("' OR pg_sleep(5)--", &profile);
        assert!(!result.is_valid());
        assert!(result.error().unwrap().contains("pg_sleep"));
    }

    #[test]
    fn test_mysql_function_in_postgres() {
        let profile = create_profile("PostgreSQL 14");
        let result = SemanticChecker::check("' OR SLEEP(5)--", &profile);
        assert!(!result.is_valid());
        assert!(result.error().unwrap().contains("sleep"));
    }

    #[test]
    fn test_mssql_function_in_mysql() {
        let profile = create_profile("MySQL 8.0");
        let result = SemanticChecker::check("'; WAITFOR DELAY '0:0:5'--", &profile);
        assert!(!result.is_valid());
        assert!(result.error().unwrap().contains("waitfor"));
    }

    #[test]
    fn test_valid_mysql_in_mysql() {
        let profile = create_profile("MySQL 8.0");
        let result = SemanticChecker::check("' OR SLEEP(5)--", &profile);
        assert!(result.is_valid());
    }

    #[test]
    fn test_extract_functions() {
        let payload = "SELECT version(), sleep(5)";
        let funcs = SemanticChecker::extract_functions(payload);
        assert!(funcs.contains(&"version".to_string()));
        assert!(funcs.contains(&"sleep".to_string()));
    }
}
