//! SQL Syntax Validator using sqlparser.
//!
//! Validates that payloads are syntactically valid SQL before sending to target.

use super::types::{DbDialect, ValidationResult};
use sqlparser::dialect::{
    AnsiDialect, GenericDialect, MsSqlDialect, MySqlDialect, PostgreSqlDialect, SQLiteDialect,
};
use sqlparser::parser::Parser;
use tracing::{debug, instrument};

/// SQL Syntax Validator.
pub struct SyntaxValidator;

impl SyntaxValidator {
    /// Validate SQL payload syntax.
    #[instrument(skip(payload), fields(dialect = ?dialect))]
    pub fn validate(payload: &str, dialect: &DbDialect) -> ValidationResult {
        debug!("Validating SQL syntax for {} bytes", payload.len());

        let sql_dialect: Box<dyn sqlparser::dialect::Dialect> = match dialect {
            DbDialect::MySQL => Box::new(MySqlDialect {}),
            DbDialect::Postgres => Box::new(PostgreSqlDialect {}),
            DbDialect::MSSQL => Box::new(MsSqlDialect {}),
            DbDialect::SQLite => Box::new(SQLiteDialect {}),
            DbDialect::Oracle => Box::new(GenericDialect {}), // sqlparser doesn't have Oracle dialect
        };

        // Try to parse the SQL
        match Parser::parse_sql(sql_dialect.as_ref(), payload) {
            Ok(statements) => {
                if statements.is_empty() {
                    ValidationResult::SyntaxError("Empty SQL statement".to_string())
                } else {
                    debug!("SQL parsed successfully: {} statements", statements.len());
                    ValidationResult::Valid
                }
            }
            Err(e) => {
                let error_msg = format!("SQL Parse error: {}", e);
                debug!("{}", error_msg);
                ValidationResult::SyntaxError(error_msg)
            }
        }
    }

    /// Quick check - only validates basic syntax without full parsing.
    pub fn quick_check(payload: &str) -> bool {
        // Check for balanced parentheses
        let open_count = payload.chars().filter(|&c| c == '(').count();
        let close_count = payload.chars().filter(|&c| c == ')').count();
        if open_count != close_count {
            return false;
        }

        // Check for balanced quotes
        let single_quotes = payload.chars().filter(|&c| c == '\'').count();
        if single_quotes % 2 != 0 {
            return false;
        }

        let double_quotes = payload.chars().filter(|&c| c == '"').count();
        if double_quotes % 2 != 0 {
            return false;
        }

        true
    }

    /// Validate multiple dialects and return best match.
    pub fn validate_multi_dialect(payload: &str) -> (ValidationResult, Option<DbDialect>) {
        let dialects = [
            DbDialect::MySQL,
            DbDialect::Postgres,
            DbDialect::MSSQL,
            DbDialect::SQLite,
        ];

        for dialect in &dialects {
            if let ValidationResult::Valid = Self::validate(payload, dialect) {
                return (ValidationResult::Valid, Some(*dialect));
            }
        }

        (
            ValidationResult::SyntaxError(
                "Invalid SQL syntax for all tested dialects".to_string(),
            ),
            None,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_mysql() {
        let result = SyntaxValidator::validate("SELECT * FROM users", &DbDialect::MySQL);
        assert!(result.is_valid());
    }

    #[test]
    fn test_invalid_syntax() {
        let result = SyntaxValidator::validate("SELECT * FROM", &DbDialect::MySQL);
        assert!(!result.is_valid());
    }

    #[test]
    fn test_sqli_payload_mysql() {
        // SQL injection payloads are fragments, not complete SQL
        // Test a complete SQL statement that would result from injection
        let payload = "SELECT * FROM users WHERE id='' UNION SELECT null,version()-- -'";
        let result = SyntaxValidator::validate(payload, &DbDialect::MySQL);
        assert!(result.is_valid(), "Should parse: {:?}", result.error());
    }

    #[test]
    fn test_quick_check_balanced() {
        assert!(SyntaxValidator::quick_check("(())"));
        assert!(SyntaxValidator::quick_check("'test'"));
    }

    #[test]
    fn test_quick_check_unbalanced() {
        assert!(!SyntaxValidator::quick_check("(()"));
        assert!(!SyntaxValidator::quick_check("'test"));
    }
}
