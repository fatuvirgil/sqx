//! Known SQL Injection Technique Patterns.
//!
//! Regex patterns for validating that payloads match known SQLi techniques.

use lazy_static::lazy_static;
use regex::Regex;

/// SQLi technique pattern with metadata.
#[derive(Debug, Clone)]
pub struct TechniquePattern {
    /// Regex for detection
    pub regex: Regex,
    /// Technique name
    pub name: &'static str,
    /// Affected database dialects
    pub dialects: &'static [&'static str],
    /// Risk level (1-10)
    pub risk: u8,
    /// Description
    pub description: &'static str,
}

lazy_static! {
    /// Known SQLi technique patterns.
    pub static ref SQLI_TECHNIQUES: Vec<TechniquePattern> = vec![
        // Union-based
        TechniquePattern {
            regex: Regex::new(r#"(?i)'?\s*union\s+select"#).unwrap(),
            name: "union_based",
            dialects: &["mysql", "postgres", "mssql", "oracle", "sqlite"],
            risk: 8,
            description: "UNION-based data extraction",
        },
        TechniquePattern {
            regex: Regex::new(r#"(?i)union\s+all\s+select"#).unwrap(),
            name: "union_based_all",
            dialects: &["mysql", "postgres", "mssql", "oracle", "sqlite"],
            risk: 8,
            description: "UNION ALL-based data extraction",
        },
        
        // Time-based MySQL (check for word boundary or operator before sleep)
        TechniquePattern {
            regex: Regex::new(r#"(?i)(?:\s|or|and)\s+sleep\s*\(\s*\d+\s*\)"#).unwrap(),
            name: "time_based_mysql_sleep",
            dialects: &["mysql"],
            risk: 7,
            description: "MySQL SLEEP() time-based blind",
        },
        TechniquePattern {
            regex: Regex::new(r#"(?i)benchmark\s*\(\s*\d+\s*,\s*"#).unwrap(),
            name: "time_based_mysql_benchmark",
            dialects: &["mysql"],
            risk: 7,
            description: "MySQL BENCHMARK() time-based blind",
        },
        TechniquePattern {
            regex: Regex::new(r#"(?i)get_lock\s*\(\s*['\"]"#).unwrap(),
            name: "time_based_mysql_getlock",
            dialects: &["mysql"],
            risk: 6,
            description: "MySQL GET_LOCK() time-based blind",
        },
        
        // Time-based PostgreSQL
        TechniquePattern {
            regex: Regex::new(r#"(?i)pg_sleep\s*\(\s*\d+\s*\)"#).unwrap(),
            name: "time_based_postgres",
            dialects: &["postgres"],
            risk: 7,
            description: "PostgreSQL pg_sleep() time-based blind",
        },
        TechniquePattern {
            regex: Regex::new(r#"(?i)pg_read_file\s*\("#).unwrap(),
            name: "error_based_postgres_fileread",
            dialects: &["postgres"],
            risk: 8,
            description: "PostgreSQL pg_read_file() file read",
        },
        
        // Time-based MSSQL
        TechniquePattern {
            regex: Regex::new(r#"(?i)waitfor\s+delay\s*['\"]"#).unwrap(),
            name: "time_based_mssql",
            dialects: &["mssql"],
            risk: 7,
            description: "MSSQL WAITFOR DELAY time-based blind",
        },
        
        // Time-based Oracle
        TechniquePattern {
            regex: Regex::new(r#"(?i)dbms_pipe\.receive_message\s*\("#).unwrap(),
            name: "time_based_oracle",
            dialects: &["oracle"],
            risk: 7,
            description: "Oracle DBMS_PIPE time-based blind",
        },
        
        // Error-based MySQL
        TechniquePattern {
            regex: Regex::new(r#"(?i)extractvalue\s*\(\s*0x"#).unwrap(),
            name: "error_based_mysql_extractvalue",
            dialects: &["mysql"],
            risk: 8,
            description: "MySQL EXTRACTVALUE() error-based",
        },
        TechniquePattern {
            regex: Regex::new(r#"(?i)updatexml\s*\(\s*0x"#).unwrap(),
            name: "error_based_mysql_updatexml",
            dialects: &["mysql"],
            risk: 8,
            description: "MySQL UPDATEXML() error-based",
        },
        TechniquePattern {
            regex: Regex::new(r#"(?i)floor\s*\(rand\s*\("#).unwrap(),
            name: "error_based_mysql_floor",
            dialects: &["mysql"],
            risk: 7,
            description: "MySQL FLOOR(RAND()) error-based",
        },
        TechniquePattern {
            regex: Regex::new(r#"(?i)exp\s*\(~\s*\("#).unwrap(),
            name: "error_based_mysql_exp",
            dialects: &["mysql"],
            risk: 7,
            description: "MySQL EXP() error-based",
        },
        
        // Error-based PostgreSQL
        TechniquePattern {
            regex: Regex::new(r#"(?i)cast\s*\(\s*[^)]+\s+as\s+int\s*\)"#).unwrap(),
            name: "error_based_postgres_cast",
            dialects: &["postgres"],
            risk: 7,
            description: "PostgreSQL CAST() error-based",
        },
        
        // Boolean-based blind
        TechniquePattern {
            regex: Regex::new(r#"(?i)'?\s*or\s+'?\d+'?\s*=\s*'?\d+"#).unwrap(),
            name: "boolean_based_simple",
            dialects: &["mysql", "postgres", "mssql", "oracle", "sqlite"],
            risk: 6,
            description: "Simple boolean-based OR 1=1",
        },
        TechniquePattern {
            regex: Regex::new(r#"(?i)and\s*\(?\s*ascii\s*\(\s*substr"#).unwrap(),
            name: "boolean_based_ascii_substr",
            dialects: &["mysql", "postgres", "oracle"],
            risk: 7,
            description: "ASCII(SUBSTR()) boolean-based blind",
        },
        TechniquePattern {
            regex: Regex::new(r#"(?i)and\s*\(?\s*substring\s*\("#).unwrap(),
            name: "boolean_based_substring",
            dialects: &["mysql", "mssql"],
            risk: 7,
            description: "SUBSTRING() boolean-based blind",
        },
        
        // Stacked queries
        TechniquePattern {
            regex: Regex::new(r#"(?i);\s*(drop|insert|update|delete|exec)"#).unwrap(),
            name: "stacked_queries",
            dialects: &["mssql", "postgres"],
            risk: 10,
            description: "Stacked query injection",
        },
        
        // Out-of-band
        TechniquePattern {
            regex: Regex::new(r#"(?i)load_file\s*\(\s*['\"]\\\\"#).unwrap(),
            name: "oob_mysql_loadfile",
            dialects: &["mysql"],
            risk: 8,
            description: "MySQL LOAD_FILE() OOB",
        },
        TechniquePattern {
            regex: Regex::new(r#"(?i)into\s+outfile\s*['\"]"#).unwrap(),
            name: "oob_mysql_outfile",
            dialects: &["mysql"],
            risk: 9,
            description: "MySQL INTO OUTFILE",
        },
        
        // Comment variations
        TechniquePattern {
            regex: Regex::new(r#"(?i)--\s*\+?"#).unwrap(),
            name: "comment_dash",
            dialects: &["mysql", "postgres", "mssql", "oracle", "sqlite"],
            risk: 3,
            description: "SQL comment (--)",
        },
        TechniquePattern {
            regex: Regex::new(r#"(?i)/\*"#).unwrap(),
            name: "comment_block",
            dialects: &["mysql", "postgres", "mssql", "oracle", "sqlite"],
            risk: 3,
            description: "SQL block comment (/*)",
        },
        TechniquePattern {
            regex: Regex::new(r#"(?i)#\s*"#).unwrap(),
            name: "comment_hash",
            dialects: &["mysql"],
            risk: 3,
            description: "MySQL hash comment (#)",
        },
    ];
}

/// Match payload against known techniques.
pub fn matches_known_technique(payload: &str) -> Option<&'static TechniquePattern> {
    SQLI_TECHNIQUES.iter().find(|tech| tech.regex.is_match(payload))
}

/// Validate that payload matches at least one known technique.
pub fn validate_technique(payload: &str) -> Result<&'static TechniquePattern, String> {
    match matches_known_technique(payload) {
        Some(tech) => Ok(tech),
        None => Err(
            "Payload doesn't match any known SQLi technique from last 10 years".to_string()
        ),
    }
}

/// Get all matching techniques for a payload.
pub fn get_matching_techniques(payload: &str) -> Vec<&'static TechniquePattern> {
    SQLI_TECHNIQUES
        .iter()
        .filter(|tech| tech.regex.is_match(payload))
        .collect()
}

/// Get techniques applicable to a specific dialect.
pub fn get_dialect_techniques(dialect: &str) -> Vec<&'static TechniquePattern> {
    let dialect_lower = dialect.to_lowercase();
    SQLI_TECHNIQUES
        .iter()
        .filter(|tech| {
            tech.dialects.contains(&dialect_lower.as_str()) ||
            tech.dialects.contains(&"*") // Universal techniques
        })
        .collect()
}

/// Calculate risk score for a payload.
pub fn calculate_risk(payload: &str) -> u8 {
    get_matching_techniques(payload)
        .iter()
        .map(|t| t.risk)
        .max()
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_match_union_based() {
        let payload = "' UNION SELECT null,null,version()--";
        let tech = matches_known_technique(payload);
        assert!(tech.is_some());
        assert_eq!(tech.unwrap().name, "union_based");
    }

    #[test]
    fn test_match_mysql_sleep() {
        let payload = "' OR SLEEP(5)--";
        let tech = matches_known_technique(payload);
        assert!(tech.is_some());
        assert_eq!(tech.unwrap().name, "time_based_mysql_sleep");
    }

    #[test]
    fn test_match_postgres_sleep() {
        let payload = "' OR pg_sleep(5)--";
        let tech = matches_known_technique(payload);
        assert!(tech.is_some());
        assert_eq!(tech.unwrap().name, "time_based_postgres");
    }

    #[test]
    fn test_validate_unknown() {
        let payload = "SELECT * FROM users";
        let result = validate_technique(payload);
        assert!(result.is_err());
    }

    #[test]
    fn test_calculate_risk() {
        let payload = "'; DROP TABLE users;--";
        let risk = calculate_risk(payload);
        assert!(risk > 0);
    }

    #[test]
    fn test_get_matching_techniques() {
        let payload = "' UNION SELECT null,null,version()--";
        let techs = get_matching_techniques(payload);
        assert!(!techs.is_empty());
    }
}
