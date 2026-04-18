//! Response Data Extraction Helpers
//!
//! Extract version strings, users, database names, and other useful
//! information from HTTP responses.

use regex::Regex;

/// Extract version string from SQL error message
pub fn extract_version_from_error(body: &str) -> Option<String> {
    if let Some(start) = body.find("MySQL server version '") {
        let start = start + "MySQL server version ".len() + 1; // skip the opening quote
        if let Some(end) = body[start..].find('\'') {
            return Some(body[start..start + end].to_string());
        }
    }

    if let Some(start) = body.find("PostgreSQL ") {
        let start = start + "PostgreSQL ".len();
        let end = body[start..]
            .find(|c: char| !c.is_ascii_digit() && c != '.')
            .unwrap_or(body[start..].len());
        return Some(body[start..start + end].to_string());
    }

    if body.contains("Microsoft SQL Server")
        && let Some(start) = body.find("Microsoft SQL Server ")
    {
        let start = start + "Microsoft SQL Server ".len();
        let end = body[start..].find(|c: char| c.is_whitespace()).unwrap_or(4);
        return Some(body[start..start + end].to_string());
    }

    if body.contains("ORA-") {
        return Some("Oracle (version unknown)".to_string());
    }

    None
}

/// Extract version string from response body
pub fn extract_version_from_response(body: &str) -> Option<String> {
    let patterns = [
        (r"(\d+\.\d+\.\d+[-\w]*)", "MySQL/MariaDB"),
        (r"PostgreSQL\s+(\d+\.\d+[^\s,<)]*)", "PostgreSQL"),
        (r"Microsoft SQL Server[^\d]*(\d{4}|\d+\.\d+)", "MSSQL"),
        (r"(\d{1,2}\.\d{1,2}\.\d{1,2}\.\d{1,2}\.\d{1,2})", "Oracle"),
    ];

    for (pattern, _dbms) in patterns {
        if let Ok(re) = Regex::new(pattern)
            && let Some(captures) = re.captures(body)
            && let Some(version) = captures.get(1)
        {
            let version_str = version.as_str();
            if version_str.len() >= 3 && version_str.parse::<f64>().is_err() {
                return Some(version_str.to_string());
            }
        }
    }

    None
}

/// Extract user string from response body
pub fn extract_user_from_response(body: &str) -> Option<String> {
    let patterns = [
        r"([\w\-]+@[\w\-.]+)",
        r"Role:\s*([\w\-]+)",
        r"'user\(\)':\s*'([^']+)'",
        r"user[:\s]+([\w\-@.]+)",
    ];

    for pattern in patterns {
        if let Ok(re) = Regex::new(pattern)
            && let Some(captures) = re.captures(body)
            && let Some(user) = captures.get(1)
        {
            return Some(user.as_str().to_string());
        }
    }

    None
}

/// Extract database name from response body
pub fn extract_database_from_response(body: &str) -> Option<String> {
    let patterns = [
        r"database\(\)':\s*'([^']+)'",
        r"current_database\(\)|\*\*\*\*\s*([^\s,<)]+)",
        r"Database:\s*([\w\-]+)",
        r"db[:\s]+([\w\-]+)",
    ];

    for pattern in patterns {
        if let Ok(re) = Regex::new(pattern)
            && let Some(captures) = re.captures(body)
            && let Some(db) = captures.get(1)
        {
            return Some(db.as_str().to_string());
        }
    }

    None
}

/// Generic value extraction from response body.
///
/// Looks for version patterns, user@host patterns, or database-like words.
pub fn extract_value_from_response(body: &str) -> Option<String> {
    let version_pattern = r"(\d+\.\d+(?:\.\d+)*(?:[-\w]*)?)";
    if let Ok(re) = Regex::new(version_pattern) {
        for captures in re.captures_iter(body) {
            if let Some(version) = captures.get(1) {
                let version_str = version.as_str();
                if version_str.len() >= 3
                    && version_str.len() < 50
                    && !is_likely_false_positive(version_str)
                {
                    return Some(version_str.to_string());
                }
            }
        }
    }

    let user_pattern = r"([a-zA-Z][\w\-]*@[a-zA-Z][\w\-\.]+)";
    if let Ok(re) = Regex::new(user_pattern)
        && let Some(captures) = re.captures(body)
        && let Some(user) = captures.get(1)
    {
        return Some(user.as_str().to_string());
    }

    let db_pattern = r"\b([a-zA-Z_][a-zA-Z0-9_]{2,30})\b";
    if let Ok(re) = Regex::new(db_pattern) {
        for captures in re.captures_iter(body) {
            if let Some(word) = captures.get(1) {
                let word_str = word.as_str();
                if !is_common_html_word(word_str) {
                    return Some(word_str.to_string());
                }
            }
        }
    }

    None
}

/// Extract data from UNION-based response (by column index)
pub fn extract_union_data(body: &str, _column: usize) -> Option<String> {
    let version_patterns = [r"(\d+\.\d+\.\d+)", r"(\d+\.\d+)"];

    for pattern in &version_patterns {
        if let Ok(re) = Regex::new(pattern)
            && let Some(captures) = re.captures(body)
            && let Some(version) = captures.get(1)
        {
            return Some(version.as_str().to_string());
        }
    }

    None
}

/// Check if a string is likely a false positive
pub fn is_likely_false_positive(s: &str) -> bool {
    const FALSE_POSITIVES: &[&str] = &[
        "200", "201", "204", "301", "302", "304", "400", "401", "403", "404", "500", "502", "503",
        "1.0", "1.1", "2.0", "3.0", "4.0", "5.0", "6.0", "7.0", "8.0", "9.0", "10", "20", "30",
        "40", "50", "60", "70", "80", "90",
    ];
    FALSE_POSITIVES.contains(&s)
}

/// Check if a word is a common HTML/JS word to exclude
pub fn is_common_html_word(word: &str) -> bool {
    const COMMON_WORDS: &[&str] = &[
        "html",
        "head",
        "body",
        "div",
        "span",
        "script",
        "style",
        "link",
        "meta",
        "title",
        "class",
        "id",
        "src",
        "href",
        "type",
        "name",
        "value",
        "content",
        "http",
        "https",
        "www",
        "com",
        "org",
        "net",
        "json",
        "xml",
        "api",
        "url",
        "uri",
        "get",
        "post",
        "put",
        "delete",
        "patch",
        "head",
        "options",
        "true",
        "false",
        "null",
        "undefined",
        "function",
        "var",
        "let",
        "const",
        "return",
        "if",
        "else",
        "for",
        "while",
        "do",
        "switch",
        "case",
        "break",
        "continue",
        "try",
        "catch",
        "finally",
        "throw",
        "new",
        "this",
        "that",
        "self",
        "window",
        "document",
        "location",
        "navigator",
        "screen",
    ];
    COMMON_WORDS.contains(&word.to_lowercase().as_str())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_mysql_version_from_error() {
        let body = "Error: You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version '8.0.32'";
        assert_eq!(
            extract_version_from_error(body),
            Some("8.0.32".to_string())
        );
    }

    #[test]
    fn extract_postgresql_version() {
        // PostgreSQL version with 3 parts (e.g., 14.5.2) won't parse as simple f64
        let body = "PostgreSQL 14.5.2 on x86_64-pc-linux-gnu";
        assert_eq!(
            extract_version_from_response(body),
            Some("14.5.2".to_string())
        );
    }

    #[test]
    fn extract_user_pattern() {
        let body = "Current user: admin@localhost";
        assert_eq!(
            extract_user_from_response(body),
            Some("admin@localhost".to_string())
        );
    }

    #[test]
    fn extract_database_pattern() {
        let body = "Database: production_db";
        assert_eq!(
            extract_database_from_response(body),
            Some("production_db".to_string())
        );
    }

    #[test]
    fn is_common_html_word_check() {
        assert!(is_common_html_word("script"));
        assert!(is_common_html_word("div"));
        assert!(is_common_html_word("function"));
        assert!(!is_common_html_word("myapp"));
        assert!(!is_common_html_word("users"));
    }

    #[test]
    fn is_likely_false_positive_check() {
        assert!(is_likely_false_positive("200"));
        assert!(is_likely_false_positive("1.0"));
        assert!(!is_likely_false_positive("5.7.38"));
        assert!(!is_likely_false_positive("10.5.2"));
    }
}
