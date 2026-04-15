//! Similarity calculation, SQL error detection, and response value extraction helpers.

use std::collections::HashSet;
use regex::Regex;

/// Detect PHP code injection indicators in response body.
/// Returns true if the response contains PHP error patterns that indicate
/// server-side code injection (eval, create_function) rather than SQL injection.
pub(crate) fn detect_php_error(body: &str) -> bool {
    const PHP_PATTERNS: &[&str] = &[
        "ParseError",
        "Parse error:",
        "Fatal error:",
        "syntax error, unexpected",
        "create_function",
        "eval()'d code",
        "runtime-created function",
        "T_STRING",
        "T_VARIABLE",
        "T_ENCAPSED_AND_WHITESPACE",
        "T_CONSTANT_ENCAPSED_STRING",
        "T_FUNCTION",
        "expecting ','",
        "expecting ')'",
    ];
    PHP_PATTERNS.iter().any(|p| body.contains(p))
}

/// Detect SQL error messages in response body.
/// Returns the DBMS name if an error pattern is found.
pub(crate) fn detect_sql_error(body: &str) -> Option<String> {
    let body_lower = body.to_lowercase();
    for dialect in crate::sqx::dbms::all_dialects() {
        for (pattern, label) in dialect.error_signatures() {
            if body_lower.contains(&pattern.to_lowercase()) {
                return Some(label.to_string());
            }
        }
    }
    None
}

/// Extract version string from SQL error message
pub(crate) fn extract_version_from_error(body: &str) -> Option<String> {
    if let Some(start) = body.find("MySQL server version '") {
        let start = start + "MySQL server version '".len();
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
        && let Some(start) = body.find("Microsoft SQL Server ") {
            let start = start + "Microsoft SQL Server ".len();
            let end = body[start..]
                .find(|c: char| c.is_whitespace())
                .unwrap_or(4);
            return Some(body[start..start + end].to_string());
        }

    if body.contains("ORA-") {
        return Some("Oracle (version unknown)".to_string());
    }

    None
}

/// Extract version string from response body
pub(crate) fn extract_version_from_response(body: &str) -> Option<String> {
    let patterns = [
        (r"(\d+\.\d+\.\d+[-\w]*)", "MySQL/MariaDB"),
        (r"PostgreSQL\s+(\d+\.\d+[^\s,<)]*)", "PostgreSQL"),
        (r"Microsoft SQL Server[^\d]*(\d{4}|\d+\.\d+)", "MSSQL"),
        (r"(\d{1,2}\.\d{1,2}\.\d{1,2}\.\d{1,2}\.\d{1,2})", "Oracle"),
    ];

    for (pattern, _dbms) in patterns {
        if let Ok(re) = Regex::new(pattern)
            && let Some(captures) = re.captures(body)
                && let Some(version) = captures.get(1) {
                    let version_str = version.as_str();
                    if version_str.len() >= 3 && version_str.parse::<f64>().is_err() {
                        return Some(version_str.to_string());
                    }
                }
    }

    None
}

/// Extract user string from response body
pub(crate) fn extract_user_from_response(body: &str) -> Option<String> {
    let patterns = [
        r"([\w\-]+@[\w\-.]+)",
        r"Role:\s*([\w\-]+)",
        r"'user\(\)':\s*'([^']+)'",
        r"user[:\s]+([\w\-@.]+)",
    ];

    for pattern in patterns {
        if let Ok(re) = Regex::new(pattern)
            && let Some(captures) = re.captures(body)
                && let Some(user) = captures.get(1) {
                    return Some(user.as_str().to_string());
                }
    }

    None
}

/// Extract database name from response body
pub(crate) fn extract_database_from_response(body: &str) -> Option<String> {
    let patterns = [
        r"database\(\)':\s*'([^']+)'",
        r"current_database\(\)|\*\*\*\*\s*([^\s,<)]+)",
        r"Database:\s*([\w\-]+)",
        r"db[:\s]+([\w\-]+)",
    ];

    for pattern in patterns {
        if let Ok(re) = Regex::new(pattern)
            && let Some(captures) = re.captures(body)
                && let Some(db) = captures.get(1) {
                    return Some(db.as_str().to_string());
                }
    }

    None
}

/// Generic value extraction from response body.
///
/// Looks for version patterns, user@host patterns, or database-like words.
pub(crate) fn extract_value_from_response(body: &str) -> Option<String> {
    let version_pattern = r"(\d+\.\d+(?:\.\d+)*(?:[-\w]*)?)";
    if let Ok(re) = Regex::new(version_pattern) {
        for captures in re.captures_iter(body) {
            if let Some(version) = captures.get(1) {
                let version_str = version.as_str();
                if version_str.len() >= 3 && version_str.len() < 50
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
            && let Some(user) = captures.get(1) {
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
pub(crate) fn extract_union_data(body: &str, _column: usize) -> Option<String> {
    let version_patterns = [
        r"(\d+\.\d+\.\d+)",
        r"(\d+\.\d+)",
    ];

    for pattern in &version_patterns {
        if let Ok(re) = Regex::new(pattern)
            && let Some(captures) = re.captures(body)
                && let Some(version) = captures.get(1) {
                    return Some(version.as_str().to_string());
                }
    }

    None
}

/// Check if a string is likely a false positive
pub(crate) fn is_likely_false_positive(s: &str) -> bool {
    const FALSE_POSITIVES: &[&str] = &[
        "200", "201", "204", "301", "302", "304", "400", "401", "403", "404", "500", "502", "503",
        "1.0", "1.1", "2.0", "3.0", "4.0", "5.0", "6.0", "7.0", "8.0", "9.0",
        "10", "20", "30", "40", "50", "60", "70", "80", "90",
    ];
    FALSE_POSITIVES.contains(&s)
}

/// Check if a word is a common HTML/JS word to exclude
pub(crate) fn is_common_html_word(word: &str) -> bool {
    const COMMON_WORDS: &[&str] = &[
        "html", "head", "body", "div", "span", "script", "style", "link", "meta", "title",
        "class", "id", "src", "href", "type", "name", "value", "content", "http",
        "https", "www", "com", "org", "net", "json", "xml", "api", "url", "uri",
        "get", "post", "put", "delete", "patch", "head", "options",
        "true", "false", "null", "undefined", "function", "var", "let", "const",
        "return", "if", "else", "for", "while", "do", "switch", "case", "break",
        "continue", "try", "catch", "finally", "throw", "new", "this", "that",
        "self", "window", "document", "location", "navigator", "screen",
    ];
    COMMON_WORDS.contains(&word.to_lowercase().as_str())
}

/// Fast similarity check — O(1) for obvious cases, O(n) worst case.
/// Returns 0.0 to 1.0.
///
/// Uses a tiered approach:
/// 1. Identity check (O(1))
/// 2. Length ratio filter (quick rejection for very different sizes)
/// 3. Token-based Jaccard on ALL tokens including HTML attribute values
/// 4. If Jaccard ≥ 0.99, cross-check with raw length ratio to catch cases
///    where the only difference is in attribute values (e.g. src="flag.jpg"
///    vs src="slap.jpg") that happen to map to the same token count.
pub(crate) fn calculate_similarity(a: &str, b: &str) -> f32 {
    // Tier 0: Identity
    if a == b { return 1.0; }
    if a.is_empty() || b.is_empty() { return 0.0; }

    // Tier 1: Length ratio — if lengths differ by >50%, similarity is low
    let len_a = a.len() as f32;
    let len_b = b.len() as f32;
    let len_ratio = len_a.min(len_b) / len_a.max(len_b);
    if len_ratio < 0.5 {
        return len_ratio * 0.5; // Very different lengths → low similarity
    }

    // Tier 2: Token-based Jaccard on RAW tokens (NOT tag-stripped).
    // Tokenise the raw HTML including attribute values so that differences
    // like src="flag.jpg" vs src="slap.jpg" are captured as distinct tokens.
    let tokens_a: HashSet<&str> = tokenize_html(a).collect();
    let tokens_b: HashSet<&str> = tokenize_html(b).collect();

    if tokens_a.is_empty() && tokens_b.is_empty() {
        return len_ratio;
    }

    let intersection = tokens_a.intersection(&tokens_b).count() as f32;
    let union = tokens_a.union(&tokens_b).count() as f32;

    if union == 0.0 { return 0.0; }
    let jaccard = intersection / union;

    // Tier 3: If Jaccard is very close to 1.0, blend with length ratio to
    // catch responses that differ only in attribute values of equal token length
    // (e.g. "flag" vs "slap" — both 4 chars, same token count after splitting).
    if jaccard >= 0.99 && (1.0 - len_ratio).abs() > 0.01 {
        return (jaccard + len_ratio) / 2.0;
    }

    jaccard
}

/// Tokenise HTML by splitting on whitespace AND common HTML delimiters
/// (`<`, `>`, `=`, `"`, `'`, `/`) so that attribute values become
/// individual tokens. This captures differences hidden inside HTML attributes
/// that `strip_html_tags` would otherwise discard.
fn tokenize_html(s: &str) -> impl Iterator<Item = &str> {
    s.split(|c: char| c.is_whitespace() || matches!(c, '<' | '>' | '"' | '\'' | '=' | '/'))
        .filter(|t| !t.is_empty())
}

