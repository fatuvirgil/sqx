//! SQL Error Classification Engine
//!
//! Uses RegexSet DFA + n-gram Jaccard fuzzy fallback for robust classification
//! of SQL error semantics across different DBMS vendors.

use regex::RegexSet;
use std::collections::HashSet;

/// Classification of SQL error semantics.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorClass {
    /// Wrong number of columns in UNION (e.g. "equal number of expressions")
    ArityMismatch,
    /// Data type incompatibility (e.g. "Operand type clash")
    TypeMismatch,
    /// Generic syntax error — not specific enough to classify as arity/type.
    SyntaxError,
    /// Response was blocked or heavily altered by a WAF (stealth or explicit).
    BlockedByWaf,
    /// No known SQL error pattern matched.
    Unknown,
}

/// Central classifier for SQL error semantics.
/// Uses RegexSet for speed and canonical n-gram overlap as fuzzy fallback.
pub struct SqlErrorClassifier {
    arity_set: RegexSet,
    type_set: RegexSet,
    syntax_set: RegexSet,
    canonical_arity: Vec<&'static str>,
    canonical_type: Vec<&'static str>,
    canonical_syntax: Vec<&'static str>,
}

impl SqlErrorClassifier {
    fn new() -> Self {
        let arity_patterns = vec![
            r"all queries combined using a union.*must have an equal number of expressions",
            r"the used select statements have a different number of columns",
            r"has a different number of result columns",
            r"operands of union do not match",
            r"not union-compatible",
            r"each union query must have the same number of columns",
            r"union view not compatible",
            r"select list has different number of columns",
        ];

        let type_patterns = vec![
            r"operand type clash.*incompatible with",
            r"expression must have same datatype",
            r"expression must have the same datatype",
            r"ora-01790",
            r"ora-01722",
            r"incompatible data types",
            r"type mismatch",
            r"data type mismatch",
            r"conversion failed when converting",
            r"union types.*cannot be matched",
            r"union types\s+\w+\s+and\s+\w+",
            r"implicit conversion from datatype",
            r"character string does not match",
            r"numeric or value error",
        ];

        let syntax_patterns = vec![
            r"syntax error",
            r"unexpected token",
            r"near .* syntax error",
            r"unclosed quotation mark",
            r"missing right parenthesis",
            r"error in your sql syntax",
            // MySQL XPATH error-based injection vectors
            r"xpath syntax error",
            r"xml parsing error",
            // MySQL UPDATEXML/EXTRACTVALUE errors
            r"updatexml",
            r"extractvalue",
        ];

        Self {
            arity_set: RegexSet::new(arity_patterns).unwrap(),
            type_set: RegexSet::new(type_patterns).unwrap(),
            syntax_set: RegexSet::new(syntax_patterns).unwrap(),
            canonical_arity: vec![
                "all queries combined using a union must have an equal number of expressions",
                "the used select statements have a different number of columns",
            ],
            canonical_type: vec![
                "operand type clash int is incompatible with text",
                "expression must have same datatype",
                "ora-01790 expression must have same datatype",
            ],
            canonical_syntax: vec!["syntax error at or near", "error in your sql syntax"],
        }
    }

    /// Classify a raw response body.
    pub fn classify(&self, body: &str) -> ErrorClass {
        let norm = normalize_error_text(body);

        // Tier 1: RegexSet on normalized text (fast, exact-ish)
        if self.arity_set.is_match(&norm) {
            return ErrorClass::ArityMismatch;
        }
        if self.type_set.is_match(&norm) {
            return ErrorClass::TypeMismatch;
        }
        if self.syntax_set.is_match(&norm) {
            return ErrorClass::SyntaxError;
        }

        // Tier 2: Fuzzy n-gram overlap against canonical signatures.
        // This catches truncated or heavily interleaved errors.
        if let Some(cls) = self.fuzzy_classify(&norm) {
            return cls;
        }

        // Tier 3: if we know *some* SQL error exists but it didn't match,
        // conservatively label it syntax error so the caller doesn't abort.
        if detect_sql_error(body).is_some() {
            return ErrorClass::SyntaxError;
        }

        ErrorClass::Unknown
    }

    fn fuzzy_classify(&self, norm: &str) -> Option<ErrorClass> {
        const THRESHOLD: f32 = 0.75;

        for sig in &self.canonical_arity {
            if ngram_similarity(norm, sig, 4) >= THRESHOLD {
                return Some(ErrorClass::ArityMismatch);
            }
        }
        for sig in &self.canonical_type {
            if ngram_similarity(norm, sig, 4) >= THRESHOLD {
                return Some(ErrorClass::TypeMismatch);
            }
        }
        for sig in &self.canonical_syntax {
            if ngram_similarity(norm, sig, 4) >= THRESHOLD {
                return Some(ErrorClass::SyntaxError);
            }
        }
        None
    }
}

lazy_static::lazy_static! {
    static ref CLASSIFIER: SqlErrorClassifier = SqlErrorClassifier::new();
}

/// Normalize response body for robust error matching.
///   1. Decode common HTML entities.
///   2. Strip HTML tags.
///   3. Collapse whitespace.
///   4. Lowercase.
fn normalize_error_text(body: &str) -> String {
    use regex::Regex;
    
    // 1. Decode common HTML entities
    let mut decoded = body
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&#34;", "\"")
        .replace("&#39;", "'")
        .replace("&#44;", ",")
        .replace("&#32;", " ")
        .replace("&amp;", "&");

    // Hex / decimal entity decoder for the full range (lightweight)
    let hex_re = Regex::new(r"&#x([0-9a-fA-F]+);").unwrap();
    decoded = hex_re
        .replace_all(&decoded, |caps: &regex::Captures| {
            u32::from_str_radix(&caps[1], 16)
                .ok()
                .and_then(|u| char::from_u32(u))
                .map(|c| c.to_string())
                .unwrap_or_else(|| caps[0].to_string())
        })
        .to_string();

    let dec_re = Regex::new(r"&#(\d+);").unwrap();
    decoded = dec_re
        .replace_all(&decoded, |caps: &regex::Captures| {
            caps[1]
                .parse::<u32>()
                .ok()
                .and_then(|u| char::from_u32(u))
                .map(|c| c.to_string())
                .unwrap_or_else(|| caps[0].to_string())
        })
        .to_string();

    // 2. Strip HTML tags
    let tag_re = Regex::new(r"<[^>]+>").unwrap();
    let plain = tag_re.replace_all(&decoded, " ");

    // 3. Collapse whitespace and lowercase
    let ws_re = Regex::new(r"\s+").unwrap();
    ws_re.replace_all(&plain, " ").trim().to_lowercase()
}

/// Build a set of character n-grams from a string.
fn ngrams(s: &str, n: usize) -> HashSet<String> {
    let chars: Vec<char> = s.chars().collect();
    let mut set = HashSet::new();
    if chars.len() < n {
        set.insert(s.to_string());
        return set;
    }
    for window in chars.windows(n) {
        set.insert(window.iter().collect::<String>());
    }
    set
}

/// Jaccard similarity on character n-grams.
fn ngram_similarity(a: &str, b: &str, n: usize) -> f32 {
    let ga = ngrams(a, n);
    let gb = ngrams(b, n);
    if ga.is_empty() && gb.is_empty() {
        return 1.0;
    }
    let inter: HashSet<_> = ga.intersection(&gb).collect();
    let union: HashSet<_> = ga.union(&gb).collect();
    inter.len() as f32 / union.len() as f32
}

/// Detect SQL error messages in response body.
/// Returns the DBMS name if an error pattern is found.
pub fn detect_sql_error(body: &str) -> Option<String> {
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

/// Detect PHP code injection indicators in response body.
/// Returns true if the response contains PHP error patterns that indicate
/// server-side code injection (eval, create_function) rather than SQL injection.
pub fn detect_php_error(body: &str) -> bool {
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

/// Convenience: classify a raw body explicitly (no WAF awareness).
pub fn classify_sql_error(body: &str) -> ErrorClass {
    CLASSIFIER.classify(body)
}

/// Convenience: true if the response contains an arity/column-count error
/// and is NOT a WAF block.
pub fn is_column_count_error(body: &str) -> bool {
    CLASSIFIER.classify(body) == ErrorClass::ArityMismatch
}

/// Convenience: true if the response contains a data-type mismatch error
/// and is NOT a WAF block.
pub fn is_type_mismatch_error(body: &str) -> bool {
    CLASSIFIER.classify(body) == ErrorClass::TypeMismatch
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_arity_error() {
        let body = "Error: all queries combined using a union must have an equal number of expressions";
        assert_eq!(CLASSIFIER.classify(body), ErrorClass::ArityMismatch);
    }

    #[test]
    fn classify_type_error() {
        let body = "Error: operand type clash int is incompatible with varchar";
        assert_eq!(CLASSIFIER.classify(body), ErrorClass::TypeMismatch);
    }

    #[test]
    fn classify_syntax_error() {
        let body = "Error: syntax error at or near 'FROM'";
        assert_eq!(CLASSIFIER.classify(body), ErrorClass::SyntaxError);
    }

    #[test]
    fn classify_unknown_no_error() {
        // Text that should NOT trigger any SQL error detection
        let body = "This is a normal response with some content about cats and dogs";
        assert_eq!(CLASSIFIER.classify(body), ErrorClass::Unknown);
    }

    #[test]
    fn fuzzy_classify_truncated() {
        // Truncated but similar to canonical - should match via fuzzy logic
        let body = "queries combined using a union must have an equal number of expressions";
        assert_eq!(CLASSIFIER.classify(body), ErrorClass::ArityMismatch);
    }

    #[test]
    fn ngram_similarity_identical() {
        let s = "hello world";
        assert_eq!(ngram_similarity(s, s, 4), 1.0);
    }

    #[test]
    fn ngram_similarity_different() {
        let a = "hello world";
        let b = "completely different";
        let sim = ngram_similarity(a, b, 4);
        assert!(sim < 0.5, "expected low similarity, got {}", sim);
    }

    #[test]
    fn detect_cockroachdb_error() {
        // Test CockroachDB/PostgreSQL error detection
        let body = r#"{"error":"SQLSTATE[42601]: Syntax error: 7 ERROR:  lexical error: unterminated string"}"#;
        let detected = detect_sql_error(body);
        println!("Detected: {:?}", detected);
        assert!(detected.is_some(), "Should detect CockroachDB error");
    }

    #[test]
    fn detect_clickhouse_error() {
        // Test ClickHouse error detection
        let body = "Code: 6. DB::Exception: Cannot parse string";
        let detected = detect_sql_error(body);
        println!("Detected: {:?}", detected);
        assert!(detected.is_some(), "Should detect ClickHouse error");
    }
}
