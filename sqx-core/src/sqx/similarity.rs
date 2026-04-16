//! Similarity calculation, SQL error detection, and response value extraction helpers.

use std::collections::HashSet;
use regex::{Regex, RegexSet};
use crate::sqx::models::HttpResponse;

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

// ═══════════════════════════════════════════════════════════════════════════════
// MinHash Baseline Engine
// ═══════════════════════════════════════════════════════════════════════════════

/// Generate character k-shingles from normalized text.
pub(crate) fn char_shingles(s: &str, k: usize) -> Vec<String> {
    let chars: Vec<char> = s.chars().collect();
    if chars.len() < k {
        return vec![s.to_string()];
    }
    chars.windows(k)
        .map(|w| w.iter().collect())
        .collect()
}

/// Compute MinHash signature using a simple family of hash functions.
/// `num_hashes` controls the signature size (accuracy vs speed trade-off).
pub(crate) fn compute_minhash(body: &str, k: usize, num_hashes: usize) -> Vec<u64> {
    let norm = normalize_error_text(body);
    let shingles = char_shingles(&norm, k);
    if shingles.is_empty() {
        return vec![0u64; num_hashes];
    }

    let mut sig = Vec::with_capacity(num_hashes);
    for i in 0..num_hashes {
        let mut min_val = u64::MAX;
        let seed = (i + 1) as u64;
        for s in &shingles {
            // FNV-1a style hash with per-hash offset
            let mut hash: u64 = 0xcbf29ce484222325; // FNV offset basis
            for b in s.bytes() {
                hash ^= (b as u64).wrapping_add(seed);
                hash = hash.wrapping_mul(0x100000001b3); // FNV prime
            }
            if hash < min_val {
                min_val = hash;
            }
        }
        sig.push(min_val);
    }
    sig
}

/// Estimate Jaccard similarity from two MinHash signatures.
pub(crate) fn minhash_jaccard(a: &[u64], b: &[u64]) -> f32 {
    if a.len() != b.len() || a.is_empty() {
        return 0.0;
    }
    let matches = a.iter().zip(b.iter()).filter(|(x, y)| x == y).count();
    matches as f32 / a.len() as f32
}

// ═══════════════════════════════════════════════════════════════════════════════
// SQL Error Classification Engine (RegexSet + Normalization + Fuzzy Fallback)
// ═══════════════════════════════════════════════════════════════════════════════

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

/// Normalize response body for robust error matching.
///   1. Decode common HTML entities.
///   2. Strip HTML tags.
///   3. Collapse whitespace.
///   4. Lowercase.
fn normalize_error_text(body: &str) -> String {
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
    decoded = hex_re.replace_all(&decoded, |caps: &regex::Captures| {
        u32::from_str_radix(&caps[1], 16)
            .ok()
            .and_then(|u| char::from_u32(u))
            .map(|c| c.to_string())
            .unwrap_or_else(|| caps[0].to_string())
    }).to_string();

    let dec_re = Regex::new(r"&#(\d+);").unwrap();
    decoded = dec_re.replace_all(&decoded, |caps: &regex::Captures| {
        caps[1].parse::<u32>()
            .ok()
            .and_then(|u| char::from_u32(u))
            .map(|c| c.to_string())
            .unwrap_or_else(|| caps[0].to_string())
    }).to_string();

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
            canonical_syntax: vec![
                "syntax error at or near",
                "error in your sql syntax",
            ],
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

/// Returns true if the response looks like a generic WAF block page rather
/// than a DBMS-generated error. Uses status-code heuristics + body signatures.
pub(crate) fn is_likely_waf_block(response: &HttpResponse) -> bool {
    // Known WAF block status codes
    if matches!(response.status, 403 | 406 | 429 | 503) {
        let body_lower = response.body.to_lowercase();
        const WAF_SIGNS: &[&str] = &[
            "access denied",
            "blocked",
            "forbidden",
            "not acceptable",
            "security violation",
            "attack detected",
            "cloudflare",
            "request rejected",
            "waf",
            "web application firewall",
            "incapsula",
            "imperva",
            "akamai",
            "sucuri",
            "ray id",
        ];
        if WAF_SIGNS.iter().any(|s| body_lower.contains(s)) {
            return true;
        }
    }
    false
}

/// Validate that a safe-request baseline is legitimate and not already
/// a WAF block page. Returns false if the baseline itself is corrupted.
pub(crate) fn is_valid_baseline(response: &HttpResponse) -> bool {
    !is_likely_waf_block(response)
        && response.status < 500
        && !response.body.is_empty()
}

/// Detect stealth WAF blocks using structural anomaly detection.
///
/// Checks:
///   1. Explicit WAF signatures (403/406/429/503 + body signs)
///   2. Soft block: 200 OK but body is suspiciously short vs baseline
///   3. MinHash structural deviation (< 0.5 similarity vs baseline)
///   4. Length-ratio anomaly if no MinHash baseline is provided
///   5. Response-time anomaly: instant rejection vs normal DB round-trip
///
/// **Success-over-WAF priority**: If `injected_marker` is provided and the
/// response body contains it exactly, the response is NEVER classified as
/// BlockedByWaf based on structural anomalies — the physical reflection of
/// the marker is definitive proof of successful injection.
pub(crate) fn classify_response_with_baseline(
    response: &HttpResponse,
    baseline: Option<&HttpResponse>,
    baseline_minhash: Option<&[u64]>,
    injected_marker: Option<&str>,
) -> ErrorClass {
    // Success-over-WAF: physical marker reflection overrides all heuristics.
    if let Some(marker) = injected_marker {
        if response.body.contains(marker) {
            return ErrorClass::Unknown; // caller treats reflection as success
        }
    }

    // 1. Explicit WAF block
    if is_likely_waf_block(response) {
        return ErrorClass::BlockedByWaf;
    }

    // 2-5. Stealth-block heuristics (only if baseline available)
    if let Some(base) = baseline {
        // Soft block: 200 OK but body suspiciously short/empty
        if response.status == 200
            && response.body.len() < 50
            && base.body.len() > 200
        {
            return ErrorClass::BlockedByWaf;
        }

        // MinHash structural deviation
        if let Some(base_sig) = baseline_minhash {
            let resp_sig = compute_minhash(&response.body, 4, 64);
            let sim = minhash_jaccard(base_sig, &resp_sig);
            if sim < 0.5 {
                return ErrorClass::BlockedByWaf;
            }
        } else {
            // Fallback length-ratio anomaly
            let base_len = base.body.len().max(1) as f32;
            let resp_len = response.body.len() as f32;
            let len_ratio = resp_len / base_len;
            if response.status == 200
                && base.body.len() > 200
                && (len_ratio < 0.3 || len_ratio > 3.0)
            {
                return ErrorClass::BlockedByWaf;
            }
        }

        // Response-time heuristic:
        //   a) Fast rejection: WAF blocks are often instant (<50ms).
        //   b) Tarpitting: WAF intentionally delays the response to consume
        //      attacker resources (e.g. 15s for a request that normally takes 100ms).
        let base_ms = base.duration.as_millis() as u64;
        let resp_ms = response.duration.as_millis() as u64;

        if base_ms > 100 && resp_ms < base_ms / 5 && resp_ms < 50 {
            // Fast response with no obvious SQL error signature → likely WAF
            if detect_sql_error(&response.body).is_none() {
                return ErrorClass::BlockedByWaf;
            }
        }

        if resp_ms > 10_000 && resp_ms > base_ms.saturating_mul(10) {
            return ErrorClass::BlockedByWaf;
        }
    }

    // Standard SQL error classification on body text
    CLASSIFIER.classify(&response.body)
}

/// Backward-compatible WAF-aware classification without baseline.
pub(crate) fn classify_response(response: &HttpResponse) -> ErrorClass {
    classify_response_with_baseline(response, None, None, None)
}

/// Convenience: true if the response contains an arity/column-count error
/// and is NOT a WAF block.
pub(crate) fn is_column_count_error(response: &HttpResponse) -> bool {
    classify_response(response) == ErrorClass::ArityMismatch
}

/// Convenience: true if the response contains a data-type mismatch error
/// and is NOT a WAF block.
pub(crate) fn is_type_mismatch_error(response: &HttpResponse) -> bool {
    classify_response(response) == ErrorClass::TypeMismatch
}

/// Convenience: classify a raw body explicitly (no WAF awareness).
pub(crate) fn classify_sql_error(body: &str) -> ErrorClass {
    CLASSIFIER.classify(body)
}

// ═══════════════════════════════════════════════════════════════════════════════
// Extraction helpers
// ═══════════════════════════════════════════════════════════════════════════════

/// Extract version string from SQL error message
pub(crate) fn extract_version_from_error(body: &str) -> Option<String> {
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
