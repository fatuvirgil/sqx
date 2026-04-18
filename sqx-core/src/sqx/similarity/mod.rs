//! Similarity calculation, SQL error detection, and response value extraction.
//!
//! This module provides:
//! - MinHash baseline engine for stable similarity estimation
//! - SQL error classification (RegexSet + Fuzzy fallback)
//! - WAF detection with 5-layer heuristics
//! - Data extraction helpers (version, user, database, etc.)
//! - HTML-aware similarity calculation

pub mod error_classifier;
pub mod extraction;
pub mod minhash;
pub mod waf_detector;

// Re-export commonly used types
pub use error_classifier::{
    classify_sql_error, ErrorClass, SqlErrorClassifier, detect_php_error, detect_sql_error,
    is_column_count_error, is_type_mismatch_error,
};
pub use extraction::{
    extract_database_from_response, extract_union_data, extract_user_from_response,
    extract_value_from_response, extract_version_from_error, extract_version_from_response,
    is_common_html_word, is_likely_false_positive,
};
pub use minhash::{char_shingles, compute_minhash, minhash_jaccard};
pub use waf_detector::{
    classify_response, classify_response_with_baseline, is_likely_waf_block, is_valid_baseline,
};

use std::collections::HashSet;

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
pub fn calculate_similarity(a: &str, b: &str) -> f32 {
    // Tier 0: Identity
    if a == b {
        return 1.0;
    }
    if a.is_empty() || b.is_empty() {
        return 0.0;
    }

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

    if union == 0.0 {
        return 0.0;
    }
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
pub fn tokenize_html(s: &str) -> impl Iterator<Item = &str> {
    s.split(|c: char| c.is_whitespace() || matches!(c, '<' | '>' | '"' | '\'' | '=' | '/'))
        .filter(|t| !t.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn similarity_identity() {
        assert_eq!(calculate_similarity("hello", "hello"), 1.0);
    }

    #[test]
    fn similarity_empty() {
        assert_eq!(calculate_similarity("", "hello"), 0.0);
        assert_eq!(calculate_similarity("hello", ""), 0.0);
    }

    #[test]
    fn similarity_different_lengths() {
        // Very different lengths should give low similarity
        let sim = calculate_similarity("short", &"x".repeat(1000));
        assert!(sim < 0.5, "expected low similarity for different lengths, got {}", sim);
    }

    #[test]
    fn similarity_html_attributes() {
        // This was a real bug - differences in src attributes should be detected
        let a = r#"<img src="flag.jpg">"#;
        let b = r#"<img src="slap.jpg">"#;
        let sim = calculate_similarity(a, b);
        assert!(sim < 1.0, "expected less than perfect similarity for different src, got {}", sim);
        // Jaccard: intersection=[img, src], union=[img, src, flag.jpg, slap.jpg] = 2/4 = 0.5
        assert!(sim >= 0.5, "expected some similarity for same structure, got {}", sim);
    }

    #[test]
    fn tokenize_html_test() {
        let html = r#"<img src="flag.jpg" alt="test">"#;
        let tokens: Vec<_> = tokenize_html(html).collect();
        assert!(tokens.contains(&"img"));
        assert!(tokens.contains(&"src"));
        assert!(tokens.contains(&"flag.jpg"));
        assert!(tokens.contains(&"alt"));
        assert!(tokens.contains(&"test"));
    }

    #[test]
    fn similarity_near_identical() {
        let a = "hello world test";
        let b = "hello world tests";
        let sim = calculate_similarity(a, b);
        // Token intersection=[hello, world], union=[hello, world, test, tests] = 2/4 = 0.5
        // But length ratio is close, so blended result may vary
        assert!(sim > 0.4, "expected moderate similarity, got {}", sim);
        assert!(sim < 1.0, "expected less than perfect, got {}", sim);
    }
}
