//! WAF Detection Engine
//!
//! 5-layer detection:
//! 1. Explicit WAF signatures (403/406/429/503 + body signs)
//! 2. Soft block: 200 OK but body suspiciously short vs baseline
//! 3. MinHash structural deviation (< 0.5 similarity vs baseline)
//! 4. Length-ratio anomaly if no MinHash baseline is provided
//! 5. Response-time anomaly: instant rejection vs normal DB round-trip

use crate::sqx::models::HttpResponse;
use crate::sqx::similarity::error_classifier::{classify_sql_error, ErrorClass};
use crate::sqx::similarity::minhash::{compute_minhash, minhash_jaccard};

/// Returns true if the response looks like a generic WAF block page rather
/// than a DBMS-generated error. Uses status-code heuristics + body signatures.
pub fn is_likely_waf_block(response: &HttpResponse) -> bool {
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
            "rate limit",
            "too many requests",
        ];
        if WAF_SIGNS.iter().any(|s| body_lower.contains(s)) {
            return true;
        }
    }
    false
}

/// Validate that a safe-request baseline is legitimate and not already
/// a WAF block page. Returns false if the baseline itself is corrupted.
pub fn is_valid_baseline(response: &HttpResponse) -> bool {
    !is_likely_waf_block(response) && response.status < 500 && !response.body.is_empty()
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
pub fn classify_response_with_baseline(
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
        if response.status == 200 && response.body.len() < 50 && base.body.len() > 200 {
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
            if classify_sql_error(&response.body) != ErrorClass::SyntaxError {
                return ErrorClass::BlockedByWaf;
            }
        }

        if resp_ms > 10_000 && resp_ms > base_ms.saturating_mul(10) {
            return ErrorClass::BlockedByWaf;
        }
    }

    // Standard SQL error classification on body text
    classify_sql_error(&response.body)
}

/// Backward-compatible WAF-aware classification without baseline.
pub fn classify_response(response: &HttpResponse) -> ErrorClass {
    classify_response_with_baseline(response, None, None, None)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sqx::models::HttpResponse;
    use std::time::Duration;

    fn make_response(status: u16, body: &str, duration_ms: u64) -> HttpResponse {
        HttpResponse {
            status,
            body: body.to_string(),
            headers: std::collections::HashMap::new(),
            duration: Duration::from_millis(duration_ms),
        }
    }

    #[test]
    fn explicit_waf_block_403_cloudflare() {
        let resp = make_response(403, "<html>Access denied - Cloudflare Ray ID: xyz</html>", 10);
        assert!(is_likely_waf_block(&resp));
    }

    #[test]
    fn explicit_waf_block_429() {
        let resp = make_response(429, "Rate limited", 5);
        assert!(is_likely_waf_block(&resp));
    }

    #[test]
    fn not_waf_block_200() {
        let resp = make_response(200, "<html>Normal page content here</html>", 100);
        assert!(!is_likely_waf_block(&resp));
    }

    #[test]
    fn valid_baseline_check() {
        let resp = make_response(200, "<html>Normal content</html>", 100);
        assert!(is_valid_baseline(&resp));
    }

    #[test]
    fn invalid_baseline_waf_block() {
        let resp = make_response(403, "Access denied", 10);
        assert!(!is_valid_baseline(&resp));
    }

    #[test]
    fn invalid_baseline_server_error() {
        let resp = make_response(500, "Internal Server Error", 100);
        assert!(!is_valid_baseline(&resp));
    }

    #[test]
    fn classify_with_marker_override() {
        let resp = make_response(200, "<html>Page with IQX_MARKER_123</html>", 10);
        let base = make_response(200, "<html>Page content here</html>", 100);
        
        // Even with suspiciously fast response, marker should override
        let result = classify_response_with_baseline(
            &resp,
            Some(&base),
            None,
            Some("IQX_MARKER_123"),
        );
        assert_eq!(result, ErrorClass::Unknown);
    }

    #[test]
    fn soft_block_detection() {
        let resp = make_response(200, "OK", 100); // Very short body
        let base = make_response(200, &"x".repeat(500), 100); // Long baseline
        
        let result = classify_response_with_baseline(&resp, Some(&base), None, None);
        assert_eq!(result, ErrorClass::BlockedByWaf);
    }
}
