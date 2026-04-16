//! Vendor-specific WAF bypass strategies.
//!
//! When a known WAF is fingerprinted, SQX skips generic linear tamper escalation
//! and tries dedicated multi-tamper chains that are statistically more effective
//! against that vendor's rule set.

/// Return prioritized tamper chains for a detected WAF vendor.
///
/// Each inner `Vec<String>` is a chain of tamper names applied left-to-right.
/// Chains are ordered from most to least likely to bypass the specific WAF.
pub fn vendor_bypass_chains(waf_name: &str) -> Vec<Vec<String>> {
    let name_lower = waf_name.to_lowercase();

    if name_lower.contains("cloudflare") {
        // Cloudflare: heavy on keyword/union detection, sensitive to spaces,
        // but often misses comment-injected keywords + case mixing.
        vec![
            vec!["randomcase".into(), "space_to_comment".into()],
            vec!["inline_comment".into(), "randomcase".into()],
            vec!["double_urlencode".into(), "randomcase".into()],
            vec!["unicode_escape".into(), "space_to_comment".into()],
            vec!["space_to_whitespace_mix".into(), "randomcase".into()],
            vec!["keyword_newline_split".into(), "randomcase".into()],
        ]
    } else if name_lower.contains("modsecurity") || name_lower.contains("mod_security") {
        // ModSecurity (OWASP CRS): very sensitive to UNION/SELECT signatures,
        // but comment evasion + versioned keywords + hex often slip through.
        vec![
            vec!["space_to_comment".into(), "randomcase".into(), "hex_encode".into()],
            vec!["modsecurityzeroversioned".into(), "randomcase".into()],
            vec!["inline_comment".into(), "randomcase".into(), "space_to_comment".into()],
            vec!["null_byte".into(), "space_to_comment".into()],
            vec!["mysql_version_comment".into(), "randomcase".into()],
            vec!["versionedkeywords".into(), "space_to_comment".into()],
        ]
    } else if name_lower.contains("imperva") || name_lower.contains("incapsula") {
        // Imperva: good at single-layer encoding, weak against double encoding
        // combined with newline/unicode tricks.
        vec![
            vec!["double_urlencode".into(), "unicode_escape".into()],
            vec!["space_to_newline".into(), "randomcase".into()],
            vec!["unicode_escape".into(), "space_to_comment".into()],
            vec!["double_urlencode".into(), "space_to_comment".into()],
            vec!["charunicodeencode".into(), "randomcase".into()],
            vec!["overlongutf8".into(), "space_to_comment".into()],
        ]
    } else if name_lower.contains("akamai") || name_lower.contains("kona") {
        vec![
            vec!["double_urlencode".into(), "randomcase".into()],
            vec!["mysql_version_comment".into(), "randomcase".into()],
            vec!["unicode_escape".into(), "space_to_comment".into()],
            vec!["inline_comment".into(), "double_urlencode".into()],
        ]
    } else if name_lower.contains("aws") || name_lower.contains("awswaf") {
        vec![
            vec!["urlencode".into(), "space_to_tab".into(), "randomcase".into()],
            vec!["inline_comment".into(), "urlencode".into()],
            vec!["space_to_whitespace_mix".into(), "randomcase".into()],
            vec!["double_urlencode".into(), "space_to_tab".into()],
        ]
    } else if name_lower.contains("sucuri") {
        vec![
            vec!["randomcase".into(), "space_to_comment".into(), "urlencode".into()],
            vec!["inline_comment".into(), "randomcase".into()],
            vec!["double_urlencode".into(), "space_to_comment".into()],
        ]
    } else if name_lower.contains("f5") || name_lower.contains("big-ip") {
        vec![
            vec!["double_urlencode".into(), "space_to_tab".into(), "null_byte".into()],
            vec!["null_byte".into(), "space_to_comment".into()],
            vec!["randomcase".into(), "space_to_tab".into()],
        ]
    } else if name_lower.contains("forti") || name_lower.contains("fortigate") {
        vec![
            vec!["urlencode".into(), "randomcase".into(), "inline_comment".into()],
            vec!["space_to_comment".into(), "randomcase".into()],
            vec!["hex_encode".into(), "space_to_comment".into()],
        ]
    } else {
        vec![]
    }
}

/// Build a fallback escalation list for unknown or generic WAFs.
pub fn generic_escalation() -> Vec<Vec<String>> {
    vec![
        vec!["randomcase".into()],
        vec!["space_to_comment".into()],
        vec!["inline_comment".into()],
        vec!["urlencode".into()],
        vec!["space_to_tab".into()],
        vec!["double_urlencode".into()],
        vec!["hex_encode".into()],
        vec!["unicode_escape".into()],
        vec!["null_byte".into()],
        vec!["mysql_version_comment".into()],
        vec!["space_to_newline".into()],
        vec!["overlongutf8".into()],
    ]
}

/// Merge vendor-specific chains with generic escalation, deduplicating.
pub fn build_escalation_list(waf_name: Option<&str>, waf_recommended: &[String]) -> Vec<Vec<String>> {
    let mut seen = std::collections::HashSet::new();
    let mut list: Vec<Vec<String>> = Vec::new();

    // 1. WAF-recommended single tampers first (backward compat)
    for t in waf_recommended {
        let chain = vec![t.clone()];
        if seen.insert(chain.clone()) {
            list.push(chain);
        }
    }

    // 2. Vendor-specific multi-tamper chains
    if let Some(name) = waf_name {
        for chain in vendor_bypass_chains(name) {
            if seen.insert(chain.clone()) {
                list.push(chain);
            }
        }
    }

    // 3. Generic escalation
    for chain in generic_escalation() {
        if seen.insert(chain.clone()) {
            list.push(chain);
        }
    }

    list
}
