//! Stealth / WAF-evasion helpers.
//!
//! Provides:
//!  - A pool of real browser User-Agent strings for rotation.
//!  - A function that builds realistic browser-like request headers.
//!  - A jitter helper that randomizes inter-request delays.

use std::time::Duration;

// ── User-Agent pool ───────────────────────────────────────────────────────────

/// Real browser User-Agent strings drawn from recent Statcounter/UA data.
/// Rotated randomly per-request when `StealthConfig::ua_rotation` is true.
pub static UA_POOL: &[&str] = &[
    // Chrome Windows
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    // Chrome macOS
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
    // Firefox Windows
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:124.0) Gecko/20100101 Firefox/124.0",
    // Firefox Linux
    "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:124.0) Gecko/20100101 Firefox/124.0",
    // Edge Windows
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 Edg/124.0.0.0",
    // Safari macOS
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4.1 Safari/605.1.15",
    // Chrome Android (mobile — useful against mobile-only WAF rules)
    "Mozilla/5.0 (Linux; Android 13; Pixel 7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Mobile Safari/537.36",
];

/// Pick a random UA from the pool using cryptographically secure RNG.
/// Uses rand::thread_rng() for proper randomness.
pub fn random_ua() -> &'static str {
    use rand::seq::SliceRandom;
    UA_POOL.choose(&mut rand::thread_rng()).unwrap_or(&UA_POOL[0])
}

// ── Browser header sets ───────────────────────────────────────────────────────

/// Realistic Accept header for HTML page requests.
pub const ACCEPT_HTML: &str =
    "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8";

/// Accept-Language values — rotate for variety.
pub static ACCEPT_LANGUAGES: &[&str] = &[
    "en-US,en;q=0.9",
    "en-GB,en;q=0.9",
    "en-US,en;q=0.5",
    "ro-RO,ro;q=0.9,en-US;q=0.8,en;q=0.7",
    "de-DE,de;q=0.9,en-US;q=0.8,en;q=0.7",
    "fr-FR,fr;q=0.9,en-US;q=0.8,en;q=0.7",
];

pub fn random_accept_language() -> &'static str {
    use rand::seq::SliceRandom;
    ACCEPT_LANGUAGES.choose(&mut rand::thread_rng()).unwrap_or(&ACCEPT_LANGUAGES[0])
}

/// Returns a list of (header-name, value) pairs that mimic a real browser.
/// The UA is passed in separately (already chosen by the caller).
pub fn browser_headers(referer: Option<&str>) -> Vec<(&'static str, String)> {
    let mut h: Vec<(&'static str, String)> = vec![
        ("Accept", ACCEPT_HTML.to_string()),
        ("Accept-Language", random_accept_language().to_string()),
        ("Accept-Encoding", "gzip, deflate, br".to_string()),
        ("Connection", "keep-alive".to_string()),
        ("Upgrade-Insecure-Requests", "1".to_string()),
        ("Sec-Fetch-Dest", "document".to_string()),
        ("Sec-Fetch-Mode", "navigate".to_string()),
        (
            "Sec-Fetch-Site",
            if referer.is_some() {
                "same-origin"
            } else {
                "none"
            }
            .to_string(),
        ),
        ("Sec-Fetch-User", "?1".to_string()),
        ("DNT", "1".to_string()),
    ];
    if let Some(r) = referer {
        h.push(("Referer", r.to_string()));
    }
    h
}

/// Extract the origin (scheme + host) from a URL for use as Referer.
/// Returns None on parse failure.
pub fn origin_of(url: &str) -> Option<String> {
    let parsed = reqwest::Url::parse(url).ok()?;
    let host = parsed.host_str()?;
    Some(format!("{}://{}", parsed.scheme(), host))
}

// ── Delay jitter ─────────────────────────────────────────────────────────────

/// Apply jitter to `base_ms`: returns a value in the range
/// `[base * (1 - pct/100), base * (1 + pct/100)]`.
///
/// Uses rand::thread_rng() for cryptographically secure randomness,
/// preventing timing side-channel attacks that could fingerprint the scanner.
pub fn jittered_delay(base_ms: u64, jitter_pct: u64) -> Duration {
    use rand::Rng;
    
    if jitter_pct == 0 || base_ms == 0 {
        return Duration::from_millis(base_ms);
    }
    
    let range = base_ms * jitter_pct / 100; // half-width of the jitter band
    let offset = rand::thread_rng().gen_range(0..=range * 2);
    let ms = base_ms.saturating_sub(range) + offset;
    Duration::from_millis(ms)
}
