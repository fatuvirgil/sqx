//! Dynamic Payload Database for SQX
//!
//! Three tiers:
//!
//! 1. **Built-in boundaries** — our own list of SQL injection boundaries
//!    (prefix/suffix pairs to close context). Written independently; the
//!    concept of boundaries is generic SQLi knowledge, not proprietary.
//!
//! 2. **Bundled PATT payloads** — curated subset from PayloadsAllTheThings
//!    (MIT license — free to embed). Loaded at compile time.
//!
//! 3. **Fetched payloads** — `sqx update-payloads` downloads sqlmap XML
//!    (GPLv2) and fresh PATT lists into `~/.local/share/sqx/payloads/`.
//!    We never *distribute* these files; the user fetches them explicitly.

pub mod boundaries;
pub mod bundled;
pub mod fetcher;
pub mod parser;
pub mod types;

pub use boundaries::{find_boundary, Boundary, BOUNDARIES};
pub use bundled::{find_payloads_containing, get_bundled_payloads, BUNDLED_ERROR_PAYLOADS};
pub use fetcher::{cache_dir, fetch_and_cache, is_cached, read_cached};
pub use parser::{parse_sqlmap_boundaries_extended, parse_sqlmap_tests};
pub use types::{technique, technique_name, DynamicPayloadSet, SqlmapBoundary, SqlmapTest};

use std::sync::OnceLock;
use tracing::info;

// Global cache for the payload database to avoid reloading from disk
static PAYLOAD_DB_CACHE: OnceLock<PayloadDatabase> = OnceLock::new();

/// Complete payload database available at scan time.
/// Combines built-in, bundled, and fetched payloads.
#[derive(Debug, Clone)]
pub struct PayloadDatabase {
    /// Built-in boundaries (always available).
    pub built_in_boundaries: &'static [Boundary],
    /// Bundled payloads (always available).
    pub bundled_payloads: &'static [&'static str],
    /// Dynamically fetched payloads (may be empty if not cached).
    pub dynamic: DynamicPayloadSet,
}

impl PayloadDatabase {
    /// Create a new payload database with built-in and bundled payloads.
    pub fn new() -> Self {
        Self {
            built_in_boundaries: BOUNDARIES,
            bundled_payloads: BUNDLED_ERROR_PAYLOADS,
            dynamic: DynamicPayloadSet::default(),
        }
    }

    /// Load from disk cache. Falls back to built-ins if cache doesn't exist.
    /// Uses global caching to avoid reloading from disk multiple times.
    pub fn load() -> Self {
        PAYLOAD_DB_CACHE.get_or_init(|| {
            let mut db = Self::new();
            db.load_dynamic();
            db
        }).clone()
    }

    /// Load dynamic payloads from cache.
    fn load_dynamic(&mut self) {
        let dir = match cache_dir() {
            Some(d) => d,
            None => return,
        };

        let files = [
            "boolean_blind.xml",
            "error_based.xml",
            "time_blind.xml",
            "union_select.xml",
            "stacked_queries.xml",
        ];

        for file in files {
            if let Ok(xml) = std::fs::read_to_string(dir.join(file)) {
                self.dynamic.tests.extend(parse_sqlmap_tests(&xml));
            }
        }

        if let Ok(xml) = std::fs::read_to_string(dir.join("boundaries.xml")) {
            self.dynamic
                .boundaries
                .extend(parse_sqlmap_boundaries_extended(&xml));
        }

        if let Ok(txt) = std::fs::read_to_string(dir.join("patt_sqli.txt")) {
            self.dynamic.extra_patt.extend(
                txt.lines()
                    .map(str::trim)
                    .filter(|l| !l.is_empty() && !l.starts_with('#'))
                    .map(String::from),
            );
        }

        info!(
            "Dynamic payloads loaded: {} boundaries, {} tests, {} PATT strings from cache",
            self.dynamic.boundaries.len(),
            self.dynamic.tests.len(),
            self.dynamic.extra_patt.len(),
        );
    }

    /// Get total boundary count (built-in + dynamic).
    pub fn total_boundaries(&self) -> usize {
        self.built_in_boundaries.len() + self.dynamic.boundary_count()
    }

    /// Get total test count (bundled + dynamic).
    pub fn total_tests(&self) -> usize {
        self.bundled_payloads.len() + self.dynamic.test_count()
    }

    /// Look up a boundary by label.
    /// Searches built-in first, then dynamic.
    pub fn find_boundary(&self, label: &str) -> Option<(String, String)> {
        // First check built-in
        for b in self.built_in_boundaries {
            if b.label.eq_ignore_ascii_case(label) {
                return Some((b.close.to_string(), b.balance.to_string()));
            }
        }
        // Then check dynamic
        for b in &self.dynamic.boundaries {
            let synthetic = format!("dyn:{}", b.prefix);
            if synthetic.eq_ignore_ascii_case(label) || b.prefix == label {
                return Some((b.prefix.clone(), b.suffix.clone()));
            }
        }
        None
    }

    /// Get all available payload strings (bundled only for now).
    /// Note: Extra PATT payloads are owned strings and can't be returned as &str
    /// without changing the API. Use dynamic.extra_patt directly if needed.
    pub fn all_payload_strings(&self) -> Vec<&str> {
        self.bundled_payloads.to_vec()
    }

    /// True if at least one sqlmap XML file is cached.
    pub fn is_cached() -> bool {
        is_cached()
    }

    /// Fetch all sources and write to cache.
    pub async fn fetch_and_cache() -> anyhow::Result<()> {
        fetcher::fetch_and_cache().await
    }
    
    /// Static version of find_boundary for compatibility.
    /// Searches built-in boundaries only.
    pub fn find_boundary_static(label: &str) -> Option<(String, String)> {
        boundaries::find_boundary(label)
    }
}

impl Default for PayloadDatabase {
    fn default() -> Self {
        Self::new()
    }
}

/// Resolve sqlmap placeholders in a string.
///
/// Supported placeholders:
/// - `[RANDNUM]`  → random integer (default 42)
/// - `[RANDSTR]`  → random string (default "sqx")
/// - `[ORIGVALUE]` → the original parameter value
/// - `[INFERENCE]` → the boolean condition being tested
/// - `[SLEEPTIME]` → sleep duration in seconds
pub fn resolve_placeholders(
    s: &str,
    randnum: i32,
    randstr: &str,
    origvalue: &str,
    inference: &str,
    sleeptime: u64,
) -> String {
    s.replace("[RANDNUM]", &randnum.to_string())
        .replace("[RANDSTR]", randstr)
        .replace("[ORIGVALUE]", origvalue)
        .replace("[INFERENCE]", inference)
        .replace("[SLEEPTIME]", &sleeptime.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn payload_database_new() {
        let db = PayloadDatabase::new();
        assert!(!db.built_in_boundaries.is_empty());
        assert!(!db.bundled_payloads.is_empty());
    }

    #[test]
    fn find_builtin_boundary() {
        let db = PayloadDatabase::new();
        let result = db.find_boundary("sq-comment");
        assert!(result.is_some());
        let (close, balance) = result.unwrap();
        assert_eq!(close, "'");
        assert_eq!(balance, "-- ");
    }

    #[test]
    fn resolve_placeholders_basic() {
        let s = "[RANDNUM] AND [RANDSTR] = '[ORIGVALUE]'";
        let result = resolve_placeholders(s, 42, "sqx", "test", "1=1", 5);
        assert_eq!(result, "42 AND sqx = 'test'");
    }

    #[test]
    fn resolve_placeholders_sleep() {
        let s = "SLEEP([SLEEPTIME])";
        let result = resolve_placeholders(s, 0, "", "", "", 10);
        assert_eq!(result, "SLEEP(10)");
    }
}
