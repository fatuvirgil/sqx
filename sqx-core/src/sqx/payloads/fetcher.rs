//! Payload Fetcher — Downloads sqlmap and PATT payloads.
//!
//! External sources:
//! - sqlmap XML files (GPLv2) — user fetches, we never distribute
//! - PayloadsAllTheThings (MIT) — also fetched at runtime

use anyhow::{Result, anyhow};
use std::path::PathBuf;

/// URLs for external payload sources.
const FETCH_SOURCES: &[(&str, &str)] = &[
    // sqlmap XML — GPLv2. User fetches; we never distribute.
    (
        "boolean_blind.xml",
        "https://raw.githubusercontent.com/sqlmapproject/sqlmap/master/data/xml/payloads/boolean_blind.xml",
    ),
    (
        "error_based.xml",
        "https://raw.githubusercontent.com/sqlmapproject/sqlmap/master/data/xml/payloads/error_based.xml",
    ),
    (
        "time_blind.xml",
        "https://raw.githubusercontent.com/sqlmapproject/sqlmap/master/data/xml/payloads/time_blind.xml",
    ),
    (
        "union_select.xml",
        "https://raw.githubusercontent.com/sqlmapproject/sqlmap/master/data/xml/payloads/union_select.xml",
    ),
    (
        "stacked_queries.xml",
        "https://raw.githubusercontent.com/sqlmapproject/sqlmap/master/data/xml/payloads/stacked_queries.xml",
    ),
    // PayloadsAllTheThings full list — MIT.
    (
        "patt_sqli.txt",
        "https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/SQL%20Injection/Intruder/SQL-Injection.txt",
    ),
];

/// Maximum allowed file size for downloaded payloads (10 MB).
const MAX_PAYLOAD_SIZE: usize = 10 * 1024 * 1024;

/// Fetch all payload sources and cache them locally.
pub async fn fetch_and_cache() -> Result<()> {
    let dir = cache_dir().ok_or_else(|| anyhow!("Cannot determine cache dir"))?;
    std::fs::create_dir_all(&dir)?;

    eprintln!("\nUpdating payload database (External sources: GPLv2/MIT)...");

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .user_agent("Mozilla/5.0 (compatible; sqx-updater/1.0)")
        .build()?;

    for (filename, url) in FETCH_SOURCES {
        eprint!("  {:30} ", filename);
        match client.get(*url).send().await {
            Ok(r) if r.status().is_success() => {
                // Check content length before downloading
                if let Some(content_length) = r.content_length() {
                    if content_length > MAX_PAYLOAD_SIZE as u64 {
                        eprintln!("✗ File too large ({} > {} bytes)", content_length, MAX_PAYLOAD_SIZE);
                        continue;
                    }
                }
                
                let body = r.text().await?;
                
                // Verify size limit after download (defense in depth)
                if body.len() > MAX_PAYLOAD_SIZE {
                    eprintln!("✗ File too large ({} > {} bytes)", body.len(), MAX_PAYLOAD_SIZE);
                    continue;
                }
                
                std::fs::write(dir.join(filename), &body)?;
                eprintln!("✓");
            }
            Ok(r) => eprintln!("✗ HTTP {}", r.status()),
            Err(e) => eprintln!("✗ {}", e),
        }
    }

    // Also fetch boundaries.xml explicitly
    let b_url =
        "https://raw.githubusercontent.com/sqlmapproject/sqlmap/master/data/xml/boundaries.xml";
    eprint!("  {:30} ", "boundaries.xml");
    if let Ok(r) = client.get(b_url).send().await {
        if r.status().is_success() {
            // Check content length before downloading
            if let Some(content_length) = r.content_length() {
                if content_length > MAX_PAYLOAD_SIZE as u64 {
                    eprintln!("✗ File too large ({} > {} bytes)", content_length, MAX_PAYLOAD_SIZE);
                    return Ok(());
                }
            }
            
            if let Ok(body) = r.text().await {
                // Verify size limit after download
                if body.len() > MAX_PAYLOAD_SIZE {
                    eprintln!("✗ File too large ({} > {} bytes)", body.len(), MAX_PAYLOAD_SIZE);
                    return Ok(());
                }
                let _ = std::fs::write(dir.join("boundaries.xml"), &body);
                eprintln!("✓");
            }
        }
    }

    Ok(())
}

/// Check if payload cache exists.
pub fn is_cached() -> bool {
    cache_dir()
        .map(|d| d.join("boolean_blind.xml").exists())
        .unwrap_or(false)
}

/// Get the cache directory path.
pub fn cache_dir() -> Option<PathBuf> {
    let base = std::env::var("XDG_DATA_HOME")
        .ok()
        .map(PathBuf::from)
        .or_else(|| {
            std::env::var("HOME")
                .ok()
                .map(|h| PathBuf::from(h).join(".local").join("share"))
        })?;
    Some(base.join("sqx").join("payloads"))
}

/// Read a cached file if it exists.
pub fn read_cached(filename: &str) -> Option<String> {
    let path = cache_dir()?.join(filename);
    std::fs::read_to_string(path).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cache_dir_returns_some() {
        // This test assumes HOME is set in the environment
        if std::env::var("HOME").is_ok() {
            assert!(cache_dir().is_some());
        }
    }

    #[test]
    fn is_cached_false_when_no_cache() {
        // If cache doesn't exist, should return false
        if cache_dir().map(|d| !d.exists()).unwrap_or(true) {
            assert!(!is_cached());
        }
    }
}
