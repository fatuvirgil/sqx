//! Startup checks - version, payload updates, and critical CVEs.

use std::time::Duration;
use tracing::debug;

const CURRENT_VERSION: &str = env!("CARGO_PKG_VERSION");
const GITHUB_REPO: &str = "fatuvirgil/sqx";

/// Run all startup checks asynchronously.
pub async fn run_startup_checks() {
    // Run checks in parallel
    let version_check = tokio::spawn(check_version());
    let payload_check = tokio::spawn(check_payload_updates());
    let cve_check = tokio::spawn(fetch_critical_cves());

    // Wait for all checks to complete
    let _ = tokio::join!(version_check, payload_check, cve_check);
}

/// Check if a newer version is available on GitHub.
async fn check_version() {
    debug!("Checking for SQX updates...");
    
    let client = match reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build() {
        Ok(c) => c,
        Err(_) => return,
    };

    let url = format!("https://api.github.com/repos/{}/releases/latest", GITHUB_REPO);
    
    match client
        .get(&url)
        .header("User-Agent", "sqx-version-check")
        .send()
        .await {
        Ok(response) => {
            if let Ok(json) = response.json::<serde_json::Value>().await {
                if let Some(latest) = json["tag_name"].as_str() {
                    let latest = latest.trim_start_matches('v');
                    if latest != CURRENT_VERSION {
                        eprintln!("📦 New version available: {} (current: {})", latest, CURRENT_VERSION);
                        eprintln!("   Update: cargo install --git https://github.com/{}", GITHUB_REPO);
                        eprintln!();
                    }
                }
            }
        }
        Err(_) => {
            // Silently fail - no network is okay
            debug!("Could not check for updates");
        }
    }
}

/// Check if payload cache needs updating (older than 7 days).
async fn check_payload_updates() {
    use std::time::SystemTime;
    
    debug!("Checking payload cache age...");
    
    // Check if cache directory exists and get its age
    if let Some(cache_dir) = dirs::data_local_dir().map(|d| d.join("sqx/payloads")) {
        if cache_dir.exists() {
            if let Ok(metadata) = std::fs::metadata(&cache_dir) {
                if let Ok(modified) = metadata.modified() {
                    if let Ok(age) = SystemTime::now().duration_since(modified) {
                        let days = age.as_secs() / 86400;
                        if days >= 7 {
                            eprintln!("🔄 Payload cache is {} days old. Consider updating:", days);
                            eprintln!("   sqx update-payloads");
                            eprintln!();
                        }
                    }
                }
            }
        } else {
            // No cache yet
            eprintln!("📥 Payload cache not found. To expand coverage:");
            eprintln!("   sqx update-payloads");
            eprintln!();
        }
    }
}

/// Fetch and display recent critical CVEs from NVD.
async fn fetch_critical_cves() {
    debug!("Fetching recent critical CVEs...");
    
    let client = match reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build() {
        Ok(c) => c,
        Err(_) => return,
    };

    // Get CVEs from last 7 days with CRITICAL severity
    let now = chrono::Utc::now();
    let week_ago = now - chrono::Duration::days(7);
    let pub_start = week_ago.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string();
    let pub_end = now.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string();
    
    let url = format!(
        "https://services.nvd.nist.gov/rest/json/cves/2.0?cvssV3Severity=CRITICAL&pubStartDate={}&pubEndDate={}&resultsPerPage=5",
        pub_start, pub_end
    );
    
    match client
        .get(&url)
        .header("User-Agent", "sqx-security-check")
        .send()
        .await {
        Ok(response) => {
            if let Ok(json) = response.json::<serde_json::Value>().await {
                if let Some(vulns) = json["vulnerabilities"].as_array() {
                    if !vulns.is_empty() {
                        eprintln!("🚨 Recent Critical CVEs (last 7 days):");
                        for v in vulns.iter().take(3) {
                            if let Some(cve) = v["cve"].as_object() {
                                let id = cve["id"].as_str().unwrap_or("Unknown");
                                let desc = cve["descriptions"]
                                    .as_array()
                                    .and_then(|d| d.first())
                                    .and_then(|d| d["value"].as_str())
                                    .unwrap_or("No description");
                                let short_desc = if desc.len() > 60 {
                                    format!("{}...", &desc[..60])
                                } else {
                                    desc.to_string()
                                };
                                eprintln!("   • {} - {}", id, short_desc);
                            }
                        }
                        eprintln!();
                    }
                }
            }
        }
        Err(_) => {
            // Silently fail - network issues are okay
            debug!("Could not fetch CVE data");
        }
    }
}
