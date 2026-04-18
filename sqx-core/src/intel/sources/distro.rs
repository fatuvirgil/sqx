//! Linux distribution security advisory clients.
//!
//! - Ubuntu USN (Ubuntu Security Notices)
//! - Red Hat RHSB (RHSA/RHBA)
//! - Debian DSA (Debian Security Advisory)
//! - Arch Linux Security

use crate::intel::types::DistroAdvisory;
use anyhow::{Context, Result};
use std::time::Duration;
use tracing::{debug, instrument};

// Ubuntu USN
const USN_API_BASE: &str = "https://ubuntu.com/security/notices.json";
const USN_CACHE_TTL: u64 = 12 * 3600;

// Red Hat Security Data API
const REDHAT_API_BASE: &str = "https://access.redhat.com/hydra/rest/securitydata";
const REDHAT_CACHE_TTL: u64 = 12 * 3600;

// Debian Security Tracker
const DEBIAN_TRACKER_BASE: &str = "https://security-tracker.debian.org/tracker";
const DEBIAN_CACHE_TTL: u64 = 24 * 3600;

// Arch Linux Security
const ARCH_SECURITY_BASE: &str = "https://security.archlinux.org";
const ARCH_CACHE_TTL: u64 = 12 * 3600;

/// Ubuntu USN client.
pub struct UbuntuUsnClient {
    http: reqwest::Client,
}

impl UbuntuUsnClient {
    pub fn new() -> Result<Self> {
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .build()?;
        Ok(Self { http })
    }

    /// Get USNs for a specific release.
    #[instrument(skip(self), fields(release = %release))]
    pub async fn get_advisories(&self, release: &str) -> Result<Vec<DistroAdvisory>> {
        let url = format!("{}?release={}&details=true", USN_API_BASE, release);
        debug!("Fetching Ubuntu USN for: {}", release);

        let response = self.http.get(&url).send().await?;

        if !response.status().is_success() {
            return Err(anyhow::anyhow!("USN API error: {}", response.status()));
        }

        let data: serde_json::Value = response.json().await?;
        let notices = data["notices"].as_array().cloned().unwrap_or_default();

        let advisories: Vec<DistroAdvisory> = notices
            .iter()
            .filter_map(|n| {
                Some(DistroAdvisory {
                    distro: "ubuntu".to_string(),
                    advisory_id: n["id"].as_str()?.to_string(),
                    package: n["packages"].as_array()?.first()?["name"]
                        .as_str()?
                        .to_string(),
                    severity: n["severity"].as_str().unwrap_or("unknown").to_string(),
                    fixed_version: n["packages"].as_array()?.first()?["version"]
                        .as_str()?
                        .to_string(),
                    cve_refs: n["cves"]
                        .as_array()?
                        .iter()
                        .filter_map(|c| c.as_str().map(|s| s.to_string()))
                        .collect(),
                })
            })
            .collect();

        debug!("Found {} Ubuntu USNs", advisories.len());
        Ok(advisories)
    }

    pub fn cache_ttl() -> u64 {
        USN_CACHE_TTL
    }
}

/// Red Hat Security Data client.
pub struct RedHatClient {
    http: reqwest::Client,
}

impl RedHatClient {
    pub fn new() -> Result<Self> {
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .build()?;
        Ok(Self { http })
    }

    /// Get CVE data for a package.
    #[instrument(skip(self), fields(package = %package))]
    pub async fn get_cves_for_package(&self, package: &str) -> Result<Vec<DistroAdvisory>> {
        let url = format!("{}/cve.json?package={}", REDHAT_API_BASE, package);
        debug!("Fetching Red Hat CVEs for: {}", package);

        let response = self.http.get(&url).send().await?;

        if !response.status().is_success() {
            return Err(anyhow::anyhow!("Red Hat API error: {}", response.status()));
        }

        // Parse and convert
        let data: Vec<serde_json::Value> = response.json().await?;

        let advisories: Vec<DistroAdvisory> = data
            .into_iter()
            .filter_map(|item| {
                Some(DistroAdvisory {
                    distro: "rhel".to_string(),
                    advisory_id: item["CVE"].as_str()?.to_string(),
                    package: package.to_string(),
                    severity: item["severity"].as_str().unwrap_or("unknown").to_string(),
                    fixed_version: item["fix_state"].as_str()?.to_string(),
                    cve_refs: vec![item["CVE"].as_str()?.to_string()],
                })
            })
            .collect();

        debug!("Found {} Red Hat entries", advisories.len());
        Ok(advisories)
    }

    pub fn cache_ttl() -> u64 {
        REDHAT_CACHE_TTL
    }
}

/// Debian Security Tracker client.
pub struct DebianClient {
    http: reqwest::Client,
}

impl DebianClient {
    pub fn new() -> Result<Self> {
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(60))
            .build()?;
        Ok(Self { http })
    }

    /// Get DSA list (JSON format).
    #[instrument(skip(self))]
    pub async fn get_advisories(&self) -> Result<Vec<DistroAdvisory>> {
        let url = format!("{}/data/json", DEBIAN_TRACKER_BASE);
        debug!("Fetching Debian security data");

        let response = self.http.get(&url).send().await?;

        if !response.status().is_success() {
            return Err(anyhow::anyhow!("Debian API error: {}", response.status()));
        }

        // Debian JSON is complex - simplified parsing
        let data: serde_json::Value = response.json().await?;
        
        // Extract from the 'package' structure
        let mut advisories = Vec::new();
        
        if let Some(packages) = data.as_object() {
            for (pkg_name, pkg_data) in packages.iter().take(100) { // Limit for performance
                if let Some(cves) = pkg_data["cves"].as_object() {
                    for (cve_id, cve_data) in cves {
                        if let Some(releases) = cve_data["releases"].as_object() {
                            for (release, rel_data) in releases {
                                advisories.push(DistroAdvisory {
                                    distro: "debian".to_string(),
                                    advisory_id: format!("DSA-{}-{}", pkg_name, cve_id),
                                    package: pkg_name.clone(),
                                    severity: rel_data["urgency"].as_str().unwrap_or("unknown").to_string(),
                                    fixed_version: rel_data["fixed_version"]
                                        .as_str()
                                        .unwrap_or("unknown")
                                        .to_string(),
                                    cve_refs: vec![cve_id.clone()],
                                });
                            }
                        }
                    }
                }
            }
        }

        debug!("Found {} Debian advisories", advisories.len());
        Ok(advisories)
    }

    pub fn cache_ttl() -> u64 {
        DEBIAN_CACHE_TTL
    }
}

/// Arch Linux Security client.
pub struct ArchClient {
    http: reqwest::Client,
}

impl ArchClient {
    pub fn new() -> Result<Self> {
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .build()?;
        Ok(Self { http })
    }

    /// Get recent advisories.
    #[instrument(skip(self))]
    pub async fn get_advisories(&self) -> Result<Vec<DistroAdvisory>> {
        let url = format!("{}/json", ARCH_SECURITY_BASE);
        debug!("Fetching Arch security data");

        let response = self.http.get(&url).send().await?;

        if !response.status().is_success() {
            return Err(anyhow::anyhow!("Arch API error: {}", response.status()));
        }

        let data: Vec<serde_json::Value> = response.json().await?;

        let advisories: Vec<DistroAdvisory> = data
            .into_iter()
            .filter_map(|item| {
                Some(DistroAdvisory {
                    distro: "arch".to_string(),
                    advisory_id: item["name"].as_str()?.to_string(),
                    package: item["packages"].as_array()?.first()?.as_str()?.to_string(),
                    severity: item["severity"].as_str().unwrap_or("unknown").to_string(),
                    fixed_version: item["fixed"].as_str()?.to_string(),
                    cve_refs: item["issues"]
                        .as_array()?
                        .iter()
                        .filter_map(|i| i.as_str().map(|s| s.to_string()))
                        .collect(),
                })
            })
            .collect();

        debug!("Found {} Arch advisories", advisories.len());
        Ok(advisories)
    }

    pub fn cache_ttl() -> u64 {
        ARCH_CACHE_TTL
    }
}
