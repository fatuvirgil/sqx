//! Type definitions for intelligence data.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Complete target profile aggregated from all sources.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct TargetProfile {
    /// Target domain
    pub domain: String,
    /// Resolved IP address
    pub ip: Option<String>,
    /// Technology stack detected
    pub tech_stack: TechStack,
    /// CVEs affecting this target
    pub cves: Vec<CveInfo>,
    /// Distro security advisories
    pub advisories: Vec<DistroAdvisory>,
    /// Historic endpoints discovered
    pub historic_endpoints: Vec<HistoricEndpoint>,
    /// Shodan banners
    pub shodan_banners: Vec<ShodanBanner>,
    /// Subdomains found
    pub subdomains: Vec<String>,
    /// When profile was created
    pub created_at: chrono::DateTime<chrono::Utc>,
    /// When profile expires
    pub expires_at: chrono::DateTime<chrono::Utc>,
}

impl TargetProfile {
    /// Get the database dialect based on tech stack.
    pub fn get_dialect(&self) -> crate::validator::DbDialect {
        use crate::validator::DbDialect;
        let db = &self.tech_stack.db.to_lowercase();
        if db.contains("mysql") || db.contains("mariadb") {
            DbDialect::MySQL
        } else if db.contains("postgres") {
            DbDialect::Postgres
        } else if db.contains("mssql") || db.contains("sql server") {
            DbDialect::MSSQL
        } else if db.contains("oracle") {
            DbDialect::Oracle
        } else if db.contains("sqlite") {
            DbDialect::SQLite
        } else {
            DbDialect::MySQL // Default
        }
    }

    /// Check if a specific CVE affects this target.
    pub fn has_cve(&self, cve_id: &str) -> bool {
        self.cves.iter().any(|c| c.cve_id == cve_id)
    }

    /// Get all web-exposed CVEs.
    pub fn web_exposed_cves(&self) -> Vec<&CveInfo> {
        self.cves.iter().filter(|c| c.is_web_exposed).collect()
    }
}

/// Technology stack information.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct TechStack {
    /// Web server (e.g., "nginx/1.18.0")
    pub server: String,
    /// Database (e.g., "MySQL 8.0.28")
    pub db: String,
    /// Operating system (e.g., "Ubuntu 20.04")
    pub os: String,
    /// Programming language/runtime (e.g., "PHP 7.4")
    pub runtime: String,
    /// Framework detected (e.g., "Laravel")
    pub framework: String,
    /// Additional technologies as JSON
    pub extra: HashMap<String, String>,
}

/// CVE information from NVD.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CveInfo {
    /// CVE ID (e.g., "CVE-2023-1234")
    pub cve_id: String,
    /// CVSS v3 score
    pub cvss: Option<f64>,
    /// CWE category
    pub cwe: Option<String>,
    /// Affected product/version
    pub affected_product: String,
    /// Whether this affects web components
    pub is_web_exposed: bool,
    /// Whether this is a kernel vulnerability
    pub is_kernel: bool,
    /// Whether public exploit is available
    pub exploit_available: bool,
    /// Raw JSON data
    pub json_data: Option<String>,
}

/// Distro security advisory.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DistroAdvisory {
    /// Distribution (ubuntu, rhel, debian, arch)
    pub distro: String,
    /// Advisory ID (e.g., "USN-1234-1", "RHSA-2023:1234")
    pub advisory_id: String,
    /// Affected package
    pub package: String,
    /// Severity (low, medium, high, critical)
    pub severity: String,
    /// Fixed version
    pub fixed_version: String,
    /// CVE references
    pub cve_refs: Vec<String>,
}

/// Historic endpoint from Wayback/crt.sh.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HistoricEndpoint {
    /// Full URL
    pub url: String,
    /// HTTP method (usually GET)
    pub method: String,
    /// URL parameters discovered
    pub parameters: Vec<String>,
    /// HTTP status code (if available)
    pub status_code: Option<u16>,
    /// Source (wayback, crt.sh, etc.)
    pub source: String,
}

/// Shodan banner information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShodanBanner {
    /// Port number
    pub port: u16,
    /// Raw banner
    pub banner: String,
    /// Detected product
    pub product: Option<String>,
    /// Detected version
    pub version: Option<String>,
}

/// NVD API response structures.
#[derive(Debug, Deserialize)]
pub struct NvdResponse {
    pub vulnerabilities: Vec<NvdVulnerability>,
    pub total_results: i32,
}

#[derive(Debug, Deserialize)]
pub struct NvdVulnerability {
    pub cve: NvdCve,
}

#[derive(Debug, Deserialize)]
pub struct NvdCve {
    pub id: String,
    pub descriptions: Vec<NvdDescription>,
    pub metrics: Option<NvdMetrics>,
    pub weaknesses: Option<Vec<NvdWeakness>>,
    pub configurations: Option<Vec<NvdConfiguration>>,
}

#[derive(Debug, Deserialize)]
pub struct NvdDescription {
    pub lang: String,
    pub value: String,
}

#[derive(Debug, Deserialize)]
pub struct NvdMetrics {
    pub cvss_metric_v31: Option<Vec<NvdCvssMetric>>,
    pub cvss_metric_v30: Option<Vec<NvdCvssMetric>>,
    pub cvss_metric_v2: Option<Vec<NvdCvssMetric>>,
}

#[derive(Debug, Deserialize)]
pub struct NvdCvssMetric {
    pub cvss_data: NvdCvssData,
}

#[derive(Debug, Deserialize)]
pub struct NvdCvssData {
    #[serde(rename = "baseScore")]
    pub base_score: f64,
}

#[derive(Debug, Deserialize)]
pub struct NvdWeakness {
    pub description: Vec<NvdDescription>,
}

#[derive(Debug, Deserialize)]
pub struct NvdConfiguration {
    pub nodes: Vec<NvdNode>,
}

#[derive(Debug, Deserialize)]
pub struct NvdNode {
    pub cpe_match: Option<Vec<NvdCpeMatch>>,
}

#[derive(Debug, Deserialize)]
pub struct NvdCpeMatch {
    #[serde(rename = "criteria")]
    pub criteria: String,
    #[serde(rename = "vulnerable")]
    pub vulnerable: bool,
}

/// Shodan API response.
#[derive(Debug, Deserialize)]
pub struct ShodanHostResponse {
    pub ip_str: String,
    pub ports: Vec<u16>,
    pub data: Vec<ShodanBannerData>,
}

#[derive(Debug, Deserialize)]
pub struct ShodanBannerData {
    pub port: u16,
    pub banner: String,
    pub product: Option<String>,
    pub version: Option<String>,
}

/// FOFA API response.
#[derive(Debug, Deserialize)]
pub struct FofaResponse {
    pub error: Option<String>,
    pub results: Vec<Vec<String>>,
}

/// crt.sh response.
#[derive(Debug, Deserialize)]
pub struct CrtShEntry {
    pub name_value: String,
}

/// Wayback CDX response (each entry is a JSON array).
pub type WaybackCdxEntry = Vec<String>;
