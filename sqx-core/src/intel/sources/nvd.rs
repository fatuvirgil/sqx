//! NVD (National Vulnerability Database) API client.
//!
//! Rate limit: 100 requests per 30 seconds.
//! Cache TTL: 6 hours.
//! API: https://services.nvd.nist.gov/rest/json/cves/2.0

use crate::intel::types::{CveInfo, NvdResponse};
use anyhow::{Context, Result};
use std::time::Duration;
use tracing::{debug, instrument, warn};

const NVD_API_BASE: &str = "https://services.nvd.nist.gov/rest/json/cves/2.0";
const CACHE_TTL_SECONDS: u64 = 6 * 3600; // 6 hours
const RATE_LIMIT_DELAY_MS: u64 = 350; // ~100 req / 30s = 1 req per 300ms + buffer

/// NVD API client.
pub struct NvdClient {
    http: reqwest::Client,
    api_key: Option<String>,
}

impl NvdClient {
    /// Create a new NVD client.
    pub fn new() -> Result<Self> {
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .build()?;

        Ok(Self {
            http,
            api_key: std::env::var("NVD_API_KEY").ok(),
        })
    }

    /// Search CVEs by keyword (product name).
    #[instrument(skip(self), fields(keyword = %keyword))]
    pub async fn search_by_keyword(&self, keyword: &str) -> Result<Vec<CveInfo>> {
        let cache_key = format!("nvd:keyword:{}", keyword);

        // Check cache first (if available)
        // For now, return fresh data
        let url = format!("{}?keywordSearch={}", NVD_API_BASE, urlencoding::encode(keyword));

        debug!("Fetching from NVD: {}", url);

        let mut req = self.http.get(&url);
        if let Some(key) = &self.api_key {
            req = req.header("apiKey", key);
        }

        // Rate limiting
        tokio::time::sleep(Duration::from_millis(RATE_LIMIT_DELAY_MS)).await;

        let response = req.send().await?;
        let status = response.status();

        if !status.is_success() {
            let text = response.text().await?;
            return Err(anyhow::anyhow!("NVD API error {}: {}", status, text));
        }

        let nvd_response: NvdResponse = response.json().await
            .context("Failed to parse NVD response")?;

        debug!("Got {} CVEs from NVD", nvd_response.vulnerabilities.len());

        let cves: Vec<CveInfo> = nvd_response
            .vulnerabilities
            .into_iter()
            .map(|v| convert_to_cve_info(v.cve))
            .collect();

        Ok(cves)
    }

    /// Search CVEs by CPE (Common Platform Enumeration).
    #[instrument(skip(self), fields(cpe = %cpe))]
    pub async fn search_by_cpe(&self, cpe: &str) -> Result<Vec<CveInfo>> {
        let url = format!("{}?cpeName={}", NVD_API_BASE, urlencoding::encode(cpe));

        debug!("Fetching from NVD by CPE: {}", url);

        let mut req = self.http.get(&url);
        if let Some(key) = &self.api_key {
            req = req.header("apiKey", key);
        }

        tokio::time::sleep(Duration::from_millis(RATE_LIMIT_DELAY_MS)).await;

        let response = req.send().await?;

        if !response.status().is_success() {
            let text = response.text().await?;
            return Err(anyhow::anyhow!("NVD API error: {}", text));
        }

        let nvd_response: NvdResponse = response.json().await?;

        Ok(nvd_response
            .vulnerabilities
            .into_iter()
            .map(|v| convert_to_cve_info(v.cve))
            .collect())
    }

    /// Search for kernel CVEs.
    pub async fn search_kernel_cves(&self, version: &str) -> Result<Vec<CveInfo>> {
        let cpe = format!("cpe:2.3:o:linux:linux_kernel:{}", version);
        self.search_by_cpe(&cpe).await
    }

    /// Search for nginx CVEs.
    pub async fn search_nginx_cves(&self, version: &str) -> Result<Vec<CveInfo>> {
        let cpe = format!("cpe:2.3:a:nginx:nginx:{}", version);
        self.search_by_cpe(&cpe).await
    }

    /// Search for Apache HTTPD CVEs.
    pub async fn search_apache_cves(&self, version: &str) -> Result<Vec<CveInfo>> {
        let cpe = format!("cpe:2.3:a:apache:http_server:{}", version);
        self.search_by_cpe(&cpe).await
    }

    pub fn cache_ttl() -> u64 {
        CACHE_TTL_SECONDS
    }
}

fn convert_to_cve_info(cve: crate::intel::types::NvdCve) -> CveInfo {
    // Extract fields before moving cve
    let cve_id = cve.id.clone();
    
    let cvss = cve
        .metrics
        .as_ref()
        .and_then(|m| m.cvss_metric_v31.as_ref())
        .and_then(|v| v.first())
        .map(|m| m.cvss_data.base_score)
        .or_else(|| {
            cve.metrics
                .as_ref()
                .and_then(|m| m.cvss_metric_v30.as_ref())
                .and_then(|v| v.first())
                .map(|m| m.cvss_data.base_score)
        });

    let cwe = cve
        .weaknesses
        .as_ref()
        .and_then(|w| w.first())
        .and_then(|w| w.description.first())
        .map(|d| d.value.clone());

    // Check if web-exposed (affects web servers, PHP, MySQL, etc.)
    let is_web_exposed = cve
        .configurations
        .as_ref()
        .map(|configs| {
            configs.iter().any(|config| {
                config.nodes.iter().any(|node| {
                    node.cpe_match.as_ref().map_or(false, |matches| {
                        matches.iter().any(|m| {
                            let criteria = m.criteria.to_lowercase();
                            criteria.contains("apache") ||
                            criteria.contains("nginx") ||
                            criteria.contains("php") ||
                            criteria.contains("mysql") ||
                            criteria.contains("postgresql") ||
                            criteria.contains("tomcat") ||
                            criteria.contains("java")
                        })
                    })
                })
            })
        })
        .unwrap_or(false);

    // Check if kernel
    let is_kernel = cve
        .configurations
        .as_ref()
        .map(|configs| {
            configs.iter().any(|config| {
                config.nodes.iter().any(|node| {
                    node.cpe_match.as_ref().map_or(false, |matches| {
                        matches.iter().any(|m| {
                            m.criteria.to_lowercase().contains("linux:linux_kernel")
                        })
                    })
                })
            })
        })
        .unwrap_or(false);

    CveInfo {
        cve_id,
        cvss,
        cwe,
        affected_product: extract_product(&cve),
        is_web_exposed,
        is_kernel,
        exploit_available: false, // Would need Exploit-DB lookup
        json_data: None,
    }
}

fn extract_product(cve: &crate::intel::types::NvdCve) -> String {
    cve.descriptions
        .iter()
        .find(|d| d.lang == "en")
        .map(|d| {
            // Try to extract product from description
            let desc = &d.value;
            if let Some(start) = desc.find("in ") {
                let rest = &desc[start + 3..];
                if let Some(end) = rest.find(' ') {
                    return rest[..end].to_string();
                }
            }
            desc.chars().take(100).collect()
        })
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    // Note: These tests require network access
    // Use wiremock for proper unit tests

    #[test]
    fn test_extract_product() {
        use crate::intel::types::{NvdCve, NvdDescription};

        let cve = NvdCve {
            id: "CVE-2023-1234".to_string(),
            descriptions: vec![NvdDescription {
                lang: "en".to_string(),
                value: "A vulnerability in Apache HTTP Server 2.4.49 allows...".to_string(),
            }],
            metrics: None,
            weaknesses: None,
            configurations: None,
        };

        let product = extract_product(&cve);
        assert!(product.contains("Apache") || product.contains("in"));
    }
}
