//! Shodan API client for banner grabbing and asset discovery.
//!
//! Rate limit: Varies by plan (free tier: 1 request/second).
//! Cache TTL: 12 hours.
//! API: https://api.shodan.io

use crate::intel::types::{ShodanBanner, ShodanHostResponse};
use anyhow::{Context, Result};
use std::time::Duration;
use tracing::{debug, instrument, warn};

const SHODAN_API_BASE: &str = "https://api.shodan.io";
const CACHE_TTL_SECONDS: u64 = 12 * 3600; // 12 hours
const RATE_LIMIT_DELAY_MS: u64 = 1100; // 1 req/sec for free tier

/// Shodan API client.
pub struct ShodanClient {
    http: reqwest::Client,
    api_key: String,
}

impl ShodanClient {
    /// Create a new Shodan client.
    /// Requires SHODAN_API_KEY environment variable.
    pub fn new() -> Result<Self> {
        let api_key = std::env::var("SHODAN_API_KEY")
            .context("SHODAN_API_KEY environment variable not set")?;

        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .build()?;

        Ok(Self { http, api_key })
    }

    /// Create client with explicit API key.
    pub fn with_key(api_key: String) -> Result<Self> {
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .build()?;

        Ok(Self { http, api_key })
    }

    /// Check if API key is configured.
    pub fn is_configured() -> bool {
        std::env::var("SHODAN_API_KEY").is_ok()
    }

    /// Search for hosts by query.
    #[instrument(skip(self), fields(query = %query))]
    pub async fn search(&self, query: &str) -> Result<Vec<ShodanHost>> {
        let url = format!(
            "{}/shodan/host/search?key={}&query={}",
            SHODAN_API_BASE,
            self.api_key,
            urlencoding::encode(query)
        );

        debug!("Shodan search: {}", query);

        tokio::time::sleep(Duration::from_millis(RATE_LIMIT_DELAY_MS)).await;

        let response = self.http.get(&url).send().await?;

        if response.status() == 429 {
            return Err(anyhow::anyhow!("Shodan rate limit exceeded"));
        }

        if !response.status().is_success() {
            let text = response.text().await?;
            return Err(anyhow::anyhow!("Shodan API error: {}", text));
        }

        let result: serde_json::Value = response.json().await?;

        let hosts: Vec<ShodanHost> = result["matches"]
            .as_array()
            .unwrap_or(&vec![])
            .iter()
            .filter_map(|m| {
                Some(ShodanHost {
                    ip: m["ip_str"].as_str()?.to_string(),
                    port: m["port"].as_u64()? as u16,
                    banner: m["data"].as_str()?.to_string(),
                    product: m["product"].as_str().map(|s| s.to_string()),
                    version: m["version"].as_str().map(|s| s.to_string()),
                    org: m["org"].as_str().map(|s| s.to_string()),
                    hostnames: m["hostnames"]
                        .as_array()
                        .map(|arr| {
                            arr.iter()
                                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                                .collect()
                        })
                        .unwrap_or_default(),
                })
            })
            .collect();

        debug!("Shodan found {} hosts", hosts.len());
        Ok(hosts)
    }

    /// Get host details by IP.
    #[instrument(skip(self), fields(ip = %ip))]
    pub async fn host(&self, ip: &str) -> Result<ShodanHostResponse> {
        let url = format!("{}/shodan/host/{}", SHODAN_API_BASE, ip);

        debug!("Shodan host lookup: {}", ip);

        tokio::time::sleep(Duration::from_millis(RATE_LIMIT_DELAY_MS)).await;

        let response = self
            .http
            .get(&url)
            .query(&[("key", self.api_key.as_str())])
            .send()
            .await?;

        if response.status() == 404 {
            return Err(anyhow::anyhow!("Host not found in Shodan"));
        }

        if !response.status().is_success() {
            let text = response.text().await?;
            return Err(anyhow::anyhow!("Shodan API error: {}", text));
        }

        let host: ShodanHostResponse = response.json().await?;
        Ok(host)
    }

    /// Extract banners as intel types.
    pub fn extract_banners(host: &ShodanHostResponse) -> Vec<ShodanBanner> {
        host.data
            .iter()
            .map(|d| ShodanBanner {
                port: d.port,
                banner: d.banner.clone(),
                product: d.product.clone(),
                version: d.version.clone(),
            })
            .collect()
    }

    pub fn cache_ttl() -> u64 {
        CACHE_TTL_SECONDS
    }
}

/// Simplified Shodan host representation.
#[derive(Debug, Clone)]
pub struct ShodanHost {
    pub ip: String,
    pub port: u16,
    pub banner: String,
    pub product: Option<String>,
    pub version: Option<String>,
    pub org: Option<String>,
    pub hostnames: Vec<String>,
}
