//! crt.sh client for subdomain enumeration via certificate transparency.
//!
//! No API key required.
//! Cache TTL: 48 hours.
//! API: https://crt.sh/?q=%.{domain}&output=json

use crate::intel::types::CrtShEntry;
use anyhow::{Context, Result};
use std::time::Duration;
use std::collections::HashSet;
use tracing::{debug, instrument};

const CRTSH_API_BASE: &str = "https://crt.sh";
const CACHE_TTL_SECONDS: u64 = 48 * 3600; // 48 hours

/// crt.sh client.
pub struct CrtShClient {
    http: reqwest::Client,
}

impl CrtShClient {
    /// Create a new crt.sh client.
    pub fn new() -> Result<Self> {
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(60))
            .build()?;

        Ok(Self { http })
    }

    /// Get subdomains for a domain.
    #[instrument(skip(self), fields(domain = %domain))]
    pub async fn get_subdomains(&self, domain: &str) -> Result<Vec<String>> {
        let url = format!(
            "{}/?q=%.{}&output=json",
            CRTSH_API_BASE,
            urlencoding::encode(domain)
        );

        debug!("crt.sh query: {}", url);

        let response = self.http.get(&url).send().await?;

        if !response.status().is_success() {
            let text = response.text().await?;
            return Err(anyhow::anyhow!("crt.sh error: {}", text));
        }

        let entries: Vec<CrtShEntry> = response.json().await
            .context("Failed to parse crt.sh response")?;

        // Extract unique subdomains
        let mut subdomains: HashSet<String> = HashSet::new();
        for entry in entries {
            for line in entry.name_value.lines() {
                let subdomain = line.trim().to_lowercase();
                if subdomain.ends_with(domain) && subdomain != domain {
                    subdomains.insert(subdomain);
                }
            }
        }

        let result: Vec<String> = subdomains.into_iter().collect();
        debug!("crt.sh found {} unique subdomains", result.len());
        Ok(result)
    }

    pub fn cache_ttl() -> u64 {
        CACHE_TTL_SECONDS
    }
}
