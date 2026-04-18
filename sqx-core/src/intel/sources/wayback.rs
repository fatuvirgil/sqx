//! Wayback Machine (Internet Archive) CDX API client.
//!
//! No API key required.
//! Cache TTL: 24 hours.
//! API: https://web.archive.org/cdx/search/cdx

use crate::intel::types::{HistoricEndpoint, WaybackCdxEntry};
use anyhow::{Context, Result};
use std::time::Duration;
use std::collections::HashSet;
use tracing::{debug, instrument};

const WAYBACK_CDX_BASE: &str = "https://web.archive.org/cdx/search/cdx";
const CACHE_TTL_SECONDS: u64 = 24 * 3600; // 24 hours

/// Wayback Machine CDX client.
pub struct WaybackClient {
    http: reqwest::Client,
}

impl WaybackClient {
    /// Create a new Wayback client.
    pub fn new() -> Result<Self> {
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(120))
            .build()?;

        Ok(Self { http })
    }

    /// Get historic URLs for a domain.
    #[instrument(skip(self), fields(domain = %domain))]
    pub async fn get_urls(&self, domain: &str) -> Result<Vec<HistoricEndpoint>> {
        let url = format!(
            "{}?url={}/*&output=json&fl=original&collapse=urlkey",
            WAYBACK_CDX_BASE,
            domain
        );

        debug!("Wayback CDX query for: {}", domain);

        let response = self.http.get(&url).send().await?;

        if !response.status().is_success() {
            let text = response.text().await?;
            return Err(anyhow::anyhow!("Wayback error: {}", text));
        }

        let entries: Vec<WaybackCdxEntry> = response.json().await
            .context("Failed to parse Wayback response")?;

        // Parse and filter URLs with parameters
        let mut seen = HashSet::new();
        let endpoints: Vec<HistoricEndpoint> = entries
            .into_iter()
            .filter_map(|entry| {
                let url = entry.first()?.clone();
                
                // Only keep URLs with query parameters
                if !url.contains('?') && !url.contains('&') {
                    return None;
                }

                // Deduplicate
                if !seen.insert(url.clone()) {
                    return None;
                }

                let params = extract_params(&url);
                
                Some(HistoricEndpoint {
                    url: url.clone(),
                    method: "GET".to_string(),
                    parameters: params,
                    status_code: None,
                    source: "wayback".to_string(),
                })
            })
            .collect();

        debug!("Wayback found {} URLs with parameters", endpoints.len());
        Ok(endpoints)
    }

    pub fn cache_ttl() -> u64 {
        CACHE_TTL_SECONDS
    }
}

fn extract_params(url: &str) -> Vec<String> {
    let mut params = Vec::new();
    
    if let Some(query_start) = url.find('?') {
        let query = &url[query_start + 1..];
        for part in query.split('&') {
            if let Some(eq_pos) = part.find('=') {
                params.push(part[..eq_pos].to_string());
            } else {
                params.push(part.to_string());
            }
        }
    }
    
    params
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_params() {
        let url = "https://example.com/page?id=1&user=admin&page=2";
        let params = extract_params(url);
        assert_eq!(params, vec!["id", "user", "page"]);
    }

    #[test]
    fn test_extract_params_none() {
        let url = "https://example.com/page";
        let params = extract_params(url);
        assert!(params.is_empty());
    }
}
