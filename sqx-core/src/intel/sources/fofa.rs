//! FOFA API client (Chinese search engine for cyberspace mapping).
//!
//! Rate limit: Varies by membership level.
//! Cache TTL: 12 hours.
//! API: https://fofa.info/api/v1/search/all

use crate::intel::types::FofaResponse;
use anyhow::{Context, Result};
use std::time::Duration;
use tracing::{debug, instrument, warn};

const FOFA_API_BASE: &str = "https://fofa.info/api/v1/search/all";
const CACHE_TTL_SECONDS: u64 = 12 * 3600; // 12 hours
const RATE_LIMIT_DELAY_MS: u64 = 1500; // Conservative

/// FOFA API client.
pub struct FofaClient {
    http: reqwest::Client,
    email: String,
    api_key: String,
}

impl FofaClient {
    /// Create a new FOFA client.
    /// Requires FOFA_EMAIL and FOFA_KEY environment variables.
    pub fn new() -> Result<Self> {
        let email = std::env::var("FOFA_EMAIL")
            .context("FOFA_EMAIL environment variable not set")?;
        let api_key = std::env::var("FOFA_KEY")
            .context("FOFA_KEY environment variable not set")?;

        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(60))
            .build()?;

        Ok(Self {
            http,
            email,
            api_key,
        })
    }

    /// Check if FOFA is configured.
    pub fn is_configured() -> bool {
        std::env::var("FOFA_EMAIL").is_ok() && std::env::var("FOFA_KEY").is_ok()
    }

    /// Search by query (FOFA syntax).
    /// Query is Base64 encoded as per API requirement.
    #[instrument(skip(self), fields(query = %query))]
    pub async fn search(&self, query: &str, size: usize) -> Result<Vec<FofaResult>> {
        let encoded_query = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, query);

        let url = format!(
            "{}?email={}&key={}&qbase64={}&size={}",
            FOFA_API_BASE, self.email, self.api_key, encoded_query, size
        );

        debug!("FOFA search (encoded): {}", &encoded_query[..20.min(encoded_query.len())]);

        tokio::time::sleep(Duration::from_millis(RATE_LIMIT_DELAY_MS)).await;

        let response = self.http.get(&url).send().await?;

        if !response.status().is_success() {
            let text = response.text().await?;
            return Err(anyhow::anyhow!("FOFA API error: {}", text));
        }

        let fofa_response: FofaResponse = response.json().await?;

        if let Some(err) = fofa_response.error {
            return Err(anyhow::anyhow!("FOFA error: {}", err));
        }

        let results: Vec<FofaResult> = fofa_response
            .results
            .into_iter()
            .map(|fields| FofaResult {
                host: fields.get(0).cloned().unwrap_or_default(),
                title: fields.get(1).cloned().unwrap_or_default(),
                ip: fields.get(2).cloned().unwrap_or_default(),
                port: fields
                    .get(3)
                    .and_then(|p| p.parse().ok())
                    .unwrap_or(0),
                domain: fields.get(4).cloned().unwrap_or_default(),
                protocol: fields.get(5).cloned().unwrap_or_default(),
                server: fields.get(6).cloned().unwrap_or_default(),
            })
            .collect();

        debug!("FOFA found {} results", results.len());
        Ok(results)
    }

    /// Search for domain assets.
    pub async fn search_domain(&self, domain: &str) -> Result<Vec<FofaResult>> {
        let query = format!("domain={}", domain);
        self.search(&query, 100).await
    }

    /// Search for specific service/port.
    pub async fn search_service(&self, ip: &str, port: u16) -> Result<Vec<FofaResult>> {
        let query = format!("ip={} && port={}", ip, port);
        self.search(&query, 10).await
    }

    pub fn cache_ttl() -> u64 {
        CACHE_TTL_SECONDS
    }
}

/// FOFA search result.
#[derive(Debug, Clone)]
pub struct FofaResult {
    pub host: String,
    pub title: String,
    pub ip: String,
    pub port: u16,
    pub domain: String,
    pub protocol: String,
    pub server: String,
}
