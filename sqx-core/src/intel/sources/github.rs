//! GitHub Code Search API client for finding code leaks.
//!
//! Rate limit: 30 requests per minute for authenticated requests.
//! Cache TTL: 24 hours.
//! API: https://api.github.com/search/code

use anyhow::{Context, Result};
use std::time::Duration;
use tracing::{debug, instrument, warn};

const GITHUB_API_BASE: &str = "https://api.github.com";
const CACHE_TTL_SECONDS: u64 = 24 * 3600; // 24 hours
const RATE_LIMIT_DELAY_MS: u64 = 2100; // 30 req/min = 1 req per 2s + buffer

/// GitHub API client.
pub struct GitHubClient {
    http: reqwest::Client,
    token: String,
}

impl GitHubClient {
    /// Create a new GitHub client.
    /// Requires GITHUB_TOKEN environment variable.
    pub fn new() -> Result<Self> {
        let token = std::env::var("GITHUB_TOKEN")
            .context("GITHUB_TOKEN environment variable not set")?;

        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .build()?;

        Ok(Self { http, token })
    }

    /// Check if GitHub token is configured.
    pub fn is_configured() -> bool {
        std::env::var("GITHUB_TOKEN").is_ok()
    }

    /// Search code with a query.
    #[instrument(skip(self), fields(query = %query))]
    pub async fn search_code(&self, query: &str) -> Result<Vec<GitHubCodeResult>> {
        let url = format!(
            "{}/search/code?q={}&per_page=30",
            GITHUB_API_BASE,
            urlencoding::encode(query)
        );

        debug!("GitHub code search: {}", query);

        tokio::time::sleep(Duration::from_millis(RATE_LIMIT_DELAY_MS)).await;

        let response = self
            .http
            .get(&url)
            .header("Authorization", format!("token {}", self.token))
            .header("Accept", "application/vnd.github.v3+json")
            .header("User-Agent", "SQX-IntelCollector")
            .send()
            .await?;

        if response.status() == 403 || response.status() == 429 {
            return Err(anyhow::anyhow!("GitHub rate limit exceeded"));
        }

        if !response.status().is_success() {
            let text = response.text().await?;
            return Err(anyhow::anyhow!("GitHub API error: {}", text));
        }

        let data: serde_json::Value = response.json().await?;
        let items = data["items"].as_array().cloned().unwrap_or_default();

        let results: Vec<GitHubCodeResult> = items
            .iter()
            .filter_map(|item| {
                Some(GitHubCodeResult {
                    name: item["name"].as_str()?.to_string(),
                    path: item["path"].as_str()?.to_string(),
                    url: item["html_url"].as_str()?.to_string(),
                    repository: item["repository"]["full_name"].as_str()?.to_string(),
                    score: item["score"].as_f64()?,
                })
            })
            .collect();

        debug!("GitHub found {} code results", results.len());
        Ok(results)
    }

    /// Search for SQL files related to a domain.
    #[instrument(skip(self), fields(domain = %domain))]
    pub async fn search_sql_files(&self, domain: &str) -> Result<Vec<GitHubCodeResult>> {
        let query = format!("extension:sql {}", domain);
        self.search_code(&query).await
    }

    /// Search for config files that might contain database credentials.
    #[instrument(skip(self), fields(domain = %domain))]
    pub async fn search_config_files(&self, domain: &str) -> Result<Vec<GitHubCodeResult>> {
        let query = format!("filename:.env {} OR filename:config.php {}", domain, domain);
        self.search_code(&query).await
    }

    /// Search for database migration files.
    pub async fn search_migrations(&self, domain: &str) -> Result<Vec<GitHubCodeResult>> {
        let query = format!("filename:migration extension:sql {}", domain);
        self.search_code(&query).await
    }

    pub fn cache_ttl() -> u64 {
        CACHE_TTL_SECONDS
    }
}

/// GitHub code search result.
#[derive(Debug, Clone)]
pub struct GitHubCodeResult {
    pub name: String,
    pub path: String,
    pub url: String,
    pub repository: String,
    pub score: f64,
}

/// Predefined GitHub dorks for SQLi recon.
pub mod dorks {
    /// Dork for finding SQL files.
    pub fn sql_files(domain: &str) -> String {
        format!("extension:sql {}", domain)
    }

    /// Dork for finding .env files.
    pub fn env_files(domain: &str) -> String {
        format!("filename:.env {}", domain)
    }

    /// Dork for finding database config.
    pub fn db_config(domain: &str) -> String {
        format!("filename:database.php {} OR filename:config.php {}", domain, domain)
    }

    /// Dork for finding stored procedures.
    pub fn stored_procedures(domain: &str) -> String {
        format!("extension:sql \"CREATE PROCEDURE\" {}", domain)
    }

    /// Dork for finding inline SQL in code.
    pub fn inline_sql(domain: &str) -> String {
        format!("\"SELECT * FROM\" extension:php {}", domain)
    }
}
