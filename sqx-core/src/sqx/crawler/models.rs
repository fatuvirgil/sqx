//! Crawler data models — injection points discovered during HTML crawling.

use serde::{Deserialize, Serialize};

/// A discovered injection point ready for SQX scanning.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InjectionPoint {
    /// Full URL (with query params if GET).
    pub url: String,
    /// HTTP method to use when testing this point.
    pub method: HttpMethod,
    /// Parameters and their observed default values.
    pub parameters: Vec<DiscoveredParam>,
    /// Page URL where this injection point was found.
    pub found_on: String,
    /// Content-Type for POST requests (e.g. `application/x-www-form-urlencoded`).
    pub content_type: Option<String>,
}

/// HTTP method for an injection point.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum HttpMethod {
    Get,
    Post,
}

/// A single parameter found during crawling.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoveredParam {
    pub name: String,
    /// Where the parameter lives in the request.
    pub location: ParamLocation,
    /// Default/example value found in HTML (e.g. `value="1"`).
    pub default_value: Option<String>,
    /// Input type from HTML (`text`, `hidden`, `number`, etc.).
    pub input_type: Option<String>,
}

/// Where a parameter appears in the HTTP request.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ParamLocation {
    QueryString,
    PostBody,
    Cookie,
    Header,
}

/// Full result of a crawl run.
#[derive(Debug, Default)]
pub struct CrawlResult {
    /// Injection points with parameters already discovered.
    pub injection_points: Vec<InjectionPoint>,
    /// All HTML page URLs visited (no query string, deduplicated).
    /// These may harbour injectable params not visible in the HTML — the auto
    /// scanner will fuzz common param names against them.
    pub visited_pages: Vec<String>,
}

/// Crawler configuration.
#[derive(Debug, Clone)]
pub struct CrawlerConfig {
    /// Maximum pages to visit before stopping.
    pub max_pages: usize,
    /// Maximum crawl depth from the start URL.
    pub max_depth: usize,
    /// Stay within the same domain as the start URL.
    pub same_domain_only: bool,
    /// Respect robots.txt (currently informational — not enforced).
    pub respect_robots: bool,
    /// Delay between requests in milliseconds.
    pub delay_ms: u64,
    /// URL patterns (regex) to skip.
    pub exclude_patterns: Vec<String>,
}

impl Default for CrawlerConfig {
    fn default() -> Self {
        Self {
            max_pages: 50,
            max_depth: 3,
            same_domain_only: true,
            respect_robots: true,
            delay_ms: 200,
            exclude_patterns: vec![
                // Match static assets even when followed by a query string (?v=1, ?t=123…)
                r"(?i)\.(jpg|jpeg|png|gif|svg|css|js|ico|woff|woff2|ttf|eot|map|min\.js|min\.css)(\?[^#]*)?$".to_string(),
                r"(?i)(logout|signout|disconnect)".to_string(),
            ],
        }
    }
}
