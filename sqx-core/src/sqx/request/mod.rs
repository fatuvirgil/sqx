//! HTTP Request Replay Module
//!
//! Parse and replay HTTP requests from various formats:
//! - Raw HTTP request text
//! - curl commands
//! - Burp/ZAP saved requests

pub mod parser;

pub use parser::{ParsedRequest, parse_curl_command, parse_raw_http, parse_request};

use anyhow::Result;
use crate::sqx::models::HttpResponse;

/// Replay a request from text.
pub async fn replay_request(text: &str, client: &reqwest::Client) -> Result<HttpResponse> {
    let request = parse_request(text)?;
    request.execute(client).await
}

/// Load and replay requests from a file.
pub async fn replay_from_file(path: &str, client: &reqwest::Client) -> Result<Vec<HttpResponse>> {
    let content = std::fs::read_to_string(path)?;
    
    // Try to split by common separators (---, blank lines between requests)
    let requests: Vec<&str> = content
        .split("\n---\n")
        .filter(|s| !s.trim().is_empty())
        .collect();
    
    if requests.is_empty() {
        // Try as single request
        let response = replay_request(&content, client).await?;
        return Ok(vec![response]);
    }
    
    let mut responses = Vec::new();
    for req_text in requests {
        match replay_request(req_text.trim(), client).await {
            Ok(resp) => responses.push(resp),
            Err(e) => eprintln!("Failed to replay request: {}", e),
        }
    }
    
    Ok(responses)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_request_new() {
        let req = ParsedRequest::new("GET", "http://example.com");
        assert_eq!(req.method, "GET");
        assert_eq!(req.url, "http://example.com");
    }

    #[test]
    fn test_parse_request_with_header() {
        let req = ParsedRequest::new("GET", "http://example.com")
            .with_header("X-Custom", "value");
        assert_eq!(req.headers.get("X-Custom"), Some(&"value".to_string()));
    }

    #[test]
    fn test_parse_request_with_body() {
        let req = ParsedRequest::new("POST", "http://example.com")
            .with_body("data=test");
        assert_eq!(req.body, Some("data=test".to_string()));
    }
}
