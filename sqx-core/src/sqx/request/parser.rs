//! HTTP Request Parser
//!
//! Parses HTTP requests from various formats:
//! - Raw HTTP request text
//! - curl commands (-H for headers, -d for data)
//! - Burp/OWASP ZAP saved requests

use crate::sqx::models::HttpResponse;
use anyhow::{Result, anyhow};
use std::collections::HashMap;

/// Parsed HTTP request ready for replay.
#[derive(Debug, Clone)]
pub struct ParsedRequest {
    /// HTTP method (GET, POST, etc.)
    pub method: String,
    /// Target URL (including query string)
    pub url: String,
    /// HTTP headers
    pub headers: HashMap<String, String>,
    /// Request body (if any)
    pub body: Option<String>,
    /// Original request text (for reference)
    pub raw: String,
}

impl ParsedRequest {
    /// Create a new empty request.
    pub fn new(method: &str, url: &str) -> Self {
        Self {
            method: method.to_string(),
            url: url.to_string(),
            headers: HashMap::new(),
            body: None,
            raw: String::new(),
        }
    }

    /// Add a header.
    pub fn with_header(mut self, name: &str, value: &str) -> Self {
        self.headers.insert(name.to_string(), value.to_string());
        self
    }

    /// Set the request body.
    pub fn with_body(mut self, body: &str) -> Self {
        self.body = Some(body.to_string());
        self
    }

    /// Convert to a reqwest::RequestBuilder.
    pub fn to_reqwest(&self, client: &reqwest::Client) -> reqwest::RequestBuilder {
        let mut builder = match self.method.to_ascii_uppercase().as_str() {
            "GET" => client.get(&self.url),
            "POST" => client.post(&self.url),
            "PUT" => client.put(&self.url),
            "DELETE" => client.delete(&self.url),
            "PATCH" => client.patch(&self.url),
            "HEAD" => client.head(&self.url),
            "OPTIONS" => client.request(reqwest::Method::OPTIONS, &self.url),
            _ => client.request(
                reqwest::Method::from_bytes(self.method.as_bytes()).unwrap_or(reqwest::Method::GET),
                &self.url,
            ),
        };

        for (name, value) in &self.headers {
            builder = builder.header(name, value);
        }

        if let Some(body) = &self.body {
            builder = builder.body(body.clone());
        }

        builder
    }

    /// Execute the request and return the response.
    pub async fn execute(&self, client: &reqwest::Client) -> Result<HttpResponse> {
        let start = std::time::Instant::now();
        let response = self.to_reqwest(client).send().await?;
        let duration = start.elapsed();

        let status = response.status().as_u16();
        let headers: HashMap<String, String> = response
            .headers()
            .iter()
            .filter_map(|(k, v)| {
                Some((k.to_string(), v.to_str().ok()?.to_string()))
            })
            .collect();
        let body = response.text().await?;

        Ok(HttpResponse {
            status,
            body,
            headers,
            duration,
        })
    }
}

/// Parse a raw HTTP request from text.
/// Format:
/// ```text
/// GET /path?param=value HTTP/1.1
/// Host: example.com
/// User-Agent: test
/// 
/// request body (for POST/PUT)
/// ```
pub fn parse_raw_http(text: &str) -> Result<ParsedRequest> {
    let lines: Vec<&str> = text.lines().collect();
    if lines.is_empty() {
        return Err(anyhow!("Empty request"));
    }

    // Parse request line: METHOD PATH HTTP/VERSION
    let request_line = lines[0];
    let parts: Vec<&str> = request_line.split_whitespace().collect();
    if parts.len() < 2 {
        return Err(anyhow!("Invalid request line: {}", request_line));
    }

    let method = parts[0].to_string();
    let path = parts[1];

    // Parse headers until empty line
    let mut headers = HashMap::new();
    let mut i = 1;
    while i < lines.len() && !lines[i].is_empty() {
        let line = lines[i];
        if let Some(colon_pos) = line.find(':') {
            let name = line[..colon_pos].trim().to_string();
            let value = line[colon_pos + 1..].trim().to_string();
            headers.insert(name, value);
        }
        i += 1;
    }

    // Get Host header to construct full URL
    let host = headers
        .get("Host")
        .ok_or_else(|| anyhow!("Missing Host header"))?
        .clone();

    // Determine scheme (default to http if not specified)
    let scheme = if host.starts_with("https://") {
        "https"
    } else {
        "http"
    };

    let url = if path.starts_with("http") {
        path.to_string()
    } else {
        format!("{}://{}{}", scheme, host, path)
    };

    // Parse body (everything after empty line)
    let body = if i < lines.len() {
        let body_lines = &lines[i + 1..];
        if body_lines.is_empty() {
            None
        } else {
            Some(body_lines.join("\n"))
        }
    } else {
        None
    };

    Ok(ParsedRequest {
        method,
        url,
        headers,
        body,
        raw: text.to_string(),
    })
}

/// Parse a curl command.
/// Supports: curl [options] URL
/// Options: -H/--header, -d/--data, -X/--request, -b/--cookie
/// Note: This is a simple parser that handles common cases.
pub fn parse_curl_command(command: &str) -> Result<ParsedRequest> {
    // Simple tokenization - split on whitespace but keep quoted strings together
    let args = tokenize_curl(command);
    
    // Remove 'curl' from start if present
    let args: Vec<&str> = if !args.is_empty() && args[0] == "curl" {
        args[1..].to_vec()
    } else {
        args
    };

    let mut method = "GET".to_string();
    let mut url = None;
    let mut headers = HashMap::new();
    let mut body = None;
    let mut i = 0;

    while i < args.len() {
        match args[i] {
            "-X" | "--request" => {
                i += 1;
                if i < args.len() {
                    method = args[i].to_string();
                }
            }
            "-H" | "--header" => {
                i += 1;
                if i < args.len() {
                    let header = args[i].trim_matches('"').trim_matches('\'');
                    if let Some(colon_pos) = header.find(':') {
                        let name = header[..colon_pos].trim().to_string();
                        let value = header[colon_pos + 1..].trim().to_string();
                        headers.insert(name, value);
                    }
                }
            }
            "-d" | "--data" | "--data-raw" => {
                i += 1;
                if i < args.len() {
                    let data = args[i].trim_matches('"').trim_matches('\'');
                    body = Some(data.to_string());
                }
            }
            "-b" | "--cookie" => {
                i += 1;
                if i < args.len() {
                    headers.insert("Cookie".to_string(), args[i].to_string());
                }
            }
            arg if !arg.starts_with('-') && url.is_none() => {
                url = Some(arg.to_string());
            }
            _ => {}
        }
        i += 1;
    }

    let url = url.ok_or_else(|| anyhow!("No URL found in curl command"))?;

    Ok(ParsedRequest {
        method,
        url,
        headers,
        body,
        raw: command.to_string(),
    })
}

/// Simple tokenizer for curl commands.
/// Handles basic quoted strings.
fn tokenize_curl(input: &str) -> Vec<&str> {
    let mut tokens = Vec::new();
    let mut start = 0;
    let mut in_quotes = false;
    let mut quote_char = ' ';
    
    for (i, c) in input.char_indices() {
        if in_quotes {
            if c == quote_char {
                in_quotes = false;
                tokens.push(&input[start..i + 1]);
                start = i + 1;
            }
        } else if c == '"' || c == '\'' {
            in_quotes = true;
            quote_char = c;
            if start < i {
                tokens.extend(input[start..i].split_whitespace());
            }
            start = i;
        } else if c.is_whitespace() {
            if start < i {
                tokens.extend(input[start..i].split_whitespace());
            }
            start = i + 1;
        }
    }
    
    if start < input.len() && !in_quotes {
        tokens.extend(input[start..].split_whitespace());
    }
    
    tokens.into_iter().filter(|t| !t.is_empty()).collect()
}

/// Auto-detect format and parse request.
pub fn parse_request(text: &str) -> Result<ParsedRequest> {
    let trimmed = text.trim();
    
    if trimmed.starts_with("curl ") {
        parse_curl_command(trimmed)
    } else if trimmed.contains("HTTP/1.") || trimmed.contains("HTTP/2") {
        parse_raw_http(trimmed)
    } else {
        Err(anyhow!("Unknown request format"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_raw_http_get() {
        let text = r#"GET /test?id=1 HTTP/1.1
Host: example.com
User-Agent: TestAgent
"#;
        let req = parse_raw_http(text).unwrap();
        assert_eq!(req.method, "GET");
        assert_eq!(req.url, "http://example.com/test?id=1");
        assert_eq!(req.headers.get("Host"), Some(&"example.com".to_string()));
        assert_eq!(req.headers.get("User-Agent"), Some(&"TestAgent".to_string()));
    }

    #[test]
    fn parse_raw_http_post() {
        let text = r#"POST /api/login HTTP/1.1
Host: example.com
Content-Type: application/x-www-form-urlencoded

username=admin&password=secret
"#;
        let req = parse_raw_http(text).unwrap();
        assert_eq!(req.method, "POST");
        assert_eq!(req.body, Some("username=admin&password=secret".to_string()));
    }

    #[test]
    fn parse_curl_get() {
        let cmd = r#"curl -H "User-Agent: Test" http://example.com/test"#;
        let req = parse_curl_command(cmd).unwrap();
        assert_eq!(req.method, "GET");
        assert_eq!(req.url, "http://example.com/test");
        assert_eq!(req.headers.get("User-Agent"), Some(&"Test".to_string()));
    }

    #[test]
    fn parse_curl_post() {
        let cmd = r#"curl -X POST -d "data=value" -H "Content-Type: text/plain" http://example.com/api"#;
        let req = parse_curl_command(cmd).unwrap();
        assert_eq!(req.method, "POST");
        assert_eq!(req.body, Some("data=value".to_string()));
    }

    #[test]
    fn tokenize_curl_basic() {
        let input = r#"curl -H "Header: Value" http://test.com"#;
        let tokens = tokenize_curl(input);
        assert!(tokens.contains(&"curl"));
        assert!(tokens.contains(&"-H"));
        assert!(tokens.contains(&"\"Header: Value\""));
        assert!(tokens.contains(&"http://test.com"));
    }

    #[test]
    fn parse_auto_detect_curl() {
        let cmd = r#"curl http://example.com"#;
        let req = parse_request(cmd).unwrap();
        assert_eq!(req.method, "GET");
    }

    #[test]
    fn parse_auto_detect_http() {
        let text = r#"GET /test HTTP/1.1
Host: example.com
"#;
        let req = parse_request(text).unwrap();
        assert_eq!(req.method, "GET");
    }
}
