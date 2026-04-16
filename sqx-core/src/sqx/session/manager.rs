use super::models::*;
use anyhow::{anyhow, Result};
use base64::{engine::general_purpose::STANDARD, Engine};
use regex::Regex;
use reqwest::{Client, RequestBuilder};
use std::collections::HashMap;
use std::sync::RwLock;
use std::time::{Duration, Instant};
use tracing::{debug, info, warn};

/// How often to auto-refresh CSRF tokens (30 seconds).
const CSRF_REFRESH_INTERVAL: Duration = Duration::from_secs(30);

/// Manages authentication state, cookies, and CSRF tokens.
/// Apply session state to every outgoing request via `apply()`.
/// Update cookies from response headers via `update_from_response()`.
/// CSRF tokens are auto-refreshed before each request if configured.
pub struct SessionManager {
    config: RwLock<SessionConfig>,
    /// Current CSRF token (refreshed automatically)
    csrf_token: RwLock<Option<String>>,
    /// Current cookies (updated from Set-Cookie headers)
    cookies: RwLock<HashMap<String, String>>,
    /// Extra headers updated at runtime (e.g., dynamic Authorization)
    runtime_headers: RwLock<HashMap<String, String>>,
    /// Last time CSRF token was refreshed (for auto-refresh)
    last_csrf_refresh: RwLock<Option<Instant>>,
}

impl SessionManager {
    pub fn new(config: SessionConfig) -> Self {
        let initial_cookies = config.cookies.clone();
        Self {
            config: RwLock::new(config),
            csrf_token: RwLock::new(None),
            cookies: RwLock::new(initial_cookies),
            runtime_headers: RwLock::new(HashMap::new()),
            last_csrf_refresh: RwLock::new(None),
        }
    }

    /// Create from a raw cookie string (e.g., from browser DevTools):
    /// `"session=abc123; user=admin; token=xyz"`
    pub fn from_cookie_string(cookie_str: &str) -> Self {
        let mut cookies = HashMap::new();
        for part in cookie_str.split(';') {
            let part = part.trim();
            if part.is_empty() {
                continue;
            }
            if let Some(eq_pos) = part.find('=') {
                let name = part[..eq_pos].trim().to_string();
                let value = part[eq_pos + 1..].trim().to_string();
                cookies.insert(name, value);
            }
        }
        Self::new(SessionConfig {
            cookies,
            ..Default::default()
        })
    }

    /// Create from a curl command string (e.g., "Copy as cURL" from browser).
    /// Parses `-H 'Cookie: ...'` and `-H 'Authorization: ...'` headers.
    pub fn from_curl(curl_cmd: &str) -> Result<Self> {
        let mut cookies = HashMap::new();
        let mut headers = HashMap::new();

        // Parse -H or --header arguments
        let header_re = Regex::new(r#"(?:-H|--header)\s+['"](.*?)['"]"#)?;

        for cap in header_re.captures_iter(curl_cmd) {
            let header_str = &cap[1];
            if let Some(colon_pos) = header_str.find(':') {
                let name = header_str[..colon_pos].trim();
                let value = header_str[colon_pos + 1..].trim();

                if name.eq_ignore_ascii_case("cookie") {
                    for part in value.split(';') {
                        let part = part.trim();
                        if let Some(eq_pos) = part.find('=') {
                            cookies.insert(
                                part[..eq_pos].trim().to_string(),
                                part[eq_pos + 1..].trim().to_string(),
                            );
                        }
                    }
                } else {
                    headers.insert(name.to_string(), value.to_string());
                }
            }
        }

        Ok(Self::new(SessionConfig {
            cookies,
            headers,
            ..Default::default()
        }))
    }

    /// Apply session state to a request builder.
    /// Call this on every outgoing request.
    pub fn apply(&self, builder: RequestBuilder) -> RequestBuilder {
        let mut b = builder;

        // Apply cookies
        let cookies = self.cookies.read().unwrap();
        if !cookies.is_empty() {
            let cookie_str: String = cookies
                .iter()
                .map(|(k, v)| format!("{}={}", k, v))
                .collect::<Vec<_>>()
                .join("; ");
            b = b.header("Cookie", cookie_str);
        }

        // Apply static custom headers
        let config = self.config.read().unwrap();
        for (name, value) in &config.headers {
            b = b.header(name.as_str(), value.as_str());
        }

        // Apply runtime headers (e.g., dynamic Authorization)
        let runtime = self.runtime_headers.read().unwrap();
        for (name, value) in runtime.iter() {
            b = b.header(name.as_str(), value.as_str());
        }

        // Apply CSRF token
        if let Some(ref csrf_config) = config.csrf {
            if let Some(ref token) = *self.csrf_token.read().unwrap() {
                if let Some(ref header_name) = csrf_config.header_name {
                    b = b.header(header_name.as_str(), token.as_str());
                }
            }
        }

        b
    }

    /// Update cookies from a response's Set-Cookie headers.
    pub fn update_from_response(&self, response: &reqwest::Response) {
        let mut cookies = self.cookies.write().unwrap();
        for cookie_header in response.headers().get_all("set-cookie") {
            if let Ok(val) = cookie_header.to_str() {
                // Parse "name=value; path=/; ..." — only need name=value
                if let Some(eq_pos) = val.find('=') {
                    let name = val[..eq_pos].trim().to_string();
                    let rest = &val[eq_pos + 1..];
                    let value = if let Some(semi) = rest.find(';') {
                        rest[..semi].trim().to_string()
                    } else {
                        rest.trim().to_string()
                    };
                    cookies.insert(name, value);
                }
            }
        }
    }

    /// Refresh CSRF token by fetching from token_url and extracting with regex.
    pub async fn refresh_csrf(&self, client: &Client) -> Result<()> {
        let (token_url, token_regex_str) = {
            let config = self.config.read().unwrap();
            let csrf_config = config.csrf.as_ref()
                .ok_or_else(|| anyhow!("No CSRF config"))?;
            let token_url = csrf_config.token_url.clone()
                .ok_or_else(|| anyhow!("No CSRF token URL"))?;
            let token_regex_str = csrf_config.token_regex.clone()
                .ok_or_else(|| anyhow!("No CSRF token regex"))?;
            (token_url, token_regex_str)
        };

        let resp = self.apply(client.get(&token_url)).send().await?;
        self.update_from_response(&resp);
        let body = resp.text().await?;

        let re = Regex::new(&token_regex_str)?;
        if let Some(captures) = re.captures(&body) {
            if let Some(token) = captures.get(1) {
                let mut csrf = self.csrf_token.write().unwrap();
                *csrf = Some(token.as_str().to_string());
                debug!("CSRF token refreshed");
                return Ok(());
            }
        }

        warn!("Failed to extract CSRF token from response");
        Err(anyhow!("CSRF token not found in response"))
    }

    /// Auto-refresh CSRF token if it's stale or never fetched.
    /// Called before each request to guarantee a valid token.
    /// Only refreshes if `CSRF_REFRESH_INTERVAL` has elapsed.
    pub async fn maybe_refresh_csrf(&self, client: &Client) {
        let needs_token = {
            let config = self.config.read().unwrap();
            let csrf_config = config.csrf.as_ref();
            csrf_config
                .and_then(|c| c.token_url.as_ref())
                .is_some()
                && csrf_config.and_then(|c| c.token_regex.as_ref()).is_some()
        };

        if !needs_token {
            return;
        }

        // Check if refresh is needed
        {
            let last = self.last_csrf_refresh.read().unwrap();
            let has_existing_token = self.csrf_token.read().unwrap().is_some();

            // If we already have a token and it's fresh enough, skip
            if has_existing_token {
                if let Some(last_refresh) = *last {
                    if last_refresh.elapsed() < CSRF_REFRESH_INTERVAL {
                        return;
                    }
                }
            }
        }

        // Attempt refresh (ignore errors — token may still be valid)
        if self.refresh_csrf(client).await.is_ok() {
            let mut last = self.last_csrf_refresh.write().unwrap();
            *last = Some(Instant::now());
        }
    }

    /// Perform auto-login using the configured auth method.
    /// After successful login, session cookies/headers are updated for subsequent requests.
    pub async fn login(&self, client: &Client) -> Result<()> {
        let auth = {
            let config = self.config.read().unwrap();
            config.auth.clone()
                .ok_or_else(|| anyhow!("No auth config"))?
        };

        match auth.method.as_str() {
            "form" => {
                let resp = self
                    .apply(
                        client
                            .post(&auth.login_url)
                            .form(&auth.credentials),
                    )
                    .send()
                    .await?;
                self.update_from_response(&resp);

                if let Some(ref indicator) = auth.success_indicator {
                    self.verify_login_success(&resp, indicator)?;
                }

                info!("Form login completed (status: {})", resp.status());
            }
            "json" => {
                let resp = self
                    .apply(
                        client
                            .post(&auth.login_url)
                            .json(&auth.credentials),
                    )
                    .send()
                    .await?;
                self.update_from_response(&resp);

                if let Some(ref indicator) = auth.success_indicator {
                    self.verify_login_success(&resp, indicator)?;
                }

                info!("JSON login completed (status: {})", resp.status());
            }
            "basic" => {
                let user = auth.basic_username.as_deref().unwrap_or("");
                let pass = auth.basic_password.as_deref().unwrap_or("");
                let encoded = STANDARD.encode(format!("{}:{}", user, pass));
                let mut runtime = self.runtime_headers.write().unwrap();
                runtime.insert("Authorization".to_string(), format!("Basic {}", encoded));
                debug!("Basic auth configured for user: {}", user);
            }
            "bearer" => {
                if let Some(ref token) = auth.bearer_token {
                    let mut runtime = self.runtime_headers.write().unwrap();
                    runtime.insert(
                        "Authorization".to_string(),
                        format!("Bearer {}", token),
                    );
                    debug!("Bearer token configured");
                }
            }
            _ => return Err(anyhow!("Unknown auth method: {}", auth.method)),
        }

        Ok(())
    }

    /// Verify login succeeded by checking a success indicator.
    /// Indicator can be:
    /// - A status code (e.g., "302" for redirect after login)
    /// - A cookie name (checks if that cookie exists after login)
    fn verify_login_success(&self, response: &reqwest::Response, indicator: &str) -> Result<()> {
        // Check if indicator matches a status code
        if let Ok(expected_status) = indicator.parse::<u16>() {
            let actual = response.status().as_u16();
            if actual == expected_status {
                debug!("Login success verified (status {})", actual);
                return Ok(());
            } else {
                warn!(
                    "Login may have failed: expected status {}, got {}",
                    expected_status, actual
                );
            }
        }

        // Check if indicator matches a cookie name
        for cookie_header in response.headers().get_all("set-cookie") {
            if let Ok(val) = cookie_header.to_str()
                && val.starts_with(&format!("{}=", indicator))
            {
                debug!("Login success verified (cookie '{}' set)", indicator);
                return Ok(());
            }
        }

        warn!(
            "Login success indicator '{}' not confirmed (status: {})",
            indicator,
            response.status()
        );
        // Don't fail — just warn, as the user may want to proceed anyway
        Ok(())
    }

    /// Get current cookie value by name.
    pub fn get_cookie(&self, name: &str) -> Option<String> {
        self.cookies.read().unwrap().get(name).cloned()
    }

    /// Get current CSRF token.
    pub fn get_csrf_token(&self) -> Option<String> {
        self.csrf_token.read().unwrap().clone()
    }

    /// Set a runtime header (e.g., dynamic Authorization token).
    pub fn set_header(&self, name: &str, value: &str) {
        let mut runtime = self.runtime_headers.write().unwrap();
        runtime.insert(name.to_string(), value.to_string());
    }

    /// Check if session is still valid (has cookies set).
    pub fn is_authenticated(&self) -> bool {
        !self.cookies.read().unwrap().is_empty()
    }

    /// Returns true if auto-detect is enabled.
    pub fn is_auto_detect_enabled(&self) -> bool {
        self.config.read().unwrap().auto_detect
    }

    /// Returns true if an auth config is present.
    pub fn has_auth(&self) -> bool {
        self.config.read().unwrap().auth.is_some()
    }

    /// Update authentication configuration.
    pub fn update_auth_config(&self, auth: AuthConfig) {
        let mut config = self.config.write().unwrap();
        config.auth = Some(auth);
    }

    /// Insert multiple cookies into the jar.
    pub fn insert_cookies(&self, new_cookies: &[(String, String)]) {
        let mut cookies = self.cookies.write().unwrap();
        for (name, value) in new_cookies {
            cookies.insert(name.clone(), value.clone());
        }
    }

    /// Detect known session cookies from Set-Cookie headers.
    pub fn detect_session_cookies(&self, headers: &reqwest::header::HeaderMap) -> Vec<(String, String)> {
        let config = self.config.read().unwrap();
        let known = &config.known_cookie_names;
        let mut found = Vec::new();
        for h in headers.get_all("set-cookie") {
            if let Ok(v) = h.to_str() {
                if let Some(eq) = v.find('=') {
                    let name = v[..eq].trim();
                    if known.iter().any(|k| k.eq_ignore_ascii_case(name)) {
                        let rest = &v[eq + 1..];
                        let value = rest.find(';').map(|i| rest[..i].trim()).unwrap_or(rest.trim());
                        found.push((name.to_string(), value.to_string()));
                    }
                }
            }
        }
        found
    }
}
