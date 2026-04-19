use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Session configuration for authenticated scanning.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionConfig {
    /// Cookies to include in every request (name → value)
    pub cookies: HashMap<String, String>,
    /// Custom headers to include (e.g., Authorization: Bearer xxx)
    pub headers: HashMap<String, String>,
    /// CSRF token configuration (if target uses CSRF protection)
    pub csrf: Option<CsrfConfig>,
    /// Auth method for auto-login
    pub auth: Option<AuthConfig>,
    /// Auto-detect session cookies from Set-Cookie headers on first request
    pub auto_detect: bool,
    /// Known session cookie names to watch for during auto-detection
    pub known_cookie_names: Vec<String>,
}

impl Default for SessionConfig {
    fn default() -> Self {
        Self {
            cookies: HashMap::new(),
            headers: HashMap::new(),
            csrf: None,
            auth: None,
            auto_detect: false,
            known_cookie_names: vec![
                "PHPSESSID".to_string(),
                "JSESSIONID".to_string(),
                "ASP.NET_SessionId".to_string(),
                "SESSIONID".to_string(),
                "session".to_string(),
                "token".to_string(),
                "auth".to_string(),
                "jwt".to_string(),
                "sid".to_string(),
                "ssid".to_string(),
                "user".to_string(),
                "uid".to_string(),
                "remember_me".to_string(),
                "csrftoken".to_string(),
            ],
        }
    }
}

/// CSRF token handling.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CsrfConfig {
    /// Name of the CSRF token parameter in forms
    pub param_name: String,
    /// Name of the CSRF token in cookies (if double-submit pattern)
    pub cookie_name: Option<String>,
    /// Name of the CSRF header (e.g., X-CSRF-Token)
    pub header_name: Option<String>,
    /// URL to fetch fresh CSRF token from
    pub token_url: Option<String>,
    /// Regex to extract token from response body (capture group 1 = token)
    pub token_regex: Option<String>,
}

/// Auto-login configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthConfig {
    /// Login URL
    pub login_url: String,
    /// Login method: "form" | "json" | "basic" | "bearer"
    pub method: String,
    /// For form/json auth: field name → value mapping
    pub credentials: HashMap<String, String>,
    /// For basic auth
    pub basic_username: Option<String>,
    pub basic_password: Option<String>,
    /// For bearer token
    pub bearer_token: Option<String>,
    /// How to detect successful login (e.g., "302" for redirect, or cookie name)
    pub success_indicator: Option<String>,
    /// If true, treat login verification failure as fatal error
    /// If false (default), only warn and continue
    pub strict_auth: bool,
}
