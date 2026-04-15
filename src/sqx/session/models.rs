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
}

impl Default for SessionConfig {
    fn default() -> Self {
        Self {
            cookies: HashMap::new(),
            headers: HashMap::new(),
            csrf: None,
            auth: None,
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
}
