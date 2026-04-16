//! Session management module for authenticated SQL injection scanning.
//! Handles cookies, CSRF tokens, custom headers, and auto-login.

pub mod manager;
pub mod models;

pub use manager::SessionManager;
pub use models::{AuthConfig, CsrfConfig, SessionConfig};
