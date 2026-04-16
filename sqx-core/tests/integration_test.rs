//! Integration tests against containerized vulnerable apps.
//!
//! Run with:
//!   cd tests/integration && docker compose up -d && cd ../..
//!   cargo test --test integration_test -- --nocapture
//!
//! Requirements:
//!   - Docker + docker compose
//!   - sqli-labs on http://localhost:8888
//!   - DVWA on http://localhost:8889

use sqx_core::sqx::{
    SqliDetector, SqliConfig, SqliTechnique,
};
use sqx_core::sqx::session::SessionManager;
use std::sync::Arc;

fn build_detector(techniques: Vec<SqliTechnique>) -> SqliDetector {
    let config = SqliConfig {
        techniques,
        delay_ms: 50,
        timeout_secs: 30,
        sleep_duration_secs: 2,
        ..SqliConfig::default()
    };
    SqliDetector::with_config(config).expect("detector build")
}

fn sqli_labs_url(lesson: &str) -> String {
    format!("http://localhost:8888/{}/?id=1", lesson)
}

fn dvwa_url() -> String {
    "http://localhost:8889/vulnerabilities/sqli/?id=1&Submit=Submit".to_string()
}

/// Extract DVWA `user_token` from an HTML form.
fn extract_dvwa_token(html: &str) -> Option<String> {
    let token_start = html.find("name='user_token'")?;
    let value_start = html[token_start..].find("value='")? + token_start + 7;
    let value_end = html[value_start..].find('\'')? + value_start;
    Some(html[value_start..value_end].to_string())
}

/// Helper: merge Set-Cookie headers into a cookie map.
fn merge_cookies(cookies: &mut Vec<(String, String)>, headers: &reqwest::header::HeaderMap) {
    for h in headers.get_all("set-cookie") {
        if let Ok(s) = h.to_str() {
            if let Some(eq) = s.find('=') {
                let name = s[..eq].trim();
                let rest = &s[eq + 1..];
                let value = rest.find(';').map(|i| rest[..i].trim()).unwrap_or(rest.trim());
                if let Some(existing) = cookies.iter_mut().find(|(n, _)| n == name) {
                    existing.1 = value.to_string();
                } else {
                    cookies.push((name.to_string(), value.to_string()));
                }
            }
        }
    }
}

fn format_cookie_header(cookies: &[(String, String)]) -> String {
    cookies
        .iter()
        .map(|(k, v)| format!("{}={}", k, v))
        .collect::<Vec<_>>()
        .join("; ")
}

/// Authenticate against DVWA, create/reset DB, set security=low, and return a detector
/// with a session manager that carries the resulting cookies.
async fn dvwa_authenticated_detector(techniques: Vec<SqliTechnique>) -> SqliDetector {
    let client = reqwest::Client::new();
    let mut cookies: Vec<(String, String)> = Vec::new();

    // 1. Create / reset database (DVWA requires this before login works)
    let setup_html = client
        .get("http://localhost:8889/setup.php")
        .send()
        .await
        .expect("DVWA setup GET")
        .text()
        .await
        .expect("DVWA setup body");
    let setup_token = extract_dvwa_token(&setup_html).expect("DVWA setup token");
    let setup_resp = client
        .post("http://localhost:8889/setup.php")
        .form(&[("create_db", "Create / Reset Database"), ("user_token", &setup_token)])
        .send()
        .await
        .expect("DVWA setup POST");
    merge_cookies(&mut cookies, setup_resp.headers());

    // 2. Log in
    let login_html = client
        .get("http://localhost:8889/login.php")
        .header("Cookie", format_cookie_header(&cookies))
        .send()
        .await
        .expect("DVWA login GET")
        .text()
        .await
        .expect("DVWA login body");
    let login_token = extract_dvwa_token(&login_html).expect("DVWA login token");
    let login_resp = client
        .post("http://localhost:8889/login.php")
        .header("Cookie", format_cookie_header(&cookies))
        .form(&[
            ("username", "admin"),
            ("password", "password"),
            ("Login", "Login"),
            ("user_token", &login_token),
        ])
        .send()
        .await
        .expect("DVWA login POST");
    merge_cookies(&mut cookies, login_resp.headers());

    // 3. Set security level to low
    let security_html = client
        .get("http://localhost:8889/security.php")
        .header("Cookie", format_cookie_header(&cookies))
        .send()
        .await
        .expect("DVWA security GET")
        .text()
        .await
        .expect("DVWA security body");
    let security_token = extract_dvwa_token(&security_html).expect("DVWA security token");
    let security_resp = client
        .post("http://localhost:8889/security.php")
        .header("Cookie", format_cookie_header(&cookies))
        .form(&[
            ("security", "low"),
            ("seclev_submit", "Submit"),
            ("user_token", &security_token),
        ])
        .send()
        .await
        .expect("DVWA security POST");
    merge_cookies(&mut cookies, security_resp.headers());

    // 4. Attach cookies to detector via SessionManager
    let cookie_str = format_cookie_header(&cookies);
    let session = Arc::new(SessionManager::from_cookie_string(&cookie_str));

    build_detector(techniques).with_session(session)
}

// ── sqli-labs: Error-based + Union-based (Less-1) ───────────────────────────

#[tokio::test]
#[ignore = "requires docker compose in tests/integration/"]
async fn sqli_labs_less1_error_based() {
    let detector = build_detector(vec![SqliTechnique::ErrorBased]);
    let url = sqli_labs_url("Less-1");
    let findings = detector.test_url(&url).await.expect("scan");
    assert!(
        findings.iter().any(|f| f.technique == SqliTechnique::ErrorBased),
        "Expected error-based detection on Less-1"
    );
}

#[tokio::test]
#[ignore = "requires docker compose in tests/integration/"]
async fn sqli_labs_less1_union_based() {
    let detector = build_detector(vec![SqliTechnique::UnionBased]);
    let url = sqli_labs_url("Less-1");
    let findings = detector.test_url(&url).await.expect("scan");
    assert!(
        findings.iter().any(|f| f.technique == SqliTechnique::UnionBased),
        "Expected union-based detection on Less-1"
    );
}

// ── sqli-labs: Boolean blind (Less-5) ───────────────────────────────────────

#[tokio::test]
#[ignore = "requires docker compose in tests/integration/"]
async fn sqli_labs_less5_boolean_blind() {
    let detector = build_detector(vec![SqliTechnique::BooleanBlind]);
    let url = sqli_labs_url("Less-5");
    let findings = detector.test_url(&url).await.expect("scan");
    assert!(
        findings.iter().any(|f| f.technique == SqliTechnique::BooleanBlind),
        "Expected boolean-blind detection on Less-5"
    );
}

// ── sqli-labs: Boolean blind in numeric-in-quotes (Less-8) ──────────────────

#[tokio::test]
#[ignore = "requires docker compose in tests/integration/"]
async fn sqli_labs_less8_boolean_blind() {
    let detector = build_detector(vec![SqliTechnique::BooleanBlind]);
    let url = sqli_labs_url("Less-8");
    let findings = detector.test_url(&url).await.expect("scan");
    assert!(
        findings.iter().any(|f| f.technique == SqliTechnique::BooleanBlind),
        "Expected boolean-blind detection on Less-8"
    );
}

// ── sqli-labs: Time-based blind (Less-9) ───────────────────────────────────

#[tokio::test]
#[ignore = "requires docker compose in tests/integration/"]
async fn sqli_labs_less9_time_based() {
    let detector = build_detector(vec![SqliTechnique::TimeBased]);
    let url = sqli_labs_url("Less-9");
    let findings = detector.test_url(&url).await.expect("scan");
    assert!(
        findings.iter().any(|f| f.technique == SqliTechnique::TimeBased),
        "Expected time-based detection on Less-9"
    );
}

// ── sqli-labs: POST error-based (Less-11) ───────────────────────────────────

#[tokio::test]
#[ignore = "requires docker compose in tests/integration/"]
async fn sqli_labs_less11_post_error_based() {
    let detector = build_detector(vec![SqliTechnique::ErrorBased]);
    let url = "http://localhost:8888/Less-11/".to_string();
    let body = "uname=admin&passwd=x";
    let findings = detector.test_url_post(&url, body, "form").await.expect("post scan");
    assert!(
        findings.iter().any(|f| f.technique == SqliTechnique::ErrorBased),
        "Expected error-based POST detection on Less-11"
    );
}

// ── sqli-labs: File-read (Less-1, MySQL LOAD_FILE) ──────────────────────────

#[tokio::test]
#[ignore = "requires docker compose in tests/integration/"]
async fn sqli_labs_file_read() {
    let detector = build_detector(vec![]);
    let url = sqli_labs_url("Less-1");
    let result = detector.file_read(&url, "id", "1", "mysql", "/var/www/html/Less-1/index.php").await.expect("file read");
    assert!(
        result.content.is_some(),
        "Expected file-read to return content on Less-1"
    );
    let content = result.content.unwrap();
    assert!(content.contains("<?php") || content.contains("<!DOCTYPE"), "Expected PHP file content");
}

// ── sqli-labs: Smart scan end-to-end ────────────────────────────────────────

#[tokio::test]
#[ignore = "requires docker compose in tests/integration/"]
async fn sqli_labs_smart_scan_finds_vulns() {
    let detector = build_detector(vec![
        SqliTechnique::ErrorBased,
        SqliTechnique::BooleanBlind,
        SqliTechnique::UnionBased,
        SqliTechnique::TimeBased,
    ]);
    let url = sqli_labs_url("Less-1");
    let (profile, findings) = detector.scan_smart(&url).await.expect("smart scan");
    assert!(!findings.is_empty(), "Expected smart scan to find vulnerabilities on Less-1");
    assert!(profile.dbms_hint.as_ref().map(|h| h.to_lowercase().contains("mysql")).unwrap_or(false),
        "Expected DBMS hint to be MySQL");
}

// ── sqli-labs: Auto scan discovers injection points ─────────────────────────

#[tokio::test]
#[ignore = "requires docker compose in tests/integration/"]
async fn sqli_labs_auto_scan_discovers_points() {
    let config = sqx_core::sqx::models::SqliConfig {
        techniques: vec![SqliTechnique::ErrorBased],
        delay_ms: 0,
        timeout_secs: 10,
        param_wordlist: vec!["id".to_string()],
        ..sqx_core::sqx::models::SqliConfig::default()
    };
    let detector = sqx_core::sqx::SqliDetector::with_config(config).expect("detector build");
    let url = "http://localhost:8888/".to_string();
    let crawler_config = sqx_core::sqx::crawler::CrawlerConfig {
        max_pages: 5,
        max_depth: 1,
        exclude_patterns: vec![
            r"index-\d+\.html".to_string(),
            r"setup-db\.php".to_string(),
        ],
        ..sqx_core::sqx::crawler::CrawlerConfig::default()
    };
    let results = sqx_core::sqx::auto_scan(&url, detector, Some(crawler_config), None).await.expect("auto scan");
    let total_findings: usize = results.iter().map(|r| r.findings.len()).sum();
    assert!(total_findings > 0, "Expected auto scan to discover at least one injection point");
}

// ── DVWA: GET SQL Injection (low security) ──────────────────────────────────

#[tokio::test]
#[ignore = "requires docker compose in tests/integration/"]
async fn dvwa_get_sqli_error_based() {
    let detector = dvwa_authenticated_detector(vec![SqliTechnique::ErrorBased]).await;
    let url = dvwa_url();
    let findings = detector.test_url(&url).await.expect("scan");
    // DVWA low security should be detectable via error-based or union-based
    assert!(
        findings.iter().any(|f|
            f.technique == SqliTechnique::ErrorBased || f.technique == SqliTechnique::UnionBased
        ),
        "Expected error-based or union-based detection on DVWA"
    );
}
