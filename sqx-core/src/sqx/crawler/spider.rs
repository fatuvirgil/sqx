//! Lightweight injection-point spider.
//!
//! Follows links, parses HTML forms with regex (no external HTML parser required),
//! and returns [`InjectionPoint`] structs ready for SQX scanning.

use std::collections::{HashSet, VecDeque};
use std::sync::Arc;
use std::sync::OnceLock;
use std::time::Duration;

use anyhow::Result;
use regex::Regex;
use reqwest::Client;
use tracing::{debug, info, warn};

use super::models::{
    CrawlResult, CrawlerConfig, DiscoveredParam, HttpMethod, InjectionPoint, ParamLocation,
};
use crate::sqx::models::FormType;
use crate::sqx::session::SessionManager;

// ── Lazy-compiled regexes (avoids re-compilation on every page) ─────────────

static FORM_RE: OnceLock<Regex> = OnceLock::new();
static ACTION_RE: OnceLock<Regex> = OnceLock::new();
static METHOD_RE: OnceLock<Regex> = OnceLock::new();
static INPUT_RE: OnceLock<Regex> = OnceLock::new();
static NAME_RE: OnceLock<Regex> = OnceLock::new();
static TYPE_RE: OnceLock<Regex> = OnceLock::new();
static VALUE_RE: OnceLock<Regex> = OnceLock::new();
static SELECT_RE: OnceLock<Regex> = OnceLock::new();
static TEXTAREA_RE: OnceLock<Regex> = OnceLock::new();

fn form_re() -> &'static Regex {
    FORM_RE.get_or_init(|| Regex::new(r"(?si)<form\b([^>]*)>(.*?)</form>").unwrap())
}
fn action_re() -> &'static Regex {
    ACTION_RE.get_or_init(|| Regex::new(r#"(?i)action\s*=\s*["']([^"']*)["']"#).unwrap())
}
fn method_re() -> &'static Regex {
    METHOD_RE.get_or_init(|| Regex::new(r#"(?i)method\s*=\s*["']([^"']*)["']"#).unwrap())
}
fn input_re() -> &'static Regex {
    INPUT_RE.get_or_init(|| Regex::new(r#"(?si)<input\b([^>]*)/?>"#).unwrap())
}
fn name_re() -> &'static Regex {
    NAME_RE.get_or_init(|| Regex::new(r#"(?i)name\s*=\s*["']([^"']*)["']"#).unwrap())
}
fn type_re() -> &'static Regex {
    TYPE_RE.get_or_init(|| Regex::new(r#"(?i)type\s*=\s*["']([^"']*)["']"#).unwrap())
}
fn value_re() -> &'static Regex {
    VALUE_RE.get_or_init(|| Regex::new(r#"(?i)value\s*=\s*["']([^"']*)["']"#).unwrap())
}
fn select_re() -> &'static Regex {
    SELECT_RE.get_or_init(|| {
        Regex::new(r#"(?si)<select\b[^>]*name\s*=\s*["']([^"']*)["'][^>]*>"#).unwrap()
    })
}
fn textarea_re() -> &'static Regex {
    TEXTAREA_RE.get_or_init(|| {
        Regex::new(r#"(?si)<textarea\b[^>]*name\s*=\s*["']([^"']*)["'][^>]*>"#).unwrap()
    })
}

/// Lightweight injection-point crawler.
pub struct Spider {
    client: Client,
    config: CrawlerConfig,
    user_agent: String,
    session: Option<Arc<SessionManager>>,
}

impl Spider {
    pub fn new(client: Client, config: CrawlerConfig, user_agent: String) -> Self {
        Self {
            client,
            config,
            user_agent,
            session: None,
        }
    }

    pub fn with_session(mut self, session: Arc<SessionManager>) -> Self {
        self.session = Some(session);
        self
    }

    /// Crawl from `start_url` and return injection points plus all visited page URLs.
    pub async fn crawl(&self, start_url: &str) -> Result<CrawlResult> {
        let base_domain = reqwest::Url::parse(start_url)
            .ok()
            .and_then(|u| u.domain().map(str::to_string))
            .unwrap_or_default();

        let exclude_regexes: Vec<Regex> = self
            .config
            .exclude_patterns
            .iter()
            .filter_map(|p| Regex::new(p).ok())
            .collect();

        let mut visited: HashSet<String> = HashSet::new();
        let mut visited_pages: Vec<String> = Vec::new();
        let mut queue: VecDeque<(String, usize)> = VecDeque::new();
        let mut injection_points: Vec<InjectionPoint> = Vec::new();

        queue.push_back((start_url.to_string(), 0));

        while let Some((url, depth)) = queue.pop_front() {
            if visited.len() >= self.config.max_pages {
                break;
            }
            if depth > self.config.max_depth {
                continue;
            }
            if visited.contains(&url) {
                continue;
            }
            if exclude_regexes.iter().any(|re| re.is_match(&url)) {
                continue;
            }
            if self.config.same_domain_only {
                if let Ok(parsed) = reqwest::Url::parse(&url) {
                    if !self.is_valid_target_url(&parsed, &base_domain) {
                        continue;
                    }
                }
            }

            // Delay before every request *except* the very first one.
            if !visited.is_empty() && self.config.delay_ms > 0 {
                tokio::time::sleep(Duration::from_millis(self.config.delay_ms)).await;
            }

            visited.insert(url.clone());
            debug!(
                "Crawling [{}/{}] depth={}: {}",
                visited.len(),
                self.config.max_pages,
                depth,
                url
            );

            // Fetch page
            if let Some(ref session) = self.session {
                session.maybe_refresh_csrf(&self.client).await;
            }
            let mut builder = self
                .client
                .get(&url)
                .header("User-Agent", &self.user_agent)
                .timeout(Duration::from_secs(10));
            if let Some(ref session) = self.session {
                builder = session.apply(builder).await;
            }
            let resp = match builder.send().await {
                Ok(r) => r,
                Err(e) => {
                    if visited.len() == 1 {
                        // First URL failed — warn loudly so the user knows the target is unreachable.
                        warn!("Cannot reach start URL {}: {}", url, e);
                    } else {
                        debug!("Failed to fetch {}: {}", url, e);
                    }
                    continue;
                }
            };
            if let Some(ref session) = self.session {
                session.update_from_response(&resp).await;
                if !session.is_authenticated().await && session.is_auto_detect_enabled().await {
                    let detected = session.detect_session_cookies(resp.headers()).await;
                    if !detected.is_empty() {
                        session.insert_cookies(&detected).await;
                    }
                }
            }

            // Re-validate after redirects (same-domain + scheme check).
            if self.config.same_domain_only {
                if !self.is_valid_target_url(resp.url(), &base_domain) {
                    continue;
                }
            }

            let final_url = resp.url().to_string();

            // Only parse HTML responses
            let content_type = resp
                .headers()
                .get("content-type")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("")
                .to_string();

            // Abort early on huge responses to avoid OOM.
            if let Some(len) = resp.content_length() {
                if len > 10_000_000 {
                    debug!("Skipping huge response ({} bytes) for {}", len, final_url);
                    continue;
                }
            }

            let body = resp.text().await.unwrap_or_default();

            if content_type.to_lowercase().contains("html") || content_type.is_empty() {
                // Record this as a visited HTML page (strip query string).
                let clean_url = reqwest::Url::parse(&final_url)
                    .map(|mut u| {
                        u.set_query(None);
                        u.to_string()
                    })
                    .unwrap_or_else(|_| final_url.clone());
                if !visited_pages.contains(&clean_url) {
                    visited_pages.push(clean_url);
                }

                // Extract forms → injection points
                let points = self.extract_injection_points(&body, &final_url);
                injection_points.extend(points);

                // Enqueue links for further crawling
                for link in self.extract_links(&body, &final_url) {
                    if !visited.contains(&link) {
                        queue.push_back((link, depth + 1));
                    }
                }
            }

            // URL query params are always injection points
            if let Ok(parsed) = reqwest::Url::parse(&final_url) {
                let params: Vec<DiscoveredParam> = parsed
                    .query_pairs()
                    .map(|(k, v)| DiscoveredParam {
                        name: k.to_string(),
                        location: ParamLocation::QueryString,
                        default_value: Some(v.to_string()),
                        input_type: None,
                    })
                    .collect();

                if !params.is_empty() {
                    injection_points.push(InjectionPoint {
                        url: final_url.clone(),
                        method: HttpMethod::Get,
                        parameters: params,
                        found_on: url.clone(),
                        content_type: None,
                        form_type: Some(FormType::GenericInput),
                    });
                }
            }
        }

        let injection_points = Self::deduplicate(injection_points);

        info!(
            "Crawl complete: {} pages visited, {} injection points found",
            visited.len(),
            injection_points.len()
        );

        Ok(CrawlResult {
            injection_points,
            visited_pages,
        })
    }

    // ── Private helpers ──────────────────────────────────────────────────────

    fn is_valid_target_url(&self, url: &reqwest::Url, base_domain: &str) -> bool {
        if url.scheme() != "http" && url.scheme() != "https" {
            return false;
        }
        url.domain().unwrap_or("") == base_domain
    }

    /// Extract `<form>` elements and return one [`InjectionPoint`] per form.
    fn extract_injection_points(&self, html: &str, page_url: &str) -> Vec<InjectionPoint> {
        let mut points = Vec::new();

        const SKIP_TYPES: &[&str] = &["submit", "button", "image", "reset", "file"];

        for form_cap in form_re().captures_iter(html) {
            let form_attrs = &form_cap[1];
            let form_body = &form_cap[2];

            let action = action_re()
                .captures(form_attrs)
                .map(|c| c[1].to_string())
                .unwrap_or_default();

            // Strip fragment (#...) — posting to a fragment URL fails; the
            // fragment is client-side only and never sent to the server.
            let action_no_frag = action.split('#').next().unwrap_or(&action).to_string();
            let form_url = self.resolve_url(page_url, &action_no_frag);

            let method_str = method_re()
                .captures(form_attrs)
                .map(|c| c[1].to_uppercase())
                .unwrap_or_else(|| "GET".to_string());

            let http_method = if method_str == "POST" {
                HttpMethod::Post
            } else {
                HttpMethod::Get
            };

            let param_location = if http_method == HttpMethod::Post {
                ParamLocation::PostBody
            } else {
                ParamLocation::QueryString
            };

            let mut params: Vec<DiscoveredParam> = Vec::new();

            // <input> fields
            for input_cap in input_re().captures_iter(form_body) {
                let attrs = &input_cap[1];

                let name = match name_re().captures(attrs) {
                    Some(c) => c[1].to_string(),
                    None => continue,
                };

                let input_type = type_re().captures(attrs).map(|c| c[1].to_lowercase());

                if let Some(ref t) = input_type {
                    if SKIP_TYPES.contains(&t.as_str()) {
                        continue;
                    }
                }

                let value = value_re().captures(attrs).map(|c| c[1].to_string());

                params.push(DiscoveredParam {
                    name,
                    location: param_location.clone(),
                    default_value: value,
                    input_type,
                });
            }

            // <select> fields
            for cap in select_re().captures_iter(form_body) {
                params.push(DiscoveredParam {
                    name: cap[1].to_string(),
                    location: param_location.clone(),
                    default_value: None,
                    input_type: Some("select".to_string()),
                });
            }

            // <textarea> fields
            for cap in textarea_re().captures_iter(form_body) {
                params.push(DiscoveredParam {
                    name: cap[1].to_string(),
                    location: param_location.clone(),
                    default_value: None,
                    input_type: Some("textarea".to_string()),
                });
            }

            if !params.is_empty() {
                let form_type = self.detect_form_type(form_body, &params);
                points.push(InjectionPoint {
                    url: form_url,
                    method: http_method,
                    parameters: params,
                    found_on: page_url.to_string(),
                    content_type: Some("application/x-www-form-urlencoded".to_string()),
                    form_type: Some(form_type),
                });
            }
        }

        points
    }

    fn detect_form_type(&self, html: &str, params: &[DiscoveredParam]) -> FormType {
        let text = html.to_lowercase();
        let param_names: HashSet<String> = params.iter().map(|p| p.name.to_lowercase()).collect();

        // Registration heuristics: confirm password or register keywords
        if param_names.contains("confirm_password")
            || param_names.contains("password_confirm")
            || param_names.contains("repassword")
            || text.contains("create account")
            || text.contains("sign up")
            || text.contains("register")
        {
            return FormType::Registration;
        }

        // Login heuristics: username/password and login keywords
        if (param_names.contains("username")
            || param_names.contains("user")
            || param_names.contains("email")
            || param_names.contains("login"))
            && (param_names.contains("password")
                || param_names.contains("pass")
                || param_names.contains("pwd"))
        {
            return FormType::Login;
        }

        // Profile update heuristics
        if text.contains("update profile")
            || text.contains("save changes")
            || text.contains("edit profile")
            || text.contains("my account")
        {
            return FormType::ProfileUpdate;
        }

        FormType::GenericInput
    }

    /// Extract `href` links from `<a>` and `<area>` tags for BFS queueing.
    fn extract_links(&self, html: &str, base_url: &str) -> Vec<String> {
        static HREF_RE: OnceLock<Regex> = OnceLock::new();
        let href_re = HREF_RE.get_or_init(|| {
            Regex::new(r#"(?i)<(?:a|area)\s+[^>]*href\s*=\s*["']([^"']+)["']"#).unwrap()
        });

        href_re
            .captures_iter(html)
            .map(|cap| cap[1].to_string())
            .filter(|href| {
                let lower = href.to_lowercase();
                !lower.starts_with("javascript:")
                    && !lower.starts_with("mailto:")
                    && !lower.starts_with("tel:")
                    && !lower.starts_with("data:")
                    && !lower.starts_with("vbscript:")
                    && !lower.starts_with("file:")
                    && !lower.starts_with("ftp:")
                    && !lower.starts_with("about:")
                    && !lower.starts_with("chrome-extension:")
            })
            .map(|href| self.resolve_url(base_url, &href))
            .collect()
    }

    /// Resolve a potentially relative URL against `base`.
    fn resolve_url(&self, base: &str, href: &str) -> String {
        if href.starts_with("http://") || href.starts_with("https://") {
            // Still strip any fragment so the server-side crawler treats them as one page.
            if let Ok(mut u) = reqwest::Url::parse(href) {
                u.set_fragment(None);
                return u.to_string();
            }
            return href.to_string();
        }
        reqwest::Url::parse(base)
            .ok()
            .and_then(|b| b.join(href).ok())
            .map(|mut u| {
                u.set_fragment(None);
                u.to_string()
            })
            .unwrap_or_else(|| href.to_string())
    }

    /// Remove duplicate injection points by `(method, url, sorted param names)`.
    fn deduplicate(points: Vec<InjectionPoint>) -> Vec<InjectionPoint> {
        let mut seen: HashSet<String> = HashSet::new();
        let mut unique: Vec<InjectionPoint> = Vec::new();

        for point in points {
            let mut param_names: Vec<&str> =
                point.parameters.iter().map(|p| p.name.as_str()).collect();
            param_names.sort_unstable();
            let key = format!("{:?}|{}|{}", point.method, point.url, param_names.join(","));

            if seen.insert(key) {
                unique.push(point);
            }
        }

        unique
    }
}

// ── Unit tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use reqwest::Client;

    fn make_spider() -> Spider {
        Spider::new(
            Client::new(),
            CrawlerConfig::default(),
            "test/1.0".to_string(),
        )
    }

    #[test]
    fn extracts_get_form() {
        let html = r#"
            <form action="/search" method="get">
                <input name="q" type="text" value="hello" />
                <input type="submit" value="Go" />
            </form>
        "#;
        let spider = make_spider();
        let points = spider.extract_injection_points(html, "http://example.com/");
        assert_eq!(points.len(), 1);
        assert_eq!(points[0].method, HttpMethod::Get);
        assert_eq!(points[0].parameters.len(), 1);
        assert_eq!(points[0].parameters[0].name, "q");
        assert_eq!(
            points[0].parameters[0].default_value.as_deref(),
            Some("hello")
        );
    }

    #[test]
    fn extracts_post_form_with_select_and_textarea() {
        let html = r#"
            <form action="/login" method="POST">
                <input name="username" type="text" />
                <input name="password" type="password" />
                <select name="role"><option value="user">User</option></select>
                <textarea name="bio"></textarea>
                <input type="submit" value="Login" />
            </form>
        "#;
        let spider = make_spider();
        let points = spider.extract_injection_points(html, "http://example.com/");
        assert_eq!(points.len(), 1);
        assert_eq!(points[0].method, HttpMethod::Post);
        let names: Vec<&str> = points[0]
            .parameters
            .iter()
            .map(|p| p.name.as_str())
            .collect();
        assert!(names.contains(&"username"));
        assert!(names.contains(&"password"));
        assert!(names.contains(&"role"));
        assert!(names.contains(&"bio"));
        // submit button should be excluded
        assert!(!names.contains(&"submit"));
    }

    #[test]
    fn skips_submit_buttons() {
        let html = r#"
            <form action="/" method="get">
                <input name="q" type="text" />
                <input name="go" type="submit" value="Search" />
                <input name="rst" type="reset" />
            </form>
        "#;
        let spider = make_spider();
        let points = spider.extract_injection_points(html, "http://example.com/");
        assert_eq!(points[0].parameters.len(), 1);
        assert_eq!(points[0].parameters[0].name, "q");
    }

    #[test]
    fn deduplicate_removes_identical_forms() {
        let html = r#"
            <form action="/search" method="get">
                <input name="q" type="text" />
            </form>
            <form action="/search" method="get">
                <input name="q" type="text" />
            </form>
        "#;
        let spider = make_spider();
        let points = spider.extract_injection_points(html, "http://example.com/");
        // Two identical forms → two raw points
        let deduped = Spider::deduplicate(points);
        assert_eq!(deduped.len(), 1);
    }

    #[test]
    fn resolve_url_handles_relative_paths() {
        let spider = make_spider();
        assert_eq!(
            spider.resolve_url("http://example.com/page", "/login"),
            "http://example.com/login"
        );
        assert_eq!(
            spider.resolve_url("http://example.com/dir/", "search"),
            "http://example.com/dir/search"
        );
        assert_eq!(
            spider.resolve_url("http://example.com/", "https://other.com/x"),
            "https://other.com/x"
        );
    }

    #[test]
    fn resolve_url_strips_fragments() {
        let spider = make_spider();
        assert_eq!(
            spider.resolve_url("http://example.com/", "/page#section"),
            "http://example.com/page"
        );
        assert_eq!(
            spider.resolve_url("http://example.com/", "https://other.com/x#y"),
            "https://other.com/x"
        );
    }

    #[test]
    fn extract_links_skips_non_anchors() {
        let html = r#"
            <link rel="stylesheet" href="/style.css">
            <base href="/subdir/">
            <a href="/page1">Page 1</a>
            <area shape="rect" href="/page2" alt="Page 2">
            <a href="javascript:void(0)">JS</a>
            <a href="mailto:a@b.com">Mail</a>
        "#;
        let spider = make_spider();
        let links = spider.extract_links(html, "http://example.com/");
        assert_eq!(links.len(), 2);
        assert!(links.contains(&"http://example.com/page1".to_string()));
        assert!(links.contains(&"http://example.com/page2".to_string()));
    }
}
