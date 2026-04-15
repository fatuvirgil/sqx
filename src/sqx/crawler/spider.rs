//! Lightweight injection-point spider.
//!
//! Follows links, parses HTML forms with regex (no external HTML parser required),
//! and returns [`InjectionPoint`] structs ready for SQX scanning.

use std::collections::{HashSet, VecDeque};
use std::time::Duration;

use anyhow::Result;
use regex::Regex;
use reqwest::Client;
use tracing::{debug, info};

use super::models::{CrawlerConfig, DiscoveredParam, HttpMethod, InjectionPoint, ParamLocation};

/// Lightweight injection-point crawler.
pub struct Spider {
    client: Client,
    config: CrawlerConfig,
    user_agent: String,
}

impl Spider {
    pub fn new(client: Client, config: CrawlerConfig, user_agent: String) -> Self {
        Self { client, config, user_agent }
    }

    /// Crawl from `start_url` and return all discovered injection points.
    pub async fn crawl(&self, start_url: &str) -> Result<Vec<InjectionPoint>> {
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
                    if parsed.domain().unwrap_or("") != base_domain {
                        continue;
                    }
                }
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
            let resp = match self
                .client
                .get(&url)
                .header("User-Agent", &self.user_agent)
                .timeout(Duration::from_secs(10))
                .send()
                .await
            {
                Ok(r) => r,
                Err(e) => {
                    debug!("Failed to fetch {}: {}", url, e);
                    continue;
                }
            };

            let final_url = resp.url().to_string();

            // Only parse HTML responses
            let content_type = resp
                .headers()
                .get("content-type")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("")
                .to_string();

            let body = resp.text().await.unwrap_or_default();

            if content_type.contains("html") || content_type.is_empty() {
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
                    });
                }
            }

            tokio::time::sleep(Duration::from_millis(self.config.delay_ms)).await;
        }

        let injection_points = Self::deduplicate(injection_points);

        info!(
            "Crawl complete: {} pages visited, {} injection points found",
            visited.len(),
            injection_points.len()
        );

        Ok(injection_points)
    }

    // ── Private helpers ──────────────────────────────────────────────────────

    /// Extract `<form>` elements and return one [`InjectionPoint`] per form.
    fn extract_injection_points(&self, html: &str, page_url: &str) -> Vec<InjectionPoint> {
        let mut points = Vec::new();

        // Pre-compile regexes (static initialization with lazy_static-style one-time compile)
        let form_re = Regex::new(r"(?si)<form\b([^>]*)>(.*?)</form>").unwrap();
        let action_re = Regex::new(r#"(?i)action\s*=\s*["']([^"']*)["']"#).unwrap();
        let method_re = Regex::new(r#"(?i)method\s*=\s*["']([^"']*)["']"#).unwrap();
        let input_re = Regex::new(r#"(?si)<input\b([^>]*)/?>"#).unwrap();
        let name_re = Regex::new(r#"(?i)name\s*=\s*["']([^"']*)["']"#).unwrap();
        let type_re = Regex::new(r#"(?i)type\s*=\s*["']([^"']*)["']"#).unwrap();
        let value_re = Regex::new(r#"(?i)value\s*=\s*["']([^"']*)["']"#).unwrap();
        let select_re =
            Regex::new(r#"(?si)<select\b[^>]*name\s*=\s*["']([^"']*)["'][^>]*>"#).unwrap();
        let textarea_re =
            Regex::new(r#"(?si)<textarea\b[^>]*name\s*=\s*["']([^"']*)["'][^>]*>"#).unwrap();

        const SKIP_TYPES: &[&str] = &["submit", "button", "image", "reset", "file"];

        for form_cap in form_re.captures_iter(html) {
            let form_attrs = &form_cap[1];
            let form_body = &form_cap[2];

            let action = action_re
                .captures(form_attrs)
                .map(|c| c[1].to_string())
                .unwrap_or_default();

            let form_url = self.resolve_url(page_url, &action);

            let method_str = method_re
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
            for input_cap in input_re.captures_iter(form_body) {
                let attrs = &input_cap[1];

                let name = match name_re.captures(attrs) {
                    Some(c) => c[1].to_string(),
                    None => continue,
                };

                let input_type = type_re.captures(attrs).map(|c| c[1].to_lowercase());

                if let Some(ref t) = input_type {
                    if SKIP_TYPES.contains(&t.as_str()) {
                        continue;
                    }
                }

                let value = value_re.captures(attrs).map(|c| c[1].to_string());

                params.push(DiscoveredParam {
                    name,
                    location: param_location.clone(),
                    default_value: value,
                    input_type,
                });
            }

            // <select> fields
            for cap in select_re.captures_iter(form_body) {
                params.push(DiscoveredParam {
                    name: cap[1].to_string(),
                    location: param_location.clone(),
                    default_value: None,
                    input_type: Some("select".to_string()),
                });
            }

            // <textarea> fields
            for cap in textarea_re.captures_iter(form_body) {
                params.push(DiscoveredParam {
                    name: cap[1].to_string(),
                    location: param_location.clone(),
                    default_value: None,
                    input_type: Some("textarea".to_string()),
                });
            }

            if !params.is_empty() {
                points.push(InjectionPoint {
                    url: form_url,
                    method: http_method,
                    parameters: params,
                    found_on: page_url.to_string(),
                    content_type: Some(
                        "application/x-www-form-urlencoded".to_string(),
                    ),
                });
            }
        }

        points
    }

    /// Extract `href` links from HTML for BFS queueing.
    fn extract_links(&self, html: &str, base_url: &str) -> Vec<String> {
        let href_re =
            Regex::new(r#"(?i)href\s*=\s*["']([^"'#][^"']*)["']"#).unwrap();

        href_re
            .captures_iter(html)
            .map(|cap| cap[1].to_string())
            .filter(|href| {
                !href.starts_with("javascript:")
                    && !href.starts_with("mailto:")
                    && !href.starts_with("tel:")
                    && !href.starts_with("data:")
            })
            .map(|href| self.resolve_url(base_url, &href))
            .collect()
    }

    /// Resolve a potentially relative URL against `base`.
    fn resolve_url(&self, base: &str, href: &str) -> String {
        if href.starts_with("http://") || href.starts_with("https://") {
            return href.to_string();
        }
        reqwest::Url::parse(base)
            .ok()
            .and_then(|b| b.join(href).ok())
            .map(|u| u.to_string())
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
        Spider::new(Client::new(), CrawlerConfig::default(), "test/1.0".to_string())
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
        let names: Vec<&str> = points[0].parameters.iter().map(|p| p.name.as_str()).collect();
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
}
