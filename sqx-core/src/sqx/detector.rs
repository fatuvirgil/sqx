//! Core SqliDetector struct: construction, URL/POST scanning, HTTP helpers,
//! and conversion of results to Finding objects.

use anyhow::{Result, anyhow};
use reqwest::Client;
use std::time::{Duration, Instant};
use tracing::{debug, info, warn};

use super::evasion::tamper_chain::TamperChain;
use super::models::{HttpResponse, SqliConfig, SqliTechnique, SqliTestResult};
use super::session::SessionManager;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

/// Trait for out-of-band (OOB) server implementations.
/// The OOB server provides DNS/HTTP endpoints for detecting blind SQL injection
/// via external interactions (DNS lookups, HTTP callbacks).
pub trait OobServer: Send + Sync {
    /// Generate a unique callback URL/payload marker for a test.
    /// The returned string should be used in SQL payloads (e.g., for LOAD_FILE, UTL_HTTP).
    fn generate_callback(&self, test_id: &str) -> String;
    
    /// Check if a callback was received for the given test_id within timeout.
    /// Returns true if the OOB server detected an interaction.
    fn check_callback<'a>(&'a self, test_id: &'a str, timeout_secs: u64) -> std::pin::Pin<Box<dyn std::future::Future<Output = bool> + Send + 'a>>;
}

/// Main SQL injection detector
#[derive(Clone)]
pub struct SqliDetector {
    pub(crate) client: Client,
    pub(crate) config: SqliConfig,
    /// OOB server for out-of-band detection (Pro feature).
    pub(crate) oob_server: Option<Arc<dyn OobServer>>,
    /// Session manager for authenticated scanning.
    /// Wrapped in Arc for safe concurrent access across tokio tasks.
    pub(crate) session: Option<Arc<SessionManager>>,
    /// Adaptive inter-request delay (ms). Grows when the target returns 429
    /// so that a scan against a rate-limited endpoint self-paces.
    pub(crate) adaptive_delay_ms: Arc<AtomicU64>,
    /// Optional cancellation token — when cancelled, all scan loops exit early.
    /// Set via `with_cancel_token` before starting the scan.
    pub(crate) cancel_token: Option<super::models::CancellationToken>,
    /// Total HTTP requests issued by this detector (incremented in send_request / send_post_request).
    pub(crate) request_count: Arc<AtomicUsize>,
    /// Dynamically adjusted SLEEP duration based on live baseline timing.
    /// When zero, falls back to `config.sleep_duration_secs`.
    pub(crate) adaptive_sleep_secs: Arc<AtomicU64>,
}

fn build_client(timeout: Duration, proxy: Option<&str>, insecure_tls: bool) -> Result<Client> {
    let mut b = Client::builder().timeout(timeout);
    if insecure_tls {
        b = b
            .danger_accept_invalid_certs(true)
            .danger_accept_invalid_hostnames(true);
    }
    if let Some(p) = proxy {
        b = b.proxy(reqwest::Proxy::all(p)?);
    }
    b.build()
        .map_err(|e| anyhow!("Failed to create HTTP client: {}", e))
}

impl SqliDetector {
    /// Create a new SQL injection detector
    pub fn new() -> Result<Self> {
        let client = build_client(Duration::from_secs(30), None, false)?;

        Ok(Self {
            client,
            config: SqliConfig::default(),
            oob_server: None,
            session: None,
            adaptive_delay_ms: Arc::new(AtomicU64::new(0)),
            cancel_token: None,
            request_count: Arc::new(AtomicUsize::new(0)),
            adaptive_sleep_secs: Arc::new(AtomicU64::new(0)),
        })
    }

    /// Create detector with custom config
    pub fn with_config(config: SqliConfig) -> Result<Self> {
        let client = build_client(
            Duration::from_secs(config.timeout_secs),
            config.proxy.as_deref(),
            config.insecure_tls,
        )?;

        Ok(Self {
            client,
            config,
            oob_server: None,
            session: None,
            adaptive_delay_ms: Arc::new(AtomicU64::new(0)),
            cancel_token: None,
            request_count: Arc::new(AtomicUsize::new(0)),
            adaptive_sleep_secs: Arc::new(AtomicU64::new(0)),
        })
    }

    /// Attach a cancellation token. Call `token.cancel()` from another task/thread
    /// to stop the scan at the next safe checkpoint.
    pub fn with_cancel_token(mut self, token: super::models::CancellationToken) -> Self {
        self.cancel_token = Some(token);
        self
    }

    /// Returns true if a cancellation has been requested.
    #[inline]
    pub(crate) fn is_scan_cancelled(&self) -> bool {
        self.cancel_token
            .as_ref()
            .map(|t| t.is_cancelled())
            .unwrap_or(false)
    }

    /// Total HTTP requests issued by this detector so far.
    pub fn request_count(&self) -> usize {
        self.request_count.load(Ordering::Relaxed)
    }

    /// If a session manager with auth is configured, perform login.
    /// Returns Ok(()) if no auth is configured or login succeeds.
    pub async fn ensure_authenticated(&self) -> Result<()> {
        if let Some(ref sess) = self.session {
            if sess.has_auth() {
                return sess.login(&self.client).await;
            }
        }
        Ok(())
    }

    /// Returns true if a session with authentication is attached.
    pub fn has_auth_session(&self) -> bool {
        self.session.as_ref().map(|s| s.has_auth()).unwrap_or(false)
    }

    /// Set OOB server for out-of-band detection (Pro feature).
    /// The OOB server must implement the OobServer trait.
    pub fn with_oob_server<T: OobServer + 'static>(mut self, server: Arc<T>) -> Self {
        self.oob_server = Some(server as Arc<dyn OobServer>);
        self
    }

    /// Set OOB server from a trait object (internal use for cloning detector with OOB).
    pub(crate) fn with_oob_dyn(mut self, server: Arc<dyn OobServer>) -> Self {
        self.oob_server = Some(server);
        self
    }

    /// Effective sleep duration for time-based tests.
    /// Returns the dynamically adjusted value if set, otherwise the config default.
    #[inline]
    pub(crate) fn sleep_duration_secs(&self) -> u64 {
        let adaptive = self.adaptive_sleep_secs.load(Ordering::Relaxed);
        if adaptive > 0 {
            adaptive
        } else {
            self.config.sleep_duration_secs
        }
    }

    /// Update the adaptive sleep duration based on live baseline timing.
    #[inline]
    pub(crate) fn set_adaptive_sleep(&self, secs: u64) {
        self.adaptive_sleep_secs.store(secs, Ordering::Relaxed);
    }

    /// Set OOB server for out-of-band detection
    // OOB server is Pro-only
    // pub fn with_oob_server(mut self, server: Arc<crate::oob::OobServer>) -> Self {
    //     self.oob_server = Some(server);
    //     self
    // }

    /// Set session manager for authenticated scanning.
    /// All requests will include configured cookies, headers, and CSRF tokens.
    /// Accepts Arc<SessionManager> for safe concurrent access across tokio tasks.
    pub fn with_session(mut self, session: Arc<SessionManager>) -> Self {
        self.session = Some(session);
        self
    }

    /// Send HTTP GET request and return response details.
    /// If a session manager is configured, its cookies/headers are automatically applied
    /// and session cookies are updated from the response. CSRF tokens are auto-refreshed
    /// if stale (every 30s or on first request).
    pub async fn send_request(&self, url: &str) -> Result<HttpResponse> {
        // Auto-refresh CSRF token if needed before sending request
        if let Some(ref session) = self.session {
            session.maybe_refresh_csrf(&self.client).await;
        }

        let st = &self.config.stealth;

        // UA rotation
        let ua = if st.ua_rotation {
            crate::sqx::stealth::random_ua().to_string()
        } else {
            self.config.user_agent.clone()
        };

        // Optional referer spoofing — use the target's own origin
        let referer = if st.spoof_referer {
            crate::sqx::stealth::origin_of(url)
        } else {
            None
        };

        let start = Instant::now();
        let mut builder = self.client.get(url).header("User-Agent", &ua);

        // Realistic browser headers
        if st.mimic_browser_headers {
            for (k, v) in crate::sqx::stealth::browser_headers(referer.as_deref()) {
                builder = builder.header(k, v);
            }
        }

        // Apply session if configured
        if let Some(ref session) = self.session {
            builder = session.apply(builder);
        }

        let response = builder.send().await?;
        self.request_count.fetch_add(1, Ordering::Relaxed);

        // Update session cookies from response
        if let Some(ref session) = self.session {
            session.update_from_response(&response);

            // Auto-detect session cookies if not yet authenticated
            if !session.is_authenticated() && session.is_auto_detect_enabled() {
                let detected = session.detect_session_cookies(response.headers());
                if !detected.is_empty() {
                    for (name, value) in &detected {
                        info!("Auto-detected session cookie: {}={}", name, value);
                    }
                    session.insert_cookies(&detected);
                }
            }
        }

        let status = response.status().as_u16();
        let headers: std::collections::HashMap<String, String> = response
            .headers()
            .iter()
            .filter_map(|(k, v)| {
                v.to_str()
                    .ok()
                    .map(|vs| (k.as_str().to_lowercase(), vs.to_string()))
            })
            .collect();
        let body = response.text().await?;
        let duration = start.elapsed();

        Ok(HttpResponse {
            status,
            body,
            duration,
            headers,
        })
    }

    /// Send a POST request with a raw body. Applies session + User-Agent.
    /// Retries up to 3 times with exponential backoff when the server returns 429.
    pub(crate) async fn send_post_request(
        &self,
        url: &str,
        body: String,
        content_type: &str,
    ) -> Result<HttpResponse> {
        let mut attempt: u32 = 0;
        loop {
            // Self-pace: sleep the current adaptive floor before sending.
            let floor = self.adaptive_delay_ms.load(Ordering::Relaxed);
            if floor > 0 {
                tokio::time::sleep(Duration::from_millis(floor)).await;
            }

            if let Some(ref session) = self.session {
                session.maybe_refresh_csrf(&self.client).await;
            }

            let st = &self.config.stealth;
            let ua = if st.ua_rotation {
                crate::sqx::stealth::random_ua().to_string()
            } else {
                self.config.user_agent.clone()
            };
            let referer = if st.spoof_referer {
                crate::sqx::stealth::origin_of(url)
            } else {
                None
            };

            let start = Instant::now();
            let mut builder = self
                .client
                .post(url)
                .header("Content-Type", content_type)
                .header("User-Agent", &ua)
                .body(body.clone());

            if st.mimic_browser_headers {
                for (k, v) in crate::sqx::stealth::browser_headers(referer.as_deref()) {
                    builder = builder.header(k, v);
                }
            }

            if let Some(ref session) = self.session {
                builder = session.apply(builder);
            }
            let resp = builder.send().await?;
            self.request_count.fetch_add(1, Ordering::Relaxed);
            if let Some(ref session) = self.session {
                session.update_from_response(&resp);
            }
            let status = resp.status().as_u16();
            let headers: std::collections::HashMap<String, String> = resp
                .headers()
                .iter()
                .filter_map(|(k, v)| {
                    v.to_str()
                        .ok()
                        .map(|vs| (k.as_str().to_lowercase(), vs.to_string()))
                })
                .collect();
            let body_text = resp.text().await?;

            if status == 429 && attempt < 5 {
                let wait = Duration::from_secs(2u64 << attempt);
                // Grow the self-pacing floor so future requests spread out.
                let new_floor = (self.adaptive_delay_ms.load(Ordering::Relaxed) + 500).min(4000);
                self.adaptive_delay_ms.store(new_floor, Ordering::Relaxed);
                debug!(
                    "429 — backing off {:?}, adaptive floor now {}ms (attempt {})",
                    wait,
                    new_floor,
                    attempt + 1
                );
                tokio::time::sleep(wait).await;
                attempt += 1;
                continue;
            }

            return Ok(HttpResponse {
                status,
                body: body_text,
                duration: start.elapsed(),
                headers,
            });
        }
    }

    /// Dispatch a single technique test — used by both the main loop and escalation.
    pub(crate) async fn run_technique(
        &self,
        url: &str,
        param: &super::fingerprint::ParameterProfile,
        technique: SqliTechnique,
        tamper: Option<&TamperChain>,
        _dbms_hint: Option<&str>,
    ) -> Option<SqliTestResult> {
        match technique {
            SqliTechnique::ErrorBased => {
                let baseline = self.send_request(url).await.ok()?;
                self.test_error_based(url, &param.name, &param.original_value, &baseline, tamper)
                    .await
            }
            SqliTechnique::BooleanBlind => {
                let baseline = self.send_request(url).await.ok()?;
                self.test_boolean_blind(url, &param.name, &param.original_value, &baseline, tamper)
                    .await
            }
            SqliTechnique::TimeBased => {
                self.test_time_based(url, &param.name, &param.original_value, tamper)
                    .await
            }
            SqliTechnique::UnionBased => {
                let baseline = self.send_request(url).await.ok()?;
                self.test_union_based(url, &param.name, &param.original_value, &baseline, tamper)
                    .await
            }
            SqliTechnique::StackedQueries => {
                self.test_stacked_queries(url, &param.name, &param.original_value, tamper)
                    .await
            }
            SqliTechnique::OutOfBand => {
                // OOB is a Pro feature (requires OOB server)
                warn!("Out-of-band detection requires SQX Pro");
                None
            }
            SqliTechnique::SecondOrder => {
                // Second-order is a Pro feature
                warn!("Second-order detection requires SQX Pro");
                None
            }
            SqliTechnique::CodeInjection => {
                self.test_code_injection(url, &param.name, &param.original_value)
                    .await
            }
        }
    }
}
