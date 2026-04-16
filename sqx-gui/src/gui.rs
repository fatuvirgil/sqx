//! SQX GUI — egui-based desktop interface.

use eframe::egui::{self, Color32, RichText, ScrollArea, Ui};
use std::sync::{Arc, Mutex};
use std::sync::mpsc::{channel, Receiver, Sender};

use reqwest::Url;
use sqx_core::sqx::{SqliDetector, SqliConfig, SqliTechnique, TamperChain};
use sqx_core::sqx::pipeline::PipelineConfig;
use sqx_core::sqx::crawler::CrawlerConfig;
use sqx_core::sqx::ai_advisor::{
    AiAdvisor, AiAdvisorConfig, AiBackend, AiSuggestedPayload, TargetContext,
    list_ollama_models,
};

// ── Messages from async workers ───────────────────────────────────────────────

#[derive(Debug, Clone)]
pub enum ScanMsg {
    Finding { param: String, technique: String, confidence: f32, payload: String, evidence: String, payload_id: Option<String> },
    Status(String),
    Done,
    Error(String),
    /// Ollama model list fetched (for AI settings dropdown)
    OllamaModels(Vec<String>),
    /// AI payload suggestions ready
    AiSuggestions(Vec<AiSuggestedPayload>),
    /// Target profile from scan_smart — enriches AI context with real scan data
    ScanProfile {
        dbms: Option<String>,
        waf_name: Option<String>,
        waf_block_status: u16,
        waf_recommended_tampers: Vec<String>,
        reflects_errors: bool,
        reflects_input: bool,
        first_param: Option<String>,
        first_param_is_numeric: bool,
    },
}

// ── Persisted settings ────────────────────────────────────────────────────────

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct GuiSettings {
    pub ui_scale: f32,
    pub scan_smart: bool,
    pub scan_oob: bool,
    pub tech_error: bool,
    pub tech_blind: bool,
    pub tech_union: bool,
    pub tech_time: bool,
    pub tech_stacked: bool,
    pub delay_ms: u64,
    pub auto_smart: bool,
    pub auto_max_pages: usize,
    pub auto_max_depth: usize,
    pub oob_domain: String,
    pub oob_port: u16,
    pub ai_enabled: bool,
    pub ai_backend_choice: String,
    pub ai_ollama_url: String,
    pub ai_selected_model: String,
    pub ai_api_key: String,
    pub ai_openai_base_url: String,
    pub ai_consent_given: bool,
    pub stealth_ua_rotation: bool,
    pub stealth_browser_headers: bool,
    pub stealth_jitter_pct: u64,
    pub stealth_spoof_referer: bool,
    pub proxy_url: String,
    pub cookie_string: String,
    pub cookie_auto_detect: bool,
    pub login_url: String,
    pub auth_method_choice: String,
    pub auth_creds: String,
    pub auth_user: String,
    pub auth_pass: String,
    pub auth_token: String,
    pub auth_success: String,
}

impl Default for GuiSettings {
    fn default() -> Self {
        Self {
            ui_scale: 1.4,
            scan_smart: false,
            scan_oob: false,
            tech_error: true,
            tech_blind: true,
            tech_union: true,
            tech_time: true,
            tech_stacked: false,
            delay_ms: 100,
            auto_smart: true,
            auto_max_pages: 50,
            auto_max_depth: 3,
            oob_domain: "sqx.local".to_string(),
            oob_port: 8080,
            ai_enabled: false,
            ai_backend_choice: "ollama".to_string(),
            ai_ollama_url: "http://localhost:11434".to_string(),
            ai_selected_model: String::new(),
            ai_api_key: String::new(),
            ai_openai_base_url: "https://api.openai.com".to_string(),
            ai_consent_given: false,
            stealth_ua_rotation: true,
            stealth_browser_headers: true,
            stealth_jitter_pct: 30,
            stealth_spoof_referer: true,
            proxy_url: String::new(),
            cookie_string: String::new(),
            cookie_auto_detect: false,
            login_url: String::new(),
            auth_method_choice: String::new(),
            auth_creds: String::new(),
            auth_user: String::new(),
            auth_pass: String::new(),
            auth_token: String::new(),
            auth_success: String::new(),
        }
    }
}

fn config_dir() -> Option<std::path::PathBuf> {
    std::env::var_os("XDG_CONFIG_HOME")
        .map(|p| std::path::PathBuf::from(p).join("sqx"))
        .or_else(|| {
            std::env::var_os("HOME")
                .map(|h| std::path::PathBuf::from(h).join(".config").join("sqx"))
        })
}

fn settings_path() -> Option<std::path::PathBuf> {
    config_dir().map(|d| d.join("settings.json"))
}

fn load_settings() -> GuiSettings {
    match settings_path().and_then(|p| std::fs::read_to_string(&p).ok()) {
        Some(json) => serde_json::from_str(&json).unwrap_or_default(),
        None => GuiSettings::default(),
    }
}

fn save_settings(settings: &GuiSettings) {
    if let Some(path) = settings_path() {
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let _ = std::fs::write(&path, serde_json::to_string_pretty(settings).unwrap_or_default());
    }
}

// ── App state ─────────────────────────────────────────────────────────────────

#[derive(PartialEq)]
enum Tab { Scan, Auto, Results, Tampers, Oob, Ai, Settings }

pub struct SqxApp {
    tab: Tab,

    // Scan tab
    scan_url: String,
    scan_smart: bool,
    scan_oob: bool,
    tech_error: bool,
    tech_blind: bool,
    tech_union: bool,
    tech_time: bool,
    tech_stacked: bool,
    tamper_input: String,
    delay_ms: u64,

    // Auto tab
    auto_url: String,
    auto_smart: bool,
    auto_max_pages: usize,
    auto_max_depth: usize,

    // OOB tab
    oob_domain: String,
    oob_port: u16,
    oob_running: bool,
    oob_server: Option<Arc<sqx_core::oob::OobServer>>,

    // AI tab state
    ai_enabled: bool,
    ai_backend_choice: String,       // "ollama" | "claude" | "openai"
    ai_ollama_url: String,
    ai_selected_model: String,
    ai_available_models: Vec<String>,
    ai_models_loading: bool,
    ai_api_key: String,
    ai_openai_base_url: String,
    ai_consent_given: bool,
    ai_show_consent_warning: bool,
    /// Context from last scan — used for "Suggest" button
    ai_last_context: Option<TargetContext>,
    ai_suggestions: Vec<AiSuggestedPayload>,
    ai_suggesting: bool,

    // Results
    findings: Vec<ScanMsg>,
    status: String,
    scanning: bool,

    /// UI zoom level — pixels per point. 1.0 = system default, 1.4 = 40% larger.
    ui_scale: f32,

    // Stealth settings
    stealth_ua_rotation: bool,
    stealth_browser_headers: bool,
    stealth_jitter_pct: u64,
    stealth_spoof_referer: bool,

    // Proxy
    proxy_url: String,

    // Session cookies
    cookie_string: String,
    cookie_auto_detect: bool,

    // Auth settings
    login_url: String,
    auth_method_choice: String,
    auth_creds: String,
    auth_user: String,
    auth_pass: String,
    auth_token: String,
    auth_success: String,

    // Payload updater
    payloads_status: String,
    payloads_fetching: bool,

    tx: Sender<ScanMsg>,
    rx: Arc<Mutex<Receiver<ScanMsg>>>,
}

impl Default for SqxApp {
    fn default() -> Self {
        let (tx, rx) = channel();
        let s = load_settings();
        Self {
            tab: Tab::Scan,
            scan_url: String::new(),
            scan_smart: s.scan_smart,
            scan_oob: s.scan_oob,
            tech_error: s.tech_error,
            tech_blind: s.tech_blind,
            tech_union: s.tech_union,
            tech_time: s.tech_time,
            tech_stacked: s.tech_stacked,
            tamper_input: String::new(),
            delay_ms: s.delay_ms,
            auto_url: String::new(),
            auto_smart: s.auto_smart,
            auto_max_pages: s.auto_max_pages,
            auto_max_depth: s.auto_max_depth,
            oob_domain: s.oob_domain,
            oob_port: s.oob_port,
            oob_running: false,
            oob_server: None,
            // AI defaults
            ai_enabled: s.ai_enabled,
            ai_backend_choice: s.ai_backend_choice,
            ai_ollama_url: s.ai_ollama_url,
            ai_selected_model: s.ai_selected_model,
            ai_available_models: Vec::new(),
            ai_models_loading: false,
            ai_api_key: s.ai_api_key,
            ai_openai_base_url: s.ai_openai_base_url,
            ai_consent_given: s.ai_consent_given,
            ai_show_consent_warning: false,
            ai_last_context: None,
            ai_suggestions: Vec::new(),
            ai_suggesting: false,
            findings: Vec::new(),
            status: "Ready.".to_string(),
            scanning: false,
            ui_scale: s.ui_scale,
            stealth_ua_rotation: s.stealth_ua_rotation,
            stealth_browser_headers: s.stealth_browser_headers,
            stealth_jitter_pct: s.stealth_jitter_pct,
            stealth_spoof_referer: s.stealth_spoof_referer,
            proxy_url: s.proxy_url,
            cookie_string: s.cookie_string,
            cookie_auto_detect: s.cookie_auto_detect,
            login_url: s.login_url,
            auth_method_choice: s.auth_method_choice,
            auth_creds: s.auth_creds,
            auth_user: s.auth_user,
            auth_pass: s.auth_pass,
            auth_token: s.auth_token,
            auth_success: s.auth_success,
            payloads_status: if sqx_core::sqx::payload_fetcher::DynamicPayloads::is_cached() {
                "Cached".to_string()
            } else {
                "Not downloaded".to_string()
            },
            payloads_fetching: false,
            tx,
            rx: Arc::new(Mutex::new(rx)),
        }
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

impl SqxApp {
    fn collect_techniques(&self) -> Vec<SqliTechnique> {
        let mut v = vec![];
        if self.tech_error   { v.push(SqliTechnique::ErrorBased); }
        if self.tech_blind   { v.push(SqliTechnique::BooleanBlind); }
        if self.tech_union   { v.push(SqliTechnique::UnionBased); }
        if self.tech_time    { v.push(SqliTechnique::TimeBased); }
        if self.tech_stacked { v.push(SqliTechnique::StackedQueries); }
        if self.scan_oob     { v.push(SqliTechnique::OutOfBand); }
        v
    }

    fn build_ai_config(&self) -> AiAdvisorConfig {
        if !self.ai_enabled {
            return AiAdvisorConfig::default();
        }
        let backend = match self.ai_backend_choice.as_str() {
            "claude" => AiBackend::Claude {
                api_key: self.ai_api_key.clone(),
                model: self.ai_selected_model.clone(),
            },
            "openai" => AiBackend::OpenAiCompat {
                base_url: self.ai_openai_base_url.clone(),
                api_key: self.ai_api_key.clone(),
                model: self.ai_selected_model.clone(),
            },
            _ => AiBackend::Ollama {
                base_url: self.ai_ollama_url.clone(),
                model: self.ai_selected_model.clone(),
            },
        };
        AiAdvisorConfig { enabled: true, backend, max_suggestions: 8, timeout_secs: 30 }
    }

    fn is_commercial_backend(&self) -> bool {
        self.ai_backend_choice == "claude" || self.ai_backend_choice == "openai"
    }

    fn build_session(&self) -> Option<Arc<sqx_core::sqx::session::SessionManager>> {
        use sqx_core::sqx::session::{SessionConfig, SessionManager, AuthConfig};
        use std::collections::HashMap;

        let mut config = SessionConfig::default();

        let cookie_str = self.cookie_string.trim();
        if !cookie_str.is_empty() {
            for part in cookie_str.split(';') {
                let part = part.trim();
                if part.is_empty() { continue; }
                if let Some(eq_pos) = part.find('=') {
                    config.cookies.insert(part[..eq_pos].trim().to_string(), part[eq_pos + 1..].trim().to_string());
                }
            }
        }
        if self.cookie_auto_detect {
            config.auto_detect = true;
        }

        let login_url = self.login_url.trim();
        if !login_url.is_empty() {
            let method = if self.auth_method_choice.is_empty() {
                "form".to_string()
            } else {
                self.auth_method_choice.clone()
            };
            let mut credentials = HashMap::new();
            for line in self.auth_creds.lines() {
                let line = line.trim();
                if line.is_empty() { continue; }
                if let Some(pos) = line.find('=') {
                    credentials.insert(line[..pos].to_string(), line[pos + 1..].to_string());
                }
            }
            config.auth = Some(AuthConfig {
                login_url: login_url.to_string(),
                method,
                credentials,
                basic_username: if self.auth_user.is_empty() { None } else { Some(self.auth_user.clone()) },
                basic_password: if self.auth_pass.is_empty() { None } else { Some(self.auth_pass.clone()) },
                bearer_token: if self.auth_token.is_empty() { None } else { Some(self.auth_token.clone()) },
                success_indicator: if self.auth_success.is_empty() { None } else { Some(self.auth_success.clone()) },
            });
        }

        if !config.cookies.is_empty() || config.auto_detect || config.auth.is_some() {
            Some(Arc::new(SessionManager::new(config)))
        } else {
            None
        }
    }

    fn launch_scan(&mut self) {
        if self.scan_url.is_empty() || self.scanning { return; }
        self.scanning = true;
        self.findings.clear();
        self.ai_suggestions.clear();
        self.status = format!("Scanning {}...", self.scan_url);

        let url = self.scan_url.clone();
        let smart = self.scan_smart;
        let techniques = self.collect_techniques();
        let delay = self.delay_ms;
        let tx = self.tx.clone();
        let oob_server = self.oob_server.clone();
        let ai_cfg = self.build_ai_config();
        let stealth_ua      = self.stealth_ua_rotation;
        let stealth_hdrs    = self.stealth_browser_headers;
        let stealth_jitter  = self.stealth_jitter_pct;
        let stealth_referer = self.stealth_spoof_referer;
        let proxy_url       = self.proxy_url.clone();
        let session         = self.build_session();

        tokio::spawn(async move {
            let proxy = if proxy_url.trim().is_empty() { None } else { Some(proxy_url) };
            let config = SqliConfig {
                techniques,
                delay_ms: delay,
                ai_advisor: ai_cfg,
                stealth: sqx_core::sqx::models::StealthConfig {
                    ua_rotation: stealth_ua,
                    mimic_browser_headers: stealth_hdrs,
                    jitter_pct: stealth_jitter,
                    spoof_referer: stealth_referer,
                },
                proxy,
                ..SqliConfig::default()
            };
            let mut detector = match SqliDetector::with_config(config) {
                Ok(d) => d,
                Err(e) => { let _ = tx.send(ScanMsg::Error(e.to_string())); return; }
            };
            if let Some(srv) = oob_server {
                detector = detector.with_oob_server(srv);
            }
            match detector.ensure_authenticated().await {
                Ok(()) => {
                    if detector.has_auth_session() {
                        let _ = tx.send(ScanMsg::Status("Login successful".to_string()));
                    }
                }
                Err(e) => {
                    let _ = tx.send(ScanMsg::Status(format!("⚠ Login failed — scanning unauthenticated: {}", e)));
                }
            }

            let results = if smart {
                match detector.scan_smart(&url).await {
                    Ok((profile, r)) => {
                        // Send real profile data so AI context is accurate
                        let first_param = profile.parameters.iter()
                            .find(|p| p.likely_db_param || p.influences_output)
                            .or_else(|| profile.parameters.first());
                        let _ = tx.send(ScanMsg::ScanProfile {
                            dbms: profile.dbms_hint.clone(),
                            waf_name: profile.waf.as_ref().map(|w| w.name.clone()),
                            waf_block_status: profile.waf.as_ref().map(|w| w.block_status).unwrap_or(0),
                            waf_recommended_tampers: profile.waf.as_ref()
                                .map(|w| w.recommended_tampers.clone())
                                .unwrap_or_default(),
                            reflects_errors: profile.behavior.reflects_errors,
                            reflects_input: profile.behavior.reflects_input,
                            first_param: first_param.map(|p| p.name.clone()),
                            first_param_is_numeric: first_param.map(|p| p.is_numeric).unwrap_or(false),
                        });
                        if let Some(waf) = &profile.waf {
                            let _ = tx.send(ScanMsg::Status(
                                format!("WAF: {} ({:.0}%)", waf.name, waf.confidence * 100.0)
                            ));
                        }
                        if let Some(dbms) = &profile.dbms_hint {
                            let _ = tx.send(ScanMsg::Status(format!("DBMS hint: {}", dbms)));
                        }
                        r
                    }
                    Err(e) => { let _ = tx.send(ScanMsg::Error(e.to_string())); return; }
                }
            } else {
                match detector.test_url(&url).await {
                    Ok(r) => r,
                    Err(e) => { let _ = tx.send(ScanMsg::Error(e.to_string())); return; }
                }
            };

            for f in results {
                let _ = tx.send(ScanMsg::Finding {
                    param: f.parameter,
                    technique: f.technique.to_string(),
                    confidence: f.confidence,
                    payload: f.payload,
                    evidence: f.evidence,
                    payload_id: f.payload_id,
                });
            }
            let _ = tx.send(ScanMsg::Done);
        });
    }

    fn launch_auto_scan(&mut self) {
        if self.auto_url.is_empty() || self.scanning { return; }
        self.scanning = true;
        self.findings.clear();
        self.ai_suggestions.clear();
        self.status = format!("Auto scan: {}...", self.auto_url);

        let url = self.auto_url.clone();
        let smart = self.auto_smart;
        let max_pages = self.auto_max_pages;
        let max_depth = self.auto_max_depth;
        let oob_server = self.oob_server.clone();
        let ai_cfg = self.build_ai_config();
        let tx = self.tx.clone();
        let proxy_url = self.proxy_url.clone();
        let session = self.build_session();

        tokio::spawn(async move {
            let proxy = if proxy_url.trim().is_empty() { None } else { Some(proxy_url) };
            let config = SqliConfig { ai_advisor: ai_cfg, proxy, ..SqliConfig::default() };
            let mut detector = match SqliDetector::with_config(config) {
                Ok(d) => d,
                Err(e) => { let _ = tx.send(ScanMsg::Error(e.to_string())); return; }
            };
            if let Some(srv) = oob_server {
                detector = detector.with_oob_server(srv);
            }
            match detector.ensure_authenticated().await {
                Ok(()) => {
                    if detector.has_auth_session() {
                        let _ = tx.send(ScanMsg::Status("Login successful".to_string()));
                    }
                }
                Err(e) => {
                    let _ = tx.send(ScanMsg::Status(format!("⚠ Login failed — scanning unauthenticated: {}", e)));
                }
            }
            let cc = CrawlerConfig { max_pages, max_depth, ..CrawlerConfig::default() };
            let pc = PipelineConfig { smart_scan: smart };

            match sqx_core::sqx::auto_scan(&url, detector, Some(cc), Some(pc)).await {
                Ok(results) => {
                    for pr in results {
                        for f in pr.findings {
                            let _ = tx.send(ScanMsg::Finding {
                                param: f.parameter,
                                technique: f.technique.to_string(),
                                confidence: f.confidence,
                                payload: f.payload,
                                evidence: f.evidence,
                                payload_id: f.payload_id,
                            });
                        }
                    }
                    let _ = tx.send(ScanMsg::Done);
                }
                Err(e) => { let _ = tx.send(ScanMsg::Error(e.to_string())); }
            }
        });
    }

    fn fetch_ollama_models(&mut self) {
        if self.ai_models_loading { return; }
        self.ai_models_loading = true;
        self.ai_available_models.clear();
        let base_url = self.ai_ollama_url.clone();
        let tx = self.tx.clone();
        tokio::spawn(async move {
            let models = list_ollama_models(&base_url).await;
            let _ = tx.send(ScanMsg::OllamaModels(models));
        });
    }

    fn request_ai_suggestions(&mut self) {
        if self.ai_suggesting || self.ai_selected_model.is_empty() { return; }

        // Build enriched context: start from stored profile data, then add
        // error snippet from first ErrorBased finding and best technique guess.
        let base_ctx = self.ai_last_context.clone().unwrap_or_else(|| {
            // Non-smart scan: build minimal context from URL param parsing
            let first_param = Url::parse(&self.scan_url)
                .ok()
                .and_then(|u| u.query_pairs().next().map(|(k, _)| k.to_string()))
                .unwrap_or_else(|| "id".to_string());
            TargetContext {
                parameter: first_param,
                param_type: "string".to_string(),
                dbms_hint: None,
                waf_name: None,
                error_snippet: None,
                reflects_errors: false,
                reflects_input: false,
                technique: "error".to_string(),
            }
        });

        // Extract error snippet from first ErrorBased finding
        let error_snippet = self.findings.iter().find_map(|m| {
            if let ScanMsg::Finding { technique, evidence, .. } = m {
                if technique.to_lowercase().contains("error") {
                    return Some(evidence.chars().take(300).collect::<String>());
                }
            }
            None
        });

        // Pick best technique based on what findings we have
        let technique = self.findings.iter().find_map(|m| {
            if let ScanMsg::Finding { technique, .. } = m {
                Some(match technique.to_lowercase().as_str() {
                    t if t.contains("error") => "error",
                    t if t.contains("boolean") || t.contains("blind") => "boolean",
                    t if t.contains("union") => "union",
                    t if t.contains("time") => "time",
                    t if t.contains("stacked") => "stacked",
                    _ => "error",
                }.to_string())
            } else { None }
        }).unwrap_or_else(|| "error".to_string());

        let ctx = TargetContext {
            error_snippet,
            technique,
            ..base_ctx
        };

        self.ai_suggesting = true;
        self.ai_suggestions.clear();

        let cfg = self.build_ai_config();
        let tx = self.tx.clone();
        tokio::spawn(async move {
            let advisor = AiAdvisor::new(cfg);
            let suggestions = advisor.suggest(&ctx).await;
            let _ = tx.send(ScanMsg::AiSuggestions(suggestions));
        });
    }
}

// ── eframe::App ───────────────────────────────────────────────────────────────

impl eframe::App for SqxApp {
    fn save(&mut self, _storage: &mut dyn eframe::Storage) {
        let settings = GuiSettings {
            ui_scale: self.ui_scale,
            scan_smart: self.scan_smart,
            scan_oob: self.scan_oob,
            tech_error: self.tech_error,
            tech_blind: self.tech_blind,
            tech_union: self.tech_union,
            tech_time: self.tech_time,
            tech_stacked: self.tech_stacked,
            delay_ms: self.delay_ms,
            auto_smart: self.auto_smart,
            auto_max_pages: self.auto_max_pages,
            auto_max_depth: self.auto_max_depth,
            oob_domain: self.oob_domain.clone(),
            oob_port: self.oob_port,
            ai_enabled: self.ai_enabled,
            ai_backend_choice: self.ai_backend_choice.clone(),
            ai_ollama_url: self.ai_ollama_url.clone(),
            ai_selected_model: self.ai_selected_model.clone(),
            ai_api_key: self.ai_api_key.clone(),
            ai_openai_base_url: self.ai_openai_base_url.clone(),
            ai_consent_given: self.ai_consent_given,
            stealth_ua_rotation: self.stealth_ua_rotation,
            stealth_browser_headers: self.stealth_browser_headers,
            stealth_jitter_pct: self.stealth_jitter_pct,
            stealth_spoof_referer: self.stealth_spoof_referer,
            proxy_url: self.proxy_url.clone(),
            cookie_string: self.cookie_string.clone(),
            cookie_auto_detect: self.cookie_auto_detect,
            login_url: self.login_url.clone(),
            auth_method_choice: self.auth_method_choice.clone(),
            auth_creds: self.auth_creds.clone(),
            auth_user: self.auth_user.clone(),
            auth_pass: self.auth_pass.clone(),
            auth_token: self.auth_token.clone(),
            auth_success: self.auth_success.clone(),
        };
        save_settings(&settings);
    }

    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        // Apply zoom — must be set every frame so it survives egui resets.
        ctx.set_pixels_per_point(self.ui_scale);

        // Drain async channel
        if let Ok(rx) = self.rx.lock() {
            while let Ok(msg) = rx.try_recv() {
                match &msg {
                    ScanMsg::Done => {
                        self.scanning = false;
                        self.status = format!("Done. {} findings.", self.findings.len());
                    }
                    ScanMsg::Error(e) => {
                        self.scanning = false;
                        self.status = format!("Error: {}", e);
                    }
                    ScanMsg::Status(s) => {
                        self.status = s.clone();
                        // Payload update completion arrives as a Status message
                        if s.contains("Payload update") {
                            self.payloads_fetching = false;
                            self.payloads_status = if s.contains("complete") {
                                "✓ Up to date".to_string()
                            } else {
                                format!("✗ {}", s)
                            };
                        }
                    }
                    ScanMsg::Finding { .. } => { self.findings.push(msg.clone()); }
                    ScanMsg::OllamaModels(models) => {
                        self.ai_available_models = models.clone();
                        self.ai_models_loading = false;
                        if self.ai_selected_model.is_empty() {
                            if let Some(first) = models.first() {
                                self.ai_selected_model = first.clone();
                            }
                        }
                    }
                    ScanMsg::AiSuggestions(suggestions) => {
                        self.ai_suggestions = suggestions.clone();
                        self.ai_suggesting = false;
                        self.status = format!("AI: {} payload suggestions ready.", suggestions.len());
                    }
                    ScanMsg::ScanProfile {
                        dbms, waf_name, reflects_errors, reflects_input,
                        first_param, first_param_is_numeric, ..
                    } => {
                        // Build a real TargetContext from scan_smart profile data.
                        // Error snippet will be enriched later from first ErrorBased finding.
                        self.ai_last_context = Some(TargetContext {
                            parameter: first_param.clone().unwrap_or_else(|| "id".to_string()),
                            param_type: if *first_param_is_numeric { "numeric".to_string() } else { "string".to_string() },
                            dbms_hint: dbms.clone(),
                            waf_name: waf_name.clone(),
                            error_snippet: None, // filled in request_ai_suggestions from findings
                            reflects_errors: *reflects_errors,
                            reflects_input: *reflects_input,
                            technique: "error".to_string(),
                        });
                    }
                }
            }
        }
        if self.scanning || self.ai_suggesting { ctx.request_repaint(); }

        egui::TopBottomPanel::top("tabs").show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.heading(RichText::new("⚡ SQX").color(Color32::YELLOW).strong());
                ui.separator();
                ui.selectable_value(&mut self.tab, Tab::Scan,    "Scan");
                ui.selectable_value(&mut self.tab, Tab::Auto,    "Auto");
                ui.selectable_value(&mut self.tab, Tab::Results,
                    format!("Results ({})", self.findings.len()));
                ui.selectable_value(&mut self.tab, Tab::Tampers, "Tampers");
                ui.selectable_value(&mut self.tab, Tab::Oob,     "OOB");
                let ai_label = if self.ai_enabled {
                    RichText::new("AI ●").color(Color32::from_rgb(100, 220, 100))
                } else {
                    RichText::new("AI")
                };
                ui.selectable_value(&mut self.tab, Tab::Ai, ai_label);
                ui.selectable_value(&mut self.tab, Tab::Settings, "⚙ Settings");

                // Zoom controls — right-aligned
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if ui.small_button("➕").on_hover_text("Zoom in").clicked() {
                        self.ui_scale = (self.ui_scale + 0.1).min(3.0);
                    }
                    ui.label(RichText::new(format!("{:.0}%", self.ui_scale * 100.0)).color(Color32::GRAY));
                    if ui.small_button("➖").on_hover_text("Zoom out").clicked() {
                        self.ui_scale = (self.ui_scale - 0.1).max(0.7);
                    }
                });
            });
        });

        egui::TopBottomPanel::bottom("status").show(ctx, |ui| {
            ui.horizontal(|ui| {
                if self.scanning || self.ai_suggesting { ui.spinner(); }
                let color = if self.status.starts_with("Error") { Color32::RED }
                            else if self.scanning { Color32::YELLOW }
                            else { Color32::GRAY };
                ui.label(RichText::new(&self.status).color(color));
            });
        });

        egui::CentralPanel::default().show(ctx, |ui| {
            match self.tab {
                Tab::Scan    => self.draw_scan(ui),
                Tab::Auto    => self.draw_auto(ui),
                Tab::Results => self.draw_results(ui),
                Tab::Tampers  => draw_tampers(ui),
                Tab::Oob      => self.draw_oob(ui),
                Tab::Ai       => self.draw_ai(ui),
                Tab::Settings => self.draw_settings(ui),
            }
        });
    }
}

// ── Text input helper with right-click context menu ───────────────────────────

/// Renders a single-line `TextEdit` and attaches a right-click context menu
/// with Copy / Paste / Clear actions.
///
/// Returns the egui `Response` (same as `ui.add(TextEdit::singleline(...))`).
///
/// Middle-click (X11 primary selection) is a known egui 0.30 limitation —
/// the primary selection is not accessible through the egui API.
fn text_input(ui: &mut Ui, value: &mut String, hint: &str, width: f32) -> egui::Response {
    text_input_ex(ui, value, hint, width, false)
}

fn text_input_password(ui: &mut Ui, value: &mut String, hint: &str, width: f32) -> egui::Response {
    text_input_ex(ui, value, hint, width, true)
}

fn text_input_ex(ui: &mut Ui, value: &mut String, hint: &str, width: f32, password: bool) -> egui::Response {
    let resp = ui.add(
        egui::TextEdit::singleline(value)
            .hint_text(hint)
            .desired_width(width)
            .password(password),
    );

    // Right-click context menu.
    // Directly mutating `value` is safe here — TextEdit::singleline borrows end
    // after ui.add() returns, so `value` is free for the closure to capture.
    let copy_val = value.clone();
    resp.context_menu(|ui| {
        if ui.button("Copy").clicked() {
            ui.ctx().copy_text(copy_val.clone());
            ui.close_menu();
        }
        if ui.button("Paste").clicked() {
            // Read clipboard on click only — not every frame.
            match arboard::Clipboard::new().and_then(|mut cb| cb.get_text()) {
                Ok(text) => *value = text,
                Err(e) => { let _ = e; } // silently ignore (Wayland/no clipboard)
            }
            ui.close_menu();
        }
        ui.separator();
        if ui.button("Clear").clicked() {
            value.clear();
            ui.close_menu();
        }
    });

    resp
}

// ── Tab renderers ─────────────────────────────────────────────────────────────

impl SqxApp {
    fn draw_scan(&mut self, ui: &mut Ui) {
        ui.heading("GET Scan");
        ui.separator();
        ui.add_space(4.0);

        ui.horizontal(|ui| {
            ui.label("URL:");
            text_input(ui, &mut self.scan_url, "http://target.com/page?id=1", 520.0);
        });

        ui.add_space(8.0);
        ui.label("Techniques:");
        ui.horizontal(|ui| {
            ui.checkbox(&mut self.tech_error,   "Error-based");
            ui.checkbox(&mut self.tech_blind,   "Boolean blind");
            ui.checkbox(&mut self.tech_union,   "Union");
            ui.checkbox(&mut self.tech_time,    "Time-based");
            ui.checkbox(&mut self.tech_stacked, "Stacked");
            ui.checkbox(&mut self.scan_oob,     "OOB");
        });

        ui.add_space(4.0);
        ui.horizontal(|ui| {
            ui.checkbox(&mut self.scan_smart, "Smart scan (fingerprint first)");
            ui.add_space(20.0);
            ui.label("Delay (ms):");
            ui.add(egui::DragValue::new(&mut self.delay_ms).range(0..=5000));
        });

        ui.horizontal(|ui| {
            ui.label("Tamper chain:");
            text_input(ui, &mut self.tamper_input, "space_to_comment,randomcase,...", 340.0);
        });

        if self.ai_enabled {
            ui.add_space(4.0);
            let model_label = if self.ai_selected_model.is_empty() {
                "(no model selected)".to_string()
            } else {
                self.ai_selected_model.clone()
            };
            ui.label(RichText::new(format!("AI advisor: {} [{}]", model_label, self.ai_backend_choice))
                .color(Color32::from_rgb(100, 220, 100)).small());
        }

        ui.add_space(12.0);
        ui.horizontal(|ui| {
            let label = if self.scanning { "Scanning..." } else { "▶  Scan" };
            let btn = egui::Button::new(RichText::new(label).color(Color32::BLACK).strong())
                .fill(if self.scanning { Color32::DARK_GRAY } else { Color32::from_rgb(255, 200, 0) })
                .min_size(egui::vec2(100.0, 30.0));
            if ui.add_enabled(!self.scanning, btn).clicked() {
                self.launch_scan();
                self.tab = Tab::Results;
            }
            if self.scanning && ui.button("■  Stop").clicked() {
                self.scanning = false;
                self.status = "Stopped.".to_string();
            }
        });
    }

    fn draw_auto(&mut self, ui: &mut Ui) {
        ui.heading("Auto Scan  (Spider → Fingerprint → Pipeline)");
        ui.separator();
        ui.add_space(4.0);

        ui.horizontal(|ui| {
            ui.label("Start URL:");
            text_input(ui, &mut self.auto_url, "http://target.com/", 520.0);
        });

        ui.add_space(6.0);
        ui.horizontal(|ui| {
            ui.checkbox(&mut self.auto_smart, "Smart scan per injection point");
        });
        ui.horizontal(|ui| {
            ui.label("Max pages:");
            ui.add(egui::DragValue::new(&mut self.auto_max_pages).range(1..=500));
            ui.label("  Max depth:");
            ui.add(egui::DragValue::new(&mut self.auto_max_depth).range(1..=10));
        });

        ui.add_space(12.0);
        let btn = egui::Button::new(
            RichText::new(if self.scanning { "Scanning..." } else { "▶  Auto Scan" })
                .color(Color32::BLACK).strong()
        )
        .fill(if self.scanning { Color32::DARK_GRAY } else { Color32::from_rgb(255, 200, 0) })
        .min_size(egui::vec2(120.0, 30.0));

        if ui.add_enabled(!self.scanning, btn).clicked() {
            self.launch_auto_scan();
            self.tab = Tab::Results;
        }
    }

    fn draw_results(&mut self, ui: &mut Ui) {
        ui.horizontal(|ui| {
            ui.heading("Results");
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if ui.button("Clear").clicked() {
                    self.findings.clear();
                    self.ai_suggestions.clear();
                }
                if ui.button("Export JSON").clicked() {
                    let rows: Vec<_> = self.findings.iter().filter_map(|m| {
                        if let ScanMsg::Finding { param, technique, confidence, payload, evidence, payload_id } = m {
                            Some(serde_json::json!({
                                "param": param, "technique": technique,
                                "confidence": confidence, "payload": payload, "evidence": evidence,
                                "payload_id": payload_id
                            }))
                        } else { None }
                    }).collect();
                    let _ = std::fs::write(
                        "sqx-results.json",
                        serde_json::to_string_pretty(&rows).unwrap_or_default()
                    );
                    self.status = "Exported sqx-results.json".to_string();
                }
            });
        });
        ui.separator();

        // ── AI Suggest panel ──────────────────────────────────────────────────
        if self.ai_enabled && self.ai_last_context.is_some() {
            egui::Frame::none()
                .fill(Color32::from_rgb(20, 30, 45))
                .inner_margin(8.0)
                .rounding(4.0)
                .show(ui, |ui| {
                    ui.horizontal(|ui| {
                        ui.label(RichText::new("AI Payload Advisor").color(Color32::from_rgb(100, 200, 255)).strong());
                        ui.add_space(8.0);

                        let can_suggest = !self.ai_suggesting
                            && !self.ai_selected_model.is_empty()
                            && (!self.is_commercial_backend() || self.ai_consent_given);

                        let suggest_btn = egui::Button::new(
                            RichText::new(if self.ai_suggesting { "Thinking..." } else { "💡 Suggest next payloads" })
                                .color(Color32::BLACK)
                        )
                        .fill(if can_suggest { Color32::from_rgb(100, 200, 255) } else { Color32::DARK_GRAY })
                        .min_size(egui::vec2(180.0, 24.0));

                        if ui.add_enabled(can_suggest, suggest_btn).clicked() {
                            self.request_ai_suggestions();
                        }

                        if !self.ai_selected_model.is_empty() {
                            ui.label(RichText::new(format!("via {}", self.ai_selected_model)).color(Color32::GRAY).small());
                        } else {
                            ui.label(RichText::new("⚠ No model selected — go to AI tab").color(Color32::YELLOW).small());
                        }
                    });

                    if !self.ai_suggestions.is_empty() {
                        ui.add_space(4.0);
                        for suggestion in &self.ai_suggestions {
                            ui.horizontal(|ui| {
                                let copy_btn = egui::Button::new("⎘")
                                    .min_size(egui::vec2(20.0, 18.0));
                                if ui.add(copy_btn).on_hover_text("Copy payload").clicked() {
                                    ui.output_mut(|o| o.copied_text = suggestion.payload.clone());
                                }
                                ui.label(
                                    RichText::new(&suggestion.payload)
                                        .color(Color32::from_rgb(255, 220, 100))
                                        .monospace()
                                );
                                ui.label(
                                    RichText::new(format!("— {}", suggestion.reasoning))
                                        .color(Color32::GRAY)
                                        .small()
                                );
                            });
                        }
                    }
                });
            ui.add_space(6.0);
        }

        if self.findings.is_empty() {
            ui.centered_and_justified(|ui| {
                ui.label(RichText::new("No findings yet. Run a scan first.").color(Color32::GRAY));
            });
            return;
        }

        ScrollArea::vertical().show(ui, |ui| {
            for msg in &self.findings {
                if let ScanMsg::Finding { param, technique, confidence, payload, evidence, payload_id } = msg {
                    let is_ai = evidence.starts_with("[AI]");
                    let frame_color = if is_ai {
                        Color32::from_rgb(20, 40, 30) // green tint for AI finds
                    } else {
                        Color32::from_rgb(45, 15, 15)
                    };
                    egui::Frame::none()
                        .fill(frame_color)
                        .inner_margin(8.0)
                        .rounding(4.0)
                        .show(ui, |ui| {
                            ui.horizontal(|ui| {
                                let badge = if is_ai { "● AI VULN" } else { "● VULN" };
                                let badge_color = if is_ai {
                                    Color32::from_rgb(80, 220, 120)
                                } else {
                                    Color32::RED
                                };
                                ui.label(RichText::new(badge).color(badge_color).strong());
                                ui.label(RichText::new(
                                    format!("param={}  |  {}  |  {:.0}%", param, technique, confidence * 100.0)
                                ).strong());
                                if let Some(id) = payload_id {
                                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                                        ui.label(RichText::new(id).color(Color32::GRAY).small());
                                    });
                                }
                            });
                            ui.label(RichText::new(format!("payload:  {}", payload))
                                .color(Color32::LIGHT_YELLOW).monospace());
                            ui.label(RichText::new(format!("evidence: {}", evidence))
                                .color(Color32::GRAY).small());
                        });
                    ui.add_space(4.0);
                }
            }
        });
    }

    fn draw_ai(&mut self, ui: &mut Ui) {
        ui.heading("AI Payload Advisor");
        ui.separator();
        ui.add_space(6.0);

        ui.checkbox(&mut self.ai_enabled, "Enable AI advisor during scans");
        ui.add_space(8.0);

        if !self.ai_enabled {
            ui.label(RichText::new(
                "When enabled, the advisor queries an LLM for context-aware payloads\n\
                 tailored to the detected DBMS, WAF, and error messages — before the\n\
                 static payload list is tried."
            ).color(Color32::GRAY));
            return;
        }

        // ── Backend selector ──────────────────────────────────────────────────
        ui.label("Backend:");
        ui.horizontal(|ui| {
            let prev = self.ai_backend_choice.clone();
            ui.selectable_value(&mut self.ai_backend_choice, "ollama".to_string(),  "Ollama (local)");
            ui.selectable_value(&mut self.ai_backend_choice, "claude".to_string(),  "Claude API");
            ui.selectable_value(&mut self.ai_backend_choice, "openai".to_string(),  "OpenAI-compat");
            if self.ai_backend_choice != prev {
                self.ai_selected_model.clear();
                self.ai_available_models.clear();
                self.ai_consent_given = false;
                self.ai_show_consent_warning = false;
            }
        });

        ui.add_space(8.0);

        match self.ai_backend_choice.as_str() {
            "ollama" => self.draw_ai_ollama_settings(ui),
            "claude" => self.draw_ai_commercial_settings(ui, "Claude API", "claude:claude-sonnet-4-6"),
            _        => self.draw_ai_commercial_settings(ui, "OpenAI-compat", "openai:gpt-4o"),
        }
    }

    fn draw_ai_ollama_settings(&mut self, ui: &mut Ui) {
        ui.horizontal(|ui| {
            ui.label("Ollama URL:");
            let prev_url = self.ai_ollama_url.clone();
            text_input(ui, &mut self.ai_ollama_url, "", 280.0);
            if self.ai_ollama_url != prev_url {
                self.ai_available_models.clear();
                self.ai_selected_model.clear();
            }
        });

        ui.add_space(6.0);

        ui.horizontal(|ui| {
            ui.label("Model:");
            if self.ai_available_models.is_empty() {
                ui.label(RichText::new(
                    if self.ai_models_loading { "Loading..." } else { "(click Refresh)" }
                ).color(Color32::GRAY));
            } else {
                egui::ComboBox::from_id_salt("ollama_model_select")
                    .selected_text(if self.ai_selected_model.is_empty() {
                        "— select —"
                    } else {
                        &self.ai_selected_model
                    })
                    .width(280.0)
                    .show_ui(ui, |ui| {
                        for model in &self.ai_available_models.clone() {
                            ui.selectable_value(
                                &mut self.ai_selected_model,
                                model.clone(),
                                model,
                            );
                        }
                    });
            }

            if ui.add_enabled(!self.ai_models_loading, egui::Button::new("↻ Refresh")).clicked() {
                self.fetch_ollama_models();
            }
        });

        if self.ai_available_models.is_empty() && !self.ai_models_loading {
            ui.add_space(4.0);
            ui.label(RichText::new(
                "No models found. Make sure Ollama is running: ollama serve"
            ).color(Color32::YELLOW).small());
        }

        ui.add_space(10.0);
        egui::Frame::none()
            .fill(Color32::from_rgb(20, 35, 20))
            .inner_margin(8.0)
            .rounding(4.0)
            .show(ui, |ui| {
                ui.label(RichText::new("Privacy: Ollama runs locally. No data leaves your machine.").color(Color32::from_rgb(100, 200, 100)));
            });

        if !self.ai_selected_model.is_empty() {
            ui.add_space(8.0);
            ui.label(RichText::new(format!("Ready: {} via {}", self.ai_selected_model, self.ai_ollama_url))
                .color(Color32::from_rgb(100, 220, 100)));
        }
    }

    fn draw_ai_commercial_settings(&mut self, ui: &mut Ui, label: &str, placeholder: &str) {
        // Consent warning box
        egui::Frame::none()
            .fill(Color32::from_rgb(50, 35, 10))
            .inner_margin(8.0)
            .rounding(4.0)
            .show(ui, |ui| {
                ui.label(RichText::new(format!("⚠  {} sends target context to a third-party API.", label))
                    .color(Color32::YELLOW).strong());
                ui.label(RichText::new(
                    "This includes: parameter names, error message snippets, DBMS fingerprint, WAF name.\n\
                     Do NOT use on confidential engagements without explicit client approval."
                ).color(Color32::GRAY).small());
                ui.add_space(6.0);
                ui.checkbox(&mut self.ai_consent_given,
                    "I understand and consent to sending this data to the external API");
            });

        if !self.ai_consent_given {
            return;
        }

        ui.add_space(8.0);
        ui.horizontal(|ui| {
            ui.label("API key:");
            text_input_password(ui, &mut self.ai_api_key, "sk-...", 360.0);
        });

        if self.ai_backend_choice == "openai" {
            ui.horizontal(|ui| {
                ui.label("Base URL:");
                text_input(ui, &mut self.ai_openai_base_url, "", 300.0);
            });
        }

        ui.add_space(6.0);
        ui.horizontal(|ui| {
            ui.label("Model:");
            text_input(ui, &mut self.ai_selected_model, placeholder, 300.0);
        });

        if !self.ai_selected_model.is_empty() && !self.ai_api_key.is_empty() {
            ui.add_space(6.0);
            ui.label(RichText::new(format!("Ready: {}", self.ai_selected_model))
                .color(Color32::from_rgb(100, 220, 100)));
        }
    }

    fn draw_oob(&mut self, ui: &mut Ui) {
        ui.heading("Out-of-Band Server");
        ui.separator();
        ui.add_space(6.0);

        ui.horizontal(|ui| {
            ui.label("Domain:");
            text_input(ui, &mut self.oob_domain, "", 260.0);
        });
        ui.horizontal(|ui| {
            ui.label("HTTP port:");
            ui.add(egui::DragValue::new(&mut self.oob_port).range(1024..=65535));
            ui.label("  DNS port: 8053 (fixed)");
        });

        ui.add_space(10.0);
        let color = if self.oob_running { Color32::GREEN } else { Color32::from_rgb(180, 60, 60) };
        ui.label(RichText::new(if self.oob_running { "● RUNNING" } else { "● STOPPED" }).color(color).strong());

        ui.add_space(8.0);
        if !self.oob_running {
            if ui.button("▶  Start OOB Server").clicked() {
                let config = sqx_core::oob::OobServerConfig {
                    http_port: self.oob_port,
                    dns_port: 8053,
                    domain: self.oob_domain.clone(),
                    public_host: "127.0.0.1".to_string(),
                    ttl_seconds: 3600,
                };
                let srv = Arc::new(sqx_core::oob::OobServer::new(config));
                let srv2 = srv.clone();
                let tx = self.tx.clone();
                tokio::spawn(async move {
                    match srv2.start().await {
                        Ok(()) => { let _ = tx.send(ScanMsg::Status("OOB server started.".to_string())); }
                        Err(e) => { let _ = tx.send(ScanMsg::Error(format!("OOB: {}", e))); }
                    }
                });
                self.oob_server = Some(srv);
                self.oob_running = true;
            }
        } else if ui.button("■  Stop OOB Server").clicked() {
            if let Some(srv) = &self.oob_server {
                let srv2 = srv.clone();
                tokio::spawn(async move { let _ = srv2.stop().await; });
            }
            self.oob_running = false;
            self.oob_server = None;
            self.status = "OOB server stopped.".to_string();
        }
    }

    fn draw_settings(&mut self, ui: &mut Ui) {
        ScrollArea::vertical().show(ui, |ui| {
            // ── Stealth / Evasion ─────────────────────────────────────────────
            ui.heading("Stealth & Evasion");
            ui.separator();
            ui.add_space(4.0);

            egui::Grid::new("stealth_grid")
                .num_columns(2)
                .spacing([16.0, 8.0])
                .show(ui, |ui| {
                    ui.label("UA rotation");
                    ui.horizontal(|ui| {
                        ui.checkbox(&mut self.stealth_ua_rotation, "");
                        ui.label(RichText::new("Rotate User-Agent randomly per request (12 real browser UAs)").color(Color32::GRAY).small());
                    });
                    ui.end_row();

                    ui.label("Browser headers");
                    ui.horizontal(|ui| {
                        ui.checkbox(&mut self.stealth_browser_headers, "");
                        ui.label(RichText::new("Add Accept, Sec-Fetch-*, DNT — identical to a real browser").color(Color32::GRAY).small());
                    });
                    ui.end_row();

                    ui.label("Referer spoofing");
                    ui.horizontal(|ui| {
                        ui.checkbox(&mut self.stealth_spoof_referer, "");
                        ui.label(RichText::new("Set Referer to target's own origin").color(Color32::GRAY).small());
                    });
                    ui.end_row();

                    ui.label("Delay jitter");
                    ui.horizontal(|ui| {
                        ui.add(egui::Slider::new(&mut self.stealth_jitter_pct, 0..=80).suffix("%"));
                        ui.label(RichText::new("Random ± variation on inter-request delay").color(Color32::GRAY).small());
                    });
                    ui.end_row();
                });

            ui.add_space(12.0);

            // ── Network ───────────────────────────────────────────────────────
            ui.heading("Network");
            ui.separator();
            ui.add_space(4.0);

            ui.horizontal(|ui| {
                ui.label("Proxy URL");
                text_input(ui, &mut self.proxy_url, "e.g. socks5://127.0.0.1:9050 or http://proxy:8080", 300.0);
                ui.label(RichText::new("HTTP or SOCKS5 proxy for all scan requests").color(Color32::GRAY).small());
            });

            ui.horizontal(|ui| {
                ui.checkbox(&mut self.cookie_auto_detect, "Auto-detect session cookies");
                ui.label(RichText::new("Watch for PHPSESSID, JSESSIONID, etc. on first request").color(Color32::GRAY).small());
            });
            ui.horizontal(|ui| {
                ui.label("Manual cookies");
                text_input(ui, &mut self.cookie_string, "PHPSESSID=abc123; user=admin", 300.0);
                ui.label(RichText::new("Raw cookie string sent with every request").color(Color32::GRAY).small());
            });

            ui.add_space(12.0);

            // ── Authentication ────────────────────────────────────────────────
            ui.heading("Authentication");
            ui.separator();
            ui.add_space(4.0);

            ui.horizontal(|ui| {
                ui.label("Login URL");
                text_input(ui, &mut self.login_url, "http://target.com/login", 300.0);
            });

            ui.horizontal(|ui| {
                let prev = self.auth_method_choice.clone();
                ui.label("Method:");
                egui::ComboBox::from_id_salt("auth_method_select")
                    .selected_text(if self.auth_method_choice.is_empty() { "— none —" } else { &self.auth_method_choice })
                    .width(120.0)
                    .show_ui(ui, |ui| {
                        ui.selectable_value(&mut self.auth_method_choice, String::new(), "— none —");
                        ui.selectable_value(&mut self.auth_method_choice, "form".to_string(), "form");
                        ui.selectable_value(&mut self.auth_method_choice, "json".to_string(), "json");
                        ui.selectable_value(&mut self.auth_method_choice, "basic".to_string(), "basic");
                        ui.selectable_value(&mut self.auth_method_choice, "bearer".to_string(), "bearer");
                    });
                if self.auth_method_choice != prev && self.auth_method_choice.is_empty() {
                    self.auth_creds.clear();
                    self.auth_user.clear();
                    self.auth_pass.clear();
                    self.auth_token.clear();
                }
            });

            match self.auth_method_choice.as_str() {
                "form" | "json" => {
                    ui.horizontal(|ui| {
                        ui.label("Creds");
                        text_input(ui, &mut self.auth_creds, "user=admin\npass=password", 300.0);
                        ui.label(RichText::new("One key=value per line").color(Color32::GRAY).small());
                    });
                }
                "basic" => {
                    ui.horizontal(|ui| {
                        ui.label("Username");
                        text_input(ui, &mut self.auth_user, "admin", 140.0);
                        ui.label("Password");
                        text_input(ui, &mut self.auth_pass, "password", 140.0);
                    });
                }
                "bearer" => {
                    ui.horizontal(|ui| {
                        ui.label("Token");
                        text_input(ui, &mut self.auth_token, "Bearer token", 300.0);
                    });
                }
                _ => {}
            }

            ui.horizontal(|ui| {
                ui.label("Success indicator");
                text_input(ui, &mut self.auth_success, "302 or PHPSESSID", 200.0);
                ui.label(RichText::new("Status code or cookie name").color(Color32::GRAY).small());
            });

            ui.add_space(12.0);

            // ── Payload Database ──────────────────────────────────────────────
            ui.heading("Payload Database");
            ui.separator();
            ui.add_space(4.0);

            ui.horizontal(|ui| {
                ui.label("Built-in boundaries:");
                ui.label(RichText::new(
                    format!("{} contexts", sqx_core::sqx::payload_fetcher::BOUNDARIES.len())
                ).color(Color32::from_rgb(100, 220, 100)));
            });
            ui.horizontal(|ui| {
                ui.label("Built-in error payloads:");
                ui.label(RichText::new(
                    format!("{} payloads (MIT)", sqx_core::sqx::payload_fetcher::BUNDLED_ERROR_PAYLOADS.len())
                ).color(Color32::from_rgb(100, 220, 100)));
            });
            ui.horizontal(|ui| {
                ui.label("External cache (sqlmap + PATT):");
                let cached = sqx_core::sqx::payload_fetcher::DynamicPayloads::is_cached();
                ui.label(RichText::new(if cached { "✓ Downloaded" } else { "✗ Not downloaded" })
                    .color(if cached { Color32::from_rgb(100, 220, 100) } else { Color32::YELLOW }));
            });

            ui.add_space(8.0);

            ui.horizontal(|ui| {
                let btn = ui.add_enabled(
                    !self.payloads_fetching,
                    egui::Button::new(if self.payloads_fetching { "Downloading..." } else { "⬇ Update Payloads" })
                );
                if btn.clicked() {
                    self.payloads_fetching = true;
                    self.payloads_status = "Downloading...".to_string();
                    let tx = self.tx.clone();
                    tokio::spawn(async move {
                        match sqx_core::sqx::payload_fetcher::DynamicPayloads::fetch_and_cache().await {
                            Ok(()) => { let _ = tx.send(ScanMsg::Status("Payload update complete.".to_string())); }
                            Err(e) => { let _ = tx.send(ScanMsg::Status(format!("Payload update failed: {}", e))); }
                        }
                    });
                }
                ui.label(RichText::new(&self.payloads_status).color(Color32::GRAY).small());
            });

            ui.add_space(4.0);
            egui::Frame::none()
                .fill(Color32::from_rgb(30, 25, 10))
                .inner_margin(8.0)
                .rounding(4.0)
                .show(ui, |ui| {
                    ui.label(RichText::new(
                        "sqlmap payloads are GPLv2 — fetched for your use only, never bundled.\n\
                         PayloadsAllTheThings is MIT — already bundled in the binary."
                    ).color(Color32::GRAY).small());
                });
        });
    }
}

fn draw_tampers(ui: &mut Ui) {
    ui.heading("Available Tamper Scripts");
    ui.separator();
    ScrollArea::vertical().show(ui, |ui| {
        for name in TamperChain::available_names() {
            ui.label(RichText::new(format!("  • {}", name)).monospace());
        }
    });
}

pub fn run() {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title("SQX — SQL Injection Scanner")
            .with_inner_size([960.0, 660.0])
            .with_min_inner_size([700.0, 460.0]),
        ..Default::default()
    };
    eframe::run_native(
        "SQX",
        options,
        Box::new(|_cc| Ok(Box::new(SqxApp::default()))),
    ).unwrap();
}
