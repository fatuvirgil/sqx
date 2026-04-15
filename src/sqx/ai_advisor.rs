//! AI Payload Advisor — generates context-aware SQL injection payloads
//! via local Ollama (default, no consent needed) or commercial APIs
//! (Claude, OpenAI-compat — requires explicit `--ai-consent` flag).
//!
//! Graceful degradation: any error silently falls back to static payloads.

use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use std::time::Duration;
use tracing::debug;

// ── Backend ───────────────────────────────────────────────────────────────────

/// Which LLM backend to use for payload suggestions.
#[derive(Debug, Clone)]
pub enum AiBackend {
    /// Local Ollama inference — default, no network, no consent needed.
    Ollama { base_url: String, model: String },
    /// Anthropic Claude API — commercial, requires consent + API key.
    Claude { api_key: String, model: String },
    /// OpenAI-compatible API (OpenAI, Mistral, LM Studio, etc.).
    OpenAiCompat { base_url: String, api_key: String, model: String },
}

impl Default for AiBackend {
    fn default() -> Self {
        AiBackend::Ollama {
            base_url: "http://localhost:11434".to_string(),
            model: "llama3.2".to_string(),
        }
    }
}

impl AiBackend {
    /// Parse a `provider:model` string into a backend variant.
    /// Commercial backends require a non-empty `api_key`.
    pub fn from_str(spec: &str, api_key: Option<&str>, base_url: Option<&str>) -> Result<Self> {
        let (provider, model) = spec
            .split_once(':')
            .unwrap_or(("ollama", spec));

        match provider.to_lowercase().as_str() {
            "ollama" => Ok(AiBackend::Ollama {
                base_url: base_url
                    .unwrap_or("http://localhost:11434")
                    .to_string(),
                model: model.to_string(),
            }),
            "claude" => {
                let key = api_key
                    .filter(|k| !k.is_empty())
                    .ok_or_else(|| anyhow!("Claude backend requires --ai-api-key"))?;
                Ok(AiBackend::Claude {
                    api_key: key.to_string(),
                    model: model.to_string(),
                })
            }
            "openai" | "openai-compat" => {
                let key = api_key.unwrap_or("").to_string();
                Ok(AiBackend::OpenAiCompat {
                    base_url: base_url
                        .unwrap_or("https://api.openai.com")
                        .trim_end_matches('/')
                        .to_string(),
                    api_key: key,
                    model: model.to_string(),
                })
            }
            other => Err(anyhow!("Unknown AI provider '{}'. Use ollama, claude, or openai.", other)),
        }
    }

    /// Returns true if this backend sends data to a third-party commercial service.
    pub fn is_commercial(&self) -> bool {
        matches!(self, AiBackend::Claude { .. } | AiBackend::OpenAiCompat { .. })
    }
}

// ── Config ────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct AiAdvisorConfig {
    pub enabled: bool,
    pub backend: AiBackend,
    /// Max payloads to request per technique per parameter.
    pub max_suggestions: usize,
    /// Timeout for the AI API call in seconds.
    pub timeout_secs: u64,
}

impl Default for AiAdvisorConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            backend: AiBackend::default(),
            max_suggestions: 10,
            timeout_secs: 30,
        }
    }
}

// ── Context & Suggestions ─────────────────────────────────────────────────────

/// Everything the advisor needs to generate targeted payloads.
#[derive(Debug, Clone)]
pub struct TargetContext {
    pub parameter: String,
    /// "numeric" | "string"
    pub param_type: String,
    pub dbms_hint: Option<String>,
    pub waf_name: Option<String>,
    /// First SQL error snippet observed (if any), truncated to 300 chars.
    pub error_snippet: Option<String>,
    pub reflects_errors: bool,
    pub reflects_input: bool,
    /// "error" | "boolean" | "union" | "time" | "stacked"
    pub technique: String,
}

/// A single AI-generated payload with reasoning.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AiSuggestedPayload {
    pub payload: String,
    pub reasoning: String,
    pub technique: String,
}

// ── Advisor ───────────────────────────────────────────────────────────────────

/// Query Ollama for installed models. Returns empty vec on error (Ollama not running).
pub async fn list_ollama_models(base_url: &str) -> Vec<String> {
    #[derive(Deserialize)]
    struct Tags { models: Vec<ModelEntry> }
    #[derive(Deserialize)]
    struct ModelEntry { name: String }

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(3))
        .build()
        .unwrap_or_default();

    match client.get(format!("{}/api/tags", base_url)).send().await {
        Ok(resp) if resp.status().is_success() => {
            resp.json::<Tags>().await
                .map(|t| t.models.into_iter().map(|m| m.name).collect())
                .unwrap_or_default()
        }
        _ => vec![],
    }
}

pub struct AiAdvisor {
    config: AiAdvisorConfig,
    client: reqwest::Client,
}

impl AiAdvisor {
    pub fn new(config: AiAdvisorConfig) -> Self {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(config.timeout_secs))
            .build()
            .expect("Failed to build AI advisor HTTP client");
        Self { config, client }
    }

    /// Generate payload suggestions. Returns empty vec on any error.
    pub async fn suggest(&self, ctx: &TargetContext) -> Vec<AiSuggestedPayload> {
        if !self.config.enabled {
            return vec![];
        }
        match self.call_backend(ctx).await {
            Ok(payloads) => {
                debug!(
                    "AI advisor returned {} payload(s) for param={} technique={}",
                    payloads.len(),
                    ctx.parameter,
                    ctx.technique,
                );
                payloads
            }
            Err(e) => {
                debug!("AI advisor error (falling back to static payloads): {}", e);
                vec![]
            }
        }
    }

    async fn call_backend(&self, ctx: &TargetContext) -> Result<Vec<AiSuggestedPayload>> {
        let prompt = build_prompt(ctx, self.config.max_suggestions);
        match &self.config.backend {
            AiBackend::Ollama { base_url, model } => {
                call_ollama(&self.client, base_url, model, &prompt).await
            }
            AiBackend::Claude { api_key, model } => {
                call_claude(&self.client, api_key, model, &prompt).await
            }
            AiBackend::OpenAiCompat { base_url, api_key, model } => {
                call_openai_compat(&self.client, base_url, api_key, model, &prompt).await
            }
        }
    }
}

// ── Prompt builder ────────────────────────────────────────────────────────────

fn build_prompt(ctx: &TargetContext, max: usize) -> String {
    let dbms = ctx.dbms_hint.as_deref().unwrap_or("unknown");
    let waf = ctx.waf_name.as_deref().unwrap_or("none");
    let error = ctx.error_snippet.as_deref().unwrap_or("none");

    format!(
        r#"You are a SQL injection security researcher generating test payloads for authorized penetration testing.

Target context:
- Parameter name: {param}
- Parameter type: {ptype}
- Detected DBMS: {dbms}
- WAF detected: {waf}
- SQL error snippet observed: {error}
- Target reflects SQL errors in response: {reflects_errors}
- Target reflects input value in response: {reflects_input}
- Technique: {technique}

Instructions:
1. Generate exactly {max} SQL injection payloads tailored to this specific context.
2. Use DBMS-specific functions and syntax for "{dbms}".
3. If WAF is detected (not "none"), apply evasion: case variation, inline comments (/*!*/), URL encoding, alternative whitespace, string splitting.
4. If an error snippet is provided, parse the SQL context from it and craft payloads that fit the surrounding query structure.
5. For "error" technique: use functions that cause verbose errors leaking data (EXTRACTVALUE, UPDATEXML, CAST errors, etc.).
6. For "boolean" technique: return pairs where first payload evaluates TRUE and second FALSE.
7. For "union" technique: probe column count and inject into visible columns.
8. For "time" technique: use SLEEP/pg_sleep/WAITFOR DELAY with 3-second delays.
9. For "stacked" technique: use semicolon-separated statements.

Respond ONLY with a valid JSON array. No markdown fences, no explanation outside JSON:
[
  {{"payload": "...", "reasoning": "one sentence why this fits the context", "technique": "{technique}"}},
  ...
]"#,
        param = ctx.parameter,
        ptype = ctx.param_type,
        dbms = dbms,
        waf = waf,
        error = error,
        reflects_errors = ctx.reflects_errors,
        reflects_input = ctx.reflects_input,
        technique = ctx.technique,
        max = max,
    )
}

// ── Backend callers ───────────────────────────────────────────────────────────

async fn call_ollama(
    client: &reqwest::Client,
    base_url: &str,
    model: &str,
    prompt: &str,
) -> Result<Vec<AiSuggestedPayload>> {
    #[derive(Serialize)]
    struct Req<'a> {
        model: &'a str,
        prompt: &'a str,
        stream: bool,
    }
    #[derive(Deserialize)]
    struct Resp {
        response: String,
    }

    let req = Req { model, prompt, stream: false };
    let resp = client
        .post(format!("{}/api/generate", base_url))
        .json(&req)
        .send()
        .await?;

    if !resp.status().is_success() {
        return Err(anyhow!("Ollama returned HTTP {}", resp.status()));
    }

    let body: Resp = resp.json().await?;
    parse_payload_json(&body.response)
}

async fn call_claude(
    client: &reqwest::Client,
    api_key: &str,
    model: &str,
    prompt: &str,
) -> Result<Vec<AiSuggestedPayload>> {
    #[derive(Serialize)]
    struct Req<'a> {
        model: &'a str,
        max_tokens: u32,
        messages: Vec<Msg<'a>>,
    }
    #[derive(Serialize)]
    struct Msg<'a> { role: &'a str, content: &'a str }
    #[derive(Deserialize)]
    struct Resp { content: Vec<Block> }
    #[derive(Deserialize)]
    struct Block { text: String }

    let req = Req {
        model,
        max_tokens: 2048,
        messages: vec![Msg { role: "user", content: prompt }],
    };
    let resp = client
        .post("https://api.anthropic.com/v1/messages")
        .header("x-api-key", api_key)
        .header("anthropic-version", "2023-06-01")
        .header("content-type", "application/json")
        .json(&req)
        .send()
        .await?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        return Err(anyhow!("Claude API error {}: {}", status, body));
    }

    let body: Resp = resp.json().await?;
    let text = body.content.first().map(|b| b.text.as_str()).unwrap_or("");
    parse_payload_json(text)
}

async fn call_openai_compat(
    client: &reqwest::Client,
    base_url: &str,
    api_key: &str,
    model: &str,
    prompt: &str,
) -> Result<Vec<AiSuggestedPayload>> {
    #[derive(Serialize)]
    struct Req<'a> {
        model: &'a str,
        messages: Vec<Msg<'a>>,
        response_format: Fmt,
    }
    #[derive(Serialize)]
    struct Msg<'a> { role: &'a str, content: &'a str }
    #[derive(Serialize)]
    struct Fmt { #[serde(rename = "type")] kind: &'static str }
    #[derive(Deserialize)]
    struct Resp { choices: Vec<Choice> }
    #[derive(Deserialize)]
    struct Choice { message: RespMsg }
    #[derive(Deserialize)]
    struct RespMsg { content: String }

    let req = Req {
        model,
        messages: vec![Msg { role: "user", content: prompt }],
        response_format: Fmt { kind: "json_object" },
    };
    let mut builder = client
        .post(format!("{}/v1/chat/completions", base_url))
        .json(&req);
    if !api_key.is_empty() {
        builder = builder.bearer_auth(api_key);
    }
    let resp = builder.send().await?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        return Err(anyhow!("OpenAI-compat API error {}: {}", status, body));
    }

    let body: Resp = resp.json().await?;
    let text = body.choices.first().map(|c| c.message.content.as_str()).unwrap_or("");
    parse_payload_json(text)
}

// ── JSON parser ───────────────────────────────────────────────────────────────

/// Extract a JSON array from model output that may contain surrounding text.
fn parse_payload_json(raw: &str) -> Result<Vec<AiSuggestedPayload>> {
    let trimmed = raw.trim();

    // Models sometimes wrap the array in {"payloads": [...]} — handle both
    if let Ok(arr) = serde_json::from_str::<Vec<AiSuggestedPayload>>(trimmed) {
        return Ok(arr);
    }

    // Try to find a bare JSON array by scanning for outermost [ ... ]
    let start = trimmed
        .find('[')
        .ok_or_else(|| anyhow!("No JSON array found in AI response"))?;
    let end = trimmed
        .rfind(']')
        .map(|i| i + 1)
        .ok_or_else(|| anyhow!("Unclosed JSON array in AI response"))?;
    let json_str = &trimmed[start..end];

    let payloads: Vec<AiSuggestedPayload> = serde_json::from_str(json_str)
        .map_err(|e| anyhow!("Failed to parse AI payload JSON: {}", e))?;

    // Sanity: drop entries with empty payloads
    Ok(payloads.into_iter().filter(|p| !p.payload.is_empty()).collect())
}
