# SQX Architecture

> **System design and component overview.**

## Overview

SQX is organized as a Rust workspace with three main crates:

```
workspace/
├── sqx-core/          # Open-source detection engine (library)
├── sqx-cli/           # Open-source CLI binary
└── sqx-pro/           # Commercial features (separate crate)
```

## Crate Relationships

```
                    ┌──────────────┐
                    │   sqx-cli    │
                    │  (binary)    │
                    └──────┬───────┘
                           │ uses
                           ▼
┌─────────────┐     ┌──────────────┐     ┌─────────────┐
│  sqx-pro    │────▶│   sqx-core   │◀────│  External   │
│  (binary +  │     │   (library)  │     │   Crates    │
│   library)  │     └──────────────┘     │  (tokio,    │
└─────────────┘                          │   reqwest,  │
                                         │   etc.)     │
                                         └─────────────┘
```

**Dependency Flow:**
- `sqx-cli` → depends on → `sqx-core`
- `sqx-pro` → depends on → `sqx-core`
- `sqx-core` → no internal dependencies (pure library)

## sqx-core Architecture

### Module Structure

```
sqx-core/src/
├── lib.rs              # Library entry point, re-exports
├── lib2.rs             # Extended exports
├── bench/              # Benchmarking utilities
│   └── mod.rs
├── intel/              # Intelligence gathering
│   ├── mod.rs
│   ├── collector.rs
│   └── sources/        # CVE, GitHub, NVD, etc.
├── validator/          # Payload validation
│   └── mod.rs
└── sqx/                # Main SQL injection engine
    ├── mod.rs          # Re-exports and auto-scan functions
    ├── detector.rs     # SqliDetector (main API)
    ├── models.rs       # Config, results, enums
    ├── basic_scan.rs   # Simple scan functions
    ├── smart_scan.rs   # Fingerprinting + intelligent scanning
    ├── param_scan.rs   # Parameter fuzzing
    ├── post_scan.rs    # POST request scanning
    ├── http.rs         # HTTP utilities
    ├── request.rs      # Request building
    ├── url_utils.rs    # URL manipulation
    ├── info.rs         # DBMS info extraction
    ├── findings.rs     # Finding processing
    ├── similarity.rs   # Response comparison
    ├── stealth.rs      # Stealth/anti-detection
    ├── ai_advisor.rs   # AI payload suggestions
    ├── ai_payloads.rs  # AI-generated payloads
    ├── dbms/           # Database-specific logic
    ├── crawler/        # Web crawling
    ├── evasion/        # Tamper scripts
    ├── extraction/     # Data extraction
    ├── fingerprint/    # WAF/DBMS fingerprinting
    ├── payloads/       # Payload database
    ├── pipeline/       # Scan orchestration
    ├── reporting/      # Output formats
    ├── session/        # Authentication management
    ├── shell/          # Interactive shells
    ├── takeover/       # Post-exploitation
    └── techniques/     # Detection techniques
```

### Key Components

#### 1. `detector.rs` — Main API

```rust
pub struct SqliDetector {
    pub(crate) client: Client,
    pub(crate) config: SqliConfig,
    pub(crate) oob_server: Option<Arc<dyn OobServer>>,  // Pro integration
    pub(crate) session: Option<Arc<SessionManager>>,
    pub(crate) adaptive_delay_ms: Arc<AtomicU64>,
    pub(crate) cancel_token: Option<CancellationToken>,
    pub(crate) request_count: Arc<AtomicUsize>,
    pub(crate) adaptive_sleep_secs: Arc<AtomicU64>,
}
```

**Key Methods:**
- `new()` — Create with defaults
- `with_config()` — Create with custom config
- `test_url()` — Scan GET URL
- `test_post()` — Scan POST endpoint
- `scan_smart()` — Behavioral fingerprinting first
- `with_session()` — Add authentication
- `with_oob_server()` — Add OOB server (Pro)
- `with_cancel_token()` — Enable cancellation

#### 2. `models.rs` — Core Types

```rust
// Configuration
pub struct SqliConfig {
    pub timeout_secs: u64,
    pub max_retries: u32,
    pub techniques: Vec<SqliTechnique>,
    pub delay_ms: u64,
    pub user_agent: String,
    pub insecure_tls: bool,
    pub sleep_duration_secs: u64,
    pub ai_advisor: AiAdvisorConfig,
    pub stealth: StealthConfig,
    pub param_wordlist: Vec<String>,
    pub proxy: Option<String>,
}

// Detection techniques
pub enum SqliTechnique {
    ErrorBased,
    BooleanBlind,
    TimeBased,
    UnionBased,
    StackedQueries,
    OutOfBand,      // Pro enhanced
    SecondOrder,    // Pro only
}

// Test result
pub struct SqliTestResult {
    pub parameter: String,
    pub technique: SqliTechnique,
    pub confidence: f32,
    pub payload: String,
    pub evidence: String,
    pub dbms_hint: Option<String>,
    pub injection_context: Option<String>,
    pub payload_id: Option<String>,
}
```

#### 3. `crawler/` — Web Crawling

**Core Crawler (Regex-based):**
```rust
pub struct Spider {
    config: CrawlerConfig,
    visited: HashSet<String>,
    queue: VecDeque<(String, usize)>,
    injection_points: Vec<InjectionPoint>,
}
```

**Pro Integration:**
- Core has `headless: bool` flag in config (ignored in Core)
- Pro implements actual headless crawling
- Core logs warning: "Headless is Pro feature, using regex crawler"

#### 4. `evasion/` — Tamper Scripts

```rust
pub trait Tamper: Send + Sync {
    fn name(&self) -> &'static str;
    fn apply(&self, payload: &str) -> String;
}

pub struct TamperChain {
    tampers: Vec<Box<dyn Tamper>>,
}
```

**69 Built-in Tampers:**
- `encoding.rs` — urlencode, base64, hex
- `spaces.rs` — space2comment, space2tab, etc.
- `quotes.rs` — apostrophe bypasses
- `keywords.rs` — randomcase, versioned
- `mysql.rs` — MySQL-specific
- `operators.rs` — operator substitution
- `odbc.rs` — ODBC escapes
- `misc.rs` — various bypasses

#### 5. `extraction/` — Data Extraction

```rust
// Boolean blind extraction
pub async fn extract_boolean_blind(...)

// Time-based extraction  
pub async fn extract_time_based(...)

// Union-based extraction
pub async fn extract_union_based(...)

// Schema enumeration
pub async fn enumerate_databases(...)
pub async fn enumerate_tables(...)
pub async fn enumerate_columns(...)
```

#### 6. `shell/` — Interactive Shells

```rust
pub struct SqlShell {
    detector: SqliDetector,
    url: String,
    param: String,
    dbms: String,
    config: ShellConfig,
}

pub struct OsShell {
    // Similar structure
}
```

**Features:**
- REPL interface
- Meta-commands (`.tables`, `.schema`, `.dump`)
- Command history
- Tab completion (future)

#### 7. `session/` — Authentication

```rust
pub struct SessionManager {
    config: SessionConfig,
    jar: CookieJar,
    csrf_token: Arc<RwLock<Option<CsrfToken>>>,
    last_csrf_refresh: Arc<RwLock<Instant>>,
}
```

**Supports:**
- Cookie jar with auto-refresh
- CSRF token handling
- Form-based authentication
- Basic auth
- Bearer tokens
- Auto-login flow

#### 8. `ai_advisor.rs` — AI Integration

```rust
pub enum AiBackend {
    Ollama { base_url: String, model: String },      // Local, free
    Claude { api_key: String, model: String },      // Cloud, user's key
    OpenAiCompat { base_url: String, api_key: String, model: String },
}

pub struct AiAdvisor {
    config: AiAdvisorConfig,
    client: Client,
}
```

**Note:** Cloud AI requires `--ai-consent` flag for data sharing acknowledgment.

## Pro Integration Design

### OOB Server Trait

Core defines the interface, Pro implements it:

```rust
// In sqx-core/src/sqx/detector.rs
pub trait OobServer: Send + Sync {
    fn generate_callback(&self, test_id: &str) -> String;
    fn check_callback<'a>(&'a self, test_id: &'a str, timeout_secs: u64)
        -> Pin<Box<dyn Future<Output = bool> + Send + 'a>>;
}

// SqliDetector accepts any OobServer implementation
impl SqliDetector {
    pub fn with_oob_server<T: OobServer + 'static>(mut self, server: Arc<T>) -> Self {
        self.oob_server = Some(server as Arc<dyn OobServer>);
        self
    }
}

// In sqx-pro/src/oob/server.rs
impl sqx_core::sqx::OobServer for OobServer {
    fn generate_callback(&self, test_id: &str) -> String {
        format!("{}.{}", test_id, self.config.domain)
    }
    
    fn check_callback<'a>(...)
        -> Pin<Box<dyn Future<Output = bool> + Send + 'a>> {
        // Implementation with DNS/HTTP servers
    }
}
```

### Headless Crawler

```rust
// In sqx-core: Flag exists but warns if used
if crawler_config.headless {
    warn!("Headless is Pro feature, using regex crawler");
}

// In sqx-pro: Actual implementation
pub async fn auto_scan_headless(...) {
    // Chrome CDP integration
}
```

## Data Flow

### Simple Scan Flow

```
User Input
    │
    ▼
sqx-cli::cli::Cli::run()
    │
    ▼
commands::scanning::run_scan()
    │
    ▼
sqx-core::sqx::detector::SqliDetector::test_url()
    │
    ▼
for each technique:
    detector::test_technique()
        │
        ├──► techniques::error_based::test()
        ├──► techniques::boolean_blind::test()
        ├──► techniques::time_based::test()
        ├──► techniques::union_based::test()
        └──► techniques::stacked::test()
    │
    ▼
Collect results → Return to CLI → Print/Output
```

### Auto Scan Flow

```
sqx auto http://target.com/
    │
    ▼
auto_scan()
    │
    ├──► Crawler::crawl() → Find injection points
    │
    ├──► Fingerprint::probe() → Detect WAF, DBMS
    │
    ├──► Pipeline::run() → Scan each injection point
    │       │
    │       └──► Detector::test_url() / test_post()
    │
    └──► Return aggregated results
```

## Thread Safety

All major components are thread-safe (`Send + Sync`):

```rust
// Arc for shared ownership
pub(crate) oob_server: Option<Arc<dyn OobServer>>,
pub(crate) session: Option<Arc<SessionManager>>,

// Atomic types for counters
pub(crate) adaptive_delay_ms: Arc<AtomicU64>,
pub(crate) request_count: Arc<AtomicUsize>,

// RwLock for mutable shared state
// (inside SessionManager, etc.)
```

## Concurrency Model

- **Tokio**: Async runtime with work-stealing scheduler
- **Semaphore**: Limits concurrent requests (rate limiting)
- **JoinSet**: Manages multiple concurrent scan tasks
- **CancellationToken**: Cooperative cancellation support

```rust
// Batch scanning with concurrency limit
let sem = Arc::new(Semaphore::new(concurrency));
let mut join_set = JoinSet::new();

for url in urls {
    let permit = sem.clone().acquire_owned().await?;
    join_set.spawn(async move {
        let _permit = permit; // Released when dropped
        scan_target(url).await
    });
}

while let Some(result) = join_set.join_next().await {
    // Process result
}
```

## Configuration Hierarchy

```
1. Hardcoded defaults (in Default impls)
        │
        ▼ (override)
2. Config files (future: ~/.config/sqx/config.toml)
        │
        ▼ (override)
3. Environment variables
        │
        ▼ (override)
4. CLI arguments (highest priority)
```

## Error Handling

Uses `anyhow` for ergonomic error handling:

```rust
use anyhow::{Result, Context};

pub async fn test_url(&self, url: &str) -> Result<Vec<SqliTestResult>> {
    let parsed = Url::parse(url)
        .with_context(|| format!("Invalid URL: {}", url))?;
    
    // ...
    
    Ok(results)
}
```

## Logging

Uses `tracing` for structured logging:

```rust
tracing::info!("Starting scan of {}", url);
tracing::debug!("Testing parameter: {}", param);
tracing::warn!("Rate limit detected, increasing delay");
tracing::error!("Request failed: {}", e);
```

Levels:
- `ERROR` — Failures that stop scanning
- `WARN` — Issues that continue (rate limits, etc.)
- `INFO` — High-level progress
- `DEBUG` — Detailed operation info
- `TRACE` — Request/response details

## Testing Strategy

- **Unit tests**: Individual functions in each module
- **Integration tests**: Full scan workflows
- **Benchmark tests**: `sqx bench` command
- **Test fixtures**: `tests/` directory with test targets

## Security Considerations

1. **No default credentials**: All auth requires explicit user input
2. **Consent flags**: Cloud AI requires `--ai-consent`
3. **Timeout limits**: All requests have timeouts
4. **Rate limiting**: Adaptive delay increases on 429 responses
5. **Cookie security**: Session cookies not logged

## Future Architecture

### Planned Additions

1. **Plugin system**: WASM-based tamper plugins
2. **Distributed scanning**: Multi-node coordination
3. **ML models**: On-device WAF detection
4. **Web API**: REST API wrapper

### Extension Points

```rust
// Custom tamper
impl Tamper for MyCustomTamper { ... }

// Custom detection technique
impl Technique for MyTechnique { ... }

// Custom output format
impl Report for MyReport { ... }
```

---

**Document Version:** 1.0  
**Last Updated:** 2024-04-18  
**Status:** Current
