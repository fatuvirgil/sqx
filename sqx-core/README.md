# SQX Core

> **The SQL injection detection engine powering SQX.**

SQX Core is the open-source detection and exploitation engine that powers both SQX CLI and SQX Pro. It provides comprehensive SQL injection detection capabilities with 69 tamper scripts, interactive shells, and AI-powered assistance.

## Features

### Detection Capabilities

- **All Major Techniques**: Error-based, Boolean blind, Time-based blind, UNION-based, Stacked queries
- **Header Injection**: X-Forwarded-For, User-Agent, Referer, Cookie testing
- **Automatic Calibration**: TRUE/FALSE baseline detection for blind techniques
- **Adaptive Timing**: Statistical baseline for time-based detection

### Evasion (69 Tamper Scripts)

More tamper scripts than sqlmap (~40):

| Category | Count | Examples |
|----------|-------|----------|
| Encoding | 10 | urlencode, base64, hex, unicode |
| Space Substitution | 12 | space2comment, space2tab, space2plus |
| Quote Bypass | 4 | apostrophe_mask, unmagic_quotes |
| Keyword Obfuscation | 8 | randomcase, versioned_keywords |
| MySQL Specific | 13 | version_comment, sleep2getlock |
| Operators | 6 | equal_to_like, greatest, least |
| ODBC/Multi | 2 | odbc_escape, plus2fnconcat |
| Miscellaneous | 13 | null_byte, sp_password, scientific_notation |

### Exploitation

- **SQL Shell**: Interactive REPL for executing SQL queries
- **OS Shell**: Interactive command execution via SQL injection
- **File Read**: Read arbitrary files through SQL injection
- **File Write**: Write files to the server
- **Data Extraction**: Schema enumeration and full database dumping

### AI Integration

- **Local**: Ollama integration (default, no network, no cost)
- **Cloud**: Claude, OpenAI support (requires user's API key)

### Output Formats

- **Text**: Human-readable console output
- **JSON**: Structured data for automation
- **SARIF**: GitHub Advanced Security compatible

## Usage

Add to your `Cargo.toml`:

```toml
[dependencies]
sqx-core = { path = "../sqx-core" }
```

Basic usage:

```rust
use sqx_core::sqx::{SqliDetector, SqliConfig};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let detector = SqliDetector::new()?;
    let results = detector.test_url("http://target.com/?id=1").await?;
    
    for finding in results {
        println!("Found SQLi: {:?}", finding);
    }
    
    Ok(())
}
```

### With Custom Configuration

```rust
use sqx_core::sqx::{SqliDetector, SqliConfig, SqliTechnique};

let config = SqliConfig {
    techniques: vec![
        SqliTechnique::ErrorBased,
        SqliTechnique::BooleanBlind,
    ],
    delay_ms: 200,
    proxy: Some("http://127.0.0.1:8080".to_string()),
    ..SqliConfig::default()
};

let detector = SqliDetector::with_config(config)?;
let results = detector.test_url("http://target.com/?id=1").await?;
```

### With Session Management

```rust
use sqx_core::sqx::session::{SessionConfig, SessionManager};
use std::sync::Arc;

let mut config = SessionConfig::default();
config.cookies.insert("PHPSESSID".to_string(), "abc123".to_string());

let session = Arc::new(SessionManager::new(config));
let detector = SqliDetector::new()?.with_session(session);
```

### With Tamper Chain

```rust
use sqx_core::sqx::TamperChain;

let tamper = TamperChain::from_names(&["space_to_comment", "randomcase"])?;
let results = detector.test_url_with_tamper("http://target.com/?id=1", &tamper).await?;
```

### Auto Scan with Crawler

```rust
use sqx_core::sqx::{
    auto_scan,
    crawler::CrawlerConfig,
    pipeline::PipelineConfig,
};

let crawler_config = CrawlerConfig {
    max_pages: 50,
    max_depth: 3,
    ..CrawlerConfig::default()
};

let pipeline_config = PipelineConfig {
    smart_scan: true,
};

let results = auto_scan(
    "http://target.com/",
    detector,
    Some(crawler_config),
    Some(pipeline_config),
).await?;
```

## Architecture

```
sqx-core/src/
├── sqx/
│   ├── detector.rs       # Main SqliDetector struct
│   ├── models.rs         # Config, results, techniques
│   ├── crawler/          # Regex-based spider
│   ├── evasion/          # 69 tamper scripts
│   ├── extraction/       # Data extraction (blind, union, time)
│   ├── fingerprint/      # WAF and DBMS fingerprinting
│   ├── payloads/         # Payload database management
│   ├── pipeline/         # Scan orchestration
│   ├── shell/            # SQL and OS shells
│   ├── takeover/         # File R/W, command execution
│   ├── techniques/       # Detection implementations
│   ├── ai_advisor.rs     # AI payload suggestions
│   └── ...
├── intel/                # Intelligence gathering (CVEs, etc.)
└── validator/            # Payload validation
```

## Key Modules

### `detector`

The main `SqliDetector` struct provides:
- `test_url()` - Scan a single URL
- `test_post()` - Scan POST endpoints
- `scan_smart()` - Behavioral fingerprinting first
- `with_session()` - Add authentication
- `with_cancel_token()` - Cancelable scans

### `crawler`

Regex-based web crawler:
- BFS spider with depth/page limits
- Form discovery
- Link extraction
- Injection point identification

### `evasion`

Tamper script system:
- Chain multiple tampers
- WAF-specific bypass chains
- Automatic best-tamper selection

### `extraction`

Data extraction methods:
- Boolean blind bisection
- Time-based extraction
- UNION-based fast extraction
- Schema enumeration

### `shell`

Interactive shells:
- `SqlShell` - Execute SQL queries
- `OsShell` - Execute OS commands

## Configuration

### `SqliConfig`

```rust
pub struct SqliConfig {
    pub timeout_secs: u64,           // Request timeout (default: 30)
    pub max_retries: u32,            // Retry attempts (default: 3)
    pub techniques: Vec<SqliTechnique>, // Detection techniques
    pub delay_ms: u64,               // Inter-request delay (default: 100)
    pub user_agent: String,          // HTTP User-Agent
    pub insecure_tls: bool,          // Accept invalid certificates
    pub sleep_duration_secs: u64,    // Time-based sleep (default: 3)
    pub ai_advisor: AiAdvisorConfig, // AI configuration
    pub stealth: StealthConfig,      // Evasion settings
    pub param_wordlist: Vec<String>, // For fuzzing URLs without params
    pub proxy: Option<String>,       // HTTP/SOCKS5 proxy
}
```

### `StealthConfig`

```rust
pub struct StealthConfig {
    pub ua_rotation: bool,           // Rotate User-Agents
    pub mimic_browser_headers: bool, // Add browser-like headers
    pub jitter_pct: u64,             // Request timing jitter %
    pub spoof_referer: bool,         // Spoof Referer header
}
```

## OOB Trait

SQX Core defines an `OobServer` trait for out-of-band detection:

```rust
pub trait OobServer: Send + Sync {
    fn generate_callback(&self, test_id: &str) -> String;
    fn check_callback(&self, test_id: &str, timeout_secs: u64) 
        -> Pin<Box<dyn Future<Output = bool> + Send>>;
}
```

This trait is implemented by SQX Pro's `OobServer` for DNS/HTTP callbacks.

## Core Limitations (by Design)

These features are intentionally in Pro only:

| Feature | Why | Workaround |
|---------|-----|------------|
| Batch >5 concurrent | Resource limiting | Run multiple batch commands |
| Markdown reports | Enterprise feature | Use JSON + external tool |
| Headless browser | Chrome dependency | Use Pro for SPA testing |
| OOB Server | Background services | Use Pro for blind OOB |
| Second-order SQLi | Complex tracking | Manual testing |

## Testing

```bash
# Run tests
cargo test -p sqx-core

# Run with logging
RUST_LOG=sqx=debug cargo test -p sqx-core -- --nocapture
```

## License

Dual-licensed under MIT and Apache-2.0.

## Contributing

See [CONTRIBUTING.md](../CONTRIBUTING.md).
