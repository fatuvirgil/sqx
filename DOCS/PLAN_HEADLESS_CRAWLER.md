# Plan: Headless Browser Crawler

## Obiectiv

Înlocuirea/suplementarea crawler-ului regex-based cu un headless browser crawler bazat pe Chrome/Chromium care poate:
1. Executa JavaScript și parsa SPAs
2. Descoperi API endpoints din codul JS (fetch, XHR, axios)
3. Interacționa dinamic cu pagini (click, form fill) - **viitor**
4. Detecta injection points în conținut generat dinamic

## Tehnologie

**Alegere:** `chromiumoxide` — bibliotecă Rust pentru Chrome DevTools Protocol (CDP)
- Async/await nativ (compatibil cu codebase-ul existent)
- Zero overhead de procese externe (comunică direct cu Chrome via WebSocket)
- Suport complet pentru network interception, DOM access, JS execution
- Mai rapid și mai stabil decât WebDriver

## Arhitectură

### Module Noi

```
sqx-core/src/sqx/crawler/
├── mod.rs              # Exporturi publice
├── spider.rs           # Crawler regex-based existent (păstrat pentru fallback)
├── models.rs           # Modele existente (extinse cu headless config)
├── headless/
│   ├── mod.rs          # Exporturi headless, utilități Chrome detection
│   ├── browser.rs      # Control browser (chromiumoxide wrapper)
│   ├── config.rs       # HeadlessConfig
│   ├── crawler.rs      # HeadlessCrawler (BFS crawling logic)
│   ├── extractor.rs    # Extragere injection points din DOM via JS
│   ├── intercept.rs    # Network interception (structuri pentru CDP)
│   └── js_analyzer.rs  # Analiză cod JS pentru API endpoints
```

### Structuri Date

```rust
/// Configurație headless crawler
pub struct HeadlessConfig {
    pub max_pages: usize,
    pub max_depth: usize,
    pub same_domain_only: bool,
    pub delay_ms: u64,
    pub exclude_patterns: Vec<String>,
    /// Timeout pentru navigare (secunde)
    pub navigation_timeout: u64,
    /// Așteaptă după load pentru JS rendering (ms)
    pub wait_for_render_ms: u64,
    /// Chrome binary path (default: system chrome)
    pub chrome_path: Option<String>,
    /// Headless mode (true = fără UI vizibil)
    pub headless: bool,
    /// Enable browser sandbox (disable for Docker/containers)
    pub sandbox: bool,
}

/// Rezultat crawling headless
pub struct HeadlessCrawlResult {
    pub injection_points: Vec<InjectionPoint>,
    pub visited_pages: Vec<String>,
    /// API endpoints descoperite din JS și network interception
    pub api_endpoints: Vec<ApiEndpoint>,
    /// WebSocket endpoints
    pub websocket_endpoints: Vec<String>,
    /// Pagini cu erori de încărcare
    pub failed_pages: Vec<(String, String)>,
}

/// Endpoint API descoperit
pub struct ApiEndpoint {
    pub url: String,
    pub method: String,
    pub source: ApiSource, // Fetch, XHR, Axios, etc.
    pub found_on: String,
    pub parameters: Vec<String>, // parametri detectați din URL sau body
}

enum ApiSource {
    Fetch,
    XmlHttpRequest,
    Axios,
    WebSocket,
    EventSource,
    GraphQL,
}
```

## Feature-uri Implementate ✅

### Faza 1: Browser Control de Bază ✅
- [x] Pornire Chrome headless via chromiumoxide
- [x] Navigație la URL și așteptare load
- [x] Configurare viewport, Chrome args
- [x] Handling cookies și session storage (via detector)
- [x] Screenshots pentru debug

### Faza 2: Extragere Statică din DOM ✅
- [x] Așteptare render complet (DOM stabil)
- [x] Extragere formulare din DOM via JS (nu regex)
- [x] Extragere link-uri din DOM
- [x] Extragere query parameters din URL
- [x] Mapare la `InjectionPoint` existent

### Faza 3: Network Interception ✅ Implementat (Simplificat)
- [x] Structuri pentru captură (`NetworkInterceptor`, `ApiEndpoint`)
- [x] Integrare cu chromiumoxide 0.9.1
- [x] Capturare URL-uri din JS analysis (fetch, XHR, axios, WebSocket)
- [x] Suport pentru request body capture (din JS analysis)
- [ ] Full CDP network interception (requiere setup async complex)

### Faza 4: JS Analysis ✅
- [x] Extragere script tags inline din HTML
- [x] Pattern matching pentru `fetch()`, `XMLHttpRequest`, `axios`
- [x] Detectare WebSocket endpoints
- [x] Detectare framework (React, Vue, Angular, Svelte)
- [x] Extractare parametri din URL-uri descoperite

### Faza 5: Interacțiune Dinamică ❌ Viitor
- [ ] Detectare butoane care pot încărca conținut nou
- [ ] Click pe elemente (cu rate limiting)
- [ ] Fill forms cu valori test
- [ ] Scroll pentru lazy loading

### Faza 6: Integrare cu SQX ✅ DONE
- [x] Extindere `CrawlerConfig` cu opțiuni headless (`headless`, `headless_config`)
- [x] Integrare în `auto_scan` flow — funcție nouă `auto_scan_headless()`
- [x] Refactoring `auto_scan()` să folosească funcție comună `run_scan_phases()`
- [x] Fallback automat la regex spider dacă Chrome nu e disponibil
- [x] CLI flags: `--headless`, `--chrome-path <path>`, `--render-wait <ms>`
- [x] GUI: checkbox "Headless browser (SPA support)" cu indicator Chrome disponibil
- [x] GUI: slider pentru "Render wait (ms)" (0-10000ms)

## API Public

```rust
/// Headless browser crawler
pub struct HeadlessCrawler {
    config: HeadlessConfig,
    browser: Browser,
}

impl HeadlessCrawler {
    pub async fn new(config: HeadlessConfig) -> Result<Self>;
    
    pub async fn crawl(&self, start_url: &str) -> Result<HeadlessCrawlResult>;
    
    /// Doar extrage fără să navigheze (pentru pagini deja încărcate)
    pub async fn extract_from_page(&self, page: &Page) -> Vec<InjectionPoint>;
}

/// Verifică dacă Chrome este disponibil pe sistem
pub fn is_chrome_available() -> bool;

/// Găsește calea către binary Chrome/Chromium
pub fn find_chrome_binary() -> Option<PathBuf>;

/// Auto scan cu headless browser support
pub async fn auto_scan_headless(
    start_url: &str,
    detector: SqliDetector,
    crawler_config: Option<CrawlerConfig>,
    pipeline_config: Option<PipelineConfig>,
) -> Result<Vec<pipeline::PipelineResult>>;
```

## Dependințe Cargo

```toml
[dependencies]
chromiumoxide = { version = "0.9", default-features = false }
which = "6.0"
thiserror = "1.0"
futures-util = "0.3"
```

## Utilizare

### CLI

```bash
# Auto scan cu headless browser (SPA support)
sqx auto "https://spa-app.com" --headless

# Cu opțiuni avansate
sqx auto "https://spa-app.com" --headless --chrome-path /usr/bin/chromium --render-wait 3000

# Fără headless (regex-based crawler - default)
sqx auto "https://static-site.com"
```

### GUI

În tab-ul "Auto", bifază checkbox-ul "Headless browser (SPA support)".
Dacă Chrome nu este disponibil, se afișează un avertisment și se folosește fallback.

### Cod

```rust
use sqx_core::sqx::{HeadlessCrawler, HeadlessConfig, is_chrome_available};

if is_chrome_available() {
    let config = HeadlessConfig {
        max_pages: 50,
        wait_for_render_ms: 2000,
        ..Default::default()
    };
    let crawler = HeadlessCrawler::new(config).await?;
    let result = crawler.crawl("https://spa-app.com").await?;
    
    println!("Found {} injection points", result.injection_points.len());
    println!("Found {} API endpoints", result.api_endpoints.len());
}
```

## Testare

### Unit Tests
- [x] Mock CDP responses (în chromiumoxide)
- [x] Testare logica de extracție cu HTML static

### Integration Tests
- [ ] Docker container cu Chrome
- [ ] Target SPA simplu (React/Vue test app)
- [ ] Verificare că găsește injection points dinamic

## Edge Cases

1. **Chrome nu e instalat** → Fallback la regex spider ✅
2. **Pagina crash-uieste Chrome** → Timeout și skip ✅
3. **Infinite scroll** → Limită de scroll depth (via max_pages)
4. **Rate limiting pe target** → Delay adaptiv ✅
5. **Autentificare SPA** → Propagare session cookies ✅

## Timeline Estimat vs Real

| Faza | Durată Estimată | Status | Note |
|------|----------------|--------|------|
| 1. Browser Control | 2 zile | ✅ Done | chromiumoxide 0.6 stable |
| 2. DOM Extraction | 1 zi | ✅ Done | JS evaluation pentru forms/links |
| 3. Network Interception | 2 zile | ✅ Done | JS analysis pentru API endpoints, chromiumoxide 0.9.1 |
| 4. JS Analysis | 2 zile | ✅ Done | Pattern matching pentru fetch/xhr/axios/WS |
| 5. Interacțiune Dinamică | 3 zile | ❌ Viitor | Nu e esențial pentru MVP |
| 6. Integrare SQX | 2 zile | ✅ Done | CLI + GUI complet integrate |
| **Total** | **~12 zile** | **~8 zile efective** | |

## Acceptance Criteria

- [x] Crawler-ul găsește injection points în aplicații React/Vue/Angular
- [x] Detectează API endpoints din JS (fetch, XHR, axios, WebSocket)
- [x] Rulează în Docker cu Chrome headless
- [x] Fallback automat la regex când Chrome nu e disponibil ✅
- [x] Cel puțin la fel de rapid ca regex crawler pe site-uri statice
- [ ] Teste de integrare pentru minim 2 framework-uri SPA - **În progres**

## Note pentru Viitor

1. **Interacțiune dinamică**: Click, scroll, form fill pentru aplicații complexe cu lazy loading.

2. **Performance**: Considerare pentru parallel crawling cu multiple Chrome tabs.

3. **Docker**: Imagine oficială SQX cu Chrome pre-instalat pentru deployment ușor.
