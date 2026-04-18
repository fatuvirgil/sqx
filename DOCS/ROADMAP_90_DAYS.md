# SQX 90-Day Roadmap

## Objective

In 90 days, SQX Core should become the best free SQL injection scanner available, while SQX Pro establishes the commercial feature set that justifies upgrading.

**Ediții:**
- **SQX Core**: Open source, CLI-only, toate tehnicile de detecție, suficient pentru 90% din scenarii
- **SQX Pro**: Commercial, GUI + advanced features pentru profesioniști și enterprise

Vezi [`SQX_CORE_VS_PRO.md`](SQX_CORE_VS_PRO.md) pentru separarea completă a features.

## Phase 1: Days 1-30

### Goal

Close the most damaging SQLi capability gaps and establish engineering discipline.

### Day 1 Progress (2026-04-17) — DBMS Exotic Testing Matrix

**Realizări principale:**
- ✅ Adăugat `error_based_payloads()` trait method în `DbmsDialect`
- ✅ Implementat payload-uri error-based pentru 13 DBMS-uri (6 major + 7 exotice)
- ✅ Adăugat containere Docker pentru **ClickHouse**, **CockroachDB**, **TiDB**
- ✅ Testat real **7 DBMS-uri** cu containere funcționale (100% success rate)
- ✅ Fixat DBMS detection order — pattern-uri specifice înaintea celor generice
- ✅ Documentat gap-uri reale în `tests/payload_audit.md`

### Day 2 Progress (2026-04-18) — Headless Browser Crawler

**Realizări principale:**
- ✅ Implementat `HeadlessCrawler` cu `chromiumoxide` 0.9.1
- ✅ DOM extraction via JavaScript (formulare, link-uri)
- ✅ JS analysis pentru API endpoints (`fetch`, `XHR`, `axios`, `WebSocket`)
- ✅ Framework detection (React, Vue, Angular, Svelte)
- ✅ CLI: `--headless`, `--chrome-path`, `--render-wait`
- ✅ GUI: checkbox + indicator Chrome disponibil + slider render wait
- ✅ Fallback automat la regex crawler când Chrome lipsește
- ✅ Integrare în `auto_scan` via `auto_scan_headless()`

**Arhitectură livrată:**
```
sqx-core/src/sqx/crawler/headless/
├── browser.rs, config.rs, crawler.rs
├── extractor.rs, intercept.rs, js_analyzer.rs
└── mod.rs (is_chrome_available(), find_chrome_binary())
```

**DBMS testate și funcționale:**
| DBMS | Port | Status |
|------|------|--------|
| MySQL 5.7 | 8057 | ✅ |
| MySQL 8.0 | 8080 | ✅ |
| MariaDB 10 | 8010 | ✅ |
| PostgreSQL 13 | 8113 | ✅ |
| **CockroachDB** | 26258 | ✅ **Nou** |
| **ClickHouse** | 8124 | ✅ **Nou** |
| **TiDB** | 4001 | ✅ **Nou** |

**Decizie strategică:**
> NU mai implementăm payload-uri pentru DBMS-uri pe care nu le putem testa în Docker. Codul netestat = cod potențial greșit.

### Day 2 Progress — Continued (2026-04-18)

**Realizări principale:**
- ✅ **Fix timeout/hang pe endpoint-uri safe** — Scanner-ul nu se mai blochează pe prepared statements
- ✅ **Fix false positive UNION-based** — Cerem coloane printabile pentru confirmare
- ✅ **Fix false positive error-based** — Pattern-uri mai specifice pentru SQLite și CockroachDB
- ✅ **False Positive Suite** — Testat 20+ endpoint-uri safe (PHP/Python/Node), 0 fals pozitive

**Metrics:**
- Timp scan per endpoint: ~12 secunde (de la >30 secunde)
- False positive rate: 0% (20+ endpoint-uri testate)

### Day 2 Remaining (Next Steps)

- testare headless crawler pe aplicații SPA reale (React, Vue, Angular)
- continuare testare DBMS exotice cu imagini disponibile (Firebird, H2)
- validare payload-uri error-based pe toate DBMS-urile testate
- unificare tamper selection logic cu runtime heuristics
- add request replay/request file workflows
- begin benchmark harness pentru comparisons vs `sqlmap`

### Immediate Next Steps

- test headless crawler on real SPA applications (React, Vue, Angular)
- continue modularization of large core files (start with similarity or payload_fetcher)
- unify tamper selection logic with runtime heuristics (expand beyond static list)
- add request replay/request file workflows
- begin benchmark harness for comparisons vs `sqlmap`

### Phase 1 Additions — Core vs Pro Split & UDF

| Item | Ediție | Prioritate | Detalii |
|------|--------|------------|---------|
| **Workspace refactor Core/Pro** | Both | High | Separare `sqx-core`, `sqx-cli` (Core), `sqx-gui`, `sqx-pro` (Pro). Feature flags pentru compilare condiționată. |
| **License system** | Pro | High | File-based license + online verification (opțional). Tier: Personal ($99), Team ($499), Enterprise ($1999). |
| **UDF injection automat** | Pro | Medium | Deploy automat librării UDF (lib_mysqludf_sys, pg_exec) via SQL injection. Detectare arhitectură, upload binar, CREATE FUNCTION. |
| **Metasploit integration** | Pro | Low | Export sesiuni SQX către Metasploit (XML/JSON format). Comandă `sqx export --msf`. |

**Core = Free / Open Source:**
- ✅ Toate tehnicile de detecție SQLi (error, blind, union, time, stacked, headers)
- ✅ **68 tampers complete** — mai multe decât sqlmap (~40)
- ✅ AI local (Ollama) pentru WAF fingerprinting
- ✅ **SQL Shell + OS Shell interactive** (REPL cu .tables, .schema, .dump)
- ✅ **Session management** (cookies, CSRF refresh, auth auto-login)
- ✅ **Proxy support** (HTTP + SOCKS5)
- ✅ **File read/write** via SQLi
- ✅ **Batch scanning** multi-target
- ✅ **Reporting** text + JSON + SARIF
- ✅ Data extraction completă (async Rust)
- ✅ Crawler regex-based

**Pro = Commercial:**
- 🚀 **GUI nativ** (egui/eframe)
- 🚀 **Headless browser crawling** (SPA support React/Vue/Angular)
- 🚀 **Cloud AI** (Claude/OpenAI) — payload generation contextuală
- 🚀 **OOB server** built-in (HTTP + DNS callbacks)
- 🚀 **Second-order SQLi** detection (stored injection)
- 🚀 **Markdown/HTML reporting** — client-ready reports
- 🚀 **WAF vendor-specific chains** — pre-configurat per vendor
- 🚀 **Team server** — shared sessions, multi-operator

### Deliverables

- stabilize current CLI and GUI flows
- improve second-order support beyond current narrow form-based logic
- add custom SQL execution workflow
- add stronger file read and file write workflows via SQLi
- add command execution primitives where DBMS capabilities permit
- expand tamper management and selection logic
- add request replay and request file workflows
- introduce comparative benchmark targets against `sqlmap`

### Engineering Work

- refactor detector APIs to support user-specified exploit workflows
- unify GET, POST, header, authenticated, and second-order execution paths
- remove hidden feature gaps between CLI and GUI
- add better artifact persistence for scans and exploitation results

### Testing

- create repeatable Docker lab matrix
- add regression suite for core SQLi techniques
- add authenticated scan coverage
- add CLI wiring tests for all user-facing exploit flags

### Exit Criteria

- SQX reliably detects and exploits core SQLi techniques across the in-repo test matrix
- SQX has no known CLI or GUI no-op flags for critical workflows
- comparative benchmarks exist and run locally

## Phase 2: Days 31-60

### Goal

Beat `sqlmap` on operator workflow and move beyond single-step exploitation.

### Deliverables

- artifact store for findings, payloads, derived links, files, and pivots
- chain engine foundation
- downstream sink discovery from SQLi results
- HTML and DOM diffing for generated links and rendered artifacts
- structured exploit reports with next-step recommendations
- better interactive CLI workflows for staged exploitation

### Engineering Work

- add `chains/`, `artifacts/`, and `rendering/` modules
- model exploit steps and derived artifacts
- build sink discovery over HTML outputs
- create reusable workflow APIs for follow-on exploitation

### Testing

- add labs that require multi-step stateful exploitation
- verify sink discovery on synthetic targets
- validate artifact serialization and replay

### Exit Criteria

- SQX can preserve state across multi-step workflows
- SQX can discover and report downstream sinks from SQLi-controlled outputs
- operator can resume a chain without reconstructing context manually

## Phase 3: Days 61-90

### Goal

Surpass `sqlmap` with exploit chain coverage.

### Deliverables

- result shaping and deferred result shaping techniques
- LFI engine foundation
- source disclosure and source analysis workflows
- hash and signature inference engine
- playbooks for SQLi -> sink -> LFI style chains

### Engineering Work

- add dedicated result shaping modules
- add LFI probing and wrapper support
- add PHP source pattern extraction and crypto inference
- wire playbooks into CLI and reports

### Testing

- add chain-oriented labs inspired by targets like Moebius
- verify end-to-end progression from SQLi to derived sink to file disclosure
- compare manual effort vs baseline workflow

### Exit Criteria

- SQX can automate part of at least one realistic chained exploit beyond raw SQLi
- SQX produces actionable artifacts and recommendations for unresolved steps
- SQX demonstrates a capability class that `sqlmap` does not cover well

## Weekly Cadence

Every week should produce:

- one capability milestone
- one regression expansion
- one comparative evaluation vs `sqlmap`
- one operator UX improvement

## Metrics

Track these continuously:

- successful SQLi detections across test matrix
- successful exploitation rate across test matrix
- median time from target to useful data extraction
- number of manual steps required after first finding
- number of exploit chains with preserved artifacts
- number of comparative wins vs `sqlmap`

## Risks

### Risk 1: Building too broad, too early

Mitigation:

- phase strictness
- parity first, then expansion

### Risk 2: CTF-specific overfitting

Mitigation:

- generalize every new capability into reusable abstractions

### Risk 3: Weak validation

Mitigation:

- mandate comparative tests and lab coverage before claiming success

## End-of-Roadmap Target

At day 90, SQX should be able to say:

- it competes seriously with `sqlmap` on core SQLi
- it is more pleasant to operate
- it has begun solving exploit chains that `sqlmap` does not handle cleanly
