# SQX — Project Status

**Data:** 2026-04-15  
**Codebase:** ~14,500 linii Rust  
**Binary:** `target/release/sqx` (~9MB, self-contained executable — ships as a single file)  
**Build:** ✅ `Finished release` — zero erori

---

## Ce avem

### Engine de detecție SQL injection

| Tehnică | Status | Note |
|---|---|---|
| Error-based | ✅ Funcțional | MySQL, PostgreSQL, MSSQL, Oracle, SQLite |
| Boolean-based blind | ✅ Funcțional | Calibrare diferențială TRUE/FALSE, 23 boundary contexts, dual-context (numeric + single-quote) |
| Time-based blind | ✅ Funcțional | Statistical baseline (mean + 2σ), toate dialectele DBMS, prefix-aware payloads |
| UNION-based | ✅ Funcțional | ORDER BY + UNION SELECT NULL, status-code oracle pentru coloane printabile |
| Stacked queries | ✅ Funcțional | Semicolon injection |
| Header injection | ✅ Funcțional | X-Forwarded-For, User-Agent, Referer, Cookie, X-Real-IP (GET+POST) |
| Out-of-band (OOB) | ✅ Funcțional | Server HTTP+DNS built-in, callback detection |
| Code injection | ✅ Funcțional | PHP eval, create_function |

### Motor de decizie autonom

- **SqlErrorClassifier** — ierarhie 3 niveluri: RegexSet DFA → n-gram Jaccard fuzzy → `detect_sql_error` fallback
- **MinHash baseline** — 4-shingles, 64 hash-uri FNV-1a; stabil față de CSRF tokens, timestamps, ID-uri dinamice
- **WAF detection 5 straturi** — semnături explicite, soft-block, MinHash deviance, length-ratio, timing anomaly
- **Success-over-WAF priority** — reflecția markerului IQX în body overridează toate heuristicile de blocare
- **is_valid_baseline** — verifică că request-ul curat nu e deja blocat înainte de scan
- **tokenize_html** — capturează diferențe din atribute HTML (`src="flag.jpg"` vs `src="slap.jpg"`); prag relativ gap > 0.02

### Scanner

- **GET scan** — parametri query string, fuzzing common params pe URL-uri fără params
- **POST scan** — form-encoded, JSON, XML body; Phase 2 boolean-blind + Phase 3 UNION
- **Auto scan** — spider BFS → Phase 2 (injection points) → Phase 3 (param fuzzing pe pagini fără params)
- **Smart scan** — fingerprint DBMS+WAF înainte de injecție, adaptează strategia
- **Batch scan** — multiple URL-uri concurent
- **Header injection** — testat automat după fiecare scan GET/POST

### Crawler / Spider

- BFS cu `max_pages` și `max_depth` configurabile
- Parsare `<a href>`, `<area href>`, `<form>`, `<input>`, `<select>`, `<textarea>`
- Deduplicare injection points
- Fragment URL stripping (`#anchor` eliminat din form action)
- Excludere automată fișiere statice (CSS/JS/img cu sau fără query string — regex `\.css(\?[^#]*)?$`)
- Warning explicit dacă start URL e unreachable
- Returnează `CrawlResult { injection_points, visited_pages }` pentru Phase 3

### Extracție date (dump)

- `sqx dump` — schema enumeration + full data extraction
- Boolean-blind bisection O(log n) per caracter
- Time-based blind extraction pentru toate dialectele
- Oracle diferențial pentru MySQL numeric-in-quotes (Less-8 style)
- Single-quote context fallback când numeric calibration eșuează
- Upper bound realist: 500 tabele, 1000 rânduri (nu 9999)
- `discover_boundary_blind` și `discover_boundary_time_based` pentru context automat

### Stealth / Evasion

- **UA rotation** — pool de 12 browsere reale (Chrome/Firefox/Edge/Safari, Win/Mac/Linux/Android)
- **Browser headers** — Accept, Accept-Language, Accept-Encoding, Connection, Upgrade-Insecure-Requests
- **Referer spoofing** — origin-ul target-ului
- **Delay jitter** — ±30% variație aleatorie (configurabil 0-80%)
- **Adaptive delay** — `Arc<AtomicU64>` crește automat la 429 Too Many Requests
- Toate active by default, configurabile din GUI → Settings

### Tamper / Evasion payloads

- 68 tamper scripts: `randomcase`, `space_to_comment`, `inline_comment`, `urlencode`, `space_to_tab`, `mysql_version_comment`, `double_urlencode`, `hex_encode`, `space_to_newline`, `unicode_escape`, `null_byte`, `charencode`, `apostrophemask`, `overlongutf8`, `modsecurityzeroversioned`, `sleep2getlock` și altele
- Auto-escalation WAF bypass (pornește light, escaladează la heavy dacă e blocat)
- Per-target tamper chain din fingerprint

### Fingerprint

- DBMS detection din error messages, comportament SLEEP, banner
- WAF detection (block status, pattern matching)
- Parameter profiling (numeric/string, reflection, error reflection)
- Scan strategy adaptivă bazată pe profil

### Payload database

- **Built-in boundaries**: 23 contexte de injecție (independent written)
- **Built-in PATT payloads**: ~50 payloads curate (MIT license, bundled)
- **Integrare sqlmap (GPLv2)**: Mecanism de integrare `boundaries.xml` + `payloads.xml` complet implementat (clause/where/vector parsing, placeholder resolution). Coverage efectiv ~5% din sqlmap — vezi [`tests/payload_audit.md`](tests/payload_audit.md) pentru harta detaliată a gap-urilor.
- **Fetch la runtime**: `sqx update-payloads` descarcă bazele externe (GPLv2, user fetch).
- **Param wordlist extinsă**: ~100 params default (SecLists style), suport `--param-wordlist <file>`
- Cache în `~/.local/share/sqx/payloads/`

### Session management

- Cookie jar, CSRF token auto-refresh
- Auth config (login URL, credentials)
- Session persistă între requests în același scan
- **Session cookie auto-detect**: `SessionManager::detect_session_cookies()`
- **Login end-to-end**: `--login-url`, `--auth-method <form|json|basic|bearer>`, `--auth-cred key=val`
- Login per-task în batch scan; eșec → warning, nu abort

### Proxy / Network

- SOCKS5 + HTTP proxy via `reqwest::Proxy::all()`
- CLI: `--proxy <url>` global
- GUI: câmp în Settings tab

### AI Advisor

- Ollama (local, default) — fără consent necesar
- Claude API, OpenAI-compatible
- Generare payloads contextuale (DBMS, WAF, technique)
- Timeout explicit pe întreg call-ul AI (nu doar HTTP)
- Sanitizare prompt injection (truncate, strip control chars, escape `{{}}`)
- Fallback la static payloads cu `warn!` dacă AI eșuează
- Parse JSON robust (bracket-depth tracking, nu `rfind(']')`)

### GUI (egui/eframe)

- Tab-uri: Scan, Auto, Results, Tampers, OOB, AI, Settings
- Zoom butons ➕/➖ (70%-300%, default 140%)
- Right-click context menu pe toate câmpurile (Copy/Paste/Clear)
- Settings tab: toggleuri stealth, slider jitter, payload updater cu status, proxy, auth
- Spinner + status bar în timp real
- Cancel scan via `CancellationToken`
- **Persistent config**: `GuiSettings` serializabil în `~/.config/sqx/settings.json`

### CLI

- `sqx scan` — GET scan direct
- `sqx post` — POST scan
- `sqx auto` — spider + full scan
- `sqx dump` — data extraction
- `sqx batch` — multiple targets
- `sqx update-payloads` — fetch payload database
- `sqx tampers` — listare tamper scripts
- `sqx oob` — start OOB server
- `sqx gui` — lansare GUI
- Output: text, JSON, Markdown, SARIF

---

## Ce am corectat și de ce

### BUG-1 — POST scan detecta 0 vulnerabilități
**Cauza:** `test_url_post` rula doar error-based + time superficial. Nu testa boolean blind cu TRUE/FALSE pair și nu testa UNION deloc.  
**Fix:** Adăugat Phase 2 (boolean blind TRUE/FALSE per context) și Phase 3 (UNION via ORDER BY + UNION SELECT NULL) în `test_url_post`.

### BUG-2 — UNION detection: "No printable columns detected" pe login forms
**Cauza:** Detecția coloanelor "printabile" căuta conținut reflectat în body. Login forms răspund cu 302 redirect la login reușit — nu reflectă date.  
**Fix:** `detect_printable_columns_with_bypass` — dacă `response.status != baseline.status` și status < 500, coloana e marcată printabilă. O schimbare de status (200→302) e semnal suficient.

### BUG-3 — `sqx dump` raporta "Found 9999 tables"
**Cauza:** `test_condition_blind` folosea body similarity ca singurul oracle (threshold > 0.9). Pe login forms toate răspunsurile arată similar → orice condiție părea TRUE → binary search converge la upper bound (9999).  
**Fix (2 părți):** (1) `test_condition_blind` folosește status code ca semnal primar. (2) Upper bound redus de la 9999 la 500 (tabele) și 1000 (rânduri).

### BUG-4 — Character extraction eșua cu comparație directă `=`
**Cauza:** Același oracle defect ca BUG-3 — similarity-only nu detecta diferența TRUE/FALSE pe login forms.  
**Fix:** Același fix din BUG-3.

### BUG-5 — Boolean blind detection eșua pe pagini cu diferență vizuală mică (~3%)
**Cauza:** `calculate_similarity` stripa tag-urile HTML înainte de tokenizare, eliminând valorile atributelor. Singurul token diferit (`flag.jpg` vs `slap.jpg`) era în `src=""` — după stripuire, ambele pagini aveau token sets identice. Pragul de detecție era absolut (`false_similarity < 0.7`).  
**Fix:** (1) Tokenizare pe delimitatori HTML (`<>"'=/`) în loc de strip — valorile atributelor devin tokeni separați. (2) Prag relativ: `gap = true_sim - false_sim > 0.02`.

### BUG-6 — GET blind detection eșua pentru valori numerice în câmpuri cu quotes
**Cauza:** `test_boolean_blind` determina contextul din tipul valorii: `id=1` → numeric → testa `1 AND 1=1`. Dar serverul executa `WHERE id='1 AND 1=1'` — injecția era în string.  
**Fix:** `test_boolean_blind` încearcă acum ambele contexte pentru valori numerice: mai întâi numeric, apoi single-quote.

### BUG-7 — Time-based detection eșua pentru valori numerice în câmpuri cu quotes
**Cauza:** `time_based_payload()` returna sufixul fără prefixul original. `build_test_url` înlocuia ÎNTREAGA valoare. Rezultat: `?id=' AND SLEEP(5)` → `WHERE id='' AND SLEEP(5)` → `id=''` FALSE → SLEEP nu rulat.  
**Fix:** `test_time_based` construiește candidați cu prefixul original: `1' AND SLEEP(5)-- ` (string ctx), `1 AND SLEEP(5)-- ` (numeric), `1 OR SLEEP(5)-- ` (OR fallback).

### BUG-8 — Oracle blind defect pe MySQL numeric-in-quotes (Less-8, dump)
**Cauza:** `test_condition_blind` — calibrarea diferențială folosea context numeric (`1 AND 1=1` / `1 AND 1=2`) pentru valori numerice. Pe `WHERE id='$id'`, payloads numerice nu se injectează → gap calibrare ≈ 0 → toate condițiile par TRUE → binary search converge la cap (500 tabele).  
**Fix:** Când calibrarea numerică arată gap ≤ 0.02, se încearcă single-quote context: `1' AND '1'='1` vs `1' AND '1'='2`. Dacă gap > 0.02, se re-fetch-uiește condiția cu payload single-quote și se clasifică prin proximitate.

### BUG-9 — Auto scan găsea 0 injection points pe sqli-labs
**Cauza (3 probleme):**  
(1) Spider-ul vizita `/Less-1/` etc. dar paginile fără query params nu produceau injection points.  
(2) `auto_scan` nu scana paginile vizitate fără params.  
(3) CSS/JS cu `?v=1` scăpau de exclude filter (`\.css$` nu matchuia `style.css?v=1`).  
**Fix:** (1+2) `crawl()` returnează `CrawlResult { injection_points, visited_pages }`. `auto_scan` Phase 3: iterează `visited_pages` fără injection points și rulează `test_url` cu param fuzzing (error-based + boolean-blind only, fără UNION/time — prea lent pentru discovery). (3) Regex exclude actualizat: `\.css(\?[^#]*)?$`.

### BUG-10 — Scanner blocat cu 403 de nginx (User-Agent filtrat)
**Cauza:** User-Agent default `"Intelexia/1.0"` era blocat instant de nginx cu 403.  
**Fix:** UA default schimbat la Chrome 124 real. Plus: stealth module cu UA rotation pool de 12 browsere reale.

### BUG-11 — Form action cu fragment URL (`/contact/#trimite-mesaj`) genera POST invalid
**Cauza:** Spider-ul crea injection point cu URL `https://target.ro/contact/#trimite-mesaj`. POST la un fragment eșuează — fragmentul nu e trimis la server.  
**Fix:** `action_no_frag = action.split('#').next()` — fragmentul e strippuit din form action.

### BUG-12 — `parse_payload_json` tăia greșit JSON cu `]` în payload strings
**Cauza:** `rfind(']')` găsea ultimul `]` din string, nu cel care închide array-ul — payloads SQL cu `SUBSTRING(x,1,1)]` rupeau parsing-ul.  
**Fix:** Bracket-depth tracking cu string state awareness — walk forward de la `[`, numărăm adâncimea, ignorăm `]` din interiorul string-urilor JSON.

### BUG-13 — Cancellation token lipsea complet în scanner
**Cauza:** `test_url`, `test_url_post`, `scan_smart` nu aveau niciun mecanism de oprire. GUI "Stop" nu funcționa.  
**Fix:** `SqliDetector` are acum `cancel_token: Option<CancellationToken>` + `with_cancel_token()` + `is_scan_cancelled()`. Verificat la fiecare iterație de param în toate cele 3 funcții principale.

### BUG-14 — AI call putea bloca scan-ul indefinit
**Cauza:** `advisor.suggest()` nu avea `tokio::time::timeout` explicit — doar HTTP client timeout (30s) care nu acoperea generarea lentă Ollama.  
**Fix:** `tokio::time::timeout(deadline, self.call_backend(ctx))` wrappat în jurul întregului call AI. Fallback cu `warn!` la timeout.

### BUG-15 — Build errors după refactoring motor de decizie (2026-04-15)
**Cauza (3 probleme):**  
(1) `BlindExtractionProgress` folosit în `dump.rs` dar absent din import.  
(2) `discover_boundary_blind` definit `async fn` (private) în `blind.rs`, apelat din `dump.rs`.  
(3) `injection_context: None` duplicat în două struct literals din `header_injection.rs`.  
**Fix:** (1) Adăugat `BlindExtractionProgress` la import. (2) `pub(crate) async fn discover_boundary_blind`. (3) Eliminat câmpul duplicat din ambele struct literals.

---

## Strategie: Cum depășim sqlmap

### Ce facem deja mai bine

| Avantaj | De ce contează |
|---------|----------------|
| **Single binary, zero deps** | ~9MB, rulează oriunde fără Python/stack. Incomparabil mai bun pentru CI/CD, containere, distribuție rapidă. |
| **GUI nativ cross-platform** | sqlmap nu are GUI built-in. SQX oferă experiență vizuală completă cu zoom, tab-uri, status live, export direct. |
| **AI Payload Advisor** | sqlmap nu are nicio integrare LLM. SQX generează payloads adaptate la DBMS+WAF+error snippet în timp real. |
| **OOB Server built-in (HTTP + DNS)** | La sqlmap, OOB necesită setup manual extern. La SQX e un checkbox în GUI. |
| **Stealth modern out-of-the-box** | UA rotation, browser headers, referer spoofing, jitter, adaptive delay — toate active by default. |
| **Reporting enterprise-ready** | SARIF, JSON structurat cu `reproduction.curl`, Markdown — gata pentru GitHub Advanced Security, Defect Dojo, bug bounty. |
| **Arhitectură async Rust** | Batch scan concurent mult mai stabil și rapid decât threading Python. Memory safety, zero GC pauses. |
| **Session management formalizat** | Cookie jar auto-updating, CSRF auto-refresh, import din `curl`, auth form/json/basic/bearer. |
| **Motor de decizie semantic** | SqlErrorClassifier cu RegexSet + Fuzzy fallback + MinHash baseline — nu simplă căutare de cuvinte cheie. |
| **WAF detection 5 straturi** | Depășește simpla verificare de cod HTTP: soft-block, structural anomaly, timing anomaly. |
| **Proxy SOCKS5 + HTTP** | Suport nativ, configurat din CLI și GUI. |

### Ce facem mai prost (gaps rămase)

| Gap | Impact |
|-----|--------|
| **Coverage payload database ~5% din sqlmap** | sqlmap are mii de payload-uri testate în sute de edge-case-uri. Vezi [`tests/payload_audit.md`](tests/payload_audit.md). |
| **Post-exploitation avansată** | Sqlmap oferă `--os-shell`, `--sql-shell`, `--file-read/write`, UDF injection, Metasploit integration. SQX are doar payload database. |
| **Crawler rudimentar** | Regex-based HTML parsing. Nu urmărește JS, SPA routing, AJAX, API endpoints din JavaScript. |
| **Databases exotice — structuri goale** | FrontBase, MonetDb, Virtuoso, mSQL au doar skeletons fără `sleep_function` sau extragere reală. |
| **Brute-force fără information_schema** | Sqlmap brute-forcează numele de coloane cu wordlist. SQX nu are acest fallback. |
| **WAF bypass dedicat per vendor** | Logici specifice pentru Cloudflare, ModSecurity, Imperva lipsesc — doar tamper escalation generic. |
| **SARIF output complet** | Schema parțial implementată; trebuie extinsă cu rules complete și relationships. |

---

## Ce am implementat recent

### ✅ Motor de decizie autonom (2026-04-15)

| Componentă | Status | Note implementare |
|---|---|---|
| **SqlErrorClassifier (RegexSet DFA + Fuzzy fallback)** | ✅ Done | `similarity.rs`: `RegexSet` pentru clasificare instantanee în `ArityMismatch`/`TypeMismatch`/`SyntaxError`. Tier 2: n-gram Jaccard (n=4) contra canonicale cu prag 0.75 — reziliență la erori trunchiate de WAF. |
| **MinHash baseline engine (4-shingles, 64 hash-uri FNV-1a)** | ✅ Done | `compute_minhash` + `minhash_jaccard` în `similarity.rs`. Stabil față de noise dinamic (CSRF tokens, timestamps). Folosit în `classify_response_with_baseline`. |
| **WAF detection 5 straturi** | ✅ Done | `classify_response_with_baseline`: (1) semnături explicite 403/429+string, (2) soft-block 200 OK cu body scurt, (3) MinHash deviance < 0.5, (4) length-ratio anomaly, (5) timing: reject <50ms sau tarpit >10s×baseline. |
| **Success-over-WAF priority** | ✅ Done | Dacă `injected_marker` (IQX) e găsit în body, toate anomaliile WAF/MinHash sunt ignorate — reflecția fizică e dovada supremă. |
| **is_valid_baseline** | ✅ Done | Verifică că request-ul curat nu e deja blocat de WAF înainte de a porni scanul. |
| **tokenize_html pentru calculate_similarity** | ✅ Done | Split pe delimitatori HTML (`<>"'=/`) în loc de strip tags — valorile atributelor (`src="flag.jpg"`) devin tokeni separați, gap relativ `true_sim - false_sim > 0.02`. |

### ✅ Low-hanging fruit (completat)

| Item | Status | Note implementare |
|---|---|---|
| **Request counting corect** | ✅ Done | `Arc<AtomicUsize>` în `SqliDetector`, incrementat în `send_request` / `send_post_request`. `Pipeline::run()` raportează acum request count real. |
| **Persistent config GUI** | ✅ Done | `GuiSettings` serializabil în `~/.config/sqx/settings.json`. Restaurare la startup și salvare automată via `eframe::App::save`. |
| **Proxy support (SOCKS5 + HTTP)** | ✅ Done | `SqliConfig.proxy` + `build_client()` cu `reqwest::Proxy::all()`. CLI: `--proxy` global. GUI: câmp în Settings tab. |
| **Parameter fuzzing wordlist extinsă** | ✅ Done | `SqliConfig.param_wordlist` cu ~100 params default (SecLists style). CLI: `--param-wordlist <file>`. |
| **SQLite dialect complet pentru dump** | ✅ Done | `DbmsDialect` extins cu `char_code_function()` și `substring_function()`. SQLite folosește `unicode`/`substr` + sleep via `randomblob(1000000000)`. |
| **Session cookie auto-detect** | ✅ Done | `SessionConfig.auto_detect` + `SessionManager::detect_session_cookies()`. CLI: `--cookie` și `--cookie-auto-detect`. |

### ✅ Must-have — Autentificare automată end-to-end

| Componentă | Status | Note |
|---|---|---|
| **CLI flags** | ✅ Done | `--login-url`, `--auth-method <form|json|basic|bearer>`, `--auth-cred key=val` (repetabil), `--auth-user`, `--auth-pass`, `--auth-token`, `--auth-success <string>`. |
| **SessionManager login** | ✅ Done | `SessionManager::login()` apelat automat în `run_scan` și per-task în `run_batch`. Eșecul login → warning, dar continuă scanul (nu abort). |
| **TargetProber autentificat** | ✅ Done | `TargetProber` are `with_session(Arc<SessionManager>)`; `scan_smart` transmite sesiunea la prober astfel încât fingerprinting să ruleze autentificat. |
| **GUI auth settings** | ✅ Done | Tab Settings are secțiune "Authentication" cu: Login URL, Method, Credentials (TextEdit multiline), Username, Password, Token, Success String. Persistate în `settings.json`. |

---

## Ce ne lipsește — Roadmap

### 🏗️ Must-have pentru parity cu sqlmap

| Item | Status | Detalii |
|---|---|---|
| **Integrare completă sqlmap payloads în blind/dump** | ✅ Done | Toate boundary-urile și payload-urile fetch-uite sunt folosite în `test_condition_blind`, `test_time_based` și `dump_all` via `[INFERENCE]`. |
| **SQL shell + OS shell interactiv** | — | REPL real care comunică cu targetul via blind injection. Transformă SQX din detector în exploitation framework. |
| **WAF bypass dedicat per vendor** | ✅ Done | Modul `waf_bypass` cu chain-uri multi-tamper dedicate pentru Cloudflare, ModSecurity, Imperva, Akamai, AWS WAF, Sucuri, F5, Fortinet. Escalare hibridă: vendor chains → generic fallback. |
| **File-read/write automat end-to-end** | ✅ Done | CLI `sqx file-read <url> --param X --file /etc/passwd --dbms mysql` + `sqx file-write`. Fast payloads (UNION/error) + blind extraction fallback pentru MySQL, PostgreSQL, MSSQL. |
| **Dynamic differential timing** | ✅ Done | `compute_adaptive_sleep(mean, stddev)` = `mean*3 + stddev*2` clamped [2,10]s. Adaptive sleep persistat în `SqliDetector.adaptive_sleep_secs` și folosit în toate căile time-based. |
| **Column name brute-forcing** | ✅ Done | `DEFAULT_COLUMN_WORDLIST` cu ~150 nume comune. Fallback automat în `enumerate_columns_blind` când `information_schema` returnează 0 coloane. |
| **SARIF output complet** | ✅ Done | Toate cele 7 reguli (inclusiv SQX007 CodeInjection), OWASP taxonomy, `logicalLocations`, `codeFlows`, `relatedLocations`, `artifacts`, `automationDetails`. Fixat CLI `--output sarif` pentru scan/post/auto/batch. |

### 🚀 Killer features pentru a depăși sqlmap

| Item | Detalii |
|---|---|
| **Headless browser integration** | Puppeteer/Playwright în Rust (via `chromiumoxide`) pentru a scana SPAs și API-uri JS-heavy. |
| **AI-first adaptive detection** | LLM analizează răspunsurile și decide TRUE/FALSE/ERROR — un "detection oracle" neuronal. |
| **Visual attack tree în GUI** | Graf vizual: *Payload trimis → Răspuns primit → Decizie luată → Următorul payload*. |
| **Team server / distributed scanning** | Server SQX built-in cu centralizare de rezultate pentru echipe. |
| **Auto-remediation suggestions** | Snippet-uri de fix specifice limbajului detectat (PHP, Java, .NET). |
| **One-click PoC generation** | Generează automat: curl, Python script, mini-report HTML exploitable. |
| **OOB DNS server complet** | ✅ Done — Server DNS async cu `tokio::net::UdpSocket`, răspuns A record folosind `public_host` din config (cu fallback la rezolvare DNS), înlocuirea socket-ului blocant din implementarea inițială. |

---

## 🚨 Reality Check — Structurale & Debt (2026-04-16)

### Probleme identificate

1. **Technical debt în parsing**
   - 14.500 linii cu "zero dependențe externe" înseamnă reinventare: HTML parser regex-based, HTTP client (reqwest e ok), JSON parser fixat manual (BUG-12), URL handling manual.
   - **Risc**: edge cases în HTML malformat (nested quotes, CDATA, encoding declarations) vor da fals negative în crawler.
   - **Decizie**: NU adăugăm html5ever acum (contradice zero-deps promise), dar documentăm limitarea și planificăm headless browser ca *replacement*, nu ca *killer feature*.

2. **Scope creep periculos**
   - Densitatea de funcționalitate e prea mare: GUI + CLI + OOB server + AI + Crawler + Dump + File I/O într-un singur binary.
   - BUG-15 (build errors după refactoring) confirmă fragilitatea.
   - **Decizie**: Următorul milestone nu adaugă feature-uri noi. Focalizare pe: tests, modularizare, payload parity.

3. **Crawler-ul e o vulnerabilitate pentru scan coverage**
   - Regex-based parsing ratează injection points în JS (`var url = "/api?q=" + input`), SPA routing, AJAX endpoints.
   - **Decizie**: Documentat ca known limitation. Headless browser devine *must-have* pentru parity cu web apps moderne.

4. **Payload coverage încă critică**
   - Admitem <5% din payloads sqlmap. Cu 23 boundaries vs 100+ la sqlmap, vom da fals negative pe targeturi reale.
   - **Decizie**: Audit complet și integrare xmlmap payloads înainte de orice feature AI/team.

### Recomandări implementate ACUM

- ✅ **Integration test suite** creată în `sqx-core/tests/integration/` cu docker-compose pentru sqli-labs + DVWA.
- ✅ **Payload audit** creat în `sqx-core/tests/payload_audit.md` — hartă detaliată a gap-urilor per-technique.
- ✅ **Workspace modularizare** — refactor complet în workspace Cargo cu 3 crate:
  - `sqx-core` — engine (~11.000 linii, zero UI deps)
  - `sqx-cli` — CLI binary (`sqx`)
  - `sqx-gui` — GUI binary (`sqx-gui`)

### Pivot strategic

**NU mai adăugăm:** AI-first adaptive detection, Team server, Visual attack tree, Auto-remediation.
**Focus exclusiv:**
1. ✅ Integrare completă sqlmap payloads (boundaries + contexts)
2. SQL shell + OS shell interactiv (parity cu sqlmap)
3. ✅ Workspace modularizare (`sqx-core`, `sqx-cli`, `sqx-gui`)
4. Headless browser crawler (înlocuiește regex-based)

**Concluzie:** Fără test coverage robust și payload parity, SQX rămâne un POC elegant. Vom închide parity-ul înainte de orice altceva.
