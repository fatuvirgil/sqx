//! DBMS dialect registry.
//! Add a new engine by implementing DbmsDialect in major.rs or exotic.rs,
//! then push a boxed instance into all_dialects().

pub mod dialect;
pub mod exotic;
pub mod major;

pub use dialect::DbmsDialect;

use exotic::{
    Cache, ClickHouse, CockroachDb, Db2, Derby, Firebird, FrontBase, H2, Hsqldb, Informix, Ingres,
    Mckoi, MonetDb, Msql, Sybase, TiDb, Virtuoso,
};
use major::{MariaDB, Mssql, MySQL, Oracle, PostgreSQL, Sqlite};

/// All known DBMS dialects, major engines first.
pub fn all_dialects() -> Vec<Box<dyn DbmsDialect>> {
    vec![
        // Major DBMS (most common first)
        Box::new(MariaDB),  // Check before MySQL - more specific patterns (MariaDB server version)
        Box::new(MySQL),
        Box::new(PostgreSQL),
        Box::new(Mssql),
        Box::new(Oracle),
        // ClickHouse (very specific error patterns - check early)
        Box::new(ClickHouse),
        // PostgreSQL-compatible (check before generic SQLite)
        Box::new(CockroachDb),
        Box::new(TiDb),
        // Generic SQLite (lowest priority - generic error patterns)
        Box::new(Sqlite),
        // Legacy/Enterprise
        Box::new(Db2),
        Box::new(Sybase),
        Box::new(Firebird),
        Box::new(Informix),
        Box::new(Ingres),
        // Embedded/Java
        Box::new(Hsqldb),
        Box::new(H2),
        Box::new(Derby),
        // Niche/Specialty
        Box::new(Mckoi),
        Box::new(Cache),
        Box::new(FrontBase),
        Box::new(MonetDb),
        Box::new(Virtuoso),
        Box::new(Msql),
    ]
}

/// Find a dialect by name (case-insensitive).
pub fn dialect_by_name(name: &str) -> Option<Box<dyn DbmsDialect>> {
    let lower = name.to_lowercase();
    all_dialects()
        .into_iter()
        .find(|d| d.name().to_lowercase() == lower)
}
