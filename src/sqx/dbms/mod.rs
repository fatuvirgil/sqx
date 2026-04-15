//! DBMS dialect registry.
//! Add a new engine by implementing DbmsDialect in major.rs or exotic.rs,
//! then push a boxed instance into all_dialects().

pub mod dialect;
pub mod major;
pub mod exotic;

pub use dialect::DbmsDialect;

use major::{MySQL, MariaDB, PostgreSQL, Mssql, Oracle, Sqlite};
use exotic::{
    Db2, Sybase, Firebird, Hsqldb, H2, Informix, Ingres,
    CockroachDb, TiDb, ClickHouse, Mckoi, Derby, Cache,
    FrontBase, MonetDb, Virtuoso, Msql,
};

/// All known DBMS dialects, major engines first.
pub fn all_dialects() -> Vec<Box<dyn DbmsDialect>> {
    vec![
        Box::new(MySQL),
        Box::new(PostgreSQL),
        Box::new(Mssql),
        Box::new(Oracle),
        Box::new(Sqlite),
        Box::new(MariaDB),
        Box::new(Db2),
        Box::new(Sybase),
        Box::new(Firebird),
        Box::new(Hsqldb),
        Box::new(H2),
        Box::new(Informix),
        Box::new(Ingres),
        Box::new(CockroachDb),
        Box::new(TiDb),
        Box::new(ClickHouse),
        Box::new(Mckoi),
        Box::new(Derby),
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
    all_dialects().into_iter().find(|d| d.name().to_lowercase() == lower)
}
