//! DbmsDialect trait — one implementation per database engine.

/// Per-engine SQL dialect: error patterns, extraction functions, and query templates.
///
/// Implementing this trait for a new DBMS is the single place to register all
/// engine-specific SQL. Consumers dispatch through `dbms::all_dialects()` or
/// `dbms::dialect_by_name()` — no match-on-string scattered across modules.
pub trait DbmsDialect: Send + Sync {
    fn name(&self) -> &'static str;

    // ── Detection ─────────────────────────────────────────────────────────────

    /// SQL error strings that identify this DBMS in response bodies.
    /// Returns pairs of (pattern, label). Matching is case-insensitive.
    fn error_signatures(&self) -> &[(&'static str, &'static str)];

    // ── Union extraction ──────────────────────────────────────────────────────

    /// Expressions to extract [version, user, database] via UNION SELECT.
    fn union_extraction_functions(&self) -> [&'static str; 3];

    // ── Schema enumeration ────────────────────────────────────────────────────

    fn table_count_query(&self) -> String;
    fn table_name_query(&self, index: usize) -> String;
    fn column_count_query(&self, table: &str) -> String;
    fn column_name_query(&self, table: &str, index: usize) -> String;

    // ── Time-based ────────────────────────────────────────────────────────────

    /// Returns the DBMS sleep expression, e.g. `SLEEP(3)` or `pg_sleep(3)`.
    /// Returns an empty string for engines without a native sleep primitive.
    fn sleep_function(&self, _seconds: u64) -> String { String::new() }

    /// Conditional sleep: execute the delay only when `condition` is TRUE.
    fn conditional_sleep(&self, _condition: &str, _seconds: u64) -> String { String::new() }

    // ── Stacked queries ───────────────────────────────────────────────────────

    /// Full stacked-query sleep payload incorporating `original_value`.
    /// Returns an empty string for engines that don't support stacked queries.
    fn stacked_sleep_payload(&self, _original_value: &str, _seconds: u64) -> String {
        String::new()
    }

    // ── Time-based blind ─────────────────────────────────────────────────────

    /// Payload suffix appended to a parameter value for time-based blind detection.
    /// Default: `' AND {sleep_fn}-- ` (works for most DBMS).
    /// Returns an empty string for engines with no sleep primitive.
    fn time_based_payload(&self, seconds: u64) -> String {
        let sleep = self.sleep_function(seconds);
        if sleep.is_empty() {
            String::new()
        } else {
            format!("' AND {}-- ", sleep)
        }
    }
}
