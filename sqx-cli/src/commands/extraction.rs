use std::sync::Arc;

use sqx_core::sqx::{SqliConfig, SqliDetector, models::BlindTechnique, session::SessionManager};

pub(crate) async fn run_dump(
    url: String,
    param: String,
    value: String,
    dbms: String,
    technique: String,
    max_rows: usize,
    output: String,
    out_file: Option<String>,
    proxy: Option<String>,
    session: Option<Arc<SessionManager>>,
    delay: u64,
) {
    let blind_technique = match technique.to_lowercase().as_str() {
        "time" => BlindTechnique::Time,
        _ => BlindTechnique::Boolean,
    };

    let config = SqliConfig {
        proxy,
        delay_ms: delay,
        ..SqliConfig::default()
    };
    let mut detector = match SqliDetector::with_config(config) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("[!] Failed to build detector: {}", e);
            return;
        }
    };
    if let Some(sess) = session {
        detector = detector.with_session(sess);
    }

    match detector.ensure_authenticated().await {
        Ok(()) => {
            if detector.has_auth_session() {
                eprintln!("[+] Login successful");
            }
        }
        Err(e) => eprintln!("⚠ Login failed — scanning unauthenticated: {}", e),
    }

    eprintln!(
        "[*] dump-all: {} param={} dbms={} technique={:?} max_rows={}",
        url, param, dbms, blind_technique, max_rows
    );

    match detector
        .dump_all(
            &url,
            &param,
            &value,
            &dbms,
            blind_technique,
            max_rows,
            None,
            None,
        )
        .await
    {
        Ok(result) => {
            eprintln!(
                "[+] Dump complete — {} table(s), {} requests, {:.1}s",
                result.tables.len(),
                result.total_requests,
                result.elapsed_secs
            );

            let content = match output.as_str() {
                "json" => serde_json::to_string_pretty(&result).unwrap_or_default(),
                "csv" => result.to_csv(),
                _ => result.to_text(),
            };

            match out_file.as_deref() {
                Some(path) => {
                    if let Err(e) = std::fs::write(path, &content) {
                        eprintln!("[!] Failed to write output: {}", e);
                    } else {
                        eprintln!("[+] Output written to {}", path);
                    }
                }
                None => print!("{}", content),
            }
        }
        Err(e) => eprintln!("[!] Dump error: {}", e),
    }
}
