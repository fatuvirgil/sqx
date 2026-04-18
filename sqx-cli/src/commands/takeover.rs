use std::sync::Arc;

use sqx_core::sqx::{
    CustomSqlRequest, SqliConfig, SqliDetector, models::BlindTechnique, session::SessionManager,
};

fn build_detector(
    proxy: Option<String>,
    session: Option<Arc<SessionManager>>,
    delay_ms: Option<u64>,
) -> Option<SqliDetector> {
    let config = SqliConfig {
        proxy,
        delay_ms: delay_ms.unwrap_or_else(|| SqliConfig::default().delay_ms),
        ..SqliConfig::default()
    };

    let mut detector = match SqliDetector::with_config(config) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("[!] Failed to build detector: {}", e);
            return None;
        }
    };
    if let Some(sess) = session {
        detector = detector.with_session(sess);
    }
    Some(detector)
}

fn write_or_print(content: &str, out_file: Option<&str>) {
    match out_file {
        Some(path) => {
            if let Err(e) = std::fs::write(path, content) {
                eprintln!("[!] Failed to write output: {}", e);
            } else {
                eprintln!("[+] Output written to {}", path);
            }
        }
        None => print!("{}", content),
    }
}

async fn ensure_auth_if_configured(detector: &SqliDetector) -> bool {
    match detector.ensure_authenticated().await {
        Ok(()) => {
            if detector.has_auth_session() {
                eprintln!("[+] Login successful");
            }
            true
        }
        Err(e) => {
            eprintln!("⚠ Login failed — continuing unauthenticated: {}", e);
            false
        }
    }
}

pub(crate) async fn run_file_read(
    url: String,
    param: String,
    file: String,
    dbms: String,
    value: String,
    out_file: Option<String>,
    proxy: Option<String>,
    session: Option<Arc<SessionManager>>,
) {
    let Some(detector) = build_detector(proxy, session, None) else {
        return;
    };

    ensure_auth_if_configured(&detector).await;

    eprintln!(
        "[*] file-read: {} param={} file={} dbms={}",
        url, param, file, dbms
    );

    match detector.file_read(&url, &param, &value, &dbms, &file).await {
        Ok(result) => {
            let content = if let Some(ref data) = result.content {
                format!(
                    "[+] File-read succeeded ({} requests)\n\nPayload: {}\n\nContent:\n{}\n",
                    result.total_requests, result.payload_used, data
                )
            } else {
                format!(
                    "[-] File-read failed after {} requests. No readable content returned.\n",
                    result.total_requests
                )
            };
            write_or_print(&content, out_file.as_deref());
        }
        Err(e) => eprintln!("[!] File-read error: {}", e),
    }
}

pub(crate) async fn run_file_write(
    url: String,
    param: String,
    file: String,
    content: String,
    dbms: String,
    value: String,
    proxy: Option<String>,
    session: Option<Arc<SessionManager>>,
) {
    let Some(detector) = build_detector(proxy, session, None) else {
        return;
    };

    ensure_auth_if_configured(&detector).await;

    eprintln!(
        "[*] file-write: {} param={} file={} dbms={}",
        url, param, file, dbms
    );

    match detector
        .file_write(&url, &param, &value, &dbms, &file, &content)
        .await
    {
        Ok(result) => {
            if result.success {
                eprintln!(
                    "[+] File-write succeeded ({} requests)\nPayload: {}\nEvidence: {}",
                    result.total_requests, result.payload_used, result.evidence
                );
            } else {
                eprintln!(
                    "[-] File-write failed after {} requests. {}",
                    result.total_requests, result.evidence
                );
            }
        }
        Err(e) => eprintln!("[!] File-write error: {}", e),
    }
}

pub(crate) async fn run_custom_sql(
    url: String,
    param: String,
    query: String,
    value: String,
    dbms: String,
    technique: String,
    max_length: usize,
    boundary: Option<String>,
    payload_id: Option<String>,
    delay: u64,
    output: String,
    out_file: Option<String>,
    proxy: Option<String>,
    session: Option<Arc<SessionManager>>,
) {
    let blind_technique = match technique.to_lowercase().as_str() {
        "time" => BlindTechnique::Time,
        _ => BlindTechnique::Boolean,
    };

    let Some(detector) = build_detector(proxy, session, Some(delay)) else {
        return;
    };

    ensure_auth_if_configured(&detector).await;

    eprintln!(
        "[*] sql: {} param={} dbms={} technique={:?}",
        url, param, dbms, blind_technique
    );

    let request = CustomSqlRequest {
        query: query.clone(),
        technique: blind_technique,
        max_length,
        boundary_hint: boundary,
        payload_id,
    };

    match detector
        .execute_custom_sql(&url, &param, &value, &dbms, &request)
        .await
    {
        Ok(result) => {
            let content = match output.as_str() {
                "json" => serde_json::to_string_pretty(&result).unwrap_or_default(),
                _ => {
                    let value = result.value.unwrap_or_default();
                    format!(
                        "[+] SQL extraction complete\nQuery: {}\nTechnique: {}\nRequests: {}\n\nResult:\n{}\n",
                        query, result.technique_used, result.total_requests, value
                    )
                }
            };

            write_or_print(&content, out_file.as_deref());
        }
        Err(e) => eprintln!("[!] SQL extraction error: {}", e),
    }
}
