//! Interactive shell commands (sql-shell, os-shell)

use std::sync::Arc;

use sqx_core::sqx::{
    ShellConfig, ShellTechnique, SqlShell, OsShell,
    SqliConfig, SqliDetector, session::SessionManager,
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

async fn ensure_auth_if_configured(detector: &SqliDetector) -> bool {
    match detector.ensure_authenticated().await {
        Ok(()) => {
            if detector.has_auth_session().await {
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

/// Run interactive SQL shell.
pub async fn run_sql_shell(
    url: String,
    param: String,
    value: String,
    dbms: String,
    technique: String,
    max_length: usize,
    delay: u64,
    proxy: Option<String>,
    session: Option<Arc<SessionManager>>,
) {
    let Some(detector) = build_detector(proxy, session, Some(delay)) else {
        return;
    };

    ensure_auth_if_configured(&detector).await;

    let technique_enum = match technique.to_lowercase().as_str() {
        "time" => ShellTechnique::Time,
        _ => ShellTechnique::Boolean,
    };

    let config = ShellConfig {
        max_output_length: max_length,
        technique: technique_enum,
        delay_ms: delay,
        auto_detect: true,
    };

    eprintln!("[*] Starting SQL shell...");
    eprintln!("[*] Target: {}", url);
    eprintln!("[*] DBMS: {}", dbms);
    eprintln!("[*] Technique: {}", technique);

    match SqlShell::new(&detector, &url, &param, &value, &dbms, config).await {
        Ok(mut shell) => {
            if let Err(e) = shell.run_repl().await {
                eprintln!("[!] SQL shell error: {}", e);
            }
        }
        Err(e) => {
            eprintln!("[!] Failed to initialize SQL shell: {}", e);
        }
    }
}

/// Run interactive OS shell.
pub async fn run_os_shell(
    url: String,
    param: String,
    value: String,
    dbms: String,
    technique: String,
    max_length: usize,
    delay: u64,
    proxy: Option<String>,
    session: Option<Arc<SessionManager>>,
) {
    let Some(detector) = build_detector(proxy, session, Some(delay)) else {
        return;
    };

    ensure_auth_if_configured(&detector).await;

    let technique_enum = match technique.to_lowercase().as_str() {
        "time" => ShellTechnique::Time,
        _ => ShellTechnique::Boolean,
    };

    let config = ShellConfig {
        max_output_length: max_length,
        technique: technique_enum,
        delay_ms: delay,
        auto_detect: true,
    };

    eprintln!("[*] Starting OS shell...");
    eprintln!("[*] Target: {}", url);
    eprintln!("[*] DBMS: {}", dbms);
    eprintln!("[*] Technique: {}", technique);

    match OsShell::new(&detector, &url, &param, &value, &dbms, config).await {
        Ok(mut shell) => {
            if let Err(e) = shell.run_repl().await {
                eprintln!("[!] OS shell error: {}", e);
            }
        }
        Err(e) => {
            eprintln!("[!] Failed to initialize OS shell: {}", e);
        }
    }
}
