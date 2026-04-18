pub(crate) fn print_or_write_findings(
    findings: &[sqx_core::sqx::SqliTestResult],
    format: &str,
    out_file: Option<&str>,
    target_url: Option<&str>,
) {
    if findings.is_empty() {
        eprintln!("[-] No SQL injection found.");
        return;
    }

    let url = target_url.unwrap_or("unknown");
    let content: String = match format {
        "json" => serde_json::to_string_pretty(findings).unwrap_or_default(),
        "sarif" => serde_json::to_string_pretty(
            &sqx_core::sqx::reporting::SarifReport::from_findings(findings, url),
        )
        .unwrap_or_default(),
        "markdown" => {
            eprintln!("[!] Markdown output is a Pro feature. Use 'json' or 'text', or upgrade to SQX Pro.");
            std::process::exit(1);
        }
        _ => {
            let mut out = String::new();
            for f in findings {
                out.push_str(&format!(
                    "[VULN] param={} technique={} confidence={:.0}%\n  payload: {}\n  evidence: {}\n",
                    f.parameter,
                    f.technique,
                    f.confidence * 100.0,
                    f.payload,
                    f.evidence,
                ));
            }
            out
        }
    };

    match out_file {
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
