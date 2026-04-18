//! Request replay command implementation.

use std::time::Duration;

use sqx_core::sqx::request::{replay_from_file, replay_request};

pub async fn run_replay(
    file: String,
    output: String,
    out_file: Option<String>,
    timeout: u64,
    proxy: Option<String>,
) {
    // Build HTTP client
    let mut client_builder = reqwest::Client::builder()
        .timeout(Duration::from_secs(timeout));
    
    if let Some(proxy_url) = proxy {
        match reqwest::Proxy::all(&proxy_url) {
            Ok(proxy) => {
                client_builder = client_builder.proxy(proxy);
            }
            Err(e) => {
                eprintln!("[!] Warning: Failed to set proxy: {}", e);
            }
        }
    }
    
    let client = match client_builder.build() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("[-] Failed to build HTTP client: {}", e);
            std::process::exit(1);
        }
    };
    
    // Read request content
    let content = if file == "-" {
        use std::io::Read;
        let mut buf = String::new();
        if let Err(e) = std::io::stdin().read_to_string(&mut buf) {
            eprintln!("[-] Failed to read from stdin: {}", e);
            std::process::exit(1);
        }
        buf
    } else {
        match std::fs::read_to_string(&file) {
            Ok(c) => c,
            Err(e) => {
                eprintln!("[-] Failed to read file '{}': {}", file, e);
                std::process::exit(1);
            }
        }
    };
    
    // Check if file contains multiple requests (separated by ---)
    let responses = if content.contains("\n---\n") {
        match replay_from_file(&file, &client).await {
            Ok(r) => r,
            Err(e) => {
                eprintln!("[-] Failed to replay requests: {}", e);
                std::process::exit(1);
            }
        }
    } else {
        // Single request - parse directly
        match replay_request(&content, &client).await {
            Ok(r) => vec![r],
            Err(e) => {
                eprintln!("[-] Failed to replay request: {}", e);
                std::process::exit(1);
            }
        }
    };
    
    // Format output
    let output_text = format_output(&responses, &output);
    
    // Write or print output
    if let Some(out_path) = out_file {
        if let Err(e) = std::fs::write(&out_path, output_text) {
            eprintln!("[-] Failed to write output file: {}", e);
            std::process::exit(1);
        }
        println!("[+] Output written to: {}", out_path);
    } else {
        println!("{}", output_text);
    }
    
    // Summary
    println!("\n[+] Replayed {} request(s)", responses.len());
    for (i, resp) in responses.iter().enumerate() {
        println!("  Request {}: HTTP {} ({} bytes, {:?})", 
            i + 1, resp.status, resp.body.len(), resp.duration);
    }
}

fn format_output(responses: &[sqx_core::sqx::models::HttpResponse], format: &str) -> String {
    match format {
        "json" => {
            // Manual JSON formatting since HttpResponse doesn't implement Serialize
            let mut items = Vec::new();
            for resp in responses {
                let item = format!(
                    r#"{{"status": {}, "body": {}, "duration_ms": {}}}"#,
                    resp.status,
                    serde_json::json!(resp.body),
                    resp.duration.as_millis()
                );
                items.push(item);
            }
            format!("[\n{}\n]", items.join(",\n"))
        }
        _ => {
            // Text format
            let mut output = String::new();
            for (i, resp) in responses.iter().enumerate() {
                if i > 0 {
                    output.push_str("\n---\n\n");
                }
                output.push_str(&format!("HTTP {}\n", resp.status));
                output.push_str(&format!("Duration: {:?}\n", resp.duration));
                output.push_str(&format!("Body ({} bytes):\n", resp.body.len()));
                output.push_str(&resp.body);
                output.push('\n');
            }
            output
        }
    }
}
