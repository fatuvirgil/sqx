//! Benchmark command implementation.

use sqx_core::bench::{
    BenchmarkResult, TestCase, sqli_labs_test_matrix, summarize, print_comparison,
};
use sqx_core::sqx::{
    SqliConfig, SqliDetector, SqliTechnique,
    session::{SessionConfig, SessionManager},
};
use std::sync::Arc;
use std::time::{Duration, Instant};

pub async fn run_bench(target: String, out_file: Option<String>) {
    println!("SQX Benchmark Harness");
    println!("=====================\n");
    
    // Check if target is reachable
    println!("Checking target: {}", target);
    match reqwest::get(format!("{}/", target)).await {
        Ok(resp) => {
            if resp.status().is_success() {
                println!("  ✓ Target is reachable (HTTP {})\n", resp.status());
            } else {
                println!("  ! Target responded with HTTP {}\n", resp.status());
            }
        }
        Err(e) => {
            eprintln!("  ✗ Cannot reach target: {}", e);
            eprintln!("\nPlease ensure sqli-labs or similar test target is running at: {}", target);
            std::process::exit(1);
        }
    }
    
    // Get test matrix
    let test_cases = sqli_labs_test_matrix(&target);
    println!("Test matrix: {} test cases\n", test_cases.len());
    
    // Run SQX benchmark
    let sqx_results = run_sqx_benchmark(&test_cases).await;
    let sqx_summary = summarize(&sqx_results);
    
    // Print SQX results
    println!("\nSQX Results:");
    println!("  Total tests: {}", sqx_summary.total);
    println!("  Detections: {} ({:.1}%)", sqx_summary.detections, sqx_summary.detection_rate());
    println!("  Failures: {}", sqx_summary.failures);
    println!("  Total duration: {:.2}s", sqx_summary.total_duration.as_secs_f64());
    println!("  Avg duration: {:.2}s", sqx_summary.avg_duration.as_secs_f64());
    println!("  Total requests: {}", sqx_summary.total_requests);
    
    // For now, we don't have sqlmap integration, so we just print SQX results
    // In the future, this could call sqlmap via subprocess and compare
    
    // Export results if requested
    if let Some(out_path) = out_file {
        match export_results(&sqx_results, &out_path) {
            Ok(()) => println!("\n[+] Results exported to: {}", out_path),
            Err(e) => eprintln!("\n[!] Failed to export results: {}", e),
        }
    }
    
    // Print per-test details
    println!("\nDetailed Results:");
    println!("{:<50} {:>10} {:>12} {:>10}", "Test", "Status", "Duration", "Requests");
    println!("{}", "-".repeat(85));
    for result in &sqx_results {
        let status = if result.detected {
            "✓ DETECTED"
        } else if result.error.is_some() {
            "✗ ERROR"
        } else {
            "✗ MISSED"
        };
        println!(
            "{:<50} {:>10} {:>11.?} {:>10}",
            result.target.chars().take(48).collect::<String>(),
            status,
            format_duration(result.duration),
            result.request_count
        );
    }
}

async fn run_sqx_benchmark(test_cases: &[TestCase]) -> Vec<BenchmarkResult> {
    let mut results = Vec::new();
    
    for (i, case) in test_cases.iter().enumerate() {
        println!("  [{}/{}] Testing: {}", i + 1, test_cases.len(), case.name);
        
        let start = Instant::now();
        let result = run_single_sqx_test(case).await;
        let duration = start.elapsed();
        
        results.push(BenchmarkResult {
            target: case.url.clone(),
            tool: "sqx".to_string(),
            detected: result.is_some(),
            duration,
            request_count: 0, // Would need to track this in the detector
            technique: result.clone(),
            error: None,
        });
        
        // Small delay between tests
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    
    results
}

async fn run_single_sqx_test(case: &TestCase) -> Option<String> {
    // Build detector
    let config = SqliConfig {
        techniques: vec![
            SqliTechnique::ErrorBased,
            SqliTechnique::BooleanBlind,
            SqliTechnique::UnionBased,
            SqliTechnique::TimeBased,
        ],
        delay_ms: 50,
        timeout_secs: 10,
        ..Default::default()
    };
    
    let detector = match SqliDetector::with_config(config) {
        Ok(d) => d,
        Err(_) => return None,
    };
    
    // Run scan
    match detector.test_url(&case.url).await {
        Ok(findings) => {
            if findings.is_empty() {
                None
            } else {
                // Return the technique used
                findings.first().map(|f| format!("{:?}", f.technique))
            }
        }
        Err(_) => None,
    }
}

fn format_duration(d: Duration) -> String {
    if d.as_secs() > 0 {
        format!("{:.1}s", d.as_secs_f64())
    } else {
        format!("{}ms", d.as_millis())
    }
}

fn export_results(results: &[BenchmarkResult], path: &str) -> std::io::Result<()> {
    // Simple JSON export
    let json = serde_json::json!({
        "tool": "sqx",
        "timestamp": chrono::Utc::now().to_rfc3339(),
        "results": results.iter().map(|r| {
            serde_json::json!({
                "target": r.target,
                "detected": r.detected,
                "duration_ms": r.duration.as_millis(),
                "technique": r.technique,
                "error": r.error,
            })
        }).collect::<Vec<_>>(),
    });
    
    std::fs::write(path, serde_json::to_string_pretty(&json)?)
}
