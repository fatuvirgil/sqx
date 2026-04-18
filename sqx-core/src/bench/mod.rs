//! Benchmark Harness for SQX vs sqlmap comparison.
//!
//! This module provides tools for comparing SQX performance and detection
//! capabilities against sqlmap on a test matrix of vulnerable targets.

use std::collections::HashMap;
use std::time::{Duration, Instant};

/// Benchmark result for a single test case.
#[derive(Debug, Clone, serde::Serialize)]
pub struct BenchmarkResult {
    /// Target URL tested
    pub target: String,
    /// Tool name ("sqx" or "sqlmap")
    pub tool: String,
    /// Whether SQLi was detected
    pub detected: bool,
    /// Time taken for the scan
    pub duration: Duration,
    /// Number of requests made
    pub request_count: usize,
    /// Technique that found the vulnerability (if any)
    pub technique: Option<String>,
    /// Error message if scan failed
    pub error: Option<String>,
}

/// Summary of benchmark results.
#[derive(Debug, Clone)]
pub struct BenchmarkSummary {
    /// Tool name
    pub tool: String,
    /// Total test cases
    pub total: usize,
    /// Successful detections
    pub detections: usize,
    /// Failed scans
    pub failures: usize,
    /// Total duration across all tests
    pub total_duration: Duration,
    /// Average duration per test
    pub avg_duration: Duration,
    /// Total requests made
    pub total_requests: usize,
}

impl BenchmarkSummary {
    /// Calculate detection rate as percentage.
    pub fn detection_rate(&self) -> f64 {
        if self.total == 0 {
            0.0
        } else {
            (self.detections as f64 / self.total as f64) * 100.0
        }
    }
}

/// A test case for the benchmark.
#[derive(Debug, Clone)]
pub struct TestCase {
    /// Test name/description
    pub name: String,
    /// Target URL
    pub url: String,
    /// Expected vulnerability type (if known)
    pub expected_type: Option<String>,
    /// Additional parameters or headers
    pub parameters: HashMap<String, String>,
}

/// Predefined test matrix based on sqli-labs levels.
pub fn sqli_labs_test_matrix(base_url: &str) -> Vec<TestCase> {
    vec![
        TestCase {
            name: "Less-1: Error-based GET - Single Quotes".to_string(),
            url: format!("{}/Less-1/?id=1", base_url),
            expected_type: Some("error-based".to_string()),
            parameters: HashMap::new(),
        },
        TestCase {
            name: "Less-2: Error-based GET - Integer".to_string(),
            url: format!("{}/Less-2/?id=1", base_url),
            expected_type: Some("error-based".to_string()),
            parameters: HashMap::new(),
        },
        TestCase {
            name: "Less-3: Error-based GET - Single Quotes with Parenthesis".to_string(),
            url: format!("{}/Less-3/?id=1", base_url),
            expected_type: Some("error-based".to_string()),
            parameters: HashMap::new(),
        },
        TestCase {
            name: "Less-4: Error-based GET - Double Quotes".to_string(),
            url: format!("{}/Less-4/?id=1", base_url),
            expected_type: Some("error-based".to_string()),
            parameters: HashMap::new(),
        },
        TestCase {
            name: "Less-5: Boolean-based Blind - Single Quotes".to_string(),
            url: format!("{}/Less-5/?id=1", base_url),
            expected_type: Some("boolean-blind".to_string()),
            parameters: HashMap::new(),
        },
        TestCase {
            name: "Less-6: Boolean-based Blind - Double Quotes".to_string(),
            url: format!("{}/Less-6/?id=1", base_url),
            expected_type: Some("boolean-blind".to_string()),
            parameters: HashMap::new(),
        },
        TestCase {
            name: "Less-8: Boolean-based Blind - Single Quotes".to_string(),
            url: format!("{}/Less-8/?id=1", base_url),
            expected_type: Some("boolean-blind".to_string()),
            parameters: HashMap::new(),
        },
        TestCase {
            name: "Less-9: Time-based Blind - Single Quotes".to_string(),
            url: format!("{}/Less-9/?id=1", base_url),
            expected_type: Some("time-based".to_string()),
            parameters: HashMap::new(),
        },
        TestCase {
            name: "Less-10: Time-based Blind - Double Quotes".to_string(),
            url: format!("{}/Less-10/?id=1", base_url),
            expected_type: Some("time-based".to_string()),
            parameters: HashMap::new(),
        },
        TestCase {
            name: "Less-11: Error-based POST - Single Quotes".to_string(),
            url: format!("{}/Less-11/", base_url),
            expected_type: Some("error-based".to_string()),
            parameters: {
                let mut p = HashMap::new();
                p.insert("uname".to_string(), "admin".to_string());
                p.insert("passwd".to_string(), "x".to_string());
                p
            },
        },
    ]
}

/// Run a benchmark suite.
pub async fn run_benchmark(
    tool_name: &str,
    test_cases: &[TestCase],
    run_test: impl Fn(&TestCase) -> std::pin::Pin<Box<dyn std::future::Future<Output = BenchmarkResult> + '_>>,
) -> Vec<BenchmarkResult> {
    let mut results = Vec::new();
    
    println!("Running benchmark for '{}' on {} test cases...", tool_name, test_cases.len());
    
    for (i, case) in test_cases.iter().enumerate() {
        println!("  [{}/{}] {}...", i + 1, test_cases.len(), case.name);
        let result = run_test(case).await;
        results.push(result);
    }
    
    results
}

/// Summarize benchmark results.
pub fn summarize(results: &[BenchmarkResult]) -> BenchmarkSummary {
    let tool = results.first().map(|r| r.tool.clone()).unwrap_or_default();
    let total = results.len();
    let detections = results.iter().filter(|r| r.detected).count();
    let failures = results.iter().filter(|r| r.error.is_some()).count();
    let total_duration: Duration = results.iter().map(|r| r.duration).sum();
    let avg_duration = if total > 0 {
        total_duration / total as u32
    } else {
        Duration::ZERO
    };
    let total_requests = results.iter().map(|r| r.request_count).sum();
    
    BenchmarkSummary {
        tool,
        total,
        detections,
        failures,
        total_duration,
        avg_duration,
        total_requests,
    }
}

/// Print a comparison table of two benchmark summaries.
pub fn print_comparison(sqx: &BenchmarkSummary, sqlmap: &BenchmarkSummary) {
    println!("\n╔════════════════════════════════════════════════════════════╗");
    println!("║              SQX vs sqlmap Benchmark Results               ║");
    println!("╠════════════════════════════════════════════════════════════╣");
    println!("║ {:<20} │ {:>15} │ {:>15} ║", "Metric", "SQX", "sqlmap");
    println!("╠══════════════════════╪═════════════════╪═══════════════════╣");
    println!("║ {:<20} │ {:>15} │ {:>15} ║", 
        "Total Tests", sqx.total, sqlmap.total);
    println!("║ {:<20} │ {:>15} │ {:>15} ║", 
        "Detections", sqx.detections, sqlmap.detections);
    println!("║ {:<20} │ {:>14.1}% │ {:>14.1}% ║", 
        "Detection Rate", sqx.detection_rate(), sqlmap.detection_rate());
    println!("║ {:<20} │ {:>15} │ {:>15} ║", 
        "Failures", sqx.failures, sqlmap.failures);
    println!("║ {:<20} │ {:>13.?} │ {:>13.?} ║", 
        "Total Duration", format_duration(sqx.total_duration), format_duration(sqlmap.total_duration));
    println!("║ {:<20} │ {:>13.?} │ {:>13.?} ║", 
        "Avg Duration", format_duration(sqx.avg_duration), format_duration(sqlmap.avg_duration));
    println!("║ {:<20} │ {:>15} │ {:>15} ║", 
        "Total Requests", sqx.total_requests, sqlmap.total_requests);
    println!("╚════════════════════════════════════════════════════════════╝");
    
    // Calculate improvement
    if sqx.detection_rate() > 0.0 && sqlmap.detection_rate() > 0.0 {
        let detection_diff = sqx.detection_rate() - sqlmap.detection_rate();
        let speedup = sqlmap.avg_duration.as_secs_f64() / sqx.avg_duration.as_secs_f64();
        
        println!("\nSummary:");
        if detection_diff > 0.0 {
            println!("  ✓ SQX has {:.1}% higher detection rate", detection_diff);
        } else if detection_diff < 0.0 {
            println!("  ✗ SQX has {:.1}% lower detection rate", -detection_diff);
        } else {
            println!("  = Equal detection rates");
        }
        
        if speedup > 1.0 {
            println!("  ✓ SQX is {:.1}x faster on average", speedup);
        } else if speedup < 1.0 {
            println!("  ✗ SQX is {:.1}x slower on average", 1.0 / speedup);
        } else {
            println!("  = Equal average duration");
        }
    }
}

fn format_duration(d: Duration) -> String {
    if d.as_secs() > 0 {
        format!("{:.2}s", d.as_secs_f64())
    } else {
        format!("{}ms", d.as_millis())
    }
}

/// Export results to JSON.
pub fn export_json(results: &[BenchmarkResult], path: &str) -> std::io::Result<()> {
    let json = serde_json::to_string_pretty(results)?;
    std::fs::write(path, json)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detection_rate() {
        let summary = BenchmarkSummary {
            tool: "test".to_string(),
            total: 10,
            detections: 7,
            failures: 0,
            total_duration: Duration::from_secs(100),
            avg_duration: Duration::from_secs(10),
            total_requests: 1000,
        };
        assert_eq!(summary.detection_rate(), 70.0);
    }

    #[test]
    fn test_detection_rate_zero() {
        let summary = BenchmarkSummary {
            tool: "test".to_string(),
            total: 0,
            detections: 0,
            failures: 0,
            total_duration: Duration::ZERO,
            avg_duration: Duration::ZERO,
            total_requests: 0,
        };
        assert_eq!(summary.detection_rate(), 0.0);
    }

    #[test]
    fn test_sqli_labs_matrix() {
        let matrix = sqli_labs_test_matrix("http://localhost");
        assert!(!matrix.is_empty());
        assert_eq!(matrix[0].name, "Less-1: Error-based GET - Single Quotes");
    }
}
