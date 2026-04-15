//! Structured JSON report — human-readable alternative to SARIF.
//!
//! Includes a `reproduction.curl` field per finding so developers can
//! immediately replay the attack without any additional tooling.

use serde_json::Value;

use crate::sqx::pipeline::models::PipelineResult;

/// Structured JSON report generator.
pub struct JsonReport;

impl JsonReport {
    /// Generate a structured JSON report from a pipeline result.
    pub fn generate(result: &PipelineResult) -> Value {
        let target_url = result
            .profile
            .as_ref()
            .map(|p| p.url.as_str())
            .unwrap_or("unknown");

        serde_json::json!({
            "scan": {
                "target":                 target_url,
                "duration_secs":          result.elapsed_secs,
                "total_requests":         result.total_requests,
                "parameters_tested":      result.parameters_tested,
                "parameters_vulnerable":  result.parameters_vulnerable,
            },
            "profile": result.profile.as_ref().map(|p| serde_json::json!({
                "dbms":     p.dbms_hint,
                "waf":      p.waf.as_ref().map(|w| &w.name),
                "strategy": p.strategy.technique_order,
            })),
            "findings": result.findings.iter().map(|f| {
                serde_json::json!({
                    "parameter":  f.parameter,
                    "technique":  f.technique.to_string(),
                    "confidence": format!("{:.0}%", f.confidence * 100.0),
                    "payload":    f.payload,
                    "evidence":   f.evidence,
                    "dbms":       f.dbms_hint,
                    "reproduction": {
                        "curl": format!(
                            "curl -s '{}' --data-urlencode '{}={}'",
                            target_url,
                            f.parameter,
                            f.payload
                        )
                    }
                })
            }).collect::<Vec<_>>(),
        })
    }
}
