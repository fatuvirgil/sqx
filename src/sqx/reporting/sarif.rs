//! SARIF 2.1.0 report generator.
//!
//! SARIF (Static Analysis Results Interchange Format) is the industry-standard
//! JSON format consumed by GitHub Advanced Security, Azure DevOps, Defect Dojo,
//! and most CI/CD security pipelines.

use serde_json::Value;

use crate::sqx::{
    models::{SqliTestResult, SqliTechnique},
    pipeline::models::PipelineResult,
};

/// SARIF 2.1.0 report generator.
pub struct SarifReport;

impl SarifReport {
    /// Generate SARIF JSON from a full pipeline result.
    pub fn generate(result: &PipelineResult) -> Value {
        serde_json::json!({
            "$schema": "https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [Self::build_run(result)]
        })
    }

    /// Generate SARIF from raw findings (no pipeline context required).
    pub fn from_findings(findings: &[SqliTestResult], target_url: &str) -> Value {
        let results: Vec<Value> = findings
            .iter()
            .map(|f| Self::finding_to_result(f, target_url))
            .collect();

        serde_json::json!({
            "$schema": "https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [{
                "tool": Self::tool_component(),
                "results": results,
            }]
        })
    }

    // ── Private helpers ──────────────────────────────────────────────────────

    fn build_run(result: &PipelineResult) -> Value {
        let target_url = result
            .profile
            .as_ref()
            .map(|p| p.url.as_str())
            .unwrap_or("unknown");

        let results: Vec<Value> = result
            .findings
            .iter()
            .map(|f| Self::finding_to_result(f, target_url))
            .collect();

        serde_json::json!({
            "tool": Self::tool_component(),
            "results": results,
            "invocations": [{
                "executionSuccessful": true,
                "properties": {
                    "parametersScanned":    result.parameters_tested,
                    "parametersVulnerable": result.parameters_vulnerable,
                    "totalRequests":        result.total_requests,
                    "elapsedSeconds":       result.elapsed_secs,
                }
            }]
        })
    }

    fn tool_component() -> Value {
        serde_json::json!({
            "driver": {
                "name": "SQX",
                "version": env!("CARGO_PKG_VERSION"),
                "informationUri": "https://github.com/intelexia/sqx",
                "rules": [
                    {
                        "id": "SQX001",
                        "name": "SqlInjection/ErrorBased",
                        "shortDescription": { "text": "Error-based SQL Injection" },
                        "helpUri": "https://owasp.org/www-community/attacks/SQL_Injection",
                        "defaultConfiguration": { "level": "error" }
                    },
                    {
                        "id": "SQX002",
                        "name": "SqlInjection/BooleanBlind",
                        "shortDescription": { "text": "Boolean-based blind SQL Injection" },
                        "helpUri": "https://owasp.org/www-community/attacks/Blind_SQL_Injection",
                        "defaultConfiguration": { "level": "error" }
                    },
                    {
                        "id": "SQX003",
                        "name": "SqlInjection/TimeBased",
                        "shortDescription": { "text": "Time-based blind SQL Injection" },
                        "helpUri": "https://owasp.org/www-community/attacks/Blind_SQL_Injection",
                        "defaultConfiguration": { "level": "error" }
                    },
                    {
                        "id": "SQX004",
                        "name": "SqlInjection/UnionBased",
                        "shortDescription": { "text": "Union-based SQL Injection" },
                        "helpUri": "https://owasp.org/www-community/attacks/SQL_Injection",
                        "defaultConfiguration": { "level": "error" }
                    },
                    {
                        "id": "SQX005",
                        "name": "SqlInjection/StackedQueries",
                        "shortDescription": { "text": "Stacked-queries SQL Injection" },
                        "helpUri": "https://owasp.org/www-community/attacks/SQL_Injection",
                        "defaultConfiguration": { "level": "error" }
                    },
                    {
                        "id": "SQX006",
                        "name": "SqlInjection/OutOfBand",
                        "shortDescription": { "text": "Out-of-band SQL Injection" },
                        "helpUri": "https://owasp.org/www-community/attacks/SQL_Injection",
                        "defaultConfiguration": { "level": "error" }
                    }
                ]
            }
        })
    }

    fn finding_to_result(finding: &SqliTestResult, url: &str) -> Value {
        let (rule_id, level) = Self::technique_meta(&finding.technique);

        serde_json::json!({
            "ruleId": rule_id,
            "level": level,
            "message": {
                "text": format!(
                    "SQL Injection ({}) detected in parameter '{}'. Confidence: {:.0}%. {}",
                    finding.technique,
                    finding.parameter,
                    finding.confidence * 100.0,
                    finding.evidence
                )
            },
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": { "uri": url }
                },
                "properties": {
                    "parameter": finding.parameter,
                }
            }],
            "properties": {
                "confidence": finding.confidence,
                "technique":  finding.technique.to_string(),
                "payload":    finding.payload,
                "evidence":   finding.evidence,
                "dbmsHint":   finding.dbms_hint,
            }
        })
    }

    fn technique_meta(technique: &SqliTechnique) -> (&'static str, &'static str) {
        match technique {
            SqliTechnique::ErrorBased     => ("SQX001", "error"),
            SqliTechnique::BooleanBlind   => ("SQX002", "error"),
            SqliTechnique::TimeBased      => ("SQX003", "error"),
            SqliTechnique::UnionBased     => ("SQX004", "error"),
            SqliTechnique::StackedQueries => ("SQX005", "error"),
            SqliTechnique::OutOfBand      => ("SQX006", "error"),
            SqliTechnique::CodeInjection  => ("SQX007", "error"),
        }
    }
}
