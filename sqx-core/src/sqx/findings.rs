use crate::models::{Confidence, Finding, Severity};
use crate::sqx::detector::SqliDetector;
use crate::sqx::models::{SqliTechnique, SqliTestResult};

impl SqliDetector {
    /// Convert SQX results to Finding objects
    pub fn results_to_findings(&self, results: Vec<SqliTestResult>, url: &str) -> Vec<Finding> {
        use chrono::Utc;
        use uuid::Uuid;

        results
            .into_iter()
            .map(|result| Finding {
                id: Uuid::new_v4().to_string(),
                timestamp: Utc::now(),
                tool: "sqx".to_string(),
                severity: match result.technique {
                    SqliTechnique::ErrorBased => Severity::High,
                    SqliTechnique::BooleanBlind => Severity::High,
                    SqliTechnique::TimeBased => Severity::High,
                    SqliTechnique::UnionBased => Severity::Critical,
                    SqliTechnique::StackedQueries => Severity::Critical,
                    SqliTechnique::OutOfBand => Severity::High,
                    SqliTechnique::SecondOrder => Severity::Critical,
                    SqliTechnique::CodeInjection => Severity::Critical,
                },
                confidence: if result.confidence > 0.9 {
                    Confidence::Certain
                } else {
                    Confidence::Firm
                },
                title: format!("SQL Injection ({})", result.technique),
                description: format!(
                    "Parameter '{}' is vulnerable to {} SQL injection. {}",
                    result.parameter, result.technique, result.evidence
                ),
                url: url.to_string(),
                request_id: None,
                evidence: Some(format!(
                    "Payload: {}\nEvidence: {}",
                    result.payload, result.evidence
                )),
                remediation: Some(
                    "Use parameterized queries/prepared statements. Validate and sanitize all user input."
                        .to_string(),
                ),
                cve_id: None,
                cvss_score: Some(9.8),
                tags: vec![
                    "sql-injection".to_string(),
                    result.technique.to_string().to_lowercase().replace(' ', "-"),
                ],
                raw_output: serde_json::to_string(&result).unwrap_or_default(),
            })
            .collect()
    }
}
