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
        let target_url = result
            .profile
            .as_ref()
            .map(|p| p.url.as_str())
            .unwrap_or("unknown");

        let artifacts = Self::build_artifacts(result, target_url);
        let results: Vec<Value> = result
            .findings
            .iter()
            .map(|f| Self::finding_to_result(f, target_url))
            .collect();

        serde_json::json!({
            "$schema": "https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [{
                "tool": Self::tool_component(),
                "taxonomies": [Self::owasp_taxonomy()],
                "artifacts": artifacts,
                "results": results,
                "invocations": [Self::build_invocation(result)],
                "automationDetails": {
                    "id": format!("sqx-scan-{}", uuid::Uuid::new_v4()),
                    "guid": uuid::Uuid::new_v4().to_string(),
                    "description": {
                        "text": format!(
                            "SQX SQL injection scan against {}. {} parameters tested, {} vulnerable.",
                            target_url, result.parameters_tested, result.parameters_vulnerable
                        )
                    }
                }
            }]
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
                "taxonomies": [Self::owasp_taxonomy()],
                "artifacts": [Self::artifact_for_url(target_url)],
                "results": results,
                "invocations": [{
                    "executionSuccessful": true,
                    "properties": {
                        "findingsCount": findings.len(),
                    }
                }],
            }]
        })
    }

    /// Generate SARIF from a batch scan where each finding set has its own URL.
    pub fn from_batch(batch: &[(String, Vec<SqliTestResult>)]) -> Value {
        let mut all_artifacts = Vec::new();
        let mut all_results = Vec::new();
        let mut total_findings = 0usize;

        for (url, findings) in batch {
            if !findings.is_empty() {
                all_artifacts.push(Self::artifact_for_url(url));
                for f in findings {
                    all_results.push(Self::finding_to_result(f, url));
                }
                total_findings += findings.len();
            }
        }

        serde_json::json!({
            "$schema": "https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [{
                "tool": Self::tool_component(),
                "taxonomies": [Self::owasp_taxonomy()],
                "artifacts": all_artifacts,
                "results": all_results,
                "invocations": [{
                    "executionSuccessful": true,
                    "properties": {
                        "findingsCount": total_findings,
                        "targetsScanned": batch.len(),
                    }
                }],
            }]
        })
    }

    // ── Private helpers ──────────────────────────────────────────────────────

    fn build_artifacts(result: &PipelineResult, target_url: &str) -> Vec<Value> {
        let mut artifacts = vec![Self::artifact_for_url(target_url)];
        // Add any additional URLs from findings if they differ from target_url
        // (e.g. batch scans or auto-scanned pages)
        // For now, single artifact covers the primary target.
        let _ = result; // reserved for future expansion
        artifacts
    }

    fn artifact_for_url(url: &str) -> Value {
        serde_json::json!({
            "location": { "uri": url },
            "roles": ["analyzed"],
            "mimeType": "text/html"
        })
    }

    fn build_invocation(result: &PipelineResult) -> Value {
        let profile = result.profile.as_ref();
        serde_json::json!({
            "executionSuccessful": true,
            "properties": {
                "parametersScanned":    result.parameters_tested,
                "parametersVulnerable": result.parameters_vulnerable,
                "totalRequests":        result.total_requests,
                "elapsedSeconds":       result.elapsed_secs,
                "dbmsHint":             profile.and_then(|p| p.dbms_hint.clone()),
                "wafDetected":          profile.and_then(|p| p.waf.as_ref().map(|w| w.name.clone())),
                "strategy":             profile.map(|p| p.strategy.technique_order.clone()),
                "tamperChain":          profile.map(|p| p.strategy.tamper_chain.clone()),
            }
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
                        "fullDescription": { "text": "The application returns database error messages that reveal an injectable SQL query structure." },
                        "help": {
                            "text": "Use parameterized queries/prepared statements. Validate and sanitize all user input before including it in SQL queries.",
                            "markdown": "Use **parameterized queries** / **prepared statements**. Validate and sanitize all user input before including it in SQL queries."
                        },
                        "helpUri": "https://owasp.org/www-community/attacks/SQL_Injection",
                        "defaultConfiguration": { "level": "error" },
                        "relationships": [{
                            "target": { "id": "A03", "index": 2, "toolComponent": { "name": "OWASP Top 10 2021" } },
                            "kinds": ["relevant"]
                        }]
                    },
                    {
                        "id": "SQX002",
                        "name": "SqlInjection/BooleanBlind",
                        "shortDescription": { "text": "Boolean-based blind SQL Injection" },
                        "fullDescription": { "text": "The application behaves differently (content/response changes) depending on whether a TRUE or FALSE SQL condition is injected." },
                        "help": {
                            "text": "Use parameterized queries/prepared statements. Avoid constructing SQL from user input.",
                            "markdown": "Use **parameterized queries** / **prepared statements**. Avoid constructing SQL from user input."
                        },
                        "helpUri": "https://owasp.org/www-community/attacks/Blind_SQL_Injection",
                        "defaultConfiguration": { "level": "error" },
                        "relationships": [{
                            "target": { "id": "A03", "index": 2, "toolComponent": { "name": "OWASP Top 10 2021" } },
                            "kinds": ["relevant"]
                        }]
                    },
                    {
                        "id": "SQX003",
                        "name": "SqlInjection/TimeBased",
                        "shortDescription": { "text": "Time-based blind SQL Injection" },
                        "fullDescription": { "text": "The application delays its response when a time-delay SQL payload is injected, confirming query execution." },
                        "help": {
                            "text": "Use parameterized queries/prepared statements. Avoid dynamic SQL concatenation.",
                            "markdown": "Use **parameterized queries** / **prepared statements**. Avoid dynamic SQL concatenation."
                        },
                        "helpUri": "https://owasp.org/www-community/attacks/Blind_SQL_Injection",
                        "defaultConfiguration": { "level": "error" },
                        "relationships": [{
                            "target": { "id": "A03", "index": 2, "toolComponent": { "name": "OWASP Top 10 2021" } },
                            "kinds": ["relevant"]
                        }]
                    },
                    {
                        "id": "SQX004",
                        "name": "SqlInjection/UnionBased",
                        "shortDescription": { "text": "Union-based SQL Injection" },
                        "fullDescription": { "text": "The application reflects the results of an injected UNION SELECT query in its response, allowing direct data extraction." },
                        "help": {
                            "text": "Use parameterized queries/prepared statements. Limit database privileges and apply least-privilege principles.",
                            "markdown": "Use **parameterized queries** / **prepared statements**. Limit database privileges and apply least-privilege principles."
                        },
                        "helpUri": "https://owasp.org/www-community/attacks/SQL_Injection",
                        "defaultConfiguration": { "level": "error" },
                        "relationships": [{
                            "target": { "id": "A03", "index": 2, "toolComponent": { "name": "OWASP Top 10 2021" } },
                            "kinds": ["relevant"]
                        }]
                    },
                    {
                        "id": "SQX005",
                        "name": "SqlInjection/StackedQueries",
                        "shortDescription": { "text": "Stacked-queries SQL Injection" },
                        "fullDescription": { "text": "The application executes multiple SQL statements separated by semicolons, allowing arbitrary command execution." },
                        "help": {
                            "text": "Disable stacked queries in the database driver if not needed. Use parameterized queries.",
                            "markdown": "Disable stacked queries in the database driver if not needed. Use **parameterized queries**."
                        },
                        "helpUri": "https://owasp.org/www-community/attacks/SQL_Injection",
                        "defaultConfiguration": { "level": "error" },
                        "relationships": [{
                            "target": { "id": "A03", "index": 2, "toolComponent": { "name": "OWASP Top 10 2021" } },
                            "kinds": ["relevant"]
                        }]
                    },
                    {
                        "id": "SQX006",
                        "name": "SqlInjection/OutOfBand",
                        "shortDescription": { "text": "Out-of-band SQL Injection" },
                        "fullDescription": { "text": "The application causes the database to make external network requests (DNS/HTTP) confirming code execution." },
                        "help": {
                            "text": "Restrict outbound network access from the database server. Use parameterized queries.",
                            "markdown": "Restrict outbound network access from the database server. Use **parameterized queries**."
                        },
                        "helpUri": "https://owasp.org/www-community/attacks/SQL_Injection",
                        "defaultConfiguration": { "level": "error" },
                        "relationships": [{
                            "target": { "id": "A03", "index": 2, "toolComponent": { "name": "OWASP Top 10 2021" } },
                            "kinds": ["relevant"]
                        }]
                    },
                    {
                        "id": "SQX007",
                        "name": "CodeInjection/ServerSide",
                        "shortDescription": { "text": "Server-side code injection" },
                        "fullDescription": { "text": "The application evaluates user input as server-side code (e.g. PHP eval, create_function), enabling remote code execution." },
                        "help": {
                            "text": "Never pass user input to eval(), create_function(), or similar code-execution primitives. Use safe APIs.",
                            "markdown": "Never pass user input to `eval()`, `create_function()`, or similar code-execution primitives. Use safe APIs."
                        },
                        "helpUri": "https://owasp.org/www-community/attacks/Code_Injection",
                        "defaultConfiguration": { "level": "error" },
                        "relationships": [{
                            "target": { "id": "A03", "index": 2, "toolComponent": { "name": "OWASP Top 10 2021" } },
                            "kinds": ["relevant"]
                        }]
                    }
                ]
            }
        })
    }

    fn owasp_taxonomy() -> Value {
        serde_json::json!({
            "name": "OWASP Top 10 2021",
            "version": "2021",
            "informationUri": "https://owasp.org/Top10/",
            "taxa": [
                { "id": "A01", "name": "Broken Access Control" },
                { "id": "A02", "name": "Cryptographic Failures" },
                { "id": "A03", "name": "Injection" },
                { "id": "A04", "name": "Insecure Design" },
                { "id": "A05", "name": "Security Misconfiguration" },
                { "id": "A06", "name": "Vulnerable and Outdated Components" },
                { "id": "A07", "name": "Identification and Authentication Failures" },
                { "id": "A08", "name": "Software and Data Integrity Failures" },
                { "id": "A09", "name": "Security Logging and Monitoring Failures" },
                { "id": "A10", "name": "Server-Side Request Forgery (SSRF)" }
            ]
        })
    }

    pub(crate) fn finding_to_result(finding: &SqliTestResult, url: &str) -> Value {
        let (rule_id, level) = Self::technique_meta(&finding.technique);
        let encoded_payload = Self::encode_for_curl(&finding.payload);
        let curl_cmd = format!("curl -s '{}' --data-urlencode '{}={}'", url, finding.parameter, encoded_payload);

        serde_json::json!({
            "ruleId": rule_id,
            "ruleIndex": Self::rule_index(rule_id),
            "level": level,
            "message": {
                "text": format!(
                    "SQL Injection ({}) detected in parameter '{}'. Confidence: {:.0}%. {}",
                    finding.technique,
                    finding.parameter,
                    finding.confidence * 100.0,
                    finding.evidence
                ),
                "markdown": format!(
                    "**SQL Injection ({})** detected in parameter `{}`.\n\n- **Confidence:** {:.0}%\n- **Evidence:** {}\n- **DBMS Hint:** {}\n",
                    finding.technique,
                    finding.parameter,
                    finding.confidence * 100.0,
                    finding.evidence,
                    finding.dbms_hint.as_deref().unwrap_or("N/A")
                )
            },
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": { "uri": url, "description": { "text": "Scanned URL" } }
                },
                "logicalLocations": [{
                    "fullyQualifiedName": finding.parameter,
                    "name": finding.parameter,
                    "kind": "parameter"
                }]
            }],
            "codeFlows": [{
                "threadFlows": [{
                    "locations": [
                        {
                            "location": {
                                "physicalLocation": {
                                    "artifactLocation": { "uri": url }
                                },
                                "message": { "text": format!("Inject payload into parameter '{}'", finding.parameter) }
                            },
                            "kinds": ["taint_source"],
                            "state": { "payload": finding.payload }
                        },
                        {
                            "location": {
                                "physicalLocation": {
                                    "artifactLocation": { "uri": url }
                                },
                                "message": { "text": finding.evidence.clone() }
                            },
                            "kinds": ["taint_sink"],
                            "state": { "technique": finding.technique.to_string() }
                        }
                    ]
                }]
            }],
            "relatedLocations": [{
                "id": 1,
                "physicalLocation": {
                    "artifactLocation": { "uri": url }
                },
                "message": {
                    "text": format!("Payload: {}", finding.payload)
                }
            }],
            "properties": {
                "confidence": finding.confidence,
                "technique": finding.technique.to_string(),
                "payload": finding.payload,
                "evidence": finding.evidence,
                "dbmsHint": finding.dbms_hint,
                "injectionContext": finding.injection_context,
                "reproduction": {
                    "curl": curl_cmd
                }
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
            SqliTechnique::SecondOrder    => ("SQX008", "error"),
            SqliTechnique::CodeInjection  => ("SQX007", "error"),
        }
    }

    fn rule_index(rule_id: &str) -> usize {
        match rule_id {
            "SQX001" => 0,
            "SQX002" => 1,
            "SQX003" => 2,
            "SQX004" => 3,
            "SQX005" => 4,
            "SQX006" => 5,
            "SQX007" => 6,
            "SQX008" => 7,
            _ => 0,
        }
    }

    fn encode_for_curl(payload: &str) -> String {
        // Simple escaping for curl command display: replace single quotes with unicode apostrophe
        // to avoid shell escaping issues in the reproduction string.
        payload.replace('\'', "\u{2019}")
    }
}
