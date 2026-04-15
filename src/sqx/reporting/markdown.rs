//! Markdown report generator.
//!
//! Output is suitable for pasting into GitHub issues, GitLab MRs,
//! Jira tickets, bug-bounty reports, and pentest deliverables.

use chrono::Utc;

use crate::sqx::pipeline::models::PipelineResult;

/// Markdown report generator.
pub struct MarkdownReport;

impl MarkdownReport {
    /// Generate a Markdown report from a pipeline result.
    pub fn generate(result: &PipelineResult) -> String {
        let mut md = String::with_capacity(4096);

        // ── Header ──────────────────────────────────────────────────────────
        md.push_str("# SQX SQL Injection Scan Report\n\n");
        md.push_str(&format!(
            "**Date:** {}\n\n",
            Utc::now().format("%Y-%m-%d %H:%M UTC")
        ));

        if let Some(ref profile) = result.profile {
            md.push_str(&format!("**Target:** `{}`\n\n", profile.url));

            if let Some(ref dbms) = profile.dbms_hint {
                md.push_str(&format!("**DBMS:** {}\n\n", dbms));
            }

            if let Some(ref waf) = profile.waf {
                md.push_str(&format!(
                    "**WAF Detected:** {} (confidence: {:.0}%)\n\n",
                    waf.name,
                    waf.confidence * 100.0
                ));
            }
        }

        // ── Summary table ────────────────────────────────────────────────────
        md.push_str("## Summary\n\n");
        md.push_str("| Metric | Value |\n|---|---|\n");
        md.push_str(&format!(
            "| Parameters tested | {} |\n",
            result.parameters_tested
        ));
        md.push_str(&format!(
            "| Vulnerabilities found | {} |\n",
            result.findings.len()
        ));
        md.push_str(&format!(
            "| Duration | {:.1}s |\n",
            result.elapsed_secs
        ));
        md.push_str(&format!(
            "| Total requests | {} |\n\n",
            result.total_requests
        ));

        if result.findings.is_empty() {
            md.push_str("**No SQL injection vulnerabilities detected.**\n");
            return md;
        }

        // ── Findings ─────────────────────────────────────────────────────────
        md.push_str("## Findings\n\n");

        let target_url = result
            .profile
            .as_ref()
            .map(|p| p.url.as_str())
            .unwrap_or("TARGET_URL");

        for (i, finding) in result.findings.iter().enumerate() {
            md.push_str(&format!(
                "### {}. {} — `{}`\n\n",
                i + 1,
                finding.technique,
                finding.parameter
            ));

            md.push_str(&format!(
                "- **Confidence:** {:.0}%\n",
                finding.confidence * 100.0
            ));

            if let Some(ref dbms) = finding.dbms_hint {
                md.push_str(&format!("- **DBMS:** {}\n", dbms));
            }

            md.push_str(&format!("- **Evidence:** {}\n", finding.evidence));
            md.push_str(&format!("- **Payload:** `{}`\n\n", finding.payload));

            md.push_str("**Reproduction:**\n\n");
            md.push_str(&format!(
                "```bash\ncurl -s '{}' --data-urlencode '{}={}'\n```\n\n",
                target_url, finding.parameter, finding.payload
            ));

            md.push_str("---\n\n");
        }

        // ── Remediation ───────────────────────────────────────────────────────
        md.push_str("## Remediation\n\n");
        md.push_str(
            "- Use parameterized queries / prepared statements for all database interactions\n",
        );
        md.push_str("- Implement input validation (allowlist approach)\n");
        md.push_str("- Apply principle of least privilege to database accounts\n");
        md.push_str(
            "- Deploy a Web Application Firewall (WAF) as an additional defense-in-depth layer\n",
        );
        md.push_str("- Enable database-level auditing and anomaly detection\n");

        md
    }
}
