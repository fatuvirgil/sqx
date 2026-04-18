//! PipelineResult — aggregated output of a full SQX scan run.

use serde::{Deserialize, Serialize};

use crate::sqx::{fingerprint::TargetProfile, models::SqliTestResult};

/// Complete output of a `SqliDetector::scan_smart()` run, enriched with
/// timing and coverage statistics needed by report generators.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PipelineResult {
    /// All confirmed findings from the scan.
    pub findings: Vec<SqliTestResult>,
    /// Behavioral fingerprint of the target (None if fingerprinting was skipped).
    pub profile: Option<TargetProfile>,
    /// Number of parameters that were tested.
    pub parameters_tested: usize,
    /// Number of parameters for which at least one vulnerability was confirmed.
    pub parameters_vulnerable: usize,
    /// Total HTTP requests issued during the scan (probes + injection tests).
    pub total_requests: usize,
    /// Wall-clock seconds from scan start to scan end.
    pub elapsed_secs: f64,
}

impl PipelineResult {
    /// Convenience constructor — computes `parameters_vulnerable` automatically.
    pub fn new(
        findings: Vec<SqliTestResult>,
        profile: Option<TargetProfile>,
        parameters_tested: usize,
        total_requests: usize,
        elapsed_secs: f64,
    ) -> Self {
        use std::collections::HashSet;
        let parameters_vulnerable = findings
            .iter()
            .map(|f| f.parameter.clone())
            .collect::<HashSet<String>>()
            .len();

        Self {
            findings,
            profile,
            parameters_tested,
            parameters_vulnerable,
            total_requests,
            elapsed_secs,
        }
    }
}
