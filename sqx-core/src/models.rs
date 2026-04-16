//! Shared finding models used across the SQX engine.

use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub id: String,
    pub timestamp: DateTime<Utc>,
    pub tool: String,
    pub severity: Severity,
    pub confidence: Confidence,
    pub title: String,
    pub description: String,
    pub url: String,
    pub request_id: Option<String>,
    pub evidence: Option<String>,
    pub remediation: Option<String>,
    pub cve_id: Option<String>,
    pub cvss_score: Option<f32>,
    pub tags: Vec<String>,
    pub raw_output: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Confidence {
    Certain,
    Firm,
    Tentative,
}
