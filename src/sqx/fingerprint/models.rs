use serde::{Deserialize, Serialize};
use std::time::Duration;

/// Complete behavioral profile of a scan target.
/// Built from ~10-15 benign probe requests before any injection testing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TargetProfile {
    /// Base URL tested
    pub url: String,
    /// Detected DBMS hint (from headers, error pages, behavior)
    pub dbms_hint: Option<String>,
    /// Detected WAF (from probe responses)
    pub waf: Option<WafFingerprint>,
    /// How the target responds to various inputs
    pub behavior: TargetBehavior,
    /// Timing characteristics
    pub timing: TimingProfile,
    /// Recommended scan strategy based on all observations
    pub strategy: ScanStrategy,
    /// Parameters discovered and their characteristics
    pub parameters: Vec<ParameterProfile>,
    /// Total probe requests used to build this profile
    pub probe_count: usize,
}

/// WAF identification result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WafFingerprint {
    pub name: String,
    /// 0.0 - 1.0
    pub confidence: f32,
    /// HTTP status when blocked (403, 406, 429, etc.)
    pub block_status: u16,
    /// Identifying string in block page
    pub block_signature: Option<String>,
    /// WAF-specific recommended tamper scripts
    pub recommended_tampers: Vec<String>,
}

/// How the target application behaves
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TargetBehavior {
    /// Does the target return different content for valid vs invalid input?
    pub content_varies: bool,
    /// Does the target return SQL errors in responses?
    pub reflects_errors: bool,
    /// Does the target use custom error pages (vs raw framework errors)?
    pub custom_error_pages: bool,
    /// Does the target redirect on errors?
    pub redirects_on_error: bool,
    /// Redirect target if redirects_on_error is true
    pub error_redirect_url: Option<String>,
    /// HTTP status code for normal response
    pub normal_status: u16,
    /// HTTP status code for invalid input
    pub invalid_input_status: u16,
    /// Does the response body contain the input value reflected back?
    pub reflects_input: bool,
    /// Content-Type of responses
    pub content_type: String,
    /// Approximate response body size for normal response
    pub normal_body_size: usize,
}

/// Timing characteristics of the target
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimingProfile {
    /// Mean response time from baseline probes
    pub mean_response: Duration,
    /// Standard deviation of response times
    pub stddev_response: Duration,
    /// Threshold for time-based detection: mean + 2*stddev
    pub time_threshold: Duration,
    /// Number of samples used
    pub samples: usize,
}

/// Scan strategy recommendation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanStrategy {
    /// Ordered list of techniques to try (most promising first)
    pub technique_order: Vec<String>,
    /// Should we use WAF bypass from the start?
    pub waf_bypass_required: bool,
    /// Recommended tamper chain names (empty if none needed)
    pub tamper_chain: Vec<String>,
    /// Recommended delay between requests (ms)
    pub recommended_delay_ms: u64,
    /// Can we use parallel requests?
    pub parallel_safe: bool,
    /// Maximum concurrent requests recommended
    pub max_concurrent: usize,
    /// Should time-based be skipped? (e.g., if target has high jitter)
    pub skip_time_based: bool,
    /// Use content-length comparison for boolean blind?
    pub use_content_length: bool,
    /// Use body hash comparison for boolean blind?
    pub use_body_hash: bool,
}

/// Profile of a single parameter
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParameterProfile {
    pub name: String,
    pub original_value: String,
    /// Is this parameter numeric?
    pub is_numeric: bool,
    /// Does modifying this parameter change the response?
    pub influences_output: bool,
    /// Is this parameter likely a primary key / record selector?
    pub likely_db_param: bool,
}
