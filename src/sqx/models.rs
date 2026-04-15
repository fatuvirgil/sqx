//! Data models: all structs, enums, and configs for the SQX engine.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::Duration;

/// SQL Injection test result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SqliTestResult {
    pub parameter: String,
    pub technique: SqliTechnique,
    pub confidence: f32,
    pub payload: String,
    pub evidence: String,
    pub dbms_hint: Option<String>,
}

/// Extracted information from SQL injection
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SqliInfoExtraction {
    pub version: Option<String>,
    pub user: Option<String>,
    pub database: Option<String>,
    pub hostname: Option<String>,
    pub tables: Vec<String>,
    pub columns: HashMap<String, Vec<String>>, // table -> columns
}

/// Schema enumeration configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SchemaEnumerationConfig {
    pub technique: BlindTechnique,
    pub max_tables: usize,
    pub max_columns_per_table: usize,
    pub max_name_length: usize,
}

impl Default for SchemaEnumerationConfig {
    fn default() -> Self {
        Self {
            technique: BlindTechnique::Boolean,
            max_tables: 50,
            max_columns_per_table: 50,
            max_name_length: 64,
        }
    }
}

/// Progress for schema enumeration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SchemaEnumerationProgress {
    pub phase: String, // "tables" or "columns"
    pub current_item: String,
    pub items_found: usize,
    pub total_requests: usize,
    pub status: ExtractionStatus,
}

/// SQL Injection detection techniques
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
pub enum SqliTechnique {
    ErrorBased,
    BooleanBlind,
    TimeBased,
    UnionBased,
    StackedQueries,
    OutOfBand,
    /// Server-side code injection (PHP eval, create_function, etc.) — not SQLi
    CodeInjection,
}

impl std::fmt::Display for SqliTechnique {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SqliTechnique::ErrorBased => write!(f, "Error-based"),
            SqliTechnique::BooleanBlind => write!(f, "Boolean-based blind"),
            SqliTechnique::TimeBased => write!(f, "Time-based blind"),
            SqliTechnique::UnionBased => write!(f, "Union-based"),
            SqliTechnique::StackedQueries => write!(f, "Stacked queries"),
            SqliTechnique::OutOfBand => write!(f, "Out-of-band"),
            SqliTechnique::CodeInjection => write!(f, "Code Injection"),
        }
    }
}

/// Data extracted from UNION-based SQL injection
#[derive(Debug, Clone, Default)]
pub struct UnionExtractedData {
    pub version: Option<String>,
    pub user: Option<String>,
    pub database: Option<String>,
    pub dbms_hint: Option<String>,
}

/// Blind extraction technique
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub enum BlindTechnique {
    Boolean,  // TRUE/FALSE based
    Time,     // Time delay based
}

/// Result of blind data extraction
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct BlindExtractionResult {
    pub extracted_values: Vec<String>,
    pub total_requests: usize,
    pub extraction_time_secs: u64,
    pub technique_used: String,
}

/// Progress update for blind extraction
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlindExtractionProgress {
    pub current_value_index: usize,
    pub current_char_index: usize,
    pub extracted_so_far: String,
    pub total_requests: usize,
    pub status: ExtractionStatus,
}

/// Extraction status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ExtractionStatus {
    Running,
    Completed,
    Stopped,
    Error(String),
}

/// Configuration for blind extraction with custom query
#[derive(Debug, Clone)]
pub struct BlindExtractionConfig {
    pub target_table: String,
    pub target_column: String,
    pub custom_query: Option<String>,
    pub where_clause: Option<String>,
    pub max_rows: usize,
    pub max_length_per_value: usize,
    pub technique: BlindTechnique,
}

impl Default for BlindExtractionConfig {
    fn default() -> Self {
        Self {
            target_table: "users".to_string(),
            target_column: "password".to_string(),
            custom_query: None,
            where_clause: None,
            max_rows: 1,
            max_length_per_value: 50,
            technique: BlindTechnique::Boolean,
        }
    }
}

/// Cancellation token for stopping extraction
#[derive(Debug, Clone)]
pub struct CancellationToken {
    pub(crate) cancelled: std::sync::Arc<std::sync::atomic::AtomicBool>,
}

impl CancellationToken {
    pub fn new() -> Self {
        Self {
            cancelled: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
        }
    }

    pub fn cancel(&self) {
        self.cancelled.store(true, std::sync::atomic::Ordering::SeqCst);
    }

    pub fn is_cancelled(&self) -> bool {
        self.cancelled.load(std::sync::atomic::Ordering::SeqCst)
    }
}

impl Default for CancellationToken {
    fn default() -> Self {
        Self::new()
    }
}

/// Stored state for resumable extraction
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExtractionState {
    pub id: String,
    pub url: String,
    pub param: String,
    pub technique: BlindTechnique,
    pub target_table: String,
    pub target_column: String,
    pub custom_query: Option<String>,
    pub where_clause: Option<String>,
    pub current_row: usize,
    pub current_char: usize,
    pub partial_value: String,
    pub extracted_values: Vec<String>,
    pub total_requests: usize,
    pub status: ExtractionStatus,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

impl ExtractionState {
    pub fn new(
        url: String,
        param: String,
        technique: BlindTechnique,
        config: &BlindExtractionConfig,
    ) -> Self {
        let now = chrono::Utc::now();
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            url,
            param,
            technique,
            target_table: config.target_table.clone(),
            target_column: config.target_column.clone(),
            custom_query: config.custom_query.clone(),
            where_clause: config.where_clause.clone(),
            current_row: 0,
            current_char: 0,
            partial_value: String::new(),
            extracted_values: Vec::new(),
            total_requests: 0,
            status: ExtractionStatus::Running,
            created_at: now,
            updated_at: now,
        }
    }

    pub fn update_progress(&mut self, row: usize, char_pos: usize, partial: String, requests: usize) {
        self.current_row = row;
        self.current_char = char_pos;
        self.partial_value = partial;
        self.total_requests = requests;
        self.updated_at = chrono::Utc::now();
    }

    pub fn complete_value(&mut self, value: String) {
        self.extracted_values.push(value);
        self.current_char = 0;
        self.partial_value.clear();
        self.updated_at = chrono::Utc::now();
    }

    pub fn mark_completed(&mut self) {
        self.status = ExtractionStatus::Completed;
        self.updated_at = chrono::Utc::now();
    }

    pub fn mark_stopped(&mut self) {
        self.status = ExtractionStatus::Stopped;
        self.updated_at = chrono::Utc::now();
    }
}

/// Configuration for SQL injection scanning
#[derive(Debug, Clone)]
pub struct SqliConfig {
    pub timeout_secs: u64,
    pub max_retries: u32,
    pub techniques: Vec<SqliTechnique>,
    pub delay_ms: u64,
    pub user_agent: String,
    /// Sleep duration in seconds for time-based blind detection (default: 3)
    pub sleep_duration_secs: u64,
    /// AI payload advisor configuration (disabled by default)
    pub ai_advisor: crate::sqx::ai_advisor::AiAdvisorConfig,
}

impl Default for SqliConfig {
    fn default() -> Self {
        Self {
            timeout_secs: 30,
            max_retries: 3,
            techniques: vec![
                SqliTechnique::ErrorBased,
                SqliTechnique::BooleanBlind,
                SqliTechnique::TimeBased,
                SqliTechnique::UnionBased,
                SqliTechnique::StackedQueries,
            ],
            delay_ms: 100,
            user_agent: "Intelexia/1.0".to_string(),
            sleep_duration_secs: 3,
            ai_advisor: crate::sqx::ai_advisor::AiAdvisorConfig::default(),
        }
    }
}

/// HTTP response details
#[derive(Debug, Clone)]
pub struct HttpResponse {
    pub status: u16,
    pub body: String,
    pub duration: Duration,
    /// Response headers (lowercase keys)
    pub headers: std::collections::HashMap<String, String>,
}

impl Default for HttpResponse {
    fn default() -> Self {
        Self {
            status: 0,
            body: String::new(),
            duration: Duration::ZERO,
            headers: std::collections::HashMap::new(),
        }
    }
}
