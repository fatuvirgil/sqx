//! Data models: all structs, enums, and configs for the SQX engine.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::Duration;

/// Type of form for second-order flow analysis
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum FormType {
    Registration,
    Login,
    ProfileUpdate,
    GenericInput,
}

/// A candidate for second-order SQL injection
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecondOrderCandidate {
    pub source_url: String,
    /// Parameters and values for the source form (e.g. registration)
    pub source_form_data: HashMap<String, String>,
    /// The page where the data is eventually executed/reflected
    pub sink_url: String,
    /// The parameter name in source_form_data that is the injection point
    pub affected_param: String,
    pub form_type: FormType,
}

/// Result of an auto-provisioning attempt
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProvisioningResult {
    pub success: bool,
    pub username: String,
    pub password: String,
    pub message: String,
    /// The registration URL used
    pub registration_url: String,
}

/// SQL Injection test result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SqliTestResult {
    pub parameter: String,
    pub technique: SqliTechnique,
    pub confidence: f32,
    pub payload: String,
    pub evidence: String,
    pub dbms_hint: Option<String>,
    /// Injection context (boundary label) that was successful during detection.
    /// Used by extraction routines to reuse the correct payload wrapping.
    pub injection_context: Option<String>,
    /// The ID or title of the successful payload from the database (e.g. sqlmap test title).
    pub payload_id: Option<String>,
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
    /// Wordlist of common column names used when `information_schema` is unavailable.
    pub column_wordlist: Vec<String>,
}

impl Default for SchemaEnumerationConfig {
    fn default() -> Self {
        Self {
            technique: BlindTechnique::Boolean,
            max_tables: 50,
            max_columns_per_table: 50,
            max_name_length: 64,
            column_wordlist: DEFAULT_COLUMN_WORDLIST
                .iter()
                .map(|s| s.to_string())
                .collect(),
        }
    }
}

/// Default wordlist of common database column names for brute-force fallback.
pub const DEFAULT_COLUMN_WORDLIST: &[&str] = &[
    "id",
    "uuid",
    "guid",
    "pk",
    "sk",
    "username",
    "user",
    "user_name",
    "login",
    "email",
    "e_mail",
    "mail",
    "password",
    "pass",
    "passwd",
    "pwd",
    "pass_hash",
    "password_hash",
    "name",
    "first_name",
    "last_name",
    "fullname",
    "full_name",
    "surname",
    "given_name",
    "phone",
    "phone_number",
    "mobile",
    "cell",
    "fax",
    "telephone",
    "address",
    "street",
    "city",
    "state",
    "zip",
    "zipcode",
    "postal_code",
    "country",
    "region",
    "age",
    "dob",
    "date_of_birth",
    "birthdate",
    "birth_date",
    "gender",
    "sex",
    "title",
    "job_title",
    "position",
    "department",
    "company",
    "organization",
    "org",
    "role",
    "group",
    "level",
    "rank",
    "status",
    "active",
    "enabled",
    "disabled",
    "banned",
    "avatar",
    "image",
    "photo",
    "profile_pic",
    "picture",
    "bio",
    "description",
    "summary",
    "about",
    "notes",
    "comment",
    "comments",
    "created_at",
    "created_on",
    "create_date",
    "creation_date",
    "date_created",
    "updated_at",
    "updated_on",
    "update_date",
    "last_updated",
    "modified_at",
    "timestamp",
    "deleted_at",
    "removed_at",
    "archived_at",
    "token",
    "api_token",
    "access_token",
    "refresh_token",
    "auth_token",
    "verify_token",
    "secret",
    "api_secret",
    "client_secret",
    "app_secret",
    "consumer_secret",
    "key",
    "api_key",
    "public_key",
    "private_key",
    "client_key",
    "consumer_key",
    "session",
    "session_id",
    "sessid",
    "sid",
    "phpsessid",
    "asp_session",
    "cookie",
    "cookie_id",
    "tracking_id",
    "visitor_id",
    "analytics_id",
    "ip",
    "ip_address",
    "last_ip",
    "remote_addr",
    "user_agent",
    "ua",
    "browser",
    "url",
    "link",
    "redirect",
    "return_url",
    "callback",
    "next",
    "referer",
    "referrer",
    "type",
    "kind",
    "category",
    "cat",
    "tag",
    "tags",
    "label",
    "labels",
    "code",
    "country_code",
    "lang",
    "language",
    "locale",
    "currency",
    "ccy",
    "price",
    "cost",
    "amount",
    "total",
    "subtotal",
    "discount",
    "tax",
    "fee",
    "quantity",
    "qty",
    "count",
    "cnt",
    "num",
    "number",
    "size",
    "weight",
    "volume",
    "score",
    "points",
    "rating",
    "rank",
    "priority",
    "order",
    "sort",
    "position",
    "seq",
    "content",
    "body",
    "text",
    "message",
    "msg",
    "subject",
    "topic",
    "thread",
    "data",
    "value",
    "val",
    "v",
    "meta",
    "metadata",
    "extra",
    "options",
    "settings",
    "config",
    "configuration",
    "prefs",
    "preferences",
    "params",
    "parameters",
    "args",
    "file",
    "filename",
    "file_name",
    "path",
    "filepath",
    "file_path",
    "dir",
    "directory",
    "ext",
    "extension",
    "mime",
    "mimetype",
    "mime_type",
    "content_type",
    "format",
    "hash",
    "checksum",
    "md5",
    "sha1",
    "sha256",
    "version",
    "ver",
    "revision",
    "rev",
    "build",
    "release",
    "edition",
    "owner",
    "owner_id",
    "user_id",
    "admin_id",
    "manager_id",
    "parent_id",
    "child_id",
    "account",
    "account_id",
    "account_number",
    "acc_num",
    "iban",
    "swift",
    "routing",
    "card",
    "card_num",
    "card_number",
    "cc_num",
    "cc_number",
    "cvv",
    "cvv2",
    "expiry",
    "balance",
    "credit",
    "debit",
    "deposit",
    "withdrawal",
    "transaction_id",
    "txn_id",
    "product",
    "product_id",
    "item",
    "item_id",
    "sku",
    "upc",
    "ean",
    "isbn",
    "order_id",
    "invoice_id",
    "payment_id",
    "subscription_id",
    "plan_id",
    "project_id",
    "page",
    "page_id",
    "post_id",
    "article_id",
    "blog_id",
    "forum_id",
    "thread_id",
    "status_id",
    "state_id",
    "type_id",
    "category_id",
    "role_id",
    "group_id",
];

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
    /// Second-order SQL injection (payload stored in DB, executed later)
    SecondOrder,
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
            SqliTechnique::SecondOrder => write!(f, "Second-order"),
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

/// Profile of a printable column discovered during UNION-based testing.
#[derive(Debug, Clone, Default)]
pub struct ColumnProfile {
    pub index: usize,
    /// True if the column requires a type-cast wrapper (e.g. CAST/TO_CHAR)
    /// because a plain string literal triggered a type-mismatch error.
    pub needs_cast: bool,
}

/// Blind extraction technique
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub enum BlindTechnique {
    Boolean, // TRUE/FALSE based
    Time,    // Time delay based
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
        self.cancelled
            .store(true, std::sync::atomic::Ordering::SeqCst);
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

    pub fn update_progress(
        &mut self,
        row: usize,
        char_pos: usize,
        partial: String,
        requests: usize,
    ) {
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

/// Stealth / evasion settings applied to every HTTP request.
#[derive(Debug, Clone)]
pub struct StealthConfig {
    /// Rotate User-Agent randomly from a built-in pool of real browser UAs.
    pub ua_rotation: bool,
    /// Add realistic browser headers (Accept, Accept-Language, Sec-Fetch-*, …).
    pub mimic_browser_headers: bool,
    /// Add ±jitter_pct% random jitter to every inter-request delay.
    /// 0 = no jitter, 50 = ±50%.
    pub jitter_pct: u64,
    /// Spoof Referer header with the target's own origin.
    pub spoof_referer: bool,
}

impl Default for StealthConfig {
    fn default() -> Self {
        Self {
            ua_rotation: true,
            mimic_browser_headers: true,
            jitter_pct: 30,
            spoof_referer: true,
        }
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
    /// Accept invalid TLS certificates/hostnames. Disabled by default.
    pub insecure_tls: bool,
    /// Sleep duration in seconds for time-based blind detection (default: 3)
    pub sleep_duration_secs: u64,
    /// AI payload advisor configuration (disabled by default)
    pub ai_advisor: crate::sqx::ai_advisor::AiAdvisorConfig,
    /// Stealth / WAF-evasion settings
    pub stealth: StealthConfig,
    /// Common parameter names used for fuzzing URLs without query strings.
    pub param_wordlist: Vec<String>,
    /// Proxy URL for HTTP/SOCKS5 (e.g. socks5://127.0.0.1:9050)
    pub proxy: Option<String>,
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
            user_agent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36".to_string(),
            insecure_tls: false,
            sleep_duration_secs: 3,
            ai_advisor: crate::sqx::ai_advisor::AiAdvisorConfig::default(),
            stealth: StealthConfig::default(),
            param_wordlist: vec![
                "id", "page", "user", "product", "cat", "category",
                "name", "search", "query", "sort", "order", "filter",
                "type", "status", "action", "view", "format", "limit",
                "offset", "start", "end", "from", "to", "date",
                "year", "month", "day", "lang", "locale", "region",
                "country", "currency", "price", "amount", "qty", "quantity",
                "code", "token", "api_key", "key", "secret", "auth",
                "session", "redirect", "url", "link", "path", "file",
                "filename", "dir", "directory", "folder", "ref", "referer",
                "source", "medium", "campaign", "term", "content", "callback",
                "next", "prev", "step", "tab", "section", "module",
                "component", "plugin", "theme", "template", "layout", "skin",
                "version", "v", "revision", "build", "debug", "test",
                "mode", "env", "environment", "channel", "platform", "device",
                "os", "browser", "engine", "resolution", "width", "height",
                "depth", "color", "encoding", "charset", "compress", "zip",
                "password", "pass", "pwd", "email", "mail", "phone",
                "mobile", "fax", "address", "city", "state", "zipcode",
                "postal", "latitude", "lat", "longitude", "lng", "lon",
                "altitude", "alt",
            ].into_iter().map(|s| s.to_string()).collect(),
            proxy: None,
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
