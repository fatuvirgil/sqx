use anyhow::Result;
use serde::{Deserialize, Serialize};

use crate::sqx::{
    detector::SqliDetector,
    models::{BlindExtractionConfig, BlindExtractionResult, BlindTechnique},
};

/// Request for executing a scalar custom SQL query/expression through an
/// already-confirmed injectable parameter.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CustomSqlRequest {
    pub query: String,
    pub technique: BlindTechnique,
    pub max_length: usize,
    pub boundary_hint: Option<String>,
    pub payload_id: Option<String>,
}

impl Default for CustomSqlRequest {
    fn default() -> Self {
        Self {
            query: "SELECT version()".to_string(),
            technique: BlindTechnique::Boolean,
            max_length: 256,
            boundary_hint: None,
            payload_id: None,
        }
    }
}

/// Result of a custom scalar SQL execution workflow.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CustomSqlResult {
    pub query: String,
    pub value: Option<String>,
    pub total_requests: usize,
    pub technique_used: String,
}

impl CustomSqlResult {
    fn from_extraction(query: String, extraction: BlindExtractionResult) -> Self {
        Self {
            query,
            value: extraction.extracted_values.first().cloned(),
            total_requests: extraction.total_requests,
            technique_used: extraction.technique_used,
        }
    }
}

impl SqliDetector {
    /// Execute a scalar SQL query or expression using the blind/time-based
    /// extraction engine. This keeps operator workflows out of the CLI layer.
    pub async fn execute_custom_sql(
        &self,
        url: &str,
        param: &str,
        original_value: &str,
        dbms: &str,
        request: &CustomSqlRequest,
    ) -> Result<CustomSqlResult> {
        let extraction_cfg = BlindExtractionConfig {
            target_table: String::new(),
            target_column: String::new(),
            custom_query: Some(request.query.clone()),
            where_clause: None,
            max_rows: 1,
            max_length_per_value: request.max_length,
            technique: request.technique,
        };

        let extraction = match request.technique {
            BlindTechnique::Boolean => {
                let baseline = self.send_request(url).await?;
                self.extract_data_blind(
                    url,
                    param,
                    original_value,
                    dbms,
                    &extraction_cfg,
                    &baseline,
                    request.boundary_hint.as_deref(),
                    request.payload_id.as_deref(),
                    None,
                    None,
                )
                .await?
            }
            BlindTechnique::Time => {
                self.extract_data_time_based(
                    url,
                    param,
                    original_value,
                    dbms,
                    &extraction_cfg,
                    request.boundary_hint.as_deref(),
                    request.payload_id.as_deref(),
                    None,
                    None,
                )
                .await?
            }
        };

        Ok(CustomSqlResult::from_extraction(
            request.query.clone(),
            extraction,
        ))
    }
}
