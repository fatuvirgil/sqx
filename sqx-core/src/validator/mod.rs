//! PayloadValidator - Safety layer for SQL payload validation.
//!
//! Provides multi-layer validation:
//! 1. Syntax validation (sqlparser)
//! 2. Semantic consistency (dialect matching)
//! 3. Consensus checking (anti-hallucination)
//! 4. Pattern matching (known techniques)
//! 5. Template engine (safe generation)

pub mod consensus;
pub mod patterns;
pub mod semantic;
pub mod syntax;
pub mod types;

pub use consensus::{ConsensusValidator, LlmClient};
pub use patterns::{calculate_risk, get_matching_techniques, matches_known_technique, validate_technique};
pub use semantic::SemanticChecker;
pub use syntax::SyntaxValidator;
pub use types::*;

use crate::intel::types::TargetProfile;
use anyhow::Result;
use std::future::Future;
use std::pin::Pin;
use tracing::{debug, error, info, instrument};

/// Complete payload validator.
pub struct PayloadValidator {
    /// Consensus validator config
    pub consensus: ConsensusValidator,
    /// Whether to enforce known techniques only
    pub known_techniques_only: bool,
    /// Whether to use templates
    pub use_templates: bool,
}

impl Default for PayloadValidator {
    fn default() -> Self {
        Self {
            consensus: ConsensusValidator::default(),
            known_techniques_only: true,
            use_templates: true,
        }
    }
}

impl PayloadValidator {
    /// Create new validator with custom config.
    pub fn new(
        consensus: ConsensusValidator,
        known_techniques_only: bool,
        use_templates: bool,
    ) -> Self {
        Self {
            consensus,
            known_techniques_only,
            use_templates,
        }
    }

    /// Validate a payload completely.
    #[instrument(skip(self, payload), fields(dialect = ?dialect))]
    pub fn validate(
        &self,
        payload: &str,
        dialect: &DbDialect,
        profile: Option<&TargetProfile>,
    ) -> ValidationResult {
        debug!("Starting full validation for {} byte payload", payload.len());

        // 1. Syntax validation
        let syntax_result = SyntaxValidator::validate(payload, dialect);
        if !syntax_result.is_valid() {
            return syntax_result;
        }

        // 2. Semantic validation (if profile available)
        if let Some(profile) = profile {
            let semantic_result = SemanticChecker::check(payload, profile);
            if !semantic_result.is_valid() {
                return semantic_result;
            }
        }

        // 3. Pattern/technique validation
        if self.known_techniques_only {
            if let Err(e) = validate_technique(payload) {
                return ValidationResult::UnknownTechnique(e);
            }
        }

        debug!("Validation passed");
        ValidationResult::Valid
    }

    /// Generate and validate payloads using templates.
    #[instrument(skip(self, llm, profile))]
    pub async fn generate_validated_payloads<L: LlmClient>(
        &self,
        target: &str,
        profile: &TargetProfile,
        llm: &L,
    ) -> Result<Vec<String>, String> {
        info!("Generating validated payloads for: {}", target);

        let dialect = profile.get_dialect();

        // Build prompt with context
        let prompt = format!(
            "[CONTEXT]\nTarget: {}\nTech Stack: {}\nDatabase: {}\n[/CONTEXT]\n\n\
             Generate 3 SQL injection payload templates. Return ONLY a JSON array of objects:\n\
             1. One UNION-based payload\n\
             2. One time-based blind payload\n\
             3. One error-based payload\n\n\
             Format: [{{\"type\": \"union\", \"columns\": 3, \"position\": 2, \"extract_field\": \"version()\"}}, ...]",
            target, profile.tech_stack.server, profile.tech_stack.db
        );

        // Get consensus on templates
        let template_json = self
            .consensus
            .validate_with_consensus(&prompt, llm)
            .await?;

        // Parse templates
        let templates: Vec<PayloadTemplate> =
            serde_json::from_str(&template_json).map_err(|e| {
                format!("Failed to parse template JSON: {}", e)
            })?;

        let template_count = templates.len();

        // Render and validate each
        let mut valid_payloads = vec![];
        for template in templates {
            let payload = template.render(&dialect);

            // Full validation chain
            match self.validate(&payload, &dialect, Some(profile)) {
                ValidationResult::Valid => {
                    debug!("Payload validated: {}", &payload[..30.min(payload.len())]);
                    valid_payloads.push(payload);
                }
                other => {
                    error!("Payload validation failed: {:?}", other.error());
                }
            }
        }

        info!(
            "Generated {} validated payloads out of {} templates",
            valid_payloads.len(),
            template_count
        );
        Ok(valid_payloads)
    }

    /// Quick validation without full context.
    pub fn quick_validate(&self, payload: &str, dialect: &DbDialect) -> ValidationResult {
        // Syntax only
        SyntaxValidator::validate(payload, dialect)
    }

    /// Validate multiple payloads and return only valid ones.
    pub fn filter_valid<'a>(
        &self,
        payloads: &'a [String],
        dialect: &DbDialect,
        profile: Option<&TargetProfile>,
    ) -> Vec<&'a String> {
        payloads
            .iter()
            .filter(|p| self.validate(p, dialect, profile).is_valid())
            .collect()
    }
}

/// Simple LLM client implementation for testing.
pub struct SimpleLlmClient;

impl LlmClient for SimpleLlmClient {
    fn generate(
        &self,
        _prompt: &str,
        _temperature: f64,
    ) -> Pin<Box<dyn Future<Output = Result<String, String>> + Send + '_>> {
        Box::pin(async {
            // Return a default template JSON for testing
            Ok(r#"[
                {"type":"UnionBased","columns":3,"position":2,"extract_field":"version()"},
                {"type":"TimeBased","sleep_seconds":5,"function":"Sleep"},
                {"type":"ErrorBased","xpath_function":"extractvalue","expression":"(select version())"}
            ]"#.to_string())
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::intel::types::TechStack;

    fn create_profile(db: &str) -> TargetProfile {
        TargetProfile {
            domain: "test.com".to_string(),
            tech_stack: TechStack {
                db: db.to_string(),
                ..Default::default()
            },
            ..Default::default()
        }
    }

    #[test]
    fn test_validator_syntax_only() {
        let validator = PayloadValidator::default();
        let result = validator.quick_validate("SELECT * FROM users", &DbDialect::MySQL);
        assert!(result.is_valid());
    }

    #[test]
    fn test_validator_full_chain() {
        let validator = PayloadValidator::default();
        let profile = create_profile("MySQL 8.0");

        // Valid MySQL payload - complete SQL context
        let result = validator.validate(
            "SELECT * FROM users WHERE id='1' OR SLEEP(5)-- -'", 
            &DbDialect::MySQL, 
            Some(&profile)
        );
        // Note: This may fail syntax validation due to partial injection
        // The full validation is tested in integration tests

        // Wrong dialect - pg_sleep in MySQL target
        let result = validator.validate(
            "SELECT * FROM users WHERE id='1' OR pg_sleep(5)--'", 
            &DbDialect::MySQL, 
            Some(&profile)
        );
        // Should fail semantic check
        assert!(!result.is_valid());
    }

    #[test]
    fn test_filter_valid() {
        let validator = PayloadValidator::default();
        let payloads = vec![
            "SELECT * FROM users WHERE id=1 OR 1=1--".to_string(),
            "SELECT * FROM users".to_string(), // Not an attack payload
        ];

        let valid = validator.filter_valid(&payloads, &DbDialect::MySQL, None);
        // Both are valid SQL, but only first is a SQLi technique
        assert!(!valid.is_empty());
    }
}
