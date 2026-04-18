//! Augmented Pipeline with IntelCollector + PayloadValidator integration.
//!
//! This pipeline adds:
//! - Pre-scan intelligence gathering
//! - AI-assisted payload generation with validation
//! - Context-aware scanning

use std::sync::Arc;
use std::time::Instant;

use anyhow::Result;
use tracing::{debug, error, info, instrument, warn};

use crate::intel::{IntelCollector, TargetProfile};
use crate::sqx::{
    detector::SqliDetector,
    pipeline::{Pipeline, PipelineConfig, PipelineResult},
};
use crate::validator::{PayloadValidator, ValidationResult};

/// Augmented pipeline configuration.
#[derive(Debug, Clone)]
pub struct AugmentedPipelineConfig {
    /// Base pipeline config
    pub base: PipelineConfig,
    /// Enable intelligence collection
    pub enable_intel: bool,
    /// Enable payload validation
    pub enable_validator: bool,
    /// Use AI-generated payloads
    pub use_ai_payloads: bool,
    /// Maximum validated payloads to generate
    pub max_ai_payloads: usize,
}

impl Default for AugmentedPipelineConfig {
    fn default() -> Self {
        Self {
            base: PipelineConfig::default(),
            enable_intel: true,
            enable_validator: true,
            use_ai_payloads: false, // Disabled by default (requires LLM)
            max_ai_payloads: 10,
        }
    }
}

/// Augmented pipeline with intelligence and validation.
pub struct AugmentedPipeline {
    base: Pipeline,
    detector: SqliDetector,
    config: AugmentedPipelineConfig,
    intel: Option<Arc<IntelCollector>>,
    validator: Option<Arc<PayloadValidator>>,
}

impl AugmentedPipeline {
    /// Create a new augmented pipeline.
    pub fn new(
        detector: SqliDetector,
        config: AugmentedPipelineConfig,
        intel: Option<Arc<IntelCollector>>,
        validator: Option<Arc<PayloadValidator>>,
    ) -> Self {
        let base = Pipeline::new(detector.clone(), config.base.clone());
        Self {
            base,
            detector,
            config,
            intel,
            validator,
        }
    }

    /// Run augmented scan with intelligence and validation.
    #[instrument(skip(self), fields(url = %url))]
    pub async fn run(
        &self,
        url: &str,
        post_body: Option<&str>,
        content_type: Option<&str>,
    ) -> Result<AugmentedPipelineResult> {
        let start = Instant::now();
        info!("Starting augmented pipeline scan");

        // 1. Intelligence gathering (if enabled)
        let profile = if self.config.enable_intel {
            self.collect_intel(url).await.ok()
        } else {
            None
        };

        // 2. Generate AI payloads (if enabled and validator available)
        let ai_payloads = if self.config.use_ai_payloads && self.validator.is_some() {
            self.generate_ai_payloads(url, profile.as_ref()).await.ok()
        } else {
            None
        };

        // 3. Run base pipeline
        let base_result = self.base.run(url, post_body, content_type).await?;

        // 4. Post-process with validation
        let validated_findings = if self.config.enable_validator {
            self.validate_findings(&base_result, profile.as_ref())
        } else {
            base_result.findings.clone()
        };

        let elapsed = start.elapsed().as_secs_f64();

        info!(
            "Augmented pipeline complete: {} findings ({} validated)",
            base_result.findings.len(),
            validated_findings.len()
        );

        Ok(AugmentedPipelineResult {
            base: base_result,
            profile,
            ai_payloads,
            validated_findings,
            total_duration_secs: elapsed,
        })
    }

    /// Collect intelligence for target.
    #[instrument(skip(self))]
    async fn collect_intel(&self, url: &str) -> Result<TargetProfile> {
        let Some(intel) = &self.intel else {
            return Err(anyhow::anyhow!("IntelCollector not configured"));
        };

        debug!("Collecting intelligence for: {}", url);

        // Extract domain from URL
        let domain = url
            .replace("http://", "")
            .replace("https://", "")
            .split('/')
            .next()
            .unwrap_or(url)
            .to_string();

        let profile = intel.collect(&domain).await?;

        debug!(
            "Intel collected: {} subdomains, {} endpoints, {} CVEs",
            profile.subdomains.len(),
            profile.historic_endpoints.len(),
            profile.cves.len()
        );

        Ok(profile)
    }

    /// Generate AI payloads with validation.
    #[instrument(skip(self))]
    async fn generate_ai_payloads(
        &self,
        url: &str,
        profile: Option<&TargetProfile>,
    ) -> Result<Vec<String>> {
        let Some(validator) = &self.validator else {
            return Err(anyhow::anyhow!("PayloadValidator not configured"));
        };

        let Some(profile) = profile else {
            return Err(anyhow::anyhow!("TargetProfile required for AI payload generation"));
        };

        debug!("Generating AI payloads for: {}", url);

        // Note: This requires an LLM client. For now, return an error
        // In production, this would use the LLM client from AI advisor
        warn!("AI payload generation requires LLM client integration");
        
        // Return empty for now - would be populated by actual LLM call
        Ok(vec![])
    }

    /// Validate findings against target profile.
    #[instrument(skip(self))]
    fn validate_findings(
        &self,
        result: &PipelineResult,
        profile: Option<&TargetProfile>,
    ) -> Vec<crate::sqx::models::SqliTestResult> {
        let Some(validator) = &self.validator else {
            return result.findings.clone();
        };

        let dialect = profile.map(|p| p.get_dialect())
            .unwrap_or(crate::validator::DbDialect::MySQL);

        result
            .findings
            .iter()
            .filter(|f| {
                // Validate the payload that was used
                let payload = &f.payload;
                let validation = validator.validate(payload, &dialect, profile);

                match validation {
                    ValidationResult::Valid => true,
                    other => {
                        debug!(
                            "Finding validation failed for {}: {:?}",
                            f.parameter,
                            other.error()
                        );
                        false
                    }
                }
            })
            .cloned()
            .collect()
    }

    /// Get context for a target (for external use).
    pub async fn get_context(&self, url: &str) -> Option<TargetProfile> {
        if let Ok(profile) = self.collect_intel(url).await {
            Some(profile)
        } else {
            None
        }
    }
}

/// Augmented pipeline result.
#[derive(Debug, Clone)]
pub struct AugmentedPipelineResult {
    /// Base pipeline result
    pub base: PipelineResult,
    /// Intelligence profile (if collected)
    pub profile: Option<TargetProfile>,
    /// AI-generated payloads (if generated)
    pub ai_payloads: Option<Vec<String>>,
    /// Findings that passed validation
    pub validated_findings: Vec<crate::sqx::models::SqliTestResult>,
    /// Total duration including intel collection
    pub total_duration_secs: f64,
}

impl AugmentedPipelineResult {
    /// Check if any findings were validated.
    pub fn has_validated_findings(&self) -> bool {
        !self.validated_findings.is_empty()
    }

    /// Get number of findings that passed validation.
    pub fn validated_count(&self) -> usize {
        self.validated_findings.len()
    }

    /// Get validation pass rate.
    pub fn validation_rate(&self) -> f64 {
        if self.base.findings.is_empty() {
            0.0
        } else {
            (self.validated_findings.len() as f64 / self.base.findings.len() as f64) * 100.0
        }
    }
}

/// Builder for AugmentedPipeline.
pub struct AugmentedPipelineBuilder {
    detector: Option<SqliDetector>,
    config: AugmentedPipelineConfig,
    intel_path: Option<String>,
    validator: Option<Arc<PayloadValidator>>,
}

impl AugmentedPipelineBuilder {
    /// Create new builder.
    pub fn new() -> Self {
        Self {
            detector: None,
            config: AugmentedPipelineConfig::default(),
            intel_path: None,
            validator: None,
        }
    }

    /// Set detector.
    pub fn detector(mut self, detector: SqliDetector) -> Self {
        self.detector = Some(detector);
        self
    }

    /// Set config.
    pub fn config(mut self, config: AugmentedPipelineConfig) -> Self {
        self.config = config;
        self
    }

    /// Set intel KB path.
    pub fn intel_path(mut self, path: String) -> Self {
        self.intel_path = Some(path);
        self
    }

    /// Set validator.
    pub fn validator(mut self, validator: Arc<PayloadValidator>) -> Self {
        self.validator = Some(validator);
        self
    }

    /// Build the pipeline.
    pub fn build(self) -> Result<AugmentedPipeline> {
        let detector = self.detector.ok_or_else(|| anyhow::anyhow!("Detector required"))?;

        let intel = if self.config.enable_intel {
            if let Some(path) = self.intel_path {
                Some(Arc::new(IntelCollector::new(path)?))
            } else {
                Some(Arc::new(IntelCollector::new_temp()?))
            }
        } else {
            None
        };

        let validator = if self.config.enable_validator && self.validator.is_none() {
            Some(Arc::new(PayloadValidator::default()))
        } else {
            self.validator
        };

        Ok(AugmentedPipeline::new(detector, self.config, intel, validator))
    }
}

impl Default for AugmentedPipelineBuilder {
    fn default() -> Self {
        Self::new()
    }
}
