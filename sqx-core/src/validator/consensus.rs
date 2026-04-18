//! Consensus Validator - Anti-hallucination layer.
//!
//! Generates multiple samples and checks for consensus to detect LLM hallucinations.

use super::types::{PayloadConstraints, ValidationResult};
use std::future::Future;
use std::pin::Pin;
use tracing::{debug, instrument, warn};

/// LLM client trait for consensus checking.
pub trait LlmClient: Send + Sync {
    /// Generate text with given temperature.
    fn generate(
        &self,
        prompt: &str,
        temperature: f64,
    ) -> Pin<Box<dyn Future<Output = Result<String, String>> + Send + '_>>;
}

/// Consensus validator.
pub struct ConsensusValidator {
    /// Temperature for non-first samples
    pub temperature: f64,
    /// Number of samples to generate
    pub samples: u8,
    /// Similarity threshold (0.0-1.0)
    pub threshold: f64,
}

impl Default for ConsensusValidator {
    fn default() -> Self {
        Self {
            temperature: 0.7,
            samples: 3,
            threshold: 0.9,
        }
    }
}

impl ConsensusValidator {
    /// Create new consensus validator.
    pub fn new(temperature: f64, samples: u8, threshold: f64) -> Self {
        Self {
            temperature,
            samples,
            threshold,
        }
    }

    /// Validate by consensus - generate multiple samples and check similarity.
    #[instrument(skip(self, llm), fields(samples = self.samples))]
    pub async fn validate_with_consensus<L: LlmClient>(
        &self,
        prompt: &str,
        llm: &L,
    ) -> Result<String, String> {
        debug!("Generating {} samples for consensus", self.samples);

        let mut payloads = Vec::new();

        // Generate samples
        for i in 0..self.samples {
            // First sample: low temp (focused)
            // Others: higher temp (variability)
            let temp = if i == 0 { 0.1 } else { self.temperature };

            match llm.generate(prompt, temp).await {
                Ok(payload) => {
                    debug!("Generated sample {}: {} chars", i + 1, payload.len());
                    payloads.push(payload);
                }
                Err(e) => {
                    warn!("Failed to generate sample {}: {}", i + 1, e);
                    return Err(format!("Generation failed: {}", e));
                }
            }
        }

        // Check consensus
        self.check_consensus(&payloads)
    }

    /// Check consensus among generated samples.
    fn check_consensus(&self, payloads: &[String]) -> Result<String, String> {
        if payloads.len() < 2 {
            return payloads
                .first()
                .cloned()
                .ok_or_else(|| "No payloads generated".to_string());
        }

        // Compare all pairs
        let mut best_similarity = 0.0;
        let mut best_payload = &payloads[0];

        for i in 0..payloads.len() {
            for j in (i + 1)..payloads.len() {
                let sim = normalized_levenshtein(&payloads[i], &payloads[j]);
                debug!("Similarity [{}, {}]: {:.2}", i, j, sim);

                if sim > best_similarity {
                    best_similarity = sim;
                    best_payload = &payloads[i];
                }
            }
        }

        debug!("Best similarity: {:.2} (threshold: {:.2})", best_similarity, self.threshold);

        if best_similarity >= self.threshold {
            Ok(best_payload.clone())
        } else {
            Err(format!(
                "Insufficient consensus: {:.2} < {:.2}. LLM may be hallucinating.",
                best_similarity, self.threshold
            ))
        }
    }

    /// Validate templates by consensus.
    pub async fn validate_templates<L: LlmClient>(
        &self,
        prompt: &str,
        llm: &L,
    ) -> Result<Vec<String>, String> {
        let result = self.validate_with_consensus(prompt, llm).await?;

        // Parse as JSON array
        match serde_json::from_str::<Vec<String>>(&result) {
            Ok(templates) => Ok(templates),
            Err(e) => Err(format!("Failed to parse templates JSON: {}", e)),
        }
    }
}

/// Calculate normalized Levenshtein similarity (0.0-1.0).
fn normalized_levenshtein(a: &str, b: &str) -> f64 {
    use strsim::levenshtein;

    if a.is_empty() && b.is_empty() {
        return 1.0;
    }
    if a.is_empty() || b.is_empty() {
        return 0.0;
    }

    let distance = levenshtein(a, b);
    let max_len = a.len().max(b.len());

    1.0 - (distance as f64 / max_len as f64)
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockLlm;

    impl LlmClient for MockLlm {
        fn generate(
            &self,
            _prompt: &str,
            _temperature: f64,
        ) -> Pin<Box<dyn Future<Output = Result<String, String>> + Send + '_>> {
            Box::pin(async {
                Ok("' UNION SELECT null,null,version()--".to_string())
            })
        }
    }

    #[tokio::test]
    async fn test_consensus_pass() {
        let validator = ConsensusValidator::default();
        let llm = MockLlm;

        let result = validator.validate_with_consensus("test", &llm).await;
        assert!(result.is_ok());
    }

    #[test]
    fn test_levenshtein_identical() {
        let sim = normalized_levenshtein("hello", "hello");
        assert!((sim - 1.0).abs() < 0.01);
    }

    #[test]
    fn test_levenshtein_different() {
        let sim = normalized_levenshtein("hello", "world");
        assert!(sim < 0.5);
    }

    #[test]
    fn test_levenshtein_similar() {
        let sim = normalized_levenshtein(
            "' UNION SELECT null,null,version()--",
            "' UNION SELECT null,null,version()--"
        );
        assert!((sim - 1.0).abs() < 0.01);
    }
}
