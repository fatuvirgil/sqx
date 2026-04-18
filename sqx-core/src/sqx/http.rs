//! HTTP utilities: POST body builder and timing helpers used by the scanner.

use crate::sqx::detector::SqliDetector;
use anyhow::Result;
use std::time::{Duration, Instant};

impl SqliDetector {
    /// Measure baseline response time with statistical confidence.
    ///
    /// Takes `samples` measurements and returns `(mean, stddev)`.
    /// Callers compute a detection threshold as `mean + stddev * 2`.
    pub(crate) async fn measure_baseline_timing(
        &self,
        url: &str,
        samples: usize,
    ) -> Result<(Duration, Duration)> {
        let mut durations = Vec::with_capacity(samples);

        for _ in 0..samples {
            let start = Instant::now();
            let _ = self.send_request(url).await?;
            durations.push(start.elapsed());
            tokio::time::sleep(crate::sqx::stealth::jittered_delay(
                self.config.delay_ms,
                self.config.stealth.jitter_pct,
            ))
            .await;
        }

        let mean_nanos =
            durations.iter().map(|d| d.as_nanos() as f64).sum::<f64>() / samples as f64;
        let variance = durations
            .iter()
            .map(|d| {
                let diff = d.as_nanos() as f64 - mean_nanos;
                diff * diff
            })
            .sum::<f64>()
            / samples as f64;
        let stddev_nanos = variance.sqrt();

        Ok((
            Duration::from_nanos(mean_nanos as u64),
            Duration::from_nanos(stddev_nanos as u64),
        ))
    }

    /// Compute an adaptive SLEEP duration based on live baseline timing.
    ///
    /// Formula: `mean * 3 + stddev * 2`, clamped to [2, 10] seconds.
    /// Fast targets (~50ms) → 2s sleep. Slow/jittery targets → up to 10s.
    pub(crate) fn compute_adaptive_sleep(&self, mean: Duration, stddev: Duration) -> u64 {
        let mean_secs = mean.as_secs_f64();
        let stddev_secs = stddev.as_secs_f64();
        let sleep = mean_secs * 3.0 + stddev_secs * 2.0;
        sleep.clamp(2.0, 10.0) as u64
    }
}

/// Build a modified POST body with a specific parameter injected.
///
/// Supports `content_type`: `"json"`, `"xml"`, or form-encoded (default).
pub(crate) fn build_post_body(
    original: &str,
    param: &str,
    injected_value: &str,
    content_type: &str,
) -> String {
    match content_type {
        "json" => {
            if let Ok(mut val) = serde_json::from_str::<serde_json::Value>(original) {
                if let Some(obj) = val.as_object_mut() {
                    obj.insert(
                        param.to_string(),
                        serde_json::Value::String(injected_value.to_string()),
                    );
                }
                serde_json::to_string(&val).unwrap_or_else(|_| original.to_string())
            } else {
                original.to_string()
            }
        }
        "xml" => {
            let pattern = format!("<{}>", param);
            if let Some(start) = original.find(&pattern) {
                let close_tag = format!("</{}>", param);
                if let Some(end) = original[start..].find(&close_tag) {
                    let after_open = start + pattern.len();
                    let close_abs = start + end;
                    return format!(
                        "{}{}{}",
                        &original[..after_open],
                        injected_value,
                        &original[close_abs..]
                    );
                }
            }
            original.to_string()
        }
        _ => {
            // form-encoded: replace param=value
            original
                .split('&')
                .map(|pair| {
                    let mut parts = pair.splitn(2, '=');
                    let k = parts.next().unwrap_or("");
                    let v = parts.next().unwrap_or("");
                    if k == param {
                        format!("{}={}", k, urlencoding::encode(injected_value))
                    } else {
                        format!("{}={}", k, v)
                    }
                })
                .collect::<Vec<_>>()
                .join("&")
        }
    }
}
