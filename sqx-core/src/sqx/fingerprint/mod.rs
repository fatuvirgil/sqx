//! Behavioral fingerprinting module for SQX.
//! Probes targets before injection testing to build a TargetProfile
//! that guides technique selection, threshold tuning, and WAF evasion.

pub mod models;
pub mod prober;

pub use models::{
    ParameterProfile, ScanStrategy, TargetBehavior, TargetProfile, TimingProfile, WafFingerprint,
};
pub use prober::TargetProber;
