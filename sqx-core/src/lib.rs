//! SQX Core — SQL injection detection, extraction, and reporting engine.
//!
//! This crate contains the engine without any UI dependencies (no CLI, no GUI).

pub mod bench;
pub mod intel;
pub mod models;
// Note: OOB moved to sqx-pro
// pub mod oob;
pub mod sqx;
pub mod validator;
