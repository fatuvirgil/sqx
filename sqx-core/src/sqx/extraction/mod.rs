//! Data extraction primitives: blind boolean, time-based, schema enumeration,
//! and raw helper modules used by higher-level workflows.
//!
//! Operator-facing post-exploitation APIs live under `sqx::takeover`.

pub mod blind;
pub mod dump;
pub mod schema;
pub mod time_blind;
