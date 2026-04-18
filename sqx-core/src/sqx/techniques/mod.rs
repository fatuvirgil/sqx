//! SQL injection technique modules.

pub mod boolean_blind;
pub mod error_based;
pub mod header_injection;
// Note: OOB technique moved to sqx-pro
// pub mod oob;
pub mod stacked;
pub mod time_based;
pub mod union_based;
