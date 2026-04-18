//! IntelCollector - Multi-source intelligence gathering system.
//!
//! Aggregates CVE data, asset information, and security advisories
//! from various sources into a unified Knowledge Base.

pub mod collector;
pub mod db;
pub mod sources;
pub mod types;

pub use collector::IntelCollector;
pub use db::KnowledgeBase;
pub use types::*;
