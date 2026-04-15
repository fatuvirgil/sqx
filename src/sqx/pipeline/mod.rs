//! SQX Pipeline — scan orchestration and result aggregation.

pub mod models;
pub mod pipeline;

pub use models::PipelineResult;
pub use pipeline::{Pipeline, PipelineConfig};
