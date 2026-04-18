//! SQX Reporting — multi-format scan report export.
//!
//! # Formats
//! | Format   | File                      | Consumer                              |
//! |----------|---------------------------|---------------------------------------|
//! | SARIF    | `sqx-report.sarif.json`   | GitHub Advanced Security, Azure DevOps, Defect Dojo, CI/CD |
//! | JSON     | `sqx-report.json`         | APIs, dashboards, custom tooling      |
//! | Markdown | `sqx-report.md`           | GitHub issues, bug-bounty, pentest deliverables |
//!
//! # Quick start
//! ```rust,ignore
//! use sqx::reporting::write_reports;
//! let result = detector.scan_smart(url).await?;
//! write_reports(&pipeline_result, Path::new("./reports"))?;
//! ```

pub mod json_report;
pub mod markdown;
pub mod sarif;

pub use json_report::JsonReport;
pub use markdown::MarkdownReport;
pub use sarif::SarifReport;

use anyhow::Result;
use std::path::Path;

use crate::sqx::pipeline::models::PipelineResult;

/// Write all three report formats to `output_dir`.
///
/// Creates the directory if it does not exist.
/// Files written:
/// - `sqx-report.sarif.json`
/// - `sqx-report.json`
/// - `sqx-report.md`
pub fn write_reports(result: &PipelineResult, output_dir: &Path) -> Result<()> {
    std::fs::create_dir_all(output_dir)?;

    // SARIF
    let sarif = SarifReport::generate(result);
    std::fs::write(
        output_dir.join("sqx-report.sarif.json"),
        serde_json::to_string_pretty(&sarif)?,
    )?;

    // JSON
    let json = JsonReport::generate(result);
    std::fs::write(
        output_dir.join("sqx-report.json"),
        serde_json::to_string_pretty(&json)?,
    )?;

    // Markdown
    let md = MarkdownReport::generate(result);
    std::fs::write(output_dir.join("sqx-report.md"), md)?;

    Ok(())
}
