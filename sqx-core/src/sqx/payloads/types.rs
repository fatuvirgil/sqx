//! Type Definitions for Dynamic Payloads

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// A boundary from sqlmap XML.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SqlmapBoundary {
    pub level: u8,
    pub clause: Vec<u8>,       // Bits for clauses
    pub where_clause: Vec<u8>, // Bits for where
    pub pt_type: Option<u8>,
    pub prefix: String,
    pub suffix: String,
}

/// A test from sqlmap XML.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SqlmapTest {
    pub title: String,
    pub stype: u8, // 1: boolean, 2: error, 3: union, 4: stacked, 5: time, 6: inline
    pub level: u8,
    pub risk: u8,
    pub clause: Vec<u8>,
    pub where_clause: Vec<u8>,
    pub vector: String,
    pub request_payload: String,
    pub response_comparison: Option<String>, // grep pattern
    pub details: HashMap<String, String>,
}

/// Complete payload set available at scan time.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DynamicPayloadSet {
    /// Boundaries from sqlmap XML (fetched).
    pub boundaries: Vec<SqlmapBoundary>,
    /// Tests from sqlmap XML (fetched).
    pub tests: Vec<SqlmapTest>,
    /// PayloadsAllTheThings extra strings.
    pub extra_patt: Vec<String>,
}

impl DynamicPayloadSet {
    /// Create an empty payload set.
    pub fn new() -> Self {
        Self::default()
    }

    /// Get the number of boundaries.
    pub fn boundary_count(&self) -> usize {
        self.boundaries.len()
    }

    /// Get the number of tests.
    pub fn test_count(&self) -> usize {
        self.tests.len()
    }

    /// Get the number of extra PATT payloads.
    pub fn extra_count(&self) -> usize {
        self.extra_patt.len()
    }

    /// Find tests by technique type.
    pub fn tests_by_type(&self, stype: u8) -> Vec<&SqlmapTest> {
        self.tests.iter().filter(|t| t.stype == stype).collect()
    }

    /// Find boundaries by level.
    pub fn boundaries_by_level(&self, level: u8) -> Vec<&SqlmapBoundary> {
        self.boundaries.iter().filter(|b| b.level <= level).collect()
    }
}

/// Technique type constants for sqlmap stype field.
pub mod technique {
    pub const BOOLEAN_BLIND: u8 = 1;
    pub const ERROR_BASED: u8 = 2;
    pub const UNION_BASED: u8 = 3;
    pub const STACKED_QUERIES: u8 = 4;
    pub const TIME_BASED: u8 = 5;
    pub const INLINE_QUERIES: u8 = 6;
}

/// Get human-readable name for technique type.
pub fn technique_name(stype: u8) -> &'static str {
    match stype {
        technique::BOOLEAN_BLIND => "boolean-based blind",
        technique::ERROR_BASED => "error-based",
        technique::UNION_BASED => "union-based",
        technique::STACKED_QUERIES => "stacked queries",
        technique::TIME_BASED => "time-based blind",
        technique::INLINE_QUERIES => "inline queries",
        _ => "unknown",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_payload_set() {
        let set = DynamicPayloadSet::new();
        assert_eq!(set.boundary_count(), 0);
        assert_eq!(set.test_count(), 0);
        assert_eq!(set.extra_count(), 0);
    }

    #[test]
    fn technique_names() {
        assert_eq!(technique_name(technique::BOOLEAN_BLIND), "boolean-based blind");
        assert_eq!(technique_name(technique::ERROR_BASED), "error-based");
        assert_eq!(technique_name(technique::UNION_BASED), "union-based");
        assert_eq!(technique_name(99), "unknown");
    }
}
