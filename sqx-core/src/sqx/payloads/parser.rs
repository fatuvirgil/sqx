//! XML Parsing Helpers for sqlmap Payload Files
//!
//! Lightweight XML parsing without external dependencies.
//! Handles sqlmap's payloads.xml and boundaries.xml formats.

use super::types::{SqlmapBoundary, SqlmapTest};

/// Parse sqlmap test definitions from XML.
pub fn parse_sqlmap_tests(xml: &str) -> Vec<SqlmapTest> {
    split_tags(xml, "test")
        .into_iter()
        .filter_map(|t| {
            let title = extract_tag(&t, "title")?;
            let stype = extract_tag(&t, "stype")?.parse().unwrap_or(1);
            let level = extract_tag(&t, "level")?.parse().unwrap_or(1);
            let risk = extract_tag(&t, "risk")?.parse().unwrap_or(1);

            let clause = parse_csv_u8(&extract_tag(&t, "clause").unwrap_or_default());
            let where_clause = parse_csv_u8(&extract_tag(&t, "where").unwrap_or_default());

            let vector = extract_tag(&t, "vector").unwrap_or_default();
            let request_payload =
                extract_tag(&extract_tag(&t, "request").unwrap_or_default(), "payload")
                    .unwrap_or_default();
            let response_comparison = extract_tag(
                &extract_tag(&t, "response").unwrap_or_default(),
                "comparison",
            );

            Some(SqlmapTest {
                title,
                stype,
                level,
                risk,
                clause,
                where_clause,
                vector,
                request_payload,
                response_comparison,
                details: std::collections::HashMap::new(),
            })
        })
        .collect()
}

/// Parse sqlmap boundary definitions from XML.
pub fn parse_sqlmap_boundaries_extended(xml: &str) -> Vec<SqlmapBoundary> {
    split_tags(xml, "boundary")
        .into_iter()
        .filter_map(|b| {
            let level = extract_tag(&b, "level")?.parse().unwrap_or(1);
            let clause = parse_csv_u8(&extract_tag(&b, "clause").unwrap_or_default());
            let where_clause = parse_csv_u8(&extract_tag(&b, "where").unwrap_or_default());
            let prefix = extract_tag(&b, "prefix").unwrap_or_default();
            let suffix = extract_tag(&b, "suffix").unwrap_or_default();
            let pt_type = extract_tag(&b, "ptype").and_then(|s| s.parse().ok());

            Some(SqlmapBoundary {
                level,
                clause,
                where_clause,
                prefix,
                suffix,
                pt_type,
            })
        })
        .collect()
}

/// Split XML content by a specific tag.
fn split_tags(xml: &str, tag: &str) -> Vec<String> {
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    let mut out = Vec::new();
    let mut rest = xml;
    while let Some(s) = rest.find(&open) {
        let cs = s + open.len();
        if let Some(e) = rest[cs..].find(&close) {
            out.push(rest[cs..cs + e].to_string());
            rest = &rest[cs + e + close.len()..];
        } else {
            break;
        }
    }
    out
}

/// Extract content between XML tags.
fn extract_tag(block: &str, tag: &str) -> Option<String> {
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    let s = block.find(&open)? + open.len();
    let e = block[s..].find(&close)?;
    Some(block[s..s + e].to_string())
}

/// Parse comma-separated u8 values.
fn parse_csv_u8(s: &str) -> Vec<u8> {
    s.split(',').filter_map(|v| v.trim().parse().ok()).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn split_tags_basic() {
        let xml = "<test>content1</test><test>content2</test>";
        let tags = split_tags(xml, "test");
        assert_eq!(tags.len(), 2);
        assert_eq!(tags[0], "content1");
        assert_eq!(tags[1], "content2");
    }

    #[test]
    fn extract_tag_basic() {
        let block = "<title>Test Title</title><level>1</level>";
        assert_eq!(extract_tag(block, "title"), Some("Test Title".to_string()));
        assert_eq!(extract_tag(block, "level"), Some("1".to_string()));
        assert_eq!(extract_tag(block, "missing"), None);
    }

    #[test]
    fn parse_csv_u8_basic() {
        assert_eq!(parse_csv_u8("1,2,3"), vec![1, 2, 3]);
        assert_eq!(parse_csv_u8("1, 2 ,3"), vec![1, 2, 3]);
        assert_eq!(parse_csv_u8(""), Vec::<u8>::new());
    }

    #[test]
    fn parse_sqlmap_tests_basic() {
        let xml = r#"
        <test>
            <title>MySQL Error Test</title>
            <stype>2</stype>
            <level>1</level>
            <risk>1</risk>
            <clause>1</clause>
            <where>1</where>
            <vector>SELECT * FROM users</vector>
            <request>
                <payload>' AND 1=1</payload>
            </request>
            <response>
                <comparison>error</comparison>
            </response>
        </test>
        "#;
        
        let tests = parse_sqlmap_tests(xml);
        assert_eq!(tests.len(), 1);
        assert_eq!(tests[0].title, "MySQL Error Test");
        assert_eq!(tests[0].stype, 2);
        assert_eq!(tests[0].request_payload, "' AND 1=1");
    }

    #[test]
    fn parse_boundaries_basic() {
        let xml = r#"
        <boundary>
            <level>1</level>
            <clause>1,2</clause>
            <where>1</where>
            <prefix>'</prefix>
            <suffix>-- </suffix>
            <ptype>1</ptype>
        </boundary>
        "#;
        
        let boundaries = parse_sqlmap_boundaries_extended(xml);
        assert_eq!(boundaries.len(), 1);
        assert_eq!(boundaries[0].prefix, "'");
        assert_eq!(boundaries[0].suffix, "-- ");
        assert_eq!(boundaries[0].clause, vec![1, 2]);
    }
}
