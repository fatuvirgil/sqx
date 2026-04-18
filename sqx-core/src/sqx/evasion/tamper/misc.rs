use super::TamperScript;

pub struct TamperNullByte;
impl TamperScript for TamperNullByte {
    fn name(&self) -> &'static str {
        "null_byte"
    }
    fn description(&self) -> &'static str {
        "Append null byte to terminate WAF string parsing"
    }
    fn tamper(&self, payload: &str) -> String {
        format!("{}\\x00", payload)
    }
}

pub struct TamperStringConcatBypass;
impl TamperScript for TamperStringConcatBypass {
    fn name(&self) -> &'static str {
        "string_concat_bypass"
    }
    fn description(&self) -> &'static str {
        "Break keywords via string concatenation: 'se'||'lect'"
    }
    fn tamper(&self, payload: &str) -> String {
        payload
            .replace("SELECT", "'se'||'lect'")
            .replace("UNION", "'uni'||'on'")
    }
}

pub struct TamperBacktickIdentifiers;
impl TamperScript for TamperBacktickIdentifiers {
    fn name(&self) -> &'static str {
        "backtick_identifiers"
    }
    fn description(&self) -> &'static str {
        "Wrap schema/column identifiers in backticks"
    }
    fn tamper(&self, payload: &str) -> String {
        payload
            .replace("information_schema", "`information_schema`")
            .replace("table_name", "`table_name`")
            .replace("column_name", "`column_name`")
    }
}

pub struct TamperHppMarker;
impl TamperScript for TamperHppMarker {
    fn name(&self) -> &'static str {
        "hpp_marker"
    }
    fn description(&self) -> &'static str {
        "Append HPP pollution marker (&_hpp=1) to confuse WAF parsers"
    }
    fn tamper(&self, payload: &str) -> String {
        format!("{}&_hpp=1", payload)
    }
}

pub struct TamperMisUnion;
impl TamperScript for TamperMisUnion {
    fn name(&self) -> &'static str {
        "misunion"
    }
    fn description(&self) -> &'static str {
        "Prefix UNION with %0A newline: %0AUNION (line-split WAF parsers)"
    }
    fn tamper(&self, payload: &str) -> String {
        payload
            .replace("UNION", "%0AUNION")
            .replace("union", "%0aunion")
    }
}

pub struct TamperSpPassword;
impl TamperScript for TamperSpPassword {
    fn name(&self) -> &'static str {
        "sp_password"
    }
    fn description(&self) -> &'static str {
        "Append sp_password to hide query in MSSQL audit logs"
    }
    fn tamper(&self, payload: &str) -> String {
        format!("{}%20--sp_password", payload)
    }
}

pub struct TamperPercentage;
impl TamperScript for TamperPercentage {
    fn name(&self) -> &'static str {
        "percentage"
    }
    fn description(&self) -> &'static str {
        "Insert % between each char: SELECT -> S%E%L%E%C%T"
    }
    fn tamper(&self, payload: &str) -> String {
        payload
            .chars()
            .enumerate()
            .map(|(i, c)| {
                if i == 0 {
                    c.to_string()
                } else {
                    format!("%{}", c)
                }
            })
            .collect()
    }
}

pub struct TamperInformationSchemaComment;
impl TamperScript for TamperInformationSchemaComment {
    fn name(&self) -> &'static str {
        "informationschemacomment"
    }
    fn description(&self) -> &'static str {
        "Inject /**/ inside information_schema: information_schema/**/.tables"
    }
    fn tamper(&self, payload: &str) -> String {
        payload
            .replace("information_schema.tables", "information_schema/**/.tables")
            .replace(
                "information_schema.columns",
                "information_schema/**/.columns",
            )
            .replace(
                "information_schema.schemata",
                "information_schema/**/.schemata",
            )
    }
}
