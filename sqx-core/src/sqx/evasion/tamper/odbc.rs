use super::TamperScript;

pub struct TamperOdbcEscape;
impl TamperScript for TamperOdbcEscape {
    fn name(&self) -> &'static str {
        "odbc_escape"
    }
    fn description(&self) -> &'static str {
        "Wrap SQL functions in ODBC escape syntax: {fn SLEEP(n)}"
    }
    fn tamper(&self, payload: &str) -> String {
        let re =
            regex::Regex::new(r"(?i)(SLEEP|NOW|SYSDATE|USER|DATABASE|VERSION)\(([^)]*)\)").unwrap();
        re.replace_all(payload, |caps: &regex::Captures| {
            format!("{{fn {}({})}}", caps[1].to_uppercase(), &caps[2])
        })
        .to_string()
    }
}

pub struct TamperPlus2FnConcat;
impl TamperScript for TamperPlus2FnConcat {
    fn name(&self) -> &'static str {
        "plus2fnconcat"
    }
    fn description(&self) -> &'static str {
        "Replace + with {fn CONCAT()} ODBC syntax"
    }
    fn tamper(&self, payload: &str) -> String {
        payload.replace(" + ", " {fn CONCAT(CHAR(43))} ")
    }
}
