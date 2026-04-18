use super::TamperScript;

pub struct TamperSpaceToComment;
impl TamperScript for TamperSpaceToComment {
    fn name(&self) -> &'static str {
        "space_to_comment"
    }
    fn description(&self) -> &'static str {
        "Replace space with /**/ (most WAFs)"
    }
    fn tamper(&self, payload: &str) -> String {
        payload.replace(' ', "/**/")
    }
}

pub struct TamperSpaceToTab;
impl TamperScript for TamperSpaceToTab {
    fn name(&self) -> &'static str {
        "space_to_tab"
    }
    fn description(&self) -> &'static str {
        "Replace space with URL-encoded tab"
    }
    fn tamper(&self, payload: &str) -> String {
        payload.replace(' ', "%09")
    }
}

pub struct TamperSpaceToNewline;
impl TamperScript for TamperSpaceToNewline {
    fn name(&self) -> &'static str {
        "space_to_newline"
    }
    fn description(&self) -> &'static str {
        "Replace space with URL-encoded newline"
    }
    fn tamper(&self, payload: &str) -> String {
        payload.replace(' ', "%0a")
    }
}

pub struct TamperSpaceToWhitespaceMix;
impl TamperScript for TamperSpaceToWhitespaceMix {
    fn name(&self) -> &'static str {
        "space_to_whitespace_mix"
    }
    fn description(&self) -> &'static str {
        "Rotate space through tab/LF/CR/FF encodings"
    }
    fn tamper(&self, payload: &str) -> String {
        let replacements = ["%09", "%0a", "%0d", "%0c"];
        payload
            .chars()
            .enumerate()
            .map(|(i, c)| {
                if c == ' ' {
                    replacements[i % replacements.len()].to_string()
                } else {
                    c.to_string()
                }
            })
            .collect()
    }
}

pub struct TamperMultipleSpaces;
impl TamperScript for TamperMultipleSpaces {
    fn name(&self) -> &'static str {
        "multiplespaces"
    }
    fn description(&self) -> &'static str {
        "Replace single space with triple space (regex-count WAFs)"
    }
    fn tamper(&self, payload: &str) -> String {
        payload.replace(' ', "   ")
    }
}

pub struct TamperBlueCoat;
impl TamperScript for TamperBlueCoat {
    fn name(&self) -> &'static str {
        "bluecoat"
    }
    fn description(&self) -> &'static str {
        "Replace space with ; (Blue Coat proxy bypass)"
    }
    fn tamper(&self, payload: &str) -> String {
        payload
            .replace(" AND ", ";AND;")
            .replace(" OR ", ";OR;")
            .replace(" FROM ", ";FROM;")
            .replace(" WHERE ", ";WHERE;")
            .replace(" UNION ", ";UNION;")
            .replace(" SELECT ", ";SELECT;")
    }
}

pub struct TamperSpace2Plus;
impl TamperScript for TamperSpace2Plus {
    fn name(&self) -> &'static str {
        "space2plus"
    }
    fn description(&self) -> &'static str {
        "Replace space with + (URL query-string space encoding)"
    }
    fn tamper(&self, payload: &str) -> String {
        payload.replace(' ', "+")
    }
}

pub struct TamperSpace2Dash;
impl TamperScript for TamperSpace2Dash {
    fn name(&self) -> &'static str {
        "space2dash"
    }
    fn description(&self) -> &'static str {
        "Replace space with --%0a (MySQL dash comment as space)"
    }
    fn tamper(&self, payload: &str) -> String {
        payload.replace(' ', "--%0a")
    }
}

pub struct TamperSpace2Hash;
impl TamperScript for TamperSpace2Hash {
    fn name(&self) -> &'static str {
        "space2hash"
    }
    fn description(&self) -> &'static str {
        "Replace space with #%0a (MySQL hash comment as space)"
    }
    fn tamper(&self, payload: &str) -> String {
        payload.replace(' ', "#%0a")
    }
}

pub struct TamperSpace2MssqlHash;
impl TamperScript for TamperSpace2MssqlHash {
    fn name(&self) -> &'static str {
        "space2mssqlhash"
    }
    fn description(&self) -> &'static str {
        "Replace space with %23%0A (MSSQL hash comment)"
    }
    fn tamper(&self, payload: &str) -> String {
        payload.replace(' ', "%23%0A")
    }
}

pub struct TamperSpace2RandomBlank;
impl TamperScript for TamperSpace2RandomBlank {
    fn name(&self) -> &'static str {
        "space2randomblank"
    }
    fn description(&self) -> &'static str {
        "Rotate space through MySQL blank chars: \\t \\n \\r \\x0b \\x0c"
    }
    fn tamper(&self, payload: &str) -> String {
        let blanks = ["%09", "%0a", "%0d", "%0b", "%0c"];
        payload
            .chars()
            .enumerate()
            .map(|(i, c)| {
                if c == ' ' {
                    blanks[i % blanks.len()].to_string()
                } else {
                    c.to_string()
                }
            })
            .collect()
    }
}

pub struct TamperSpace2MysqlBlank;
impl TamperScript for TamperSpace2MysqlBlank {
    fn name(&self) -> &'static str {
        "space2mysqlblank"
    }
    fn description(&self) -> &'static str {
        "Replace space with random MySQL blank byte (\\x09/\\x0a/\\x0d/\\x0b/\\x0c)"
    }
    fn tamper(&self, payload: &str) -> String {
        let blanks = ['\x09', '\x0a', '\x0d', '\x0b', '\x0c'];
        payload
            .chars()
            .enumerate()
            .map(|(i, c)| {
                if c == ' ' {
                    blanks[i % blanks.len()].to_string()
                } else {
                    c.to_string()
                }
            })
            .collect()
    }
}
