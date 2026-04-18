use super::TamperScript;

pub struct TamperApostropheMask;
impl TamperScript for TamperApostropheMask {
    fn name(&self) -> &'static str {
        "apostrophemask"
    }
    fn description(&self) -> &'static str {
        "Replace ' with %EF%BC%87 (fullwidth apostrophe)"
    }
    fn tamper(&self, payload: &str) -> String {
        payload.replace('\'', "%EF%BC%87")
    }
}

pub struct TamperApostropheNullEncode;
impl TamperScript for TamperApostropheNullEncode {
    fn name(&self) -> &'static str {
        "apostrophenullencode"
    }
    fn description(&self) -> &'static str {
        "Replace ' with %00%27 (null-byte apostrophe)"
    }
    fn tamper(&self, payload: &str) -> String {
        payload.replace('\'', "%00%27")
    }
}

pub struct TamperUnMagicQuotes;
impl TamperScript for TamperUnMagicQuotes {
    fn name(&self) -> &'static str {
        "unmagicquotes"
    }
    fn description(&self) -> &'static str {
        "Backslash-escape quotes: ' -> \\' (GBK charset / magic_quotes bypass)"
    }
    fn tamper(&self, payload: &str) -> String {
        payload.replace('\'', "\\'").replace('"', "\\\"")
    }
}

pub struct TamperEscapeQuotes;
impl TamperScript for TamperEscapeQuotes {
    fn name(&self) -> &'static str {
        "escapequotes"
    }
    fn description(&self) -> &'static str {
        "Escape quotes with backslash: ' -> \\\\' (double-escape)"
    }
    fn tamper(&self, payload: &str) -> String {
        payload.replace('\'', "\\\\'").replace('"', "\\\\\"")
    }
}
