use super::TamperScript;

pub struct TamperUrlEncode;
impl TamperScript for TamperUrlEncode {
    fn name(&self) -> &'static str {
        "urlencode"
    }
    fn description(&self) -> &'static str {
        "Single URL encoding of the whole payload"
    }
    fn tamper(&self, payload: &str) -> String {
        urlencoding::encode(payload).to_string()
    }
}

pub struct TamperDoubleUrlEncode;
impl TamperScript for TamperDoubleUrlEncode {
    fn name(&self) -> &'static str {
        "double_urlencode"
    }
    fn description(&self) -> &'static str {
        "Double URL encoding"
    }
    fn tamper(&self, payload: &str) -> String {
        urlencoding::encode(&urlencoding::encode(payload)).to_string()
    }
}

pub struct TamperCharEncode;
impl TamperScript for TamperCharEncode {
    fn name(&self) -> &'static str {
        "charencode"
    }
    fn description(&self) -> &'static str {
        "Percent-encode every character: SELECT -> %53%45%4c%45%43%54"
    }
    fn tamper(&self, payload: &str) -> String {
        payload.bytes().map(|b| format!("%{:02X}", b)).collect()
    }
}

pub struct TamperCharDoubleEncode;
impl TamperScript for TamperCharDoubleEncode {
    fn name(&self) -> &'static str {
        "chardoubleencode"
    }
    fn description(&self) -> &'static str {
        "Double percent-encode: S -> %2553 (for double-decode WAFs)"
    }
    fn tamper(&self, payload: &str) -> String {
        payload.bytes().map(|b| format!("%25{:02X}", b)).collect()
    }
}

pub struct TamperCharUnicodeEncode;
impl TamperScript for TamperCharUnicodeEncode {
    fn name(&self) -> &'static str {
        "charunicodeencode"
    }
    fn description(&self) -> &'static str {
        "Unicode percent-encode every char: S -> %u0053"
    }
    fn tamper(&self, payload: &str) -> String {
        payload
            .chars()
            .map(|c| format!("%u{:04X}", c as u32))
            .collect()
    }
}

pub struct TamperUnicodeEscape;
impl TamperScript for TamperUnicodeEscape {
    fn name(&self) -> &'static str {
        "unicode_escape"
    }
    fn description(&self) -> &'static str {
        "Unicode escape for quote characters (%u0027)"
    }
    fn tamper(&self, payload: &str) -> String {
        payload.replace('\'', "%u0027").replace('"', "%u0022")
    }
}

pub struct TamperBase64Encode;
impl TamperScript for TamperBase64Encode {
    fn name(&self) -> &'static str {
        "base64encode"
    }
    fn description(&self) -> &'static str {
        "Base64-encode the whole payload"
    }
    fn tamper(&self, payload: &str) -> String {
        const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let bytes = payload.as_bytes();
        let mut out = String::with_capacity((bytes.len() + 2) / 3 * 4);
        for chunk in bytes.chunks(3) {
            let b0 = chunk[0] as usize;
            let b1 = if chunk.len() > 1 {
                chunk[1] as usize
            } else {
                0
            };
            let b2 = if chunk.len() > 2 {
                chunk[2] as usize
            } else {
                0
            };
            let n = (b0 << 16) | (b1 << 8) | b2;
            out.push(ALPHABET[(n >> 18) & 0x3F] as char);
            out.push(ALPHABET[(n >> 12) & 0x3F] as char);
            if chunk.len() > 1 {
                out.push(ALPHABET[(n >> 6) & 0x3F] as char);
            } else {
                out.push('=');
            }
            if chunk.len() > 2 {
                out.push(ALPHABET[n & 0x3F] as char);
            } else {
                out.push('=');
            }
        }
        out
    }
}

pub struct TamperOverlongUtf8;
impl TamperScript for TamperOverlongUtf8 {
    fn name(&self) -> &'static str {
        "overlongutf8"
    }
    fn description(&self) -> &'static str {
        "Overlong UTF-8 encoding for ASCII: A -> %C1%81 (unicode normalizers)"
    }
    fn tamper(&self, payload: &str) -> String {
        payload
            .bytes()
            .map(|b| {
                if b.is_ascii_alphabetic() {
                    format!("%{:02X}%{:02X}", 0xC0 | (b >> 6), 0x80 | (b & 0x3F))
                } else {
                    (b as char).to_string()
                }
            })
            .collect()
    }
}

pub struct TamperHexEncode;
impl TamperScript for TamperHexEncode {
    fn name(&self) -> &'static str {
        "hex_encode"
    }
    fn description(&self) -> &'static str {
        "Hex-encode string literals; wrap in UNHEX() for MySQL"
    }
    fn tamper(&self, payload: &str) -> String {
        let mut out = String::new();
        let mut in_quote = false;
        let mut buf = String::new();
        for c in payload.chars() {
            match c {
                '\'' if !in_quote => {
                    in_quote = true;
                    buf.clear();
                }
                '\'' if in_quote => {
                    let hex: String = buf.bytes().map(|b| format!("{:02X}", b)).collect();
                    out.push_str(&format!("UNHEX('{}')", hex));
                    in_quote = false;
                }
                _ if in_quote => buf.push(c),
                _ => out.push(c),
            }
        }
        if in_quote {
            return payload.to_string();
        }
        out
    }
}

pub struct TamperHtmlEncode;
impl TamperScript for TamperHtmlEncode {
    fn name(&self) -> &'static str {
        "html_encode"
    }
    fn description(&self) -> &'static str {
        "HTML-entity encode single/double quotes"
    }
    fn tamper(&self, payload: &str) -> String {
        payload.replace('\'', "&#39;").replace('"', "&#34;")
    }
}
