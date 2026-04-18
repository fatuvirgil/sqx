//! TamperScript trait and built-in tamper implementations.

pub trait TamperScript: Send + Sync {
    fn name(&self) -> &'static str;
    fn description(&self) -> &'static str;
    fn tamper(&self, payload: &str) -> String;
}

mod encoding;
mod keywords;
mod misc;
mod mysql;
mod odbc;
mod operators;
mod quotes;
mod spaces;

pub use encoding::{
    TamperBase64Encode, TamperCharDoubleEncode, TamperCharEncode, TamperCharUnicodeEncode,
    TamperDoubleUrlEncode, TamperHexEncode, TamperHtmlEncode, TamperOverlongUtf8,
    TamperUnicodeEscape, TamperUrlEncode,
};
pub use keywords::{
    TamperCaseCommentMix, TamperDoubleKeyword, TamperHexKeyword, TamperInlineComment,
    TamperKeywordNewlineSplit, TamperLowercase, TamperNonRecursiveReplacement, TamperRandomCase,
    TamperRandomComments,
};
pub use misc::{
    TamperBacktickIdentifiers, TamperHppMarker, TamperInformationSchemaComment, TamperMisUnion,
    TamperNullByte, TamperPercentage, TamperSpPassword, TamperStringConcatBypass,
};
pub use mysql::{
    TamperCommalessLimit, TamperCommalessMid, TamperConcat2ConcatWs, TamperEquivalentFunctions,
    TamperHalfVersionedMoreKeywords, TamperIfNull2CaseWhenIsNull, TamperIfNull2IfIsNull,
    TamperModSecurityZeroVersioned, TamperMySql50000Comment, TamperMySqlVersionComment,
    TamperPlus2Concat, TamperSleep2GetLock, TamperSleepToBenchmark, TamperUnionAllToUnion,
    TamperUnionSelectNospace, TamperVersionComment, TamperVersionedKeywords,
};
pub use odbc::{TamperOdbcEscape, TamperPlus2FnConcat};
pub use operators::{
    TamperBetweenOperator, TamperEqualToLike, TamperGreatest, TamperLeast, TamperLogicalOperators,
    TamperScientificNotation, TamperSymbolicLogical,
};
pub use quotes::{
    TamperApostropheMask, TamperApostropheNullEncode, TamperEscapeQuotes, TamperUnMagicQuotes,
};
pub use spaces::{
    TamperBlueCoat, TamperMultipleSpaces, TamperSpace2Dash, TamperSpace2Hash,
    TamperSpace2MssqlHash, TamperSpace2MysqlBlank, TamperSpace2Plus, TamperSpace2RandomBlank,
    TamperSpaceToComment, TamperSpaceToNewline, TamperSpaceToTab, TamperSpaceToWhitespaceMix,
};

/// All built-in tamper scripts.
pub fn all_techniques() -> Vec<Box<dyn TamperScript>> {
    vec![
        // encoding
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
        // quote bypass
        Box::new(TamperApostropheMask),
        Box::new(TamperApostropheNullEncode),
        Box::new(TamperUnMagicQuotes),
        // space substitution
        Box::new(TamperSpaceToComment),
        Box::new(TamperSpaceToTab),
        Box::new(TamperSpaceToNewline),
        Box::new(TamperSpaceToWhitespaceMix),
        Box::new(TamperMultipleSpaces),
        Box::new(TamperBlueCoat),
        // keyword obfuscation
        Box::new(TamperRandomCase),
        Box::new(TamperRandomComments),
        Box::new(TamperInlineComment),
        Box::new(TamperCaseCommentMix),
        Box::new(TamperDoubleKeyword),
        Box::new(TamperKeywordNewlineSplit),
        Box::new(TamperHexKeyword),
        // MySQL comment tricks
        Box::new(TamperMySqlVersionComment),
        Box::new(TamperMySql50000Comment),
        Box::new(TamperVersionComment),
        Box::new(TamperVersionedKeywords),
        Box::new(TamperModSecurityZeroVersioned),
        // operator/function substitution
        Box::new(TamperEqualToLike),
        Box::new(TamperGreatest),
        Box::new(TamperBetweenOperator),
        Box::new(TamperLogicalOperators),
        Box::new(TamperSymbolicLogical),
        Box::new(TamperEquivalentFunctions),
        Box::new(TamperIfNull2IfIsNull),
        // MySQL syntax variants
        Box::new(TamperCommalessLimit),
        Box::new(TamperCommalessMid),
        Box::new(TamperConcat2ConcatWs),
        Box::new(TamperUnionAllToUnion),
        Box::new(TamperUnionSelectNospace),
        Box::new(TamperSleepToBenchmark),
        Box::new(TamperPlus2Concat),
        // ODBC / multi-backend
        Box::new(TamperOdbcEscape),
        Box::new(TamperPlus2FnConcat),
        // MSSQL
        Box::new(TamperSpPassword),
        // misc
        Box::new(TamperNullByte),
        Box::new(TamperScientificNotation),
        Box::new(TamperStringConcatBypass),
        Box::new(TamperBacktickIdentifiers),
        Box::new(TamperHppMarker),
        // additional 16
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
        assert_eq!(out, "TWFu");
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
