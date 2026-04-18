//! TamperChain: compose multiple tamper scripts applied left-to-right.

use super::tamper::{
    TamperApostropheMask,
    TamperApostropheNullEncode,
    TamperBacktickIdentifiers,
    TamperBase64Encode,
    TamperBetweenOperator,
    TamperBlueCoat,
    TamperCaseCommentMix,
    TamperCharDoubleEncode,
    // new 22
    TamperCharEncode,
    TamperCharUnicodeEncode,
    TamperCommalessLimit,
    TamperCommalessMid,
    TamperConcat2ConcatWs,
    TamperDoubleKeyword,
    TamperDoubleUrlEncode,
    TamperEqualToLike,
    TamperEquivalentFunctions,
    TamperEscapeQuotes,
    TamperGreatest,
    TamperHalfVersionedMoreKeywords,
    TamperHexEncode,
    TamperHexKeyword,
    TamperHppMarker,
    TamperHtmlEncode,
    TamperIfNull2CaseWhenIsNull,
    TamperIfNull2IfIsNull,
    TamperInformationSchemaComment,
    TamperInlineComment,
    TamperKeywordNewlineSplit,
    TamperLeast,
    TamperLogicalOperators,
    TamperLowercase,
    TamperMisUnion,
    TamperModSecurityZeroVersioned,
    TamperMultipleSpaces,
    TamperMySql50000Comment,
    TamperMySqlVersionComment,
    TamperNonRecursiveReplacement,
    TamperNullByte,
    TamperOdbcEscape,
    TamperOverlongUtf8,
    // additional 16
    TamperPercentage,
    TamperPlus2Concat,
    TamperPlus2FnConcat,
    TamperRandomCase,
    TamperRandomComments,
    TamperScientificNotation,
    TamperScript,
    TamperSleep2GetLock,
    TamperSleepToBenchmark,
    TamperSpPassword,
    TamperSpace2Dash,
    TamperSpace2Hash,
    TamperSpace2MssqlHash,
    TamperSpace2MysqlBlank,
    TamperSpace2Plus,
    TamperSpace2RandomBlank,
    // original 30
    TamperSpaceToComment,
    TamperSpaceToNewline,
    TamperSpaceToTab,
    TamperSpaceToWhitespaceMix,
    TamperStringConcatBypass,
    TamperSymbolicLogical,
    TamperUnMagicQuotes,
    TamperUnicodeEscape,
    TamperUnionAllToUnion,
    TamperUnionSelectNospace,
    TamperUrlEncode,
    TamperVersionComment,
    TamperVersionedKeywords,
};

/// Chain of tamper scripts applied left-to-right.
#[derive(Default)]
pub struct TamperChain {
    scripts: Vec<Box<dyn TamperScript>>,
}

impl TamperChain {
    pub fn new() -> Self {
        Self {
            scripts: Vec::new(),
        }
    }

    pub fn add(mut self, script: Box<dyn TamperScript>) -> Self {
        self.scripts.push(script);
        self
    }

    pub fn apply(&self, payload: &str) -> String {
        self.scripts
            .iter()
            .fold(payload.to_string(), |acc, t| t.tamper(&acc))
    }

    pub fn names(&self) -> Vec<&'static str> {
        self.scripts.iter().map(|s| s.name()).collect()
    }

    /// Build a chain from a list of names. Unknown names are silently skipped.
    pub fn from_names(names: &[&str]) -> Self {
        let mut chain = Self::new();
        for &name in names {
            match name {
                // original 30
                "space_to_comment" => chain.scripts.push(Box::new(TamperSpaceToComment)),
                "space_to_tab" => chain.scripts.push(Box::new(TamperSpaceToTab)),
                "space_to_newline" => chain.scripts.push(Box::new(TamperSpaceToNewline)),
                "space_to_whitespace_mix" => {
                    chain.scripts.push(Box::new(TamperSpaceToWhitespaceMix))
                }
                "urlencode" => chain.scripts.push(Box::new(TamperUrlEncode)),
                "double_urlencode" => chain.scripts.push(Box::new(TamperDoubleUrlEncode)),
                "randomcase" => chain.scripts.push(Box::new(TamperRandomCase)),
                "mysql_version_comment" => chain.scripts.push(Box::new(TamperMySqlVersionComment)),
                "mysql50000comment" => chain.scripts.push(Box::new(TamperMySql50000Comment)),
                "inline_comment" => chain.scripts.push(Box::new(TamperInlineComment)),
                "double_keyword" => chain.scripts.push(Box::new(TamperDoubleKeyword)),
                "html_encode" => chain.scripts.push(Box::new(TamperHtmlEncode)),
                "unicode_escape" => chain.scripts.push(Box::new(TamperUnicodeEscape)),
                "null_byte" => chain.scripts.push(Box::new(TamperNullByte)),
                "equal_to_like" => chain.scripts.push(Box::new(TamperEqualToLike)),
                "logical_operators" => chain.scripts.push(Box::new(TamperLogicalOperators)),
                "hex_encode" => chain.scripts.push(Box::new(TamperHexEncode)),
                "sleep_to_benchmark" => chain.scripts.push(Box::new(TamperSleepToBenchmark)),
                "union_select_nospace" => chain.scripts.push(Box::new(TamperUnionSelectNospace)),
                "equiv_functions" => chain.scripts.push(Box::new(TamperEquivalentFunctions)),
                "version_comment" => chain.scripts.push(Box::new(TamperVersionComment)),
                "case_comment_mix" => chain.scripts.push(Box::new(TamperCaseCommentMix)),
                "scientific_notation" => chain.scripts.push(Box::new(TamperScientificNotation)),
                "hex_keyword" => chain.scripts.push(Box::new(TamperHexKeyword)),
                "string_concat_bypass" => chain.scripts.push(Box::new(TamperStringConcatBypass)),
                "between_operator" => chain.scripts.push(Box::new(TamperBetweenOperator)),
                "odbc_escape" => chain.scripts.push(Box::new(TamperOdbcEscape)),
                "backtick_identifiers" => chain.scripts.push(Box::new(TamperBacktickIdentifiers)),
                "keyword_newline_split" => chain.scripts.push(Box::new(TamperKeywordNewlineSplit)),
                "hpp_marker" => chain.scripts.push(Box::new(TamperHppMarker)),
                // new 22
                "charencode" => chain.scripts.push(Box::new(TamperCharEncode)),
                "chardoubleencode" => chain.scripts.push(Box::new(TamperCharDoubleEncode)),
                "charunicodeencode" => chain.scripts.push(Box::new(TamperCharUnicodeEncode)),
                "apostrophemask" => chain.scripts.push(Box::new(TamperApostropheMask)),
                "apostrophenullencode" => chain.scripts.push(Box::new(TamperApostropheNullEncode)),
                "unmagicquotes" => chain.scripts.push(Box::new(TamperUnMagicQuotes)),
                "base64encode" => chain.scripts.push(Box::new(TamperBase64Encode)),
                "overlongutf8" => chain.scripts.push(Box::new(TamperOverlongUtf8)),
                "randomcomments" => chain.scripts.push(Box::new(TamperRandomComments)),
                "multiplespaces" => chain.scripts.push(Box::new(TamperMultipleSpaces)),
                "greatest" => chain.scripts.push(Box::new(TamperGreatest)),
                "commalesslimit" => chain.scripts.push(Box::new(TamperCommalessLimit)),
                "commalessmid" => chain.scripts.push(Box::new(TamperCommalessMid)),
                "concat2concatws" => chain.scripts.push(Box::new(TamperConcat2ConcatWs)),
                "ifnull2ifisnull" => chain.scripts.push(Box::new(TamperIfNull2IfIsNull)),
                "modsecurityzeroversioned" => {
                    chain.scripts.push(Box::new(TamperModSecurityZeroVersioned))
                }
                "versionedkeywords" => chain.scripts.push(Box::new(TamperVersionedKeywords)),
                "unionalltounion" => chain.scripts.push(Box::new(TamperUnionAllToUnion)),
                "plus2concat" => chain.scripts.push(Box::new(TamperPlus2Concat)),
                "plus2fnconcat" => chain.scripts.push(Box::new(TamperPlus2FnConcat)),
                "bluecoat" => chain.scripts.push(Box::new(TamperBlueCoat)),
                "sp_password" => chain.scripts.push(Box::new(TamperSpPassword)),
                "symboliclogical" => chain.scripts.push(Box::new(TamperSymbolicLogical)),
                // additional 16
                "percentage" => chain.scripts.push(Box::new(TamperPercentage)),
                "space2plus" => chain.scripts.push(Box::new(TamperSpace2Plus)),
                "space2dash" => chain.scripts.push(Box::new(TamperSpace2Dash)),
                "space2hash" => chain.scripts.push(Box::new(TamperSpace2Hash)),
                "space2mssqlhash" => chain.scripts.push(Box::new(TamperSpace2MssqlHash)),
                "space2randomblank" => chain.scripts.push(Box::new(TamperSpace2RandomBlank)),
                "space2mysqlblank" => chain.scripts.push(Box::new(TamperSpace2MysqlBlank)),
                "lowercase" => chain.scripts.push(Box::new(TamperLowercase)),
                "halfversionedmorekeywords" => chain
                    .scripts
                    .push(Box::new(TamperHalfVersionedMoreKeywords)),
                "sleep2getlock" => chain.scripts.push(Box::new(TamperSleep2GetLock)),
                "least" => chain.scripts.push(Box::new(TamperLeast)),
                "nonrecursivereplacement" => {
                    chain.scripts.push(Box::new(TamperNonRecursiveReplacement))
                }
                "informationschemacomment" => {
                    chain.scripts.push(Box::new(TamperInformationSchemaComment))
                }
                "misunion" => chain.scripts.push(Box::new(TamperMisUnion)),
                "escapequotes" => chain.scripts.push(Box::new(TamperEscapeQuotes)),
                "ifnull2casewhenisnull" => {
                    chain.scripts.push(Box::new(TamperIfNull2CaseWhenIsNull))
                }
                _ => {}
            }
        }
        chain
    }

    pub fn available_names() -> &'static [&'static str] {
        &[
            // encoding
            "urlencode",
            "double_urlencode",
            "charencode",
            "chardoubleencode",
            "charunicodeencode",
            "unicode_escape",
            "base64encode",
            "overlongutf8",
            "hex_encode",
            "html_encode",
            // quote bypass
            "apostrophemask",
            "apostrophenullencode",
            "unmagicquotes",
            // space substitution
            "space_to_comment",
            "space_to_tab",
            "space_to_newline",
            "space_to_whitespace_mix",
            "multiplespaces",
            "bluecoat",
            // keyword obfuscation
            "randomcase",
            "randomcomments",
            "inline_comment",
            "case_comment_mix",
            "double_keyword",
            "keyword_newline_split",
            "hex_keyword",
            // MySQL comment tricks
            "mysql_version_comment",
            "mysql50000comment",
            "version_comment",
            "versionedkeywords",
            "modsecurityzeroversioned",
            // operator/function substitution
            "equal_to_like",
            "greatest",
            "between_operator",
            "logical_operators",
            "symboliclogical",
            "equiv_functions",
            "ifnull2ifisnull",
            // MySQL syntax variants
            "commalesslimit",
            "commalessmid",
            "concat2concatws",
            "unionalltounion",
            "union_select_nospace",
            "sleep_to_benchmark",
            "plus2concat",
            // ODBC / multi-backend
            "odbc_escape",
            "plus2fnconcat",
            // MSSQL
            "sp_password",
            // misc
            "null_byte",
            "scientific_notation",
            "string_concat_bypass",
            "backtick_identifiers",
            "hpp_marker",
            // additional 16
            "percentage",
            "space2plus",
            "space2dash",
            "space2hash",
            "space2mssqlhash",
            "space2randomblank",
            "space2mysqlblank",
            "lowercase",
            "halfversionedmorekeywords",
            "sleep2getlock",
            "least",
            "nonrecursivereplacement",
            "informationschemacomment",
            "misunion",
            "escapequotes",
            "ifnull2casewhenisnull",
        ]
    }

    pub fn is_empty(&self) -> bool {
        self.scripts.is_empty()
    }
}

/// Allow TamperChain to be used as a single TamperScript (applies the full chain).
impl TamperScript for TamperChain {
    fn name(&self) -> &'static str {
        "chain"
    }
    fn description(&self) -> &'static str {
        "Composed tamper chain (multiple scripts applied left-to-right)"
    }
    fn tamper(&self, payload: &str) -> String {
        self.apply(payload)
    }
}
