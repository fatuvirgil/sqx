# SQX Payload Audit vs sqlmap

## Executive Summary

SQX currently ships with:
- **23 built-in boundary contexts**
- **~50 built-in PATT payloads**
- **68 tamper scripts**
- **Dynamic payload fetch** (`sqx update-payloads`) for sqlmap XML + PATT full

sqlmap has **thousands of payloads** across **hundreds of edge cases**. This document tracks the coverage gap.

## Coverage by Technique

### Error-Based
| Category | SQX | sqlmap | Gap |
|----------|-----|--------|-----|
| MySQL error triggers | 8 | 45+ | Missing: `DOUBLE`, `BIGINT`, `JSON`, `POINT`, `PROCEDURE ANALYSE` variants |
| PostgreSQL error triggers | 5 | 30+ | Missing: `XMLENTITY`, `pg_sleep` in cast contexts, `INTO` clause errors |
| MSSQL error triggers | 4 | 25+ | Missing: `FOR XML PATH`, `OPENROWSET` error chains, `CONVERT` overflow |
| Oracle error triggers | 3 | 20+ | Missing: `CTXSYS.DRITHSX.SN`, `dbms_xmlgen.getxmltype`, `utl_inaddr` |
| SQLite error triggers | 2 | 10+ | Missing: `json_each`, `fts3` tokenization errors |

### Boolean-Based Blind
| Context | SQX Boundaries | sqlmap Boundaries | Note |
|---------|---------------|-------------------|------|
| Numeric | `1 AND 1=1` / `1 AND 1=2` | Same | Parity ✅ |
| Single-quote string | `1' AND '1'='1` | Same | Parity ✅ |
| Double-quote string | Missing | `1" AND "1"="1` | **Gap** |
| LIKE clause | Missing | `1%' AND '%'='` | **Gap** |
| IN clause | Missing | `1) AND (1=1` | **Gap** |
| ORDER BY | Missing | `1,1) AND (1=1` | **Gap** |
| HAVING | Missing | `1) AND 1=1 GROUP BY` | **Gap** |

### Time-Based Blind
| DBMS | SQX Functions | sqlmap Functions | Gap |
|------|--------------|------------------|-----|
| MySQL | `SLEEP()`, `BENCHMARK()` | `SLEEP()`, `BENCHMARK()`, `GET_LOCK()`, `PG_SLEEP()` (via MariaDB) | Minor |
| PostgreSQL | `pg_sleep()` | `pg_sleep()`, `pg_read_file` delay, `GENERATE_SERIES` CPU burn | Minor |
| MSSQL | `WAITFOR DELAY` | `WAITFOR DELAY`, `WAITFOR TIME`, `xp_cmdshell` ping | Minor |
| Oracle | `dbms_pipe.receive_message` | `dbms_pipe.receive_message`, `dbms_lock.sleep` | Minor |
| SQLite | `randomblob(1000000000)` | Same | Parity ✅ |

### UNION-Based
| Feature | SQX | sqlmap | Gap |
|---------|-----|--------|-----|
| ORDER BY column discovery | ✅ | ✅ | Parity |
| UNION SELECT NULL filling | ✅ | ✅ | Parity |
| Printable column detection | Status-code + content | Content reflection only | SQX slightly better |
| DBMS-specific type casts | `CAST`, `TO_CHAR` | `NVL`, `COALESCE`, `IFNULL`, `CONVERT` | **Gap** |
| Partial union (column offset) | Missing | `UNION SELECT * FROM (SELECT ...)` | **Gap** |

### Stacked Queries
| DBMS | SQX | sqlmap | Gap |
|------|-----|--------|-----|
| MySQL | `; SELECT SLEEP(5)` | `; SELECT SLEEP(5)`, `; DO SLEEP(5)` | Minor |
| PostgreSQL | `; SELECT pg_sleep(5)` | `; SELECT pg_sleep(5)`, `; COPY ... TO PROGRAM` | Minor |
| MSSQL | `; WAITFOR DELAY '0:0:5'` | `; WAITFOR DELAY`, `; EXEC xp_cmdshell` | Minor |
| Oracle | Missing | `; EXECUTE IMMEDIATE` | **Major Gap** |

### Out-of-Band
| Feature | SQX | sqlmap | Gap |
|---------|-----|--------|-----|
| HTTP OOB | ✅ | ✅ | Parity |
| DNS OOB | ✅ (built-in server) | ✅ (external or built-in) | Parity after recent fix |
| SMB/UNC OOB | Missing | `xp_dirtree`, `xp_fileexist` | **Gap** |

## Root Causes of Fals Negatives

1. **Boundary coverage**: sqlmap tests 100+ injection contexts; SQX tests 23.
2. **Payload diversity**: sqlmap has vendor-specific payloads for every DBMS minor version; SQX has generic payloads.
3. **WAF bypass diversity**: sqlmap has 40+ tamper scripts and dynamically chains them; SQX has 68 tampers but static chaining logic.
4. **Nested/contextual injection**: sqlmap handles injection inside `JSON`, `XML`, `base64` parameters; SQX does not.

## Action Items

1. **Map all sqlmap XML boundaries** into `DynamicPayloads` and consume them in `test_condition_blind` / `test_time_based`.
2. **Add missing contexts**: double-quote, LIKE, IN, ORDER BY, HAVING.
3. **Add DBMS-specific UNION cast functions** for Oracle, MSSQL, PostgreSQL.
4. **Implement nested/context parsing** for JSON/XML/base64 parameters.
