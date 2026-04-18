# SQX Payload Audit vs sqlmap

## Executive Summary

SQX currently ships with:
- **32 built-in boundary contexts** (+9 from high-priority gaps)
- **~100 built-in PATT payloads** (+50 DBMS-specific error triggers pentru 13 DBMS-uri)
- **68 tamper scripts**
- **Dynamic payload fetch** (`sqx update-payloads`) for sqlmap XML + PATT full
- **Support pentru 26 DBMS-uri** (6 major + 20 exotice)

## Status Testare Reală (2026-04-17)

| DBMS | Error-Based Payloads | Testat Real | Container Docker |
|------|---------------------|-------------|------------------|
| MySQL 5.7/8.0 | ✅ 6 payloads | ✅ Da | ✅ |
| MariaDB 10 | ✅ 4 payloads | ✅ Da | ✅ |
| PostgreSQL 13 | ✅ 6 payloads | ✅ Da | ✅ |
| SQLite | ✅ 3 payloads | ✅ Da | ✅ |
| **CockroachDB** | ✅ 2 payloads | **✅ Da** | **✅ Nou** |
| **ClickHouse** | ✅ 3 payloads | **✅ Da** | **✅ Nou** |
| **TiDB** | ✅ 3 payloads | **✅ Da** | **✅ Nou** |
| Firebird | ✅ 3 payloads | ❌ Nu | ❌ Driver PDO indisponibil |
| H2 | ✅ 3 payloads | ❌ Nu | ❌ Necesită JDBC bridge |
| DB2 | ✅ 3 payloads | ❌ Nu | ❌ Imagine >2GB, licență IBM |
| Sybase | ⚠️ Skeleton | ❌ Nu | ❌ Imagini inexistente |
| Informix | ⚠️ Skeleton | ❌ Nu | ❌ Licență IBM |
| *altele 13* | ⚠️ Skeleton | ❌ Nu | ❌ Too niche/discontinued |

**Scor testare: 7/26 DBMS-uri (27%) testate real**

sqlmap has **thousands of payloads** across **hundreds of edge cases**. This document tracks the coverage gap.

## Coverage by Technique

### Error-Based
| Category | SQX | sqlmap | Gap |
|----------|-----|--------|-----|
| MySQL error triggers | 13 | 45+ | ✅ **Added**: `DOUBLE`, `BIGINT`, `JSON`, `PROCEDURE ANALYSE` variants |
| MariaDB error triggers | 8 | 35+ | ✅ **Added**: XPATH, DOUBLE, REGEXP errors |
| PostgreSQL error triggers | 10 | 30+ | ✅ **Added**: `CAST` errors, `pg_sleep` in cast contexts, `ARRAY_AGG` |
| MSSQL error triggers | 10 | 25+ | ✅ **Added**: `FOR XML PATH`, `CONVERT` overflow, `CAST` errors |
| Oracle error triggers | 10 | 20+ | ✅ **Added**: `CTXSYS.DRITHSX.SN`, `dbms_xmlgen.getxmltype`, `utl_inaddr` |
| SQLite error triggers | 5 | 10+ | ✅ **Added**: `CAST` errors, `JSON` errors, `FTS5` errors |
| **DB2** | 3 | 15+ | ✅ **Added**: `XMLPARSE`, `CAST`, recursive CTE errors |
| **Firebird** | 3 | 10+ | ✅ **Added**: `CAST`, `LIST`, `GEN_UUID` errors |
| **H2** | 3 | 10+ | ✅ **Added**: `CAST`, `XMLATTR`, division by zero |
| **Informix** | 2 | 10+ | ✅ **Added**: `TO_NUMBER`, `TO_DATE` errors |
| **ClickHouse** | 3 | 8+ | ✅ **Added**: `toInt64`, `arrayJoin`, `JSONExtract` errors |
| **CockroachDB** | 2 | 8+ | ✅ **Added**: `CAST`, `crdb_internal.force_error` |
| **TiDB** | 3 | 10+ | ✅ **Added**: XPATH, `JSON_KEYS`, `TIDB_DECODE_KEY` |

### Boolean-Based Blind
| Context | SQX Boundaries | sqlmap Boundaries | Note |
|---------|---------------|-------------------|------|
| Numeric | `1 AND 1=1` / `1 AND 1=2` | Same | Parity ✅ |
| Single-quote string | `1' AND '1'='1` | Same | Parity ✅ |
| Double-quote string | Missing | `1" AND "1"="1` | **Gap** (MySQL limitation) |
| LIKE clause | `1%' AND '%'='` | Same | ✅ **Added** |
| IN clause | `1) AND (1=1` | Same | ✅ **Added** |
| ORDER BY | `1,1) AND (1=1` | Same | ✅ **Added** |
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

### Completed ✅

1. ~~**Map all sqlmap XML boundaries** into `DynamicPayloads` and consume them in `test_condition_blind` / `test_time_based`.~~
2. ~~**Add missing contexts**: LIKE, IN, ORDER BY.~~ 
   - ✅ `like-sq` boundary: `%' AND '%'='`
   - ✅ `in-paren` boundary: `) AND (1=1`
   - ✅ `order-num` boundary: `,1) AND (1=1`
3. ~~**Add DBMS-specific error triggers** pentru toate DBMS-urile.~~
   - ✅ **Major**: MySQL, PostgreSQL, MSSQL, Oracle, MariaDB, SQLite
   - ✅ **Exotice**: DB2, Firebird, H2, Informix, ClickHouse, CockroachDB, TiDB
   - ⏳ **Rămase**: Sybase, HSQLDB, Ingres, Derby, Cache, FrontBase, MonetDB, Virtuoso, mSQL, Mckoi

### Remaining 📋

4. **Add missing contexts**: double-quote (MySQL env limitation), HAVING.
5. **Add DBMS-specific UNION cast functions** for Oracle, MSSQL, PostgreSQL.
6. **Implement nested/context parsing** for JSON/XML/base64 parameters.
7. **Stacked queries for Oracle** (`EXECUTE IMMEDIATE`).
8. **SMB/UNC OOB** for MSSQL (`xp_dirtree`, `xp_fileexist`).
