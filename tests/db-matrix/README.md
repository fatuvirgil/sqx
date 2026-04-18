# SQX DB Matrix Testing Environment

Cross-database compatibility testing environment for SQX. Tests SQL injection detection and extraction against multiple DBMS versions.

## Quick Start

```bash
cd tests/db-matrix

# Start all databases
docker compose up -d

# Wait for initialization (~60 seconds)
./scripts/verify-all.sh

# Run SQX tests
./scripts/test-sqx.sh
```

## Services

| Service | DB Port | Web Port | Purpose |
|---------|---------|----------|---------|
| MySQL 5.7 | 33057 | 8057 | Legacy MySQL testing |
| MySQL 8.0 | 33080 | 8080 | Modern MySQL testing |
| MariaDB 10 | 33010 | 8010 | MySQL fork testing |
| PostgreSQL 13 | 54313 | 8113 | Enterprise PostgreSQL |
| MSSQL 2019 | 21433 | 8143 | Microsoft SQL Server |
| SQLite | N/A | 8190 | File-based database |

## Test Scenarios

### Error-Based Injection
```bash
curl 'http://localhost:8057/?lesson=Less-1&id=1''
# Should return SQL error
```

### Boolean-Based Blind
```bash
curl 'http://localhost:8057/?lesson=Less-5&id=1'
# Returns different content based on TRUE/FALSE
```

### Time-Based Blind
```bash
curl 'http://localhost:8057/?lesson=Less-9&id=1'
# Supports SLEEP(), pg_sleep(), WAITFOR DELAY, randomblob()
```

## SQX Test Commands

```bash
# Test MySQL 5.7
echo "" | ./target/release/sqx scan "http://localhost:8057/?lesson=Less-1&id=1" --tech error

# Test PostgreSQL
echo "" | ./target/release/sqx scan "http://localhost:8113/?lesson=Less-1&id=1" --tech error

# Test all techniques on MSSQL
echo "" | ./target/release/sqx scan "http://localhost:8143/?lesson=Less-1&id=1" --tech error,blind,time
```

## Database Credentials

| DB | Username | Password | Database |
|----|----------|----------|----------|
| MySQL/MariaDB | sqx_test | sqx_pass | security |
| PostgreSQL | sqx_test | sqx_pass | security |
| MSSQL | sa | SqxTestPass123! | security |
| SQLite | N/A | N/A | /data/sqli-labs.db |

## Troubleshooting

### Containers not starting
```bash
docker compose down -v
docker compose up -d
```

### Check logs
```bash
docker logs sqx_mysql_57
docker logs sqx_postgres_13
docker logs sqx_mssql_2019
```

### Reset data
```bash
docker compose down -v
docker volume rm sqx_db_matrix_*
docker compose up -d
```

## Test Matrix

| DB | Error | Boolean | Time | Union | File Read |
|----|-------|---------|------|-------|-----------|
| MySQL 5.7 | ✓ | ✓ | ✓ | ✓ | ✓ |
| MySQL 8.0 | ✓ | ✓ | ✓ | ✓ | ✓ |
| MariaDB 10 | ✓ | ✓ | ✓ | ✓ | ✓ |
| PostgreSQL 13 | ✓ | ✓ | ✓ | ✓ | ✗ |
| MSSQL 2019 | ✓ | ✓ | ✓ | ✓ | ✓ |
| SQLite | ✓ | ✓ | ✓ | ✓ | ✗ |

## Next Phase Integration

This DB Matrix is Phase 2 of the SQX Hardening Plan:

1. **Phase 1**: False Positive Suite (safe endpoints)
2. **Phase 2**: Cross-DB Matrix (this environment) ← You are here
3. **Phase 3**: WAF Evasion Real (ModSecurity, Cloudflare)
4. **Phase 4**: Stability & Performance (1000 URLs, 2h runtime)
5. **Phase 5**: Documentation & Regression
