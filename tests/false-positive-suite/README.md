# SQX False Positive Test Suite

## Scop

Validăm că SQX NU raportează vulnerabilități acolo unde nu există. 20 de endpoint-uri safe cu practici corecte de securizare.

## Categorii de teste

### 1. PDO/MySQLi Prepared Statements (PHP) - 10 teste
- `pdo-prepared` - `?` placeholders, execute([$id])
- `pdo-named` - `:name` placeholders cu array asociativ
- `validated-prepared` - filter_var() + prepared statement
- `like-prepared` - LIKE cu wildcards în parameter bound
- `in-prepared` - Array expansion cu multiple `?`
- `stored-proc` - CALL procedure(?) cu bound param
- `orm-style` - Query builder dynamic dar parameterized
- `escaped-legacy` - quote() + escaping (discouraged)
- `cache-key` - Map/array lookup (nicio interogare SQL)
- `logging` - File append (fără DB)

### 2. SQLAlchemy (Python) - 5 teste
- `sqlalchemy-orm` - session.get(User, id)
- `sqlalchemy-core` - select().where()
- `sqlalchemy-text` - text() with bindparams
- `sqlalchemy-bulk` - Bulk ORM insert
- `nosql-json` - JSON file storage

### 3. Node.js Parameterized - 5 teste
- `mysql2-prepared` - execute() cu ? placeholders
- `mysql2-in-clause` - IN clause with array
- `pg-prepared` - $1, $2 PostgreSQL syntax
- `pg-like` - LIKE $1 cu pattern inclus în bound value
- `redis-cache` - Key-value store (simulated)

## Criterii de trecere

SQX trebuie să returneze:
- **0% confidence** pe toate endpoint-urile
- **Zero findings** (no vulnerabilities reported)
- **"Target appears safe"** sau similar

## Quick Start

```bash
# 1. Pornește toate serviciile
cd tests/false-positive-suite
docker-compose up -d

# 2. Așteaptă inițializarea (10-15 secunde)
sleep 15

# 3. Rulează testele
chmod +x run-tests.sh
./run-tests.sh

# Sau test manual
sqx scan "http://localhost:9001/?route=pdo-prepared&id=1"
# Expected: "No SQL injection detected" sau 0% confidence
```

## Test Individual

```bash
# PHP Safe Endpoints
curl "http://localhost:9001/?route=pdo-prepared&id=1"
curl "http://localhost:9001/?route=pdo-named&id=1&name=test"
curl "http://localhost:9001/?route=validated-prepared&id=1"

# Python/SQLAlchemy
curl "http://localhost:9003/sqlalchemy-orm?id=1"
curl "http://localhost:9003/sqlalchemy-core?id=1"

# Node.js
curl "http://localhost:9002/mysql2-prepared?id=1"
curl "http://localhost:9002/pg-prepared?id=1"
```

## Debugging

Dacă un test FAIL-ează:

```bash
# Verifică logurile
docker-compose logs php-safe
docker-compose logs python-safe
docker-compose logs node-safe

# Testează manual cu verbose
sqx scan "http://localhost:9001/?route=pdo-prepared&id=1" -v

# Verifică conectivitatea
curl -v "http://localhost:9001/"
```

## Note

Aceste endpoint-uri simulează best practices în industrie. Dacă SQX raportează false positives aici, va raporta și în producție pe aplicații legitime, subminând credibilitatea tool-ului.

## Dacă un test FAIL-ează

1. **Este un BUG** - false positive real
2. **Nu lansa release** până nu e fixat
3. **Root cause analysis** - de ce pattern-ul a triggerat detecția?
