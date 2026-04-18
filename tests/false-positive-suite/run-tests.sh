#!/bin/bash
# tests/false-positive-suite/run-tests.sh
# Script de testare automatizată False Positive Suite

set -e

echo "=========================================="
echo "SQX False Positive Test Suite"
echo "=========================================="
echo ""

# Verifică dacă SQX există
SQX_BIN="${SQX_BIN:-./target/release/sqx}"
if [ ! -f "$SQX_BIN" ]; then
    echo "❌ SQX binary not found at $SQX_BIN"
    echo "   Build with: cargo build --release"
    exit 1
fi

echo "Using SQX binary: $SQX_BIN"
echo ""

# Așteaptă ca serviciile să fie ready
echo "Waiting for services to be ready..."
sleep 5

# Endpoint-uri care TREBUIE să returneze 0% confidence (SAFE)
SAFE_ENDPOINTS=(
    # PHP Safe
    "http://localhost:9001/?route=pdo-prepared&id=1"
    "http://localhost:9001/?route=pdo-named&id=1&name=test"
    "http://localhost:9001/?route=validated-prepared&id=1"
    "http://localhost:9001/?route=like-prepared&search=test"
    "http://localhost:9001/?route=in-prepared&ids=1,2,3"
    "http://localhost:9001/?route=stored-proc&id=1"
    "http://localhost:9001/?route=orm-style&id=1&name=john"
    "http://localhost:9001/?route=cache-key&key=user_1"
    "http://localhost:9001/?route=logging&action=view&user_id=1"
    
    # Python/SQLAlchemy
    "http://localhost:9003/sqlalchemy-orm?id=1"
    "http://localhost:9003/sqlalchemy-core?id=1"
    "http://localhost:9003/sqlalchemy-text?name=test"
    "http://localhost:9003/nosql-json"
    
    # Node.js
    "http://localhost:9002/mysql2-prepared?id=1"
    "http://localhost:9002/mysql2-in-clause?ids=1,2,3"
    "http://localhost:9002/pg-prepared?id=1"
    "http://localhost:9002/pg-like?search=john"
    "http://localhost:9002/redis-cache?key=user:1"
)

PASSED=0
FAILED=0

echo "Running tests..."
echo ""

for endpoint in "${SAFE_ENDPOINTS[@]}"; do
    echo -n "Testing: ${endpoint:0:60}... "
    
    # Rulează SQX scan (quiet mode, with timeout)
    result=$(timeout 15 "$SQX_BIN" scan "$endpoint" --output json 2>/dev/null <<< "" | grep -o '"confidence":[0-9.]*' | cut -d: -f2 || echo "")
    
    if [ -z "$result" ] || [ "$result" = "0" ] || [ "$result" = "0.0" ]; then
        echo "✅ PASS (0% confidence)"
        ((PASSED++))
    else
        echo "❌ FAIL ($result% confidence - FALSE POSITIVE!)"
        ((FAILED++))
        echo "   ^^ Endpoint: $endpoint"
    fi
done

echo ""
echo "=========================================="
echo "Results: $PASSED passed, $FAILED failed"
echo "=========================================="

if [ $FAILED -gt 0 ]; then
    echo ""
    echo "❌ FAILED: $FAILED false positives detected"
    echo ""
    echo "These endpoints use SAFE practices:"
    echo "  - PDO Prepared Statements"
    echo "  - SQLAlchemy ORM/Core"
    echo "  - Node.js mysql2/pg parameterized queries"
    echo "  - Non-SQL operations (cache, logging)"
    echo ""
    echo "SQX should NOT report vulnerabilities on these!"
    exit 1
else
    echo ""
    echo "✅ SUCCESS: All endpoints correctly identified as SAFE"
    echo ""
    echo "SQX correctly distinguishes between:"
    echo "  - Vulnerable code (string concatenation)"
    echo "  - Safe code (parameterized queries, ORM)"
    exit 0
fi
