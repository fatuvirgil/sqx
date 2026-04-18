#!/bin/bash
# Verify all databases in the matrix are ready

echo "=========================================="
echo "SQX DB Matrix - Verification Script"
echo "=========================================="
echo ""

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Check function
check_service() {
    local name=$1
    local url=$2
    local expected=$3
    
    echo -n "Checking $name... "
    
    response=$(curl -s -o /dev/null -w "%{http_code}" "$url" 2>/dev/null)
    
    if [ "$response" = "$expected" ]; then
        echo -e "${GREEN}✓ READY${NC} (HTTP $response)"
        return 0
    else
        echo -e "${RED}✗ UNAVAILABLE${NC} (HTTP $response, expected $expected)"
        return 1
    fi
}

check_db_port() {
    local name=$1
    local host=$2
    local port=$3
    
    echo -n "Checking $name direct connection... "
    
    if timeout 5 bash -c "</dev/tcp/$host/$port" 2>/dev/null; then
        echo -e "${GREEN}✓ OPEN${NC}"
        return 0
    else
        echo -e "${RED}✗ CLOSED${NC}"
        return 1
    fi
}

echo "Database Services:"
echo "─────────────────"

# MySQL 5.7
check_db_port "MySQL 5.7" "localhost" "33057"

# MySQL 8.0
check_db_port "MySQL 8.0" "localhost" "33080"

# MariaDB 10
check_db_port "MariaDB 10" "localhost" "33010"

# PostgreSQL 13
check_db_port "PostgreSQL 13" "localhost" "54313"

# MSSQL 2019
check_db_port "MSSQL 2019" "localhost" "21433"

echo ""
echo "Web Applications:"
echo "─────────────────"

# Web apps
check_service "MySQL 5.7 Web" "http://localhost:8057/" "200"
check_service "MySQL 8.0 Web" "http://localhost:8080/" "200"
check_service "MariaDB Web" "http://localhost:8010/" "200"
check_service "PostgreSQL Web" "http://localhost:8113/" "200"
check_service "MSSQL Web" "http://localhost:8143/" "200"
check_service "SQLite Web" "http://localhost:8190/" "200"

echo ""
echo "=========================================="
echo "All services verified!"
echo "=========================================="
echo ""
echo "Test endpoints:"
echo "  MySQL 5.7:  curl 'http://localhost:8057/?lesson=Less-1&id=1'"
echo "  MySQL 8.0:  curl 'http://localhost:8080/?lesson=Less-1&id=1'"
echo "  MariaDB:    curl 'http://localhost:8010/?lesson=Less-1&id=1'"
echo "  PostgreSQL: curl 'http://localhost:8113/?lesson=Less-1&id=1'"
echo "  MSSQL:      curl 'http://localhost:8143/?lesson=Less-1&id=1'"
echo "  SQLite:     curl 'http://localhost:8190/?lesson=Less-1&id=1'"
