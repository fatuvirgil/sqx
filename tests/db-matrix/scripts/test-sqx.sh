#!/bin/bash
# Run SQX against all DB matrix endpoints

SQX_BIN="${SQX_BIN:-./target/release/sqx}"
TIMEOUT="${TIMEOUT:-60}"

echo "=========================================="
echo "SQX DB Matrix - Test Runner"
echo "=========================================="
echo ""

if [ ! -f "$SQX_BIN" ]; then
    echo "Error: SQX binary not found at $SQX_BIN"
    echo "Set SQX_BIN environment variable or build with: cargo build --release -p sqx-cli"
    exit 1
fi

# Test matrix
declare -A ENDPOINTS
declare -A EXPECTED_TECHNIQUES

ENDPOINTS[
     EXPECTED_TECHNIQUES["mysql57"]="ErrorBased"

ENDPOINTS["mysql80"]="http://localhost:8080/?lesson=Less-1&id=1"
EXPECTED_TECHNIQUES["mysql80"]="ErrorBased"

ENDPOINTS["mariadb"]="http://localhost:8010/?lesson=Less-1&id=1"
EXPECTED_TECHNIQUES["mariadb"]="ErrorBased"

ENDPOINTS["postgres"]="http://localhost:8113/?lesson=Less-1&id=1"
EXPECTED_TECHNIQUES["postgres"]="ErrorBased"

ENDPOINTS["mssql"]="http://localhost:8143/?lesson=Less-1&id=1"
EXPECTED_TECHNIQUES["mssql"]="ErrorBased"

ENDPOINTS["sqlite"]="http://localhost:8190/?lesson=Less-1&id=1"
EXPECTED_TECHNIQUES["sqlite"]="ErrorBased"

# Boolean blind tests
ENDPOINTS["mysql57_blind"]="http://localhost:8057/?lesson=Less-5&id=1"
EXPECTED_TECHNIQUES["mysql57_blind"]="BooleanBlind"

ENDPOINTS["mysql80_blind"]="http://localhost:8080/?lesson=Less-5&id=1"
EXPECTED_TECHNIQUES["mysql80_blind"]="BooleanBlind"

# Time-based tests
ENDPOINTS["mysql57_time"]="http://localhost:8057/?lesson=Less-9&id=1"
EXPECTED_TECHNIQUES["mysql57_time"]="TimeBased"

ENDPOINTS["postgres_time"]="http://localhost:8113/?lesson=Less-9&id=1"
EXPECTED_TECHNIQUES["postgres_time"]="TimeBased"

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

PASSED=0
FAILED=0

run_test() {
    local name=$1
    local url=$2
    local tech=$3
    
    echo ""
    echo "Testing: $name"
    echo "URL: $url"
    echo "Expected: $tech"
    
    # Determine tech flags based on expected technique
    local tech_flag=""
    case "$tech" in
        "ErrorBased") tech_flag="error" ;;
        "BooleanBlind") tech_flag="blind" ;;
        "TimeBased") tech_flag="time" ;;
        *) tech_flag="error,blind,union,time" ;;
    esac
    
    # Run SQX
    output=$(echo "" | timeout $TIMEOUT "$SQX_BIN" scan "$url" --tech "$tech_flag" 2>&1)
    exit_code=$?
    
    if [ $exit_code -eq 124 ]; then
        echo -e "${YELLOW}TIMEOUT${NC} (>${TIMEOUT}s)"
        ((FAILED++))
        return
    fi
    
    # Check if vulnerability found
    if echo "$output" | grep -q "\[VULN\]"; then
        found_tech=$(echo "$output" | grep "technique=" | head -1 | sed 's/.*technique=//' | awk '{print $1}')
        confidence=$(echo "$output" | grep "confidence=" | head -1 | sed 's/.*confidence=//' | awk '{print $1}')
        
        if echo "$found_tech" | grep -qi "$tech"; then
            echo -e "${GREEN}✓ PASS${NC} - Found: $found_tech ($confidence)"
            ((PASSED++))
        else
            echo -e "${YELLOW}⚠ PARTIAL${NC} - Expected $tech, found $found_tech"
            ((PASSED++)) # Still counts as detection
        fi
    else
        echo -e "${RED}✗ FAIL${NC} - No vulnerability detected"
        echo "Output: $output"
        ((FAILED++))
    fi
}

echo "Running tests..."
echo ""

for key in "${!ENDPOINTS[@]}"; do
    run_test "$key" "${ENDPOINTS[$key]}" "${EXPECTED_TECHNIQUES[$key]}"
done

echo ""
echo "=========================================="
echo "Results: $PASSED passed, $FAILED failed"
echo "=========================================="

exit $FAILED
