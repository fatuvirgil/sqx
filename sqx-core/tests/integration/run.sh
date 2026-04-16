#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

cd "$SCRIPT_DIR"

echo "[*] Starting integration test environment..."
docker compose up -d --wait 2>/dev/null || docker compose up -d

echo "[*] Waiting for services to be healthy..."
sleep 5

for i in {1..30}; do
    if curl -s -o /dev/null -w "%{http_code}" http://localhost:8888/Less-1/ | grep -q "200"; then
        echo "[+] sqli-labs ready"
        break
    fi
    sleep 1
done

for i in {1..30}; do
    if curl -s -o /dev/null -w "%{http_code}" http://localhost:8889/login.php | grep -q "200"; then
        echo "[+] DVWA ready"
        break
    fi
    sleep 1
done

echo "[*] Running integration tests..."
cd "$PROJECT_ROOT"
cargo test --test integration_test -- --nocapture --ignored

echo "[*] Shutting down integration test environment..."
cd "$SCRIPT_DIR"
docker compose down

echo "[+] Done"
