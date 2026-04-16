# SQX Integration Tests

Containerized integration test suite against real vulnerable applications.

## Targets

| Target | URL | Vulnerabilities |
|--------|-----|-----------------|
| sqli-labs | http://localhost:8888 | Error-based, Union, Boolean blind, Time-based, POST injection |
| DVWA | http://localhost:8889 | GET SQLi (low security) |

## Quick Start

```bash
cd tests/integration
./run.sh
```

Or manually:

```bash
cd tests/integration
docker compose up -d
# Wait for healthchecks
cd ../..
cargo test --test integration_test -- --nocapture --ignored
```

## Test Coverage

- `sqli_labs_less1_error_based` — Error-based detection on string context
- `sqli_labs_less1_union_based` — UNION-based data extraction
- `sqli_labs_less5_boolean_blind` — Boolean blind on pages without direct output
- `sqli_labs_less8_boolean_blind` — Numeric-in-quotes context (BUG-6/8 regression test)
- `sqli_labs_less9_time_based` — Time-based blind with adaptive sleep
- `sqli_labs_less11_post_error_based` — POST form injection
- `sqli_labs_file_read` — MySQL `LOAD_FILE` end-to-end
- `sqli_labs_smart_scan_finds_vulns` — Full behavioral fingerprinting pipeline
- `sqli_labs_auto_scan_discovers_points` — Spider + param fuzzing
- `dvwa_get_sqli_error_based` — Real-world GET injection target

## Why Ignored by Default

Tests are marked with `#[ignore]` because they require Docker containers.
This keeps `cargo test` fast for unit-test development while allowing CI to run:

```bash
cargo test --test integration_test -- --ignored
```
