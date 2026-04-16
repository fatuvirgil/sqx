# SQLmap Payload Integration (Technical Documentation)

## Overview

SQX integrates external SQL injection payload databases (specifically from the sqlmap project) while maintaining license compliance. This is achieved through a "fetch-on-demand" architecture where GPLv2 data is processed at runtime by an MIT-licensed engine.

## Architecture

```
┌─────────────────┐     fetch at runtime      ┌─────────────────────────────┐
│  sqx update-    │ ────────────────────────► │ ~/.local/share/sqx/payloads/│
│  payloads       │                           │  - boundaries.xml           │
└─────────────────┘                           │  - boolean_blind.xml        │
                                              │  - time_blind.xml           │
                                              │  - error_based.xml          │
                                              │  - union_select.xml         │
                                              │  - stacked_queries.xml      │
                                              │  - patt_sqli.txt            │
                                              └─────────────────────────────┘
                                                         ▲
                                                         │ load()
┌────────────────────────────────────────────────────────┘
│  sqx-core/src/sqx/payload_fetcher.rs
│  ├── DynamicPayloads::load()      → parse XML from cache
│  ├── DynamicPayloads::resolve_placeholders()
│  └── BOUNDARIES (23 built-in contexts)
└────────────────────────────────────────────────────────┐
                                                         │
        ┌────────────────┬────────────────┬──────────────┘
        ▼                ▼                ▼
  techniques/      extraction/      extraction/
  boolean_blind.rs blind.rs         time_blind.rs
  time_based.rs                     schema.rs
```

## Data Models

### `SqlmapBoundary`

Represents a prefix/suffix pair used to escape the SQL context.

- `level`, `risk`: Controls when the boundary is tried.
- `clause`: Bitmask of SQL clauses where this boundary is valid.
- `where_clause`: Bitmask of injection positions (`1=append`, `2=inline`, `3=replace`).
- `prefix`, `suffix`: The literal strings injected around the payload.

### `SqlmapTest`

Represents a specific detection vector.

- `stype`: Injection type (`1=Boolean`, `2=Error`, `3=Union`, `4=Stacked`, `5=Time`, `6=Inline`).
- `request_payload`: The template for detection (may contain placeholders).
- `vector`: The template for data extraction (containing `[INFERENCE]`).
- `response_comparison`: Pattern used to identify a successful hit.

## Placeholder Resolution

SQX implements a custom engine to resolve placeholders within sqlmap XML strings. All placeholders are resolved **before** a payload is sent to the target:

| Placeholder | Resolved to |
|---|---|
| `[RANDNUM]` | Random integer (default `42`) |
| `[RANDSTR]` | Random alphanumeric string (default `sqx`) |
| `[ORIGVALUE]` | The original value of the injected parameter |
| `[INFERENCE]` | The boolean condition being tested during bisection (e.g. `ORD(MID(...))>64`) |
| `[SLEEPTIME]` | The adaptive sleep duration in seconds |
| `[PRIORITY]` | Priority marker (usually `1=1`) — resolved during detection prep |

### Example

```rust
let template = "AND [INFERENCE]-- ";
let resolved = DynamicPayloads::resolve_placeholders(
    template, 42, "sqx", "1", "ORD(MID((SELECT version()),1,1))>64", 5
);
// → "AND ORD(MID((SELECT version()),1,1))>64-- "
```

## Boundary `<where>` Semantics

sqlmap boundaries encode **how** the payload is inserted relative to the original parameter value. SQX respects all three modes:

| `where` | Behavior | Example (`orig=1`, prefix=`'`, payload=`AND 1=1`, suffix=`-- `) |
|---|---|---|
| `1` (append) | `{val}{prefix}{payload}{suffix}` | `1'AND 1=1-- ` |
| `2` (inline) | `{prefix}{payload}{suffix}` | `'AND 1=1-- ` |
| `3` (replace) | `{prefix}{payload}{suffix}` | `'AND 1=1-- ` |

Both detection (`boolean_blind.rs`, `time_based.rs`) and extraction (`blind.rs`, `time_blind.rs`) use `apply_sqlmap_boundary()` which selects the correct `where` mode from the intersection of `test.where_clause` and `boundary.where_clause`.

## Integration Points

### Detection Phase

1. `test_boolean_blind()` and `test_time_based()` iterate cached `SqlmapTest` objects.
2. For each test, compatible `SqlmapBoundary` objects are selected by matching `clause` and `where_clause`.
3. The `request_payload` is resolved (placeholders replaced) and wrapped with the boundary.
4. For boolean tests, a **FALSE pair** is generated by replacing the `[INFERENCE]` condition with `1=2` (or equivalent negation).
5. The TRUE/FALSE pair is sent and classified using similarity/time-delay heuristics.

### Extraction Phase

Once a `payload_id` is confirmed, the extraction routines (`extract_data_blind`, `extract_data_time_based`) lookup the corresponding `vector`. This ensures that the **exact same SQL structure** that triggered the detection is used for bisection, significantly increasing reliability in complex injection points.

## License Compliance

SQX source code **does not contain any sqlmap XML fragments**.

1. `payload_fetcher.rs` contains only URLs to raw GitHub content.
2. `sqx update-payloads` downloads these files to `~/.local/share/sqx/payloads/`.
3. The engine parses these local files at runtime.

This follows the "browser-content" model where the software is a neutral consumer of third-party data.

## Coverage Reality Check

While the integration **mechanism** is complete (parsing, placeholders, where-logic, vectors), the **effective coverage** of sqlmap's full payload database is approximately **~5%**.

For a detailed gap analysis per technique (boundaries, DBMS-specific payloads, nested contexts), see:

➡️ [`tests/payload_audit.md`](../tests/payload_audit.md)
