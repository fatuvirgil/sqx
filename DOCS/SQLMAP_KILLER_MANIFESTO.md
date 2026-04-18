# SQX SQLMap Killer Manifesto

## Mission

SQX exists to surpass `sqlmap`, not to imitate it.

That means:

- match or exceed `sqlmap` on core SQL injection detection and exploitation
- beat `sqlmap` on operator speed, usability, and clarity
- solve exploit chains that go beyond SQLi into adjacent web attack surfaces

If SQX only becomes "sqlmap in Rust", it loses.
If SQX becomes the best tool for turning SQLi into full compromise workflows, it wins.

## Product Position

SQX should be:

- a production-grade SQLi engine
- an exploit chain orchestrator
- a source and sink analysis tool
- an operator-first CLI and GUI platform

SQX should not be:

- a proof-of-concept scanner
- a collection of disconnected payloads
- a prettier wrapper around basic SQLi checks

## Non-Negotiable Goals

### 1. SQLi Parity

SQX must reach real-world parity with `sqlmap` on:

- boolean-based blind
- time-based blind
- error-based
- UNION-based
- stacked queries
- second-order SQLi
- authenticated scanning
- cookies, CSRF, sessions
- forms, crawler, request replay
- dump, custom SQL, file read/write, command execution via SQLi
- strong WAF bypass and tamper coverage

### 2. Better Operator Workflow

SQX must be faster and easier to operate than `sqlmap`:

- single binary deployment
- simpler commands
- persistent state and artifact tracking
- clearer evidence and reporting
- better interactive workflows
- GUI without sacrificing CLI depth

### 3. Beyond SQLi

SQX must exceed `sqlmap` by handling exploit chains:

- SQLi -> second-order effects
- SQLi -> generated sink discovery
- SQLi -> LFI
- SQLi -> source disclosure
- SQLi -> secret or hash derivation
- SQLi -> RCE
- LFI -> filter chains -> RCE

This is the main strategic differentiator.

## Core Principles

### Accuracy over Demos

No feature is considered complete because it works on one lab. It is complete when it survives:

- controlled integration targets
- noisy targets
- authenticated targets
- weird encodings
- constrained payload characters
- multiple DBMS variants

### Workflow over Payload Count

Adding payloads is not enough.
SQX should model exploitation as a workflow with state, pivots, and artifacts.

### Evidence over Claims

Every major capability should produce:

- reproducible request and response traces
- stored artifacts
- exploitability reasoning
- next-step recommendations when automation stops

### Product Discipline

Every new subsystem should answer:

- what operator pain it removes
- what `sqlmap` cannot already do here
- how it will be tested
- how it integrates into CLI, GUI, and reports

## Architecture Direction

SQX should converge on three layers:

### Layer 1: Core SQLi Engine

Responsibilities:

- detection
- exploitation
- enumeration
- takeover through SQLi

### Layer 2: Chain Engine

Responsibilities:

- exploit chains
- stateful workflows
- pivot tracking
- artifact management

### Layer 3: Intelligence Layer

Responsibilities:

- HTML and DOM diffing
- sink discovery
- source analysis
- hash and signature inference
- exploit recommendation

## Success Criteria

SQX becomes a `sqlmap` killer when all of the following are true:

- it matches `sqlmap` on common SQLi exploitation tasks
- it reaches exploit outcomes with less manual work
- it handles modern chained web exploitation cases better than `sqlmap`
- operators choose it first because it is faster and clearer

## Immediate Strategic Decisions

We will:

- treat `sqlmap` as the baseline, not the aspiration
- copy proven SQLi capabilities where necessary
- build new value in exploit chains and workflow intelligence
- invest heavily in regression labs and comparative testing

We will not:

- chase vanity features
- hardcode one-off CTF logic into the core engine
- call features complete without comparative validation

## Motto

Parity on SQLi.
Superiority on workflow.
Dominance on exploit chains.
