# SQX Implementation Backlog

## Milestone 1: Core SQLi Parity

### Epic 1.1: Detection and Exploitation Hardening

- unify GET and POST exploitation behavior
- harden boolean, time, error, UNION, stacked query logic
- improve confidence scoring and evidence capture
- add custom SQL execution support

### Epic 1.2: Second-Order and Stateful SQLi

- generalize second-order beyond current registration and login flows
- support explicit second-order request definitions
- support stored and deferred result observation
- persist second-order execution context

### Epic 1.3: Auth, Session, and Replay

- unify session handling across crawler, detector, GUI, and CLI
- support request-file based execution flows
- improve CSRF refresh and state replay
- improve multi-step authenticated exploitation

### Epic 1.4: SQLi Takeover Capabilities

- strengthen file read flows
- strengthen file write flows
- add SQLi-driven command execution workflows
- add DBMS-specific takeover modules where feasible
- **UDF injection automat** — deploy lib_mysqludf_sys / pg_exec via SQL injection (detectare arhitectură, upload binar, CREATE FUNCTION)
- **Metasploit integration** — export sesiuni către Metasploit (XML/JSON format), comandă `sqx export --msf`

### Epic 1.5: Tamper and WAF Bypass

- expand tamper coverage
- improve tamper chain selection logic
- support user-defined tamper workflows
- compare tamper effectiveness against baseline targets

## Milestone 2: Operator Superiority

### Epic 2.1: Artifact Store

- add persisted artifacts for requests and responses
- store findings, payloads, files, links, and derived hypotheses
- support resume and replay from artifact state

### Epic 2.2: Reporting and UX

- add exploit-oriented reports
- surface blocking constraints explicitly
- add "next recommended action" output
- improve CLI summaries and GUI result views

### Epic 2.3: Comparative Benchmarks

- build a benchmark harness against `sqlmap`
- track success rate, speed, and manual steps
- store benchmark outputs in reproducible form

## Milestone 3: Chain Engine Foundation

### Epic 3.1: Chain Models

- add `ExploitChain`, `ChainStep`, `ChainContext`, `ExploitOutcome`
- add chain serialization and persistence
- support resumable multi-step workflows

### Epic 3.2: Pivot Graph

- add pivot nodes and edges
- model dependency chains between findings and derived capabilities
- support scoring and prioritization of pivots

### Epic 3.3: Workflow Execution

- support step scheduling and stop conditions
- support operator-guided and automatic modes
- support evidence-driven branching

## Milestone 4: Sink Discovery and Result Shaping

### Epic 4.1: HTML and DOM Diffing

- parse generated links and resource references
- diff baseline vs injected render outputs
- identify SQL-controlled downstream parameters

### Epic 4.2: Dataflow Inference

- classify path-like, hash-like, and label-like rendered values
- detect generated sink endpoints
- associate source parameters with downstream effects

### Epic 4.3: Result Shaping Techniques

- add reflective result shaping
- add deferred result shaping
- support controlled row and column injection patterns
- support constrained payload generation under character filters

## Milestone 5: LFI and Source Intelligence

### Epic 5.1: LFI Engine

- add file inclusion detection
- add traversal and wrapper probing
- add content verification for file disclosure

### Epic 5.2: Source Disclosure

- prioritize source files for retrieval
- identify application entry points and includes
- map disclosed code to endpoints and sinks

### Epic 5.3: Source Intelligence

- identify secrets and constants
- identify dangerous functions and include patterns
- identify path validation and signature logic

## Milestone 6: Crypto and Signature Inference

### Epic 6.1: Black-Box Hash Inference

- test common unsalted and salted hash hypotheses
- test HMAC-like constructions
- test path normalization variants

### Epic 6.2: White-Box Crypto Inference

- extract PHP hashing primitives from disclosed source
- infer algorithm, secret, and operand order
- generate valid signed parameter pairs

## Milestone 7: Playbooks

### Epic 7.1: Generic Playbooks

- SQLi -> second-order
- SQLi -> sink discovery
- SQLi -> result shaping
- SQLi -> LFI
- LFI -> source disclosure
- source disclosure -> hash derivation

### Epic 7.2: Operator-Guided Commands

- add `sqx chain`
- add `sqx pivot`
- add `sqx lfi`
- add `sqx derive-hash`

## Milestone 8: Validation

### Epic 8.1: Regression Labs

- expand Docker-based internal lab coverage
- add authenticated targets
- add second-order targets
- add chained exploit targets

### Epic 8.2: Comparative Evaluation

- compare against `sqlmap` on core SQLi
- compare on operator steps required
- compare on exploit chain progression

## Definition of Done

A backlog item is done only if:

- implementation exists
- tests exist
- artifacts and evidence are surfaced clearly
- CLI behavior is wired
- GUI behavior is wired if relevant
- docs are updated
- comparative impact is known
