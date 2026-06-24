# Crates

The Arbitraitor workspace is organized into focused crates. Each crate has a clear responsibility and strict boundary rules.

## Workspace layout

```
arbitraitor/                   # Workspace root (Cargo.toml)
├── crates/
│   ├── arbitraitor-cli/      # CLI entry point
│   ├── arbitraitor-core/     # State machine, config, health
│   ├── arbitraitor-model/    # Domain types, receipts, findings
│   ├── arbitraitor-fetch/    # HTTP retrieval
│   ├── arbitraitor-store/     # Content-addressed storage
│   ├── arbitraitor-analysis/  # Detection coordinator
│   ├── arbitraitor-shell/     # Shell script analyzer
│   ├── arbitraitor-powershell/ # PowerShell AST analyzer
│   ├── arbitraitor-yarax/     # YARA-X scanner
│   ├── arbitraitor-archive/   # Archive inspector
│   ├── arbitraitor-provenance/# Signature verification
│   ├── arbitraitor-intel/    # Intelligence feeds
│   ├── arbitraitor-policy/    # Policy engine
│   ├── arbitraitor-receipt/   # Receipt generation
│   ├── arbitraitor-exec/      # Execution broker
│   ├── arbitraitor-sandbox/   # Process hardening
│   ├── arbitraitor-mcp/       # MCP server
│   ├── arbitraitor-plugin-api/    # Plugin trait hierarchy
│   ├── arbitraitor-plugin-host/   # Plugin runtime
│   └── arbitraitor-daemon/    # Unix socket daemon
├── book/                      # mdBook documentation
├── docs/                      # ADRs, conventions
├── wit/                       # WIT interface definitions
├── rules/                     # YARA-X rule packs
├── schemas/                   # JSON schemas
├── plugins/                   # Built-in plugins
└── fixtures/                  # Test fixtures
```

## Crate responsibilities

### `arbitraitor-model`

Serializable domain types. Newtypes for all semantic primitives.

**Owns:** `Sha256Digest`, `ArtifactId`, `Finding`, `Verdict`, `Receipt`, `Policy`, `ExecutionPlan`
**Must not:** I/O, business logic, network, side effects

### `arbitraitor-core`

State machine and orchestration. Loads config, coordinates pipeline.

**Owns:** `Arbitraitor` state machine, config loading, health checks, metrics
**Must not:** Direct HTTP calls, store implementation details, policy syntax

### `arbitraitor-fetch`

HTTP retrieval with security controls.

**Owns:** Transport policy, redirect following, TLS verification, SSRF protection, transport metadata recording
**Must not:** Policy evaluation, release decisions

### `arbitraitor-store`

Content-addressed storage (CAS).

**Owns:** Immutable artifact storage, quarantine, retention/GC, integrity verification
**Must not:** Authorization decisions (only CAS operations)

### `arbitraitor-analysis`

Detection pipeline coordinator.

**Owns:** Orchestrating detector execution, aggregating findings, payload graph discovery
**Must not:** Direct release/execution decisions

### `arbitraitor-policy`

TOML policy engine.

**Owns:** Rule evaluation, verdict computation, policy document parsing
**Must not:** Network, retrieval, storage

### `arbitraitor-exec`

Mediated execution broker.

**Owns:** Environment construction, sandbox application, process execution
**Must not:** Trust decisions, scanning logic

### `arbitraitor-plugin-host`

Plugin runtime supporting Wasmtime Component Model and subprocess protocols.

**Owns:** Plugin lifecycle, capability enforcement, WASM sandboxing
**Must not:** Native ABI loading, arbitrary dynamic library loading

### `arbitraitor-cli`

Command-line interface.

**Owns:** Argument parsing, output formatting, user interaction
**Must not:** Business logic (delegates to core)

## Dependency graph (simplified)

```
arbitraitor-cli
└── arbitraitor-core
    ├── arbitraitor-model
    ├── arbitraitor-fetch
    ├── arbitraitor-store
    ├── arbitraitor-analysis
    │   ├── arbitraitor-shell
    │   ├── arbitraitor-archive
    │   ├── arbitraitor-yarax
    │   ├── arbitraitor-powershell
    │   └── arbitraitor-plugin-host
    ├── arbitraitor-policy
    ├── arbitraitor-provenance
    ├── arbitraitor-intel
    ├── arbitraitor-exec
    ├── arbitraitor-sandbox
    ├── arbitraitor-receipt
    └── arbitraitor-daemon
```

## Public API vs internal

### Public (re-exported through `arbitraitor` prelude)

- `Arbitraitor::new()`, `.inspect()`, `.run()`, `.approve()`, `.execute()`
- `Finding`, `Verdict`, `Receipt`, `ArtifactId`, `Sha256Digest`
- `Policy`, `PolicyEngine`
- `Config`, `ConfigBuilder`

### Internal (not exported)

- All detector implementations (except through trait objects)
- Store implementation details
- Fetch connector internals
- Plugin host internals
- Sandbox implementation details

## Boundary rules

1. **No detector calls release/execution directly.** Detectors produce `Finding` structs. The core state machine produces verdicts and orchestrates release.
2. **No crate re-fetches after approval.** Single retrieval is a security invariant.
3. **redb is a non-authoritative cache.** CAS digest + receipts are authoritative for identity.
4. **No `reqwest` types across boundaries.** All HTTP goes through the `Fetcher` trait.
5. **Newtypes for all semantic primitives.** `Sha256Digest`, not `String`; `ArtifactId`, not `String`.

## Adding a new crate

When adding a new crate:

1. Add to `workspace.members` in `Cargo.toml`
2. Define strict ownership in the crate README
3. Add boundary assertions in the parent crate's tests
4. Document any new public API in the module docstring
5. Add an ADR if the crate represents an architectural decision
