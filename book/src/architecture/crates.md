# Crates

The Arbitraitor workspace is organized into focused crates. Each crate has a clear responsibility and strict boundary rules.

## Workspace layout

```
arbitraitor/                           # Workspace root (Cargo.toml)
├── crates/
│   ├── arbitraitor-cli/               # CLI entry point (23 subcommands)
│   ├── arbitraitor-core/              # State machine, config, health checks
│   ├── arbitraitor-model/             # Domain types, receipts, findings (newtypes)
│   ├── arbitraitor-fetch/             # HTTP retrieval with SSRF protection
│   ├── arbitraitor-store/             # Content-addressed storage (CAS)
│   ├── arbitraitor-artifact/           # Content classification (ELF, PE, Mach-O, shebang)
│   ├── arbitraitor-analysis/           # Detection pipeline coordinator
│   ├── arbitraitor-shell/              # Shell script analyzer (bash/dash)
│   ├── arbitraitor-powershell/         # PowerShell AST analyzer
│   ├── arbitraitor-yarax/              # YARA-X scanner
│   ├── arbitraitor-archive/            # Archive inspector (6 formats, 15 hazards)
│   ├── arbitraitor-av/                 # Antivirus adapters (ClamAV, Defender)
│   ├── arbitraitor-provenance/         # Signature verification
│   ├── arbitraitor-intel/             # Intelligence feeds
│   ├── arbitraitor-policy/             # TOML policy engine
│   ├── arbitraitor-receipt/            # RFC 8785 canonicalized receipts
│   ├── arbitraitor-exec/              # Mediated execution (script + native + PowerShell)
│   ├── arbitraitor-sandbox/            # Process hardening (prctl, close_range, setrlimit)
│   ├── arbitraitor-mcp/               # MCP server (inspect, scan, explain, approve, execute)
│   ├── arbitraitor-plugin-api/         # Plugin trait hierarchy
│   ├── arbitraitor-plugin-host/        # Plugin runtime (subprocess + Wasmtime)
│   ├── arbitraitor-wrapper/            # curl/wget wrapper translators + per-shell init
│   ├── arbitraitor-daemon/             # Unix socket daemon (experimental)
│   ├── arbitraitor-package-manager/    # Registry adapters (experimental: cargo, npm, uv, pnpm, yarn, bun)
│   ├── arbitraitor-update/             # Signed update manifest verification
│   ├── arbitraitor-testkit/            # Test infrastructure (SSRF, TLS, raw TCP helpers)
│   └── arbitraitor-workspace-hack/      # hakari-managed dependency deduplication
├── book/                               # mdBook documentation
├── docs/                               # ADRs, conventions, research
├── wit/                                # WIT interface definitions
├── rules/                              # YARA-X rule packs
├── schemas/                            # JSON schemas
├── plugins/                            # Built-in plugins
└── fixtures/                           # Test fixtures
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

### `arbitraitor-artifact`

Content classification and magic byte detection.

**Owns:** Artifact type detection (ELF, PE, Mach-O, ZIP, tar, gzip, xz, bzip2, zstd), shell shebang parsing, content-type heuristics
**Must not:** Policy evaluation, execution decisions

### `arbitraitor-av`

Antivirus adapter trait and implementations.

**Owns:** ClamAV (`clamd` streaming), Microsoft Defender CLI adapter, signature-freshness snapshots (§18.3), macOS stable-facility helpers (`xattr`, `mdfind` per §41.13)
**Must not:** Policy decisions, trust verdicts

### `arbitraitor-package-manager`

Registry adapter trait and per-tool implementations.

> **Experimental:** This crate is under active development. Adapters provide recipe definitions and lockfile parsing, but full lifecycle enforcement (registry proxy, post-install scan, build sandbox) is not yet wired through the CLI. Per spec §39.14, per-tool adapters should eventually move to first-party plugins. The crate is included for foundational types only.

**Owns:** `RegistryAdapter` trait, cargo/uv/npm/pnpm/yarn/bun adapters, lockfile parsing, build script analysis, lifecycle policy enforcement
**Must not:** Direct execution, policy override

### `arbitraitor-wrapper`

curl/wget wrapper translators and per-shell initialization.

> **Shell support:** 10 shells — bash, zsh, sh, fish, nushell, xonsh, powershell, elvish, posix, tcsh. Use `arbitraitor wrappers init --detect-shell` to auto-detect.

**Owns:** Wrapper argument translation, shell init script generation (10 shells), rcfile installation with idempotent markers and injection-hardened path validation
**Must not:** Policy evaluation, execution

### `arbitraitor-update`

Signed update manifest verification.

**Owns:** Minisign verification, update manifest parsing, manifest validation, target verification
**Must not:** Network retrieval, policy decisions

### `arbitraitor-testkit`

Test infrastructure for integration testing.

**Owns:** Mock HTTP server, SSRF test helpers, TLS test helpers, raw TCP server (truncation/malformed response), HTTPS test fixtures
**Must not:** Production code paths

## Dependency graph (simplified)

```
arbitraitor-cli
├── arbitraitor-core
│   ├── arbitraitor-model
│   ├── arbitraitor-fetch
│   ├── arbitraitor-store
│   ├── arbitraitor-analysis
│   │   ├── arbitraitor-shell
│   │   ├── arbitraitor-archive
│   │   ├── arbitraitor-yarax
│   │   ├── arbitraitor-powershell
│   │   └── arbitraitor-plugin-host
│   ├── arbitraitor-policy
│   ├── arbitraitor-provenance
│   ├── arbitraitor-intel
│   ├── arbitraitor-exec
│   ├── arbitraitor-sandbox
│   ├── arbitraitor-receipt
│   └── arbitraitor-daemon
├── arbitraitor-artifact
├── arbitraitor-mcp
├── arbitraitor-wrapper
├── arbitraitor-package-manager
├── arbitraitor-update
└── arbitraitor-testkit (dev-dep)
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
