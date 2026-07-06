# Changelog

All notable changes to Arbitraitor are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

#### CLI

- `arbitraitor scan` — scan local files or stdin without retrieval
- `arbitraitor explain` — explain a verdict from a receipt file
- `arbitraitor store` — manage CAS artifacts (list, inspect, gc)
- `arbitraitor policy` — validate policy TOML files
- `arbitraitor doctor` — system health diagnostics (JSON output)
- `arbitraitor rules` — manage YARA-X rule packs (list, validate)
- `arbitraitor update verify` — verify signed update manifests (minisign)
- `arbitraitor plugin` — manage plugin registry (list, info, discover, remove)
- `arbitraitor hook init` — print shell hook intercepting `curl|sh` patterns
- `arbitraitor shim` — manage package manager compatibility shims (list, install, uninstall)
- `arbitraitor graph` — render payload containment tree for archives
- `arbitraitor approve` — decoupled approval flow from receipt file
- `arbitraitor execute` — execute artifact from CAS using approval file
- `arbitraitor mcp` — start MCP JSON-RPC 2.0 server over stdio
- `arbitraitor version` — print version, license, repository
- Native binary auto-detection from artifact classifier (no manual `--native` needed)

#### Package manager adapters

- `cargo` adapter — Cargo.lock parsing, build.rs analysis, lifecycle policy
- `uv`/`uvx` adapter — uv.lock parsing, source validation, sandbox-required lifecycle
- `npm` adapter — package-lock.json parsing, denied-by-default lifecycle
- `pnpm` adapter — RegistryAdapter trait conformance
- `yarn` (berry + classic) adapters — trait conformance
- `bun` adapter — trait conformance

#### Detection

- Tirith subprocess detector (external script analysis via bounded subprocess)
- Dependency vulnerability detector framework
- CWE taxonomy mapping for shell findings: only `DynamicCodeExecution → CWE-94` is emitted; the other behavioral categories (destructive, credential access, persistence, network, obfuscation, transport, etc.) are intentionally left unmapped because no defensible CWE root-cause mapping exists for them. ATT&CK/CAPEC may be added as separate taxonomies in a future release.

#### Wrapper system

- Per-shell initialization (bash, zsh, fish, dash, ksh, tcsh, sh, csh, nu, pwsh)
- Rcfile installation with idempotent markers per shell

#### Fetch

- HTTP response truncation detection (Content-Length mismatch → `FetchError::TruncatedBody`)

#### Documentation

- 26 ADRs (was 21): ADRs 0022–0026 covering SLSA, in-toto receipts, macOS containment, OpenSSF/Scorecard, EU CRA/NIST SSDF compliance
- 1103 tests passing (was 867+)

### Changed

- `WasmPlugin` and `wasm_engine` modules are now feature-gated behind `experimental-wasm` (off by default). The `analyze` method logs a warning when called, rather than silently returning empty findings. ADR-0006 remains Accepted but is partially implemented — the WIT bridge is not yet wired.
- `shim install` no longer generates broken package-manager shims that invoked the non-existent `pm run` subcommand. The command now errors with a helpful message pointing to `wrappers install` for curl/wget support.
- MCP `explain` and `sanitize_for_agent` extracted to dedicated `explain.rs` module
- Test suites extracted to `tests.rs` files across 10 crates (mcp, cli, analysis, core, yarax, shell, provenance, archive, exec, intel, store)
- `--native` flag repurposed as confirmation override (execution mode auto-detected from artifact type)
- Plugin manifest now accepts a `[capabilities]` table declaring `network`, `filesystem`, `process`, `max_memory_bytes`, `max_cpu_ms`
- `SubprocessExecutor::with_network_isolated(bool)` replaced with `with_network_capability(NetworkCapability)`; the capability must come from the plugin's admitted manifest

### Security

- Plugin registry now enforces ADR-0011 trust-tier capability admission: `community-reviewed` and `community-unreviewed` plugins are rejected at registration when they declare `network`, `process = "spawn"`, or `filesystem = "read-write"` capabilities (#379)
- `OperationPlan::validate_for_plugin_capabilities` now has a production caller via `PluginRegistry::validate_plan`, tying wrapper-produced plans to the capabilities declared at admission

### Fixed

- CLI auto-detects native vs script execution mode from artifact classifier instead of requiring `--native` flag
- Nightly release workflow no longer hangs on the deprecated `macos-13` (Intel) runner — `x86_64-apple-darwin` builds are dropped; Intel macOS users should build from source or run the `aarch64-apple-darwin` binary via Rosetta
- Nightly release publishes even when some build matrix legs fail (artifacts from successful legs are still released)
- `actions/upload-artifact` and `actions/download-artifact` bumped to v7/v8 to clear the Node.js 20 deprecation warning
- Daemon in-process `release()` now requires a prior inspection receipt and a release-permitting verdict, and routes publication through ADR-0015's `release_artifact` safe-release primitive instead of `std::fs::write`
- Tirith subprocess detector now records detector binary provenance in receipts and hardens subprocess execution with seccomp, Landlock, and pre-exec resource limits where available

## [0.1.0-alpha] — 2026-06-23

Initial alpha release. **Not ready for production use.**

### Added

#### Core pipeline

- Content-addressed storage (CAS) with SHA-256 quarantine, immutable identity, streaming sink
- HTTP retrieval with SSRF protection (connected-peer verification, IP literal blocking)
- Artifact identification (content-type detection, shell shebang, archive magic)
- Provenance verification (digest pinning, minisign, cosign, TUF metadata, TOFU mode)
- Policy engine (TOML rule evaluation, verdict computation, fail-closed defaults)
- Receipt system (RFC 8785 JCS canonicalization, audit trail)
- Configuration system (layered TOML, secret references with redaction, policy/detector integration)

#### Detection

- Shell script analysis (28+ detection categories)
- PowerShell analysis (AST parser, detection rules for encoded commands, execution policy bypass, hidden windows, registry modification, credential access, process injection)
- YARA-X scanner integration with authenticated rule packs
- Archive inspection (6 formats: zip, tar, gzip, bzip2, xz, 7z; 15 hazard types; recursive payload discovery)
- Antivirus adapters (ClamAV, Microsoft Defender)
- Intelligence feeds (URLhaus, community submission, review workflow, transparency log)

#### Execution

- Mediated script execution (sandboxed bash with network isolation, resource limits, output capping)
- Native binary execution with NativeExecutionGate opt-in
- PowerShell execution adapter
- Plan-bound approval (ADR-0013: token binds artifact + interpreter + network + policy)

#### Plugin system

- Plugin trait hierarchy (Detector, Wrapper, Intelligence, Provenance)
- Subprocess plugin protocol (framed JSON, versioned)
- Sandboxed subprocess executor (digest verification, env denylist, seccomp, Landlock)
- Wasmtime Component Model runtime (engine, WIT interfaces, component loader)
- Plugin registry (filesystem discovery, manifest validation, trust tiers)

#### CLI

- `arbitraitor inspect`, `run`, `wrappers`, `status`, `daemon`, `unpack`, `intel`

#### MCP integration

- Model Context Protocol server (inspect, scan, explain, query, approve, execute)

#### Infrastructure

- 21 ADRs, mdBook documentation site
- CI (Linux + macOS), Security (cargo-deny, cargo-audit), Markdown lint (rumdl)
- Lefthook pre-commit hooks (fmt, clippy, markdown lint, conventional commits)

### Security

- ADR-0013 plan-bound approval tokens (replay prevention, context binding)
- TOCTOU-free resource limit application (setrlimit in pre_exec)
- Seccomp-BPF network isolation for subprocess plugins
- Landlock filesystem isolation for subprocess plugins
- HMAC-SHA256 approval tokens with constant-time comparison and single-use nonces
- Forensic retention mode (cannot be downgraded)
- GC re-checks lock state before deletion

### Known limitations

- Wasmtime component loader is structural (export calling requires bindgen follow-up)
- Subprocess executor sandboxing (seccomp, Landlock) is Linux-only
- Pre-alpha API: all public types, CLI flags, and schemas are subject to change
