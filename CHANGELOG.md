# Changelog

All notable changes to Arbitraitor are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
