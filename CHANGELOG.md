# Changelog

All notable changes to Arbitraitor are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

#### Intel

- `arbitraitor-intel::redact_url`, `redact_path`, and `redact_env_var` —
  new public helpers that strip credentials, sensitive query parameters,
  home-directory paths, and sensitive environment-variable values from
  artifacts before inclusion in community reports and feeds (spec §22.6).
  `redact_url` removes userinfo entirely and replaces values whose key
  matches `token`, `secret`, `key`, `password`, `sig`, or `signature`
  (case-insensitive substring match) with `[REDACTED]`. `redact_path`
  collapses `$HOME`-prefixed and `/home/<user>/` paths to `~/`.
  `redact_env_var` returns `None` for names ending in `_KEY`, `_TOKEN`,
  `_SECRET`, or `_PASSWORD` (case-insensitive) and `Some(value)` otherwise.

#### Exec

- `arbitraitor-core::config::ExecutionConfig::allow_environment` and
  `deny_environment_patterns` — new fields implementing spec §26.5
  (policy-driven environment controls). Defaults match the historical
  hardcoded `EnvAllowlist::default_names()` allowlist and the union
  of the historical `EnvDenyList::mandatory()` exact and prefix lists,
  so existing configurations keep current behavior and operators can
  override either list from `arbitraitor.toml`.
- `arbitraitor-exec::env_allowlist_from_config` and
  `env_denylist_from_config` — new constructors that build the
  execution environment allow/deny structures from a
  `ExecutionConfig`.
- `arbitraitor-exec::ExecutionContextBuilder::environment_from_config` —
  new builder method that replaces the policy's environment allowlist
  and denylist with values derived from a `ExecutionConfig` (spec
  §26.5), wireable from any orchestrator that already loads the
  layered TOML config.
- `arbitraitor-exec::emit_artifact_to_stdout` — new release mode that
  emits verified CAS bytes to stdout (spec §26.1). Used by
  `scan --emit-on-pass` and wrapper pipe semantics. Bytes are verified
  against the scanned digest before and after emission, preserving
  invariant 2 (immutable identity).
- `ReleaseMethod::StdoutEmit` — new enum variant for the stdout release
  method recorded in receipts.

#### Daemon

- `arbitraitor_daemon::queue::CancellationToken` — shareable,
  single-shot cancellation flag backed by `Arc<AtomicBool>` (spec §37.1).
  One token is created per `OperationEntry` and cloned into the executing
  task so an external cancellation request becomes observable
  cooperatively. `CancellationToken::cancel()` is idempotent;
  `is_cancelled()` is wait-free.
- `OperationQueue::cancel_operation(&str) -> bool` and
  `OperationQueue::is_cancelled(&str) -> bool` — string-ID variants of
  the cancellation API per spec §37.1. `cancel_operation` flips the
  per-operation token and, for queued operations, immediately transitions
  the entry to `OperationStatus::Cancelled` and writes a partial receipt
  when `Config::emit_partial_receipt_on_cancel = true`.
- `Config::emit_partial_receipt_on_cancel` — new boolean field (default
  `false`) implementing spec §37.1. When `true`, the operation queue
  writes a `<operation-id>.cancelled.json` partial receipt to the
  configured receipts directory for every cancelled operation. The
  schema (`arbitraitor-partial-receipt/v1`) is intentionally distinct
  from the full-receipt schema so consumers can detect partial state.
- `ArbitraitorApi::receipts_dir()` and `emit_partial_receipt_on_cancel()`
  — accessors that allow the operation queue to read the configured
  receipts directory and the partial-receipt flag without taking a
  mutable borrow on the API.
- `Arbitraitor::builder()` and `ArbitraitorBuilder` provide the spec §40.1
  fluent library construction API with `.config(Config)`,
  `.policy(PolicyEngine)`, and `.build()`. The existing
  `ArbitraitorApi::new(Config)` constructor remains available.

#### Exec

- `arbitraitor-exec::ReleasePolicy::verdict_max_age` and
  `verdict_timestamp` — new fields implementing spec §26.2 step 4
  (freshness invalidation check before release). When set, the release
  function checks that the verdict was computed within the allowed
  age window. If stale, release fails with `ReleaseError::StaleVerdict`
  — preventing a TOCTOU where policy or intelligence was updated
  between verdict and release.

#### CLI

- `arbitraitor explain` now accepts `sha256:<hash>` form in addition to
  receipt file paths (spec §28.6). When a `sha256:` prefix is detected,
  the command looks up the most recent receipt for that artifact from
  the `~/.arbitraitor/receipts/` directory.

#### CLI (prior)

- `arbitraitor version` now reports build provenance: target architecture
  (`x86_64`/`aarch64`), Rust toolchain version, build commit (when set
  via `ARBITRAITOR_BUILD_COMMIT` env at compile time), build date (when
  set via `ARBITRAITOR_BUILD_DATE` env at compile time), and build
  profile (`debug`/`release`). Per spec §28.1.

#### Model

- `arbitraitor_model::exit_code::verdict_to_exit_code` — canonical named
  mapping point from `Verdict` to `ExitCode` per spec §23.2 + §29 (#553).
  Thin wrapper over the existing `From<Verdict>` impl; gives daemon/CLI
  call sites a single, named function to point at when the mapping rule
  changes.

#### Fetch

- `arbitraitor-fetch::FetchPolicy::allow_cross_origin_redirect` and
  `forward_authorization_cross_origin` — new fields implementing spec
  §11.2 (lines 608-612) and §11.4 (lines 644-653) redirect policy:
  - `allow_cross_origin_redirect` (default `true`) controls whether
    redirect chains may cross origin boundaries (scheme + host + port).
    When `false`, cross-origin redirects return
    `FetchError::CrossOriginRedirect`.
  - `forward_authorization_cross_origin` (default `false`) gates
    whether credential-bearing headers survive across origin
    boundaries. Forward-compatible: currently a no-op because
    `execute_request` sends a bare GET (user-supplied headers tracked
    in #498).
- `arbitraitor-policy::RedirectsConfig::allow_cross_origin` and
  `forward_authorization_cross_origin` — corresponding TOML policy
  fields per spec §11.4 example.

#### Wrapper

- `arbitraitor-wrapper::wget::WgetRequest` now carries a `findings` field so
  callers can surface transport-safety findings raised during argv
  translation. Per spec §39.9, `--no-check-certificate` is no longer silently
  dropped: the wrapper emits a `Finding` with `FindingCategory::Transport`,
  `Severity::High`, `Confidence::High`, detector `arbitraitor-wrapper`, and
  stable id `wget-no-check-certificate`. The flag remains on
  `WgetRequest::no_check_certificate` so existing consumers keep their
  semantics; the finding is the auditable signal required by spec §39.9.

#### ADRs

- ADRs 0022–0026 accepted: SLSA Build L3 target (0022), in-toto Statement receipt envelope (0023), macOS containment strategy (0024), OpenSSF Scorecard/deps.dev/GUAC integration (0025), EU CRA/NIST SSDF compliance mapping (0026). All 26 ADRs are now Accepted.

#### CLI

- `arbitraitor doctor --json` — machine-readable output (human-readable is now the default)
- `arbitraitor doctor` now shows shell integration health checks (shell detection, shim status, PATH, rcfile)
- `wrappers init --dry-run` — preview what would change without writing to rcfile
- `wrappers init --no-backup` — skip backup file creation (backup is created by default)
- `hook init` now emits a deprecation warning and supports `ARBITRAITOR_HOOK_DISABLE=1` bypass
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
- `arbitraitor pm run --tool npm` — advisory scan of npm projects: resolves the dependency tree via `package-lock.json`, detects lifecycle scripts (`preinstall`/`install`/`postinstall`/`prepare`/`prepublish`) in root and dependency packages, flags non-registry resolved URLs, and gates `npm install --ignore-scripts` behind the verdict (spec §39.14 Phase 1)
- Native binary auto-detection from artifact classifier (no manual `--native` needed)

#### Package manager adapters

- `cargo` adapter — Cargo.lock parsing, build.rs analysis, lifecycle policy
- `uv`/`uvx` adapter — uv.lock parsing, source validation, sandbox-required lifecycle
- `npm` adapter — package-lock.json parsing, denied-by-default lifecycle, advisory scan with lifecycle-script detection and `PackageManagerReceipt` generation (spec §39.14)
- `pnpm` adapter — RegistryAdapter trait conformance
- `yarn` (berry + classic) adapters — trait conformance
- `bun` adapter — trait conformance

#### Detection

- Tirith subprocess detector (external script analysis via bounded subprocess)
- Dependency vulnerability detector framework
- CWE taxonomy mapping for shell findings: only `DynamicCodeExecution → CWE-94` is emitted; the other behavioral categories (destructive, credential access, persistence, network, obfuscation, transport, etc.) are intentionally left unmapped because no defensible CWE root-cause mapping exists for them. ATT&CK/CAPEC may be added as separate taxonomies in a future release.

#### Receipts

- Finding summaries now retain representative evidence, remediation guidance, external references, and taxonomy mappings.

#### Wrapper system

- Per-shell initialization (bash, zsh, fish, dash, ksh, tcsh, sh, csh, nu, pwsh)
- Rcfile installation with idempotent markers per shell

#### Fetch

- HTTP response truncation detection (Content-Length mismatch → `FetchError::TruncatedBody`)

#### Documentation

- 26 ADRs total (21 accepted, 5 proposed): ADRs 0022–0026 covering SLSA, in-toto receipts, macOS containment, OpenSSF/Scorecard, EU CRA/NIST SSDF compliance. Note: ADRs 0022–0026 remain in Proposed status pending acceptance review.
- 1117 tests passing (was 867+)

### Changed

- `WasmPlugin` and `wasm_engine` modules are now feature-gated behind `experimental-wasm` (off by default). The `analyze` method logs a warning when called, rather than silently returning empty findings. ADR-0006 remains Accepted but is partially implemented — the WIT bridge is not yet wired.
- `shim install npm` now generates a working shim that invokes `arb pm run --tool npm`, replacing the previous stub that errored with "package-manager shims are not yet implemented".
- Corrected ADR count in AGENTS.md and README.md from "26 accepted" to "21 accepted, 5 proposed" (ADRs 0022–0026 remain Proposed)
- Fixed `book/src/cli-reference.md` global flags table: removed `--policy`, `--output`, `--log-level`, `--no-color`, `--quiet` (not implemented); documented actual global flags (`--config`, `--verbose`)
- Fixed `book/src/cli-reference.md` exit codes to match actual `Verdict`-to-exit-code mapping (0/10/21/30/33/34)
- Marked `arbitraitor-daemon` and `arbitraitor-package-manager` as experimental in architecture docs (spec §47 excludes both from pre-1.0 scope)
- Updated CLI subcommand count from 22 to 23 in README.md and book
- Rcfile installation now uses atomic writes (temp-file + rename) with backup by default
- `hook init` is deprecated — emits warning recommending `wrappers install` instead; generated trap now respects `ARBITRAITOR_HOOK_DISABLE=1`
- MCP `explain` and `sanitize_for_agent` extracted to dedicated `explain.rs` module
- Test suites extracted to `tests.rs` files across 10 crates (mcp, cli, analysis, core, yarax, shell, provenance, archive, exec, intel, store)
- `--native` flag repurposed as confirmation override (execution mode auto-detected from artifact type)
- Plugin manifest now accepts a `[capabilities]` table declaring `network`, `filesystem`, `process`, `max_memory_bytes`, `max_cpu_ms`
- `SubprocessExecutor::with_network_isolated(bool)` replaced with `with_network_capability(NetworkCapability)`; the capability must come from the plugin's admitted manifest

### Security

- Plugin registry now enforces ADR-0011 trust-tier capability admission: `community-reviewed` and `community-unreviewed` plugins are rejected at registration when they declare `network`, `process = "spawn"`, or `filesystem = "read-write"` capabilities (#379)
- `OperationPlan::validate_for_plugin_capabilities` now has a production caller via `PluginRegistry::validate_plan`, tying wrapper-produced plans to the capabilities declared at admission

### Fixed

- Refactor: extract `inspect` pipeline orchestration from main.rs into `crates/arbitraitor-cli/src/pipeline.rs` (#436)
- CLI exit codes now match the documented verdict-to-exit-code mapping: `run` command failure exits use 33 (Error) / 34 (Incomplete) / 21 (Prompt) instead of 1–5; `doctor` exits 33 on unhealthy; `main()` propagates errors as exit 33 instead of 1. CI pipelines can now reliably distinguish verdict types by exit code (#432)
- `arbitraitor inspect` now accepts local file paths and `file://` URLs in addition to `https://` URLs; bare paths (relative or absolute) are treated as local files and routed through the file fetcher (#431)
- Script and native execution (`arbitraitor run`) now applies Landlock filesystem confinement on Linux 5.13+, restricting the child process to read-execute on system paths (`/bin`, `/usr/bin`, `/lib`, etc.) and read-write-execute on its working directory and temp home only — preventing scripts from reading arbitrary absolute paths like `~/.ssh`, `~/.aws`, or `/etc/shadow` (#433)
- Escalated `missing_docs` lint from `warn` to `deny` in workspace lints and `arbitraitor-sandbox` crate lints — all public items must now have `///` doc comments or compilation fails; CI catches missing docs as errors instead of warnings (#437)
- `Contained` assurance now fail-closes unless the execution builder receives proof for every mandatory ADR-0007 control (filesystem, network, process tree, privilege suppression, syscall filtering, resource limits); receipts can now carry the per-control effective-controls matrix instead of a collapsed containment claim
- CLI `approve` / `execute` now use a schema-versioned, plan-bound approval file that binds artifact, interpreter, argv, network policy, filesystem grants, policy snapshot, detector snapshot, nonce, expiry, and approver; any post-approval tampering is rejected at execute time
- MCP approval-token nonces are now durably persisted in a redb-backed spent-nonce store so a nonce spent before restart cannot be replayed after restart when a stable signing secret is reused
- CLI auto-detects native vs script execution mode from artifact classifier instead of requiring `--native` flag
- Nightly release workflow no longer hangs on the deprecated `macos-13` (Intel) runner — `x86_64-apple-darwin` builds are dropped; Intel macOS users should build from source or run the `aarch64-apple-darwin` binary via Rosetta
- Nightly release publishes even when some build matrix legs fail (artifacts from successful legs are still released)
- `actions/upload-artifact` and `actions/download-artifact` bumped to v7/v8 to clear the Node.js 20 deprecation warning
- Daemon in-process `release()` now requires a prior inspection receipt and a release-permitting verdict, and routes publication through ADR-0015's `release_artifact` safe-release primitive instead of `std::fs::write`
- Tirith subprocess detector now records detector binary provenance in receipts and hardens subprocess execution with seccomp, Landlock, and pre-exec resource limits where available
- `Detector::analyze` trait method now returns `Result<Vec<Finding>, DetectorError>` — detectors that cannot complete analysis return `Err`, which the coordinator maps to `DetectorStatus::Error` → `Verdict::Incomplete`; previously a detector failure (e.g. subprocess crash, invalid output, timeout) silently produced zero findings and a `Pass` verdict (#434)

### Security

- **SSRF post-connect peer verification (ADR-0018, #383):** the HTTP fetcher now
  compares the connected peer address against the addresses that passed policy
  validation during DNS resolution. A DNS rebinding attack that resolves to an
  approved IP but connects to a different IP is now detected and aborted with a
  redacted error that does not leak internal addresses.
- **HTTPS→HTTP redirect downgrade protection (ADR-0018, #383):** a redirect from
  HTTPS to HTTP is now blocked by default even when both schemes are allowed by
  policy. Opt in with the new `FetchPolicy::allow_https_to_http_redirect` field.
- **No-root invariant at entry points (ADR-0009, #385):** the CLI, daemon, MCP
  server, and plugin host now refuse to run as root before any untrusted content
  is touched. A new `--allow-root` global CLI flag provides a diagnostic bypass
  for the `doctor` command and integration tests.

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
