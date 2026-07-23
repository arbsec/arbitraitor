# Arbitraitor technology stack and GitHub OSS plan

**Status:** Recommended implementation baseline; updated to reflect the pipeline-engine extraction (spec §40, v0.6).
**Version:** 0.5
**Research date:** 2026-07-23 (originally 2026-06-15; this revision supersedes v0.4)
**Scope:** Rust implementation, dependencies, repository architecture, CI/CD, OSS governance, and GitHub Projects

> **Changelog vs v0.4:**
>
> - §1: added `arbitraitor-api` row to the recommended baseline table (public embedding surface).
> - §3: workspace listing updated to match the actual 30-crate workspace (was 25 in v0.4); added `arbitraitor-api`, `arbitraitor-daemon`, `arbitraitor-mcp`, `arbitraitor-workspace-hack`, and `xtask`. Boundary rules extended to describe the pipeline engine as a first-class crate.
> - §3.5 (new): public embedding API surface — library / daemon / MCP integration matrix and pre-1.0 publishing contract.
> - §10.1: Wasmtime wording updated to "stable Wasmtime Component Model" rather than locking to WASI Preview 2 (tracks spec §41.9.1).
> - §36: added forward-looking note clarifying that the stable Rust 1.96 MSRV and the §3.5 stability contract are the two pre-1.0 release blockers for third-party embedding.
> - This file was moved from `.spec/arbitraitor-tech-stack.md` (gitignored) to `docs/spec/tech-stack.md` (committed, public). All ADR cross-references updated to point at the new canonical path.

This document turns the product specification into an opinionated engineering baseline. It intentionally chooses a smaller set of boring, auditable components over a broad collection of clever dependencies. Arbitraitor is a security boundary, so every dependency, plugin runtime, parser, workflow, and release mechanism becomes part of the attack surface.

Version numbers describe the ecosystem state when this document was written. `Cargo.lock`, automated updates, CI, and dependency review remain the source of truth. The architecture should depend on stable interfaces and capabilities rather than assuming that a particular crate version will remain current.

---

## 1. Recommended baseline

| Concern | Recommendation |
|---|---|
| Language | Rust 2024 edition |
| Bootstrap toolchain | Rust 1.96.0, pinned in `rust-toolchain.toml` |
| Workspace resolver | Cargo resolver 3 |
| Async runtime | Tokio |
| HTTP client | reqwest over rustls, behind an internal `Fetcher` trait |
| TLS trust | rustls with policy-selectable platform verifier or pinned WebPKI roots |
| DNS | System resolution initially; optional Hickory resolver behind the fetch abstraction |
| Artifact identity | SHA-256 using `sha2` |
| Filesystem confinement | `cap-std`, `cap-tempfile`, and narrowly scoped `rustix` use |
| Metadata index | `redb`, with artifact bytes kept outside the database |
| Configuration | TOML with `serde` and `toml` |
| Machine protocols | Strict JSON; RFC 8785 canonical bytes for signed receipts |
| Schemas | `schemars`, JSON Schema 2020-12 |
| CLI | `clap` derive |
| Public embedding API | Extracted `arbitraitor-api` crate; pipeline engine consumed by CLI, daemon, MCP, and third parties (spec §40) |
| Diagnostics | `thiserror` in libraries, `miette` at the CLI boundary |
| Logging | `tracing` and `tracing-subscriber` |
| Secrets | `secrecy` and `zeroize` |
| Plugin runtime | Wasmtime Component Model with WIT and WASI Preview 2 |
| Plugin fallback | Capability-restricted subprocesses using framed JSON |
| Malware rules | YARA-X |
| Script parsing | Tree-sitter plus official language parsers where available |
| External script linting | ShellCheck and PSScriptAnalyzer adapters |
| Binary parsing | `goblin` |
| File identification | Strict recognizers plus `infer` as a heuristic |
| Compression | `async-compression` plus format-specific archive crates |
| Update metadata | TUF-style metadata; implementation choice reopened after May 2026 `tough` advisories |
| Simple offline signatures | `minisign-verify` |
| OpenPGP | Sequoia OpenPGP, optional |
| Sigstore | `cosign` subprocess first; Rust library integration behind an experimental feature |
| Unit/integration test runner | `cargo-nextest`; `cargo-hack` for feature matrices |
| Property testing | `proptest`; scheduled `cargo-mutants` for critical logic |
| Snapshot testing | `insta`, used sparingly |
| Fuzzing | `cargo-fuzz` and libFuzzer |
| Concurrency model testing | `loom` for critical state machines |
| Coverage | `cargo-llvm-cov` |
| Dependency policy | `cargo-deny`, `cargo-audit`, and GitHub dependency review |
| Dependency trust | `cargo-vet`, introduced progressively |
| Unsafe inventory | `cargo-geiger`, advisory rather than a verdict |
| API compatibility | `cargo-semver-checks` for published crates |
| Release automation | release-plz plus cargo-dist |
| SBOM | `cargo-cyclonedx` and cargo-dist release metadata |
| Build provenance | GitHub artifact attestations |
| Hosting | Public GitHub organization and repository |
| Planning | Organization-level GitHub Project with issue types, fields, sub-issues, and dependencies |

---

## 2. Language and toolchain policy

### 2.1 Rust edition and compiler

Use Rust 2024 with Cargo resolver 3:

```toml
[workspace]
resolver = "3"

[workspace.package]
edition = "2024"
rust-version = "1.96"
license = "MIT OR Apache-2.0"
repository = "https://github.com/OWNER/arbitraitor"
```

At the time of research, Rust 1.96.0 is the current stable release. Rust 2024 enables the Rust-version-aware resolver 3. For the first pre-1.0 releases, pin the current stable compiler rather than carrying an artificially old minimum supported Rust version. Security-sensitive dependencies such as Wasmtime, YARA-X, TLS libraries, and parsers move quickly; forcing an old MSRV would create patch lag for little practical benefit.

Recommended policy:

- commit `rust-toolchain.toml`;
- use an exact stable toolchain for reproducible CI;
- run an additional CI job against the current stable channel to detect drift;
- reconsider a rolling six-month MSRV only after the public API and downstream users exist;
- commit `Cargo.lock`, including for library crates in this monorepo;
- prohibit nightly-only production features;
- use nightly only in isolated CI jobs such as Miri or sanitizer testing.

Example:

```toml
[toolchain]
channel = "1.96.0"
components = ["clippy", "rustfmt"]
profile = "minimal"
```

### 2.2 Compilation profiles

```toml
[profile.release]
codegen-units = 1
lto = "thin"
panic = "abort"
strip = "symbols"

[profile.release-with-debug]
inherits = "release"
debug = 1
strip = "none"

[profile.test]
debug = 1
```

Do not enable maximum optimization blindly for scanners and parsers before profiling. `panic = "abort"` is appropriate for the shipped CLI, but reusable library crates should not rely on process abortion as error handling.

### 2.3 Lints

Workspace defaults:

```toml
[workspace.lints.rust]
unsafe_code = "forbid"
missing_docs = "warn"
unexpected_cfgs = "warn"

[workspace.lints.clippy]
all = "deny"
pedantic = "warn"
cargo = "warn"
unwrap_used = "deny"
expect_used = "deny"
panic = "deny"
todo = "warn"
unimplemented = "deny"
dbg_macro = "deny"
print_stdout = "deny"
print_stderr = "deny"
```

Exceptions should be local and explained. CLI presentation modules may allow output macros. Tests may allow `unwrap` where failure context remains clear.

Do not set every Clippy nursery or restriction lint globally. That creates churn and encourages broad `allow` attributes. Adopt individual lints after evaluating their signal.

---

## 3. Workspace and crate boundaries

Use one monorepo initially. Splitting into many repositories early makes atomic security changes, versioning, and cross-platform CI harder.

Recommended workspace:

```text
arbitraitor/
  Cargo.toml
  Cargo.lock
  rust-toolchain.toml
  deny.toml
  release-plz.toml
  dist-workspace.toml

  crates/
    arbitraitor-cli/             # argument parsing and presentation only (ADR-0027)
    arbitraitor-core/            # state machine + invariant enforcement; no I/O (ADR-0002)
    arbitraitor-model/           # serializable domain types; no I/O
    arbitraitor-policy/          # TOML policy → internal AST → verdict
    arbitraitor-fetch/           # HTTP retrieval behind Fetcher trait (ADR-0003)
    arbitraitor-store/           # content-addressed quarantine store (CAS)
    arbitraitor-artifact/        # content type identification and classification
    arbitraitor-analysis/        # detector coordination
    arbitraitor-shell/           # POSIX shell / Bash / Zsh static analysis
    arbitraitor-powershell/      # PowerShell AST analysis
    arbitraitor-yarax/           # YARA-X in-process scanning
    arbitraitor-av/              # ClamAV, Defender subprocess adapters
    arbitraitor-archive/         # archive inspection under resource limits
    arbitraitor-intel/           # signed feed, URLhaus, transparency log
    arbitraitor-provenance/      # minisign, cosign, TUF, TOFU
    arbitraitor-exec/            # script + native + PowerShell execution broker
    arbitraitor-sandbox/         # platform sandbox adapters
    arbitraitor-receipt/         # RFC 8785 JCS canonicalized receipts
    arbitraitor-update/          # signed update verification
    arbitraitor-plugin-api/      # plugin trait hierarchy + capability model
    arbitraitor-plugin-host/     # Wasmtime Component Model + subprocess runtime
    arbitraitor-wrapper/          # curl/wget translators, shims
    arbitraitor-package-manager/  # package-manager lifecycle adapters (cargo, npm, uv, pnpm, yarn, bun)
    arbitraitor-api/             # (planned, see §3.5) public pipeline-engine library
    arbitraitor-daemon/           # local Unix-socket daemon; thin consumer of arbitraitor-api (socket I/O + queue + rate limit)
    arbitraitor-mcp/              # MCP server + AI-agent gateway; thin consumer of arbitraitor-api
    arbitraitor-testkit/          # testing infrastructure (mock servers, fixtures)
    arbitraitor-workspace-hack/   # hakari-managed dedup crate (autogenerated, no source logic)
    xtask/                        # repo tasks (docs-check, future generators)

  plugins/
    official/
      curl/
      wget/
      shell-posix/
      powershell/
      brew/
      arch-community/

  rules/
  schemas/
  fixtures/
  fuzz/
  docs/
    adr/
    threat-model/
  .github/
```

Boundary rules:

- `arbitraitor-model` contains serializable domain types and no I/O.
- `arbitraitor-core` owns state transitions and invariants, not presentation.
- `arbitraitor-fetch` knows networking but not policy syntax.
- `arbitraitor-policy` consumes normalized facts and produces decisions only.
- `arbitraitor-api` owns pipeline orchestration (fetch → store → analyze → provenance → receipt → verdict → release); it composes the I/O-producing crates above the `arbitraitor-core` state machine boundary, and exposes a single typed API consumed by `arbitraitor-cli`, `arbitraitor-daemon`, `arbitraitor-mcp`, and third-party embedders. Per spec §40.0, only this crate may transition the pipeline state machine across retrieval → release.
- `arbitraitor-cli` performs argument parsing, presentation, approval UX, and audit-event emission. It calls `arbitraitor-api` and formats results; it does not compose pipeline stages itself (ADR-0027 trajectory redirected by spec §40.4).
- `arbitraitor-daemon` is a thin Unix-socket consumer of `arbitraitor-api`; it owns socket I/O, the operation queue, capability-token verification, and rate-limiting only.
- `arbitraitor-mcp` is a thin JSON-RPC consumer of `arbitraitor-api`; it owns MCP protocol handling, tool discovery, capability classes, and `AgentIdentity` audit attribution.
- Platform-specific code lives behind traits in dedicated modules.
- Plugin ABI types live in `arbitraitor-plugin-api` and WIT definitions.
- No detector may call the release or execution layer directly.
- No wrapper plugin may directly perform network I/O unless a narrowly documented mode requires it.

Keep public crates to a minimum before 1.0. Most workspace crates should use `publish = false`. Pre-1.0, publish only:

- `arbitraitor-cli` — the CLI binary;
- `arbitraitor-api` — the public embedding surface, under a `0.x` semver stability contract (see §3.5).

Later, publish a deliberately stable plugin SDK. The internal adapter crates (`arbitraitor-fetch`, `arbitraitor-store`, `arbitraitor-analysis`, `arbitraitor-receipt`, `arbitraitor-provenance`, `arbitraitor-plugin-host`) remain `publish = false` and are not part of the public embedding surface; they are wrapped by `arbitraitor-api` so internal refactorings do not trigger a semver bump.

### 3.5 Public embedding API surface (v0.5)

Arbitraitor is intended to be embeddable by third-party products (package managers, IDE plugins, CI binaries, agent harnesses) without shelling out to the CLI. The pipeline engine is exposed as the `arbitraitor-api` crate; the daemon and MCP gateway are out-of-process surfaces over the same engine (full design in spec §40).

#### 3.5.1 Three integration surfaces

| Surface | Transport | Lifecycle | Use case |
|---|---|---|---|
| Library (`arbitraitor-api`) | In-process Rust typed API | Linked into binary | Rust package managers, CI binaries, compilers, CLIs that need artifact inspection |
| Daemon | Unix-socket JSON-RPC | Long-running host service | Non-Rust products (Go, Python, Node) on the same host; IDE plugins; build systems |
| MCP gateway | MCP JSON-RPC over stdio | Subprocess spawned by consumer | AI agent harnesses, IDEs, MCP-client runtimes |

#### 3.5.2 Pre-1.0 stability contract

- `arbitraitor-api` publishes under SemVer `0.x`; breaking changes are tracked in `CHANGELOG.md` and flagged in the release PR;
- The public surface is deliberately narrow: `Arbitraitor`, `ArbitraitorBuilder`, `ArbitraitorApi`, `Config`, `InspectResult`, and a typed error derived from `thiserror`;
- Feature flags gate heavier integrations (`yara-x`, `sigstore`, `package-manager`, `plugin-host`) so minimal consumers do not pull those transitive dependencies by default;
- The public API never exposes types from `arbitraitor-fetch`,
  `arbitraitor-store`, `arbitraitor-analysis`, `arbitraitor-receipt`,
  `arbitraitor-provenance`, or `arbitraitor-exec` verbatim — they are wrapped
  or mapped to ID-stable structs in `arbitraitor-api`;
- On `1.0`, breaking changes follow Rust RFC 1105: minor versions are additive, breaking changes require a major bump.

#### 3.5.3 Decision deferred to ADR-0037

Final crate name (`arbitraitor-engine` (recommended per spec §40.7) vs `arbitraitor-api` vs `arbitraitor-runtime` vs moving the API into `arbitraitor-core`) and whether the API is extracted from `arbitraitor-daemon` or `arbitraitor-daemon` is renamed and split, are deferred to a focused ADR (ADR-0037).

---

## 4. HTTP and transport stack

### 4.1 Use reqwest, but hide it

Choose `reqwest` with Tokio and rustls for the MVP. It provides redirects, proxies, TLS configuration, timeout controls, custom DNS resolution, and a mature async API. Put it behind an internal trait:

```rust
#[async_trait::async_trait]
pub trait Fetcher: Send + Sync {
    async fn fetch(
        &self,
        request: FetchRequest,
        sink: &mut dyn ArtifactSink,
    ) -> Result<FetchReceipt, FetchError>;
}
```

This preserves the option to use Hyper directly for a lower-level connector later. Do not expose reqwest types across crate boundaries.

### 4.2 Exact-byte semantics

The project must define what is hashed and scanned. HTTP transfer framing is not the artifact. Content coding can transform the response before execution.

Default behavior:

- send `Accept-Encoding: identity`;
- compile reqwest without automatic gzip, Brotli, deflate, or zstd response decoding where possible;
- explicitly disable auto-decompression in the client builder;
- hash and store the HTTP representation bytes received after transfer framing;
- if wrapper semantics request content decoding, store the encoded artifact and create a separately hashed decoded child artifact;
- scan and execute the decoded child;
- record both identities and the transformation edge.

This avoids a quiet mismatch where the library removes `Content-Encoding` and changes the bytes before Arbitraitor records them.

### 4.3 TLS

Use rustls with a policy-selectable verifier. Workstation mode may use `rustls-platform-verifier` for system and enterprise trust. Hermetic CI may use a pinned WebPKI root set. Hostile-endpoint scanning must evaluate the additional native parsing surface of platform verifiers.

Recommended defaults:

- TLS 1.2 and 1.3 only;
- certificate validation mandatory;
- hostname validation mandatory;
- no user-facing "ignore all TLS errors" shortcut;
- insecure modes require explicit policy and cannot be used for execution in enforcement mode;
- record peer certificate fingerprints and negotiated protocol where available;
- do not treat a valid certificate as publisher provenance.

### 4.4 Redirects and credentials

Implement redirects in Arbitraitor policy rather than accepting reqwest defaults unchanged.

On every redirect:

- normalize and re-evaluate the URL;
- enforce maximum count;
- block HTTPS-to-HTTP downgrade by default;
- remove authorization and cookies on cross-origin redirects;
- re-run IP-range and network-boundary policy;
- record the chain;
- detect loops and suspicious origin changes.

### 4.5 SSRF and DNS rebinding

A URL allow/deny check before resolution is insufficient.

The transport layer must:

1. parse and normalize the hostname;
2. resolve all candidate addresses;
3. reject disallowed address classes;
4. connect only to an approved resolved address;
5. verify the connected peer address where the platform exposes it;
6. repeat the process for every redirect and retry;
7. apply policy to IPv4-mapped IPv6 and unusual textual representations;
8. block cloud metadata, loopback, link-local, multicast, and private networks by default.

Start with the system resolver. Add Hickory behind a resolver trait when deterministic resolution, DNSSEC-aware experiments, or custom caching are justified. A custom DNS resolver alone does not solve rebinding; the connector must bind policy to the address actually used.

### 4.6 Backpressure and limits

- stream directly into the quarantine sink while hashing;
- enforce compressed and decoded size limits separately;
- never buffer an unbounded response in RAM;
- use `bytes` and bounded channels;
- place CPU-heavy hashing, parsing, and decompression outside Tokio executor threads when necessary;
- use cancellation tokens across retrieval and analysis;
- distinguish connect, first-byte, idle-read, and total deadlines.

---

## 5. Filesystem and content-addressed store

### 5.1 Capability-oriented filesystem access

Use `cap-std` and `cap-tempfile` for operations rooted in known directories. Use `rustix` only in a narrowly reviewed platform crate for primitives not expressed safely enough by the standard library, such as `openat`-style handling, no-follow flags, durable atomic replacement, and descriptor operations.

Do not build security around string-prefix path checks.

### 5.2 Artifact storage

Use ordinary files for artifact bytes and a small metadata database for indexes.

Recommended layout:

```text
store/
  objects/sha256/ab/cd/<digest>
  metadata.redb
  staging/
  locks/
  receipts/
```

Rules:

- artifacts are addressed by SHA-256;
- staging files use restrictive permissions;
- commit through atomic rename on the same filesystem;
- reopen objects read-only;
- verify the digest before every release;
- artifact data is never stored as large database blobs;
- metadata points to hashes, not mutable temporary paths.

### 5.3 Metadata database

Use `redb` initially as a rebuildable index and cache:

- pure Rust;
- ACID embedded key-value model;
- portable single-file storage;
- sufficient for digest-to-metadata, leases, retention, and receipt indexes;
- never authoritative for approval or integrity.

Keep a `StoreIndex` trait so SQLite remains an option if ad-hoc querying and operational tooling become more important. Avoid introducing SQLite and its C FFI solely for key-value lookups.

### 5.4 Locking and recovery

- use per-digest leases rather than one global lock;
- make incomplete staging objects unaddressable;
- reconcile orphaned staging files during `doctor`;
- use generation/version fields for metadata migrations;
- make migrations transactional and backup before destructive changes;
- fuzz metadata decoders;
- never execute directly from staging.

---

## 6. Serialization, configuration, and schemas

### 6.1 TOML for human-authored configuration

Use TOML for:

- user configuration;
- organization policy configuration;
- plugin manifests where human editing is expected;
- release configuration.

Avoid YAML for Arbitraitor policy. YAML's implicit typing, aliases, complex parsing surface, and multiple interpretations are a poor fit for a security policy language. The widely used `serde_yaml` crate is deprecated. GitHub Actions still requires YAML, but that does not require Arbitraitor itself to do so.

### 6.2 JSON for protocols and receipts

Use canonical, versioned JSON for:

- plugin subprocess messages;
- receipts;
- findings;
- intelligence records;
- SARIF adapters;
- test fixtures.

Requirements:

- explicit `schema_version`;
- `#[serde(deny_unknown_fields)]` for security-critical input structures;
- bounded message size and nesting;
- no untagged enums for ambiguous security-sensitive data;
- stable string enums;
- deterministic field ordering when signing serialized objects;
- sign a canonical binary or canonical JSON representation, not arbitrary pretty-printed JSON.

### 6.3 Schemas

Use `schemars` to derive JSON Schema where practical. Hand-review generated schemas and commit snapshots.

Schemas should:

- use JSON Schema 2020-12;
- disallow unknown properties in enforcement documents;
- define maximum string and array sizes where consumers support it;
- version independently from the binary;
- include migration tests;
- preserve forward compatibility only where explicitly intended.

### 6.4 Signed receipt canonicalization

Use RFC 8785 JSON Canonicalization Scheme for receipt signature input. Reject duplicate keys, invalid Unicode, non-I-JSON numbers, excessive nesting, and oversized values before canonicalization. Evaluate a maintained implementation such as `serde_json_canonicalizer` against official and project test vectors; do not select `serde_jcs` merely by name because current ecosystem documentation notes maintenance and conformance concerns.

### 6.5 Domain types

Prefer newtypes:

```rust
pub struct Sha256Digest([u8; 32]);
pub struct ArtifactId(Sha256Digest);
pub struct PluginId(String);
pub struct OperationId(uuid::Uuid);
```

Avoid passing raw `String` values for hashes, URLs, paths, signer identities, and policy rule IDs.

Use `url::Url` for network URLs, but retain the redacted original textual form for receipts. Use `PathBuf` and `OsString` at OS boundaries; do not assume all filenames are UTF-8.

---

## 7. Error handling and diagnostics

Use:

- `thiserror` for typed library errors;
- `miette` for user-facing reports and source spans;
- `tracing` for structured operational events;
- stable machine error codes separate from prose.

Library errors should include:

- stage;
- artifact or operation ID;
- retryability;
- policy consequence;
- underlying source;
- safe diagnostic context.

Never place secrets, full authorization headers, cookies, or unredacted signed URLs inside error strings.

CLI rules:

- artifact bytes or JSON results go to stdout;
- diagnostics, progress, and logs go to stderr;
- `--json` disables decorative output;
- color is auto-detected and can be disabled;
- machine output is versioned;
- a detector error is not represented as a clean scan.

---

## 8. Secrets and sensitive values

Use `secrecy` wrappers and `zeroize` for values that genuinely need memory clearing.

Create types that do not implement `Debug`, `Display`, or `Serialize` by default:

```rust
pub struct SecretHeaderValue(SecretString);
```

Best practices:

- pass secret references through plugin plans, not values;
- core resolves the reference only at the last responsible moment;
- redact known query parameters and user info in URLs;
- keep a separate safe diagnostic representation;
- avoid cloning secrets;
- do not persist them in receipts;
- prevent cross-origin forwarding;
- test redaction with property tests.

Memory zeroing is defense in depth, not a claim that secrets cannot remain in allocator copies, kernel buffers, or external processes.

---

## 9. Execution-context security

Exact artifact identity is insufficient unless execution context is also controlled.

A mediated execution profile must:

- construct an allowlisted environment;
- disable interpreter startup profiles;
- use temporary home and working directories by default;
- close inherited file descriptors and handles;
- deny privilege elevation;
- deny network by default;
- use a controlled PATH;
- revalidate or descriptor-pin the interpreter;
- place the process tree under cancellation and resource control;
- preserve or add platform download provenance.

Do not run the main scanner as root or administrator. A future privileged helper must expose only declarative, authenticated operations over already approved artifact digests.

Platform provenance:

- macOS: preserve or add `com.apple.quarantine`;
- Windows: preserve or add Mark of the Web (`Zone.Identifier`);
- never silently clear Gatekeeper or SmartScreen inputs.

All untrusted terminal text must pass through a core-owned strict renderer that escapes ANSI/OSC controls, carriage returns, bidi controls, and suspicious invisible Unicode. Plugins return data, not terminal markup.

Approval is a capability over a canonical execution plan, not a bare artifact digest. The plan includes interpreter, arguments, environment, grants, destination, policy, detector snapshots, expiry, and nonce.

Project `.arbitraitor.toml` files are untrusted repository content. They may tighten inherited policy or declare expected hashes/signers, but cannot add trust roots, enable plugins, permit uploads, network, or privilege elevation.

---

## 10. Plugin runtime

### 10.1 Primary runtime: Wasmtime Component Model

Use Wasmtime components and WIT interfaces for portable plugins. Target the stable Wasmtime Component Model; do not lock to WASI Preview 2 specifically and do not build new code around experimental WASI Preview 3 behavior. This tracks spec §41.9.1.

Benefits:

- typed host/guest contracts;
- language-independent plugin development;
- explicit host capabilities;
- no native ABI stability problem;
- memory isolation from the host process;
- deterministic resource controls.

Default plugin instance:

- no network;
- no ambient filesystem;
- no inherited environment;
- deterministic or host-provided clock only when requested;
- bounded memory;
- bounded table count;
- fuel or epoch-based interruption;
- total execution deadline;
- output-size limit;
- no dynamic loading;
- no access to artifact paths, only an opaque read capability or preopened read-only handle;
- per-host-call deadlines and cancellation;
- bounded host-call count and output size.

Fuel and epoch interruption do not stop a guest blocked inside a host call, so host functions must never perform unbounded blocking work.

### 10.2 WIT interfaces

Define separate worlds:

```text
arbitraitor:plugin/wrapper
arbitraitor:plugin/detector
arbitraitor:plugin/intelligence
arbitraitor:plugin/provenance
```

Do not create one universal plugin interface. A downloader argument parser should not automatically gain detector or network capabilities.

Version WIT packages semantically. Add compatibility fixtures and generated bindings to CI.

### 10.3 Subprocess fallback

Some integrations, including platform AV and package managers, require native subprocesses.

Use a framed protocol:

```text
4 or 8 byte unsigned length
JSON message
```

Never use newline-delimited JSON for arbitrary diagnostic text unless output streams are strictly separated.

Subprocess controls:

- absolute executable path;
- expected binary digest or signer policy;
- clean environment;
- dedicated working directory;
- closed inherited descriptors;
- stdout protocol only;
- stderr captured as bounded diagnostics;
- process group or Windows Job Object;
- timeout and kill-tree behavior;
- output and memory limits;
- no shell interpolation;
- platform sandbox where available.

### 10.4 No native dynamic plugin ABI initially

Do not support `.so`, `.dylib`, or `.dll` plugins in-process. A native plugin would have the same memory authority as Arbitraitor and would make community plugin compromise equivalent to core compromise.

---

## 11. Static analysis stack

### 11.1 YARA-X

Use the official YARA-X Rust API for rule compilation and scanning.

Operational model:

- compile signed rule snapshots once;
- cache compiled rules keyed by snapshot digest;
- scan immutable artifact handles;
- run high-risk scans in workers if parser/runtime risk warrants it;
- enforce per-artifact time and memory budgets;
- record engine and rule-set versions;
- make matches findings, not hard-coded final verdicts.

### 11.2 Shell and PowerShell parsing

Use Tree-sitter grammars for syntax trees and source spans. Tree-sitter is error-tolerant, which is useful for inspection, but it is not a complete shell interpreter. Arbitraitor needs its own conservative semantic layer for:

- command and argument extraction;
- constant propagation;
- literal string concatenation;
- pipe and redirection graph;
- decode-to-execute chains;
- known downloader invocation parsing;
- environment and path access;
- second-stage URL extraction.

Use ShellCheck as an optional advisory subprocess detector. Its JSON/checkstyle output is easy to normalize, but its primary job is shell correctness, not malware detection.

Use the official `System.Management.Automation.Language.Parser` through a restricted helper where PowerShell is available. Use PSScriptAnalyzer as an optional advisory detector. Tree-sitter provides portable fallback coverage.

### 11.3 Binary inspection

Use `goblin` for PE, ELF, Mach-O, and archive metadata. Keep parsing read-only and bounded. Do not turn the MVP into a disassembler.

Potential findings:

- entry point and architecture;
- import tables;
- executable sections;
- suspicious subsystem or permissions;
- embedded signer metadata;
- setuid/setgid bits from containers;
- platform mismatch;
- malformed structure.

### 11.4 File type identification

Use a layered classifier:

1. strict, project-owned recognizers for critical formats;
2. shebang and encoding inspection;
3. parser probes;
4. `infer` as a heuristic;
5. declared MIME type and filename as low-confidence evidence.

No single magic-number crate should decide whether something is executable.

---

## 12. Archives and decompression

Use format-specific crates and `async-compression` for stream codecs. Start with ZIP, tar, gzip, xz, and zstd. Add formats only with a concrete use case and security review.

Architecture:

- archive metadata parser runs under resource limits;
- extraction target is a capability-rooted directory;
- every entry path is normalized as a platform-independent virtual path first;
- reject absolute paths, parent traversal, Windows drive prefixes, UNC paths, device names, symlink escape, hard-link escape, and Unicode/case collisions;
- count entries before or during extraction;
- track cumulative decoded bytes and compression ratio;
- recursively inspect children through the same artifact pipeline;
- encrypted or unsupported members produce incomplete coverage, never a clean result.

Prefer out-of-process workers for complex native parsers. Pure Rust reduces memory-corruption risk but does not remove denial-of-service or logic vulnerabilities.

---

## 13. Provenance and update libraries

### 13.1 TUF metadata

Use TUF-style signed metadata for first-party rules, intelligence snapshots, and plugin registry metadata.

The Rust TUF client decision is reopened. AWS security bulletin 2026-019 describes multiple delegated-metadata and path-handling vulnerabilities fixed in `tough` 0.22.0.

Decision:

- use a narrowly scoped TUF-compatible first-party channel first;
- keep the update verifier behind an internal trait;
- run the official TUF conformance suite and adversarial filesystem/delegation tests;
- require rollback, freeze, mix-and-match, endless-data, and path-traversal protection;
- if `tough` is selected, require 0.22.0 or later plus local validation;
- design the community registry only after delegated trust requirements are proven.

### 13.2 Sigstore

For the first production release, invoke a pinned or system-approved `cosign` executable through the subprocess adapter. The Rust Sigstore library has historically marked parts of its API as experimental and changes faster than the desired core compatibility boundary.

Later:

- evaluate embedded verification;
- keep exact identity/issuer policy in Arbitraitor;
- test offline bundle verification;
- avoid mandatory network transparency-log queries during local scans.

### 13.3 Minisign

Use `minisign-verify` for simple offline verification of first-party metadata and emergency bootstrap material. It has a small surface and supports streaming verification.

Do not invent a custom signature format.

### 13.4 OpenPGP

Use Sequoia OpenPGP only where ecosystem compatibility requires it, such as package-source signatures. OpenPGP policy is complicated; keep it optional and isolate trust-policy interpretation from packet parsing.

---

## 14. Antivirus integrations

Prefer protocol or subprocess adapters over embedding AV engines.

- ClamAV: speak the documented `clamd` protocol or invoke `clamdscan` with a fixed argument vector.
- Microsoft Defender: use supported command-line or platform interfaces.
- macOS: use stable platform facilities only; do not scrape UI or undocumented databases.

Record:

- engine version;
- signature age;
- local versus remote processing;
- scan mode;
- timeout;
- error status.

Required scanner failure must block or produce `incomplete`, never "not detected."

---

## 15. Policy engine implementation

Start with a typed, constrained policy model rather than Rego, Cedar, or a general expression language.

Why:

- smaller attack surface;
- deterministic evaluation;
- simpler explainability;
- easier schema validation;
- no embedded scripting runtime in the security core.

Use TOML as authoring syntax and compile into an immutable internal AST. Separate:

- facts;
- predicates;
- rules;
- precedence;
- decision;
- explanation trace.

Requirements:

- total evaluation, with no unbounded loops;
- deterministic ordering;
- explicit default;
- three-valued handling for unavailable evidence;
- stable rule IDs;
- test vectors;
- policy digest in every receipt.

Consider CEL, Cedar, or Rego only after the native policy model becomes demonstrably insufficient.

---

## 16. CLI and terminal UX

Use `clap` derive and generate:

- shell completions;
- man pages;
- Markdown command reference.

Use `miette` for source-oriented findings. Use `indicatif` only for interactive progress, behind an output abstraction.

Rules:

- no hidden network actions;
- no generic `--yes` bypass;
- explicit `--non-interactive`;
- approval binds to artifact digest;
- every override requires reason and scope when policy permits it;
- stable exit codes;
- `--json` and `--sarif`;
- all commands support cancellation;
- error messages state whether release occurred.

---

## 17. Concurrency model

Use Tokio for network and orchestration, not for CPU-bound scanner work.

- async tasks own I/O state;
- CPU parsers use bounded worker pools or subprocesses;
- external detector concurrency is capped;
- recursive graph expansion uses a global byte, node, and depth budget;
- cancellation propagates through a shared token;
- no detached tasks may outlive the operation receipt;
- deterministic mode fixes detector ordering and disables nondeterministic concurrency where reproducibility matters.

Use `loom` for:

- CAS commit/lease state;
- approval-to-release transitions;
- cancellation races;
- cache invalidation;
- daemon request ownership.

---

## 18. Testing stack

### 18.1 Fast test suite

Use `cargo-nextest` for unit and integration tests. Keep tests deterministic and parallel-safe.

Test layers:

- unit tests per crate;
- contract tests for plugin protocols;
- local HTTP server integration tests;
- cross-platform execution tests;
- golden receipt and finding tests;
- adversarial archive corpus;
- end-to-end CLI tests.

### 18.2 Property tests

Use `proptest` for:

- URL normalization;
- path normalization;
- redaction;
- policy monotonicity;
- receipt round trips;
- no-release-before-verdict state transitions;
- archive virtual paths;
- wrapper argument parsing.

### 18.3 Snapshot tests

Use `insta` for reviewed human-facing diagnostics, receipts, and operation plans. Avoid snapshots for logic that should be asserted structurally.

### 18.4 Fuzzing

Use `cargo-fuzz` for:

- policy and manifest parsers;
- protocol decoders;
- URL and header normalization;
- archive metadata;
- script normalization;
- finding and receipt readers;
- wrapper CLI parsers.

Run short smoke fuzzing on pull requests and longer scheduled campaigns.

### 18.5 Miri and sanitizers

Run Miri on selected pure-Rust core crates. Run address and undefined-behavior sanitizers on supported Linux targets for crates containing or depending on unavoidable unsafe code.

### 18.6 Coverage

Use `cargo-llvm-cov`. Coverage is a navigation aid, not a merge-quality metric by itself. Require meaningful tests around security invariants rather than a single global percentage.

---

## 19. Dependency and unsafe-code governance

### 19.1 Admission checklist

Before adding a production dependency, record:

- exact capability needed;
- why the standard library or an existing dependency cannot provide it;
- maintenance activity;
- owner concentration;
- release and security history;
- unsafe code;
- native dependencies and build scripts;
- network behavior;
- license;
- MSRV impact;
- transitive dependency increase;
- alternative considered.

Put significant decisions in ADRs.

### 19.2 Automated controls

Use:

- `cargo-deny` for advisories, licenses, bans, sources, and duplicates;
- `cargo-audit` for RustSec advisory checks;
- GitHub dependency review to block vulnerable additions in pull requests;
- Dependabot for Cargo and GitHub Actions updates;
- `cargo-semver-checks` for public crates;
- `cargo-hack` for feature powersets;
- scheduled `cargo-mutants` for policy/state-machine logic;
- `cargo-geiger` as an unsafe inventory;
- `cargo-vet` after the initial dependency graph stabilizes.

`cargo-vet` should be introduced incrementally. It is designed to verify that third-party dependencies have audits from trusted entities without requiring the entire graph to be audited on day one.

### 19.3 Build scripts and proc macros

Treat build scripts and proc macros as executable supply-chain dependencies.

Policy:

- minimize them;
- list them in dependency review;
- do not add Git dependencies without a pinned commit and explicit approval;
- deny unknown registries;
- use Cargo source replacement only through documented organization policy;
- inspect changes to `Cargo.lock` as security-relevant.

### 19.4 Unsafe code

- `#![forbid(unsafe_code)]` in core policy, receipt, model, and state-machine crates;
- isolate required unsafe code in platform or FFI crates;
- require two maintainer approvals for unsafe changes;
- document safety invariants beside every unsafe block;
- run dedicated Miri/sanitizer/fuzz jobs;
- track unsafe dependency changes through `cargo-geiger` diffs.

---

## 20. CI architecture on GitHub Actions

All third-party actions must be pinned to full commit SHA with a version comment. GitHub documents a full-length commit SHA as the only immutable action reference. Dependabot should update those pins.

Use least-privilege `GITHUB_TOKEN` permissions at workflow and job level. Use OIDC or trusted publishing instead of long-lived release credentials.

### 20.1 Required pull-request workflows

`ci.yml`:

- format check;
- Clippy with all targets and features;
- `cargo check --workspace --all-targets --all-features`;
- `cargo nextest run`;
- documentation build;
- Linux primary job;
- Windows and macOS integration matrix;
- toolchain pin verification;
- schema generation diff check;
- WIT binding generation diff check.

`security.yml`:

- cargo-deny;
- cargo-audit;
- dependency review;
- CodeQL for Rust and GitHub Actions;
- secret scanning and push protection configured at repository level;
- optional OpenSSF Scorecard.

`invariants.yml`:

- state-machine property tests;
- exact-byte scan/release tests;
- redirect and SSRF regression tests;
- archive traversal corpus;
- plugin capability tests.

### 20.2 Scheduled workflows

- nightly or weekly fuzz smoke;
- weekly dependency audit;
- weekly cargo-vet verification;
- weekly rule and fixture corpus tests;
- monthly MSRV/current-stable review;
- scheduled cross-platform full suite;
- stale intelligence/update metadata simulation.

Do not run untrusted pull-request code with repository secrets. Avoid `pull_request_target` for build or test workflows.

Fork PR jobs must use read-only permissions, must not share writable caches with privileged workflows, and must not run on self-hosted release runners. Do not use `workflow_run` to ingest and execute artifacts from untrusted workflows. Release jobs rebuild from the protected tag.

### 20.3 Workflow validation

Treat `.github/workflows` as production code:

- CODEOWNERS review;
- action SHA pins;
- explicit permissions;
- concurrency cancellation for superseded PR runs;
- timeouts on every job;
- no unchecked interpolation into shell scripts;
- use environment files correctly;
- quote shell variables;
- prefer small scripts committed under `scripts/` over long inline shell blocks.

---

## 21. Release engineering

### 21.1 Versioning

Use SemVer. Before 1.0:

- minor versions may contain deliberate breaking changes;
- changelog must identify them;
- receipt, policy, and plugin protocol schemas version independently.

Use conventional PR titles rather than requiring every contributor commit to follow Conventional Commits. Squash merge uses the reviewed PR title as the release commit.

Examples:

```text
feat(fetch): enforce connected-peer address policy
fix(store): prevent release from stale artifact handle
security(plugin): reject undeclared WASI imports
docs(spec): define encoded HTTP artifact identity
```

### 21.2 release-plz

Use release-plz to maintain version and changelog release PRs for publishable crates. It supports workspaces, conventional commits, changelog generation, and semver checks.

Do not allow an automation bot to publish immediately from arbitrary main-branch changes. The release PR is reviewed and merged first.

### 21.3 cargo-dist

Use cargo-dist for:

- cross-platform binary archives;
- checksums;
- installers where appropriate;
- GitHub Releases;
- release manifests;
- SBOM integration where supported.

Initial targets:

- `x86_64-unknown-linux-gnu`;
- `aarch64-unknown-linux-gnu`;
- `x86_64-apple-darwin`;
- `aarch64-apple-darwin`;
- `x86_64-pc-windows-msvc`;
- Windows ARM64 later if demand and dependencies support it.

Consider musl only after testing TLS roots, DNS, antivirus adapters, and platform behavior. "Static binary" is not automatically a better security choice.

### 21.4 SBOM and provenance

Generate CycloneDX SBOMs with `cargo-cyclonedx`. Attach:

- SBOM;
- SHA-256 checksum file;
- release manifest;
- GitHub artifact attestation;
- source commit;
- build instructions.

GitHub artifact attestations establish GitHub Actions build provenance and can be verified using the GitHub CLI. They do not prove benign source or dependencies, and GitHub's attestation service has no public transparency log. Keep independent checksums/signatures and reproducibility work.

### 21.5 Publishing credentials

Use crates.io trusted publishing through OIDC where supported by the chosen release tool. Avoid long-lived `CARGO_REGISTRY_TOKEN` secrets.

Release jobs should:

- run only from protected tags or reviewed release workflow;
- use GitHub environments with approval for production publication;
- have narrowly scoped permissions;
- attest artifacts after build;
- never build release artifacts from untrusted forks.

---

## 22. GitHub organization and repository structure

### 22.1 Organization versus personal repository

Create a GitHub organization if the name is available. The exact account and package-name availability must be checked manually before launch.

An organization is preferable because GitHub supports organization-level:

- issue types;
- reusable issue fields;
- Projects;
- teams;
- rulesets;
- security roles;
- future plugin and rule repositories.

Suggested initial repositories:

```text
arbitraitor/arbitraitor       Core monorepo
arbitraitor/.github           Organization profile and shared community files, later
```

Do not split rules, plugins, website, registry, and documentation immediately. Add repositories when release cadence, permissions, or trust roots genuinely differ.

### 22.2 License

Use dual licensing:

```text
MIT OR Apache-2.0
```

This is conventional in the Rust ecosystem and gives downstream users flexibility. Include both license files and SPDX expressions in every publishable crate.

Use Developer Certificate of Origin sign-off rather than a custom CLA unless a future legal need arises. A CLA adds friction and centralizes rights unnecessarily for an early community project.

### 22.3 Required community files

At launch:

- `README.md`;
- `LICENSE-MIT`;
- `LICENSE-APACHE`;
- `CONTRIBUTING.md`;
- `CODE_OF_CONDUCT.md`;
- `SECURITY.md`;
- `SUPPORT.md`;
- `GOVERNANCE.md`;
- `CHANGELOG.md`;
- `CODEOWNERS`;
- `CITATION.cff`, optional but cheap;
- issue forms;
- pull request template.

`SECURITY.md` must direct vulnerability reports to GitHub private vulnerability reporting, not public issues.

### 22.4 Repository settings

Recommended:

- default branch: `main`;
- squash merge enabled;
- merge commits disabled;
- rebase merge disabled initially;
- automatically delete head branches;
- Discussions enabled for ideas, Q&A, and announcements;
- Issues enabled for actionable work;
- Wiki disabled; documentation remains versioned in the repository;
- private vulnerability reporting enabled;
- Dependabot alerts and security updates enabled;
- secret scanning and push protection enabled;
- CodeQL enabled;
- dependency graph enabled.

---

## 23. Branch and tag protection

Use repository rulesets rather than a collection of overlapping legacy branch-protection rules.

### 23.1 `main` ruleset

Require:

- pull request;
- one approval by default;
- two approvals for security-critical paths through CODEOWNERS/team policy;
- dismissal of stale approvals;
- approval of the most recent reviewable push;
- conversation resolution;
- required status checks;
- linear history;
- no force push;
- no deletion;
- merge queue later if contribution volume justifies it.

Require status checks from the expected GitHub App source where possible.

Do not require every external contributor commit to be cryptographically signed. That creates unnecessary onboarding friction and interacts awkwardly with contributor histories. Require verified release tags and trusted maintainer/release automation instead. GitHub-created squash/release commits can remain verified.

### 23.2 Tag ruleset

Protect:

```text
v*
arbitraitor-v*
```

Requirements:

- only release workflow or release maintainers can create tags;
- no update or deletion;
- release commit must be on `main`;
- artifacts must correspond to the tag commit;
- release workflow creates attestations and checksums.

### 23.3 CODEOWNERS

Example:

```text
/.github/                     @arbitraitor/maintainers
/Cargo.lock                   @arbitraitor/security
/deny.toml                    @arbitraitor/security
/crates/arbitraitor-core/     @arbitraitor/security
/crates/arbitraitor-fetch/    @arbitraitor/security
/crates/arbitraitor-store/    @arbitraitor/security
/crates/arbitraitor-exec/     @arbitraitor/security
/crates/arbitraitor-update/   @arbitraitor/security
/crates/arbitraitor-plugin-host/ @arbitraitor/security
/wit/                         @arbitraitor/plugin-maintainers
/rules/                       @arbitraitor/rule-reviewers
```

Initially, one person may occupy multiple teams. The structure still documents future review boundaries.

---

## 24. Issue forms and Discussions

Create YAML issue forms for:

1. bug report;
2. feature proposal;
3. false positive or false negative;
4. plugin proposal;
5. rule proposal;
6. package-manager compatibility report;
7. documentation problem;
8. research or ADR proposal.

Disable blank issues.

Security form text must say:

```text
Do not report vulnerabilities here. Use GitHub private vulnerability reporting according to SECURITY.md.
```

Use Discussions for:

- broad ideas;
- user support;
- design exploration before an actionable issue exists;
- announcements;
- show-and-tell for plugins and rules.

Convert a Discussion into an issue when scope and acceptance criteria are clear.

---

## 25. GitHub Projects design

Create one organization-level Project and store its intended configuration in `ops/github/project.toml` with an idempotent bootstrap/audit script. Use a GitHub App for organization Project automation rather than a maintainer PAT.

```text
Arbitraitor Roadmap
```

GitHub recommends using Projects as the single source of truth, with sub-issues, issue types, custom fields, views, and automation. Organization-level issue fields can be reused across projects.

### 25.1 Issue types

Use organization issue types:

- Epic;
- Feature;
- Bug;
- Security hardening;
- Research;
- Task;
- Documentation;
- Plugin;
- Rule.

A type describes the work. Do not duplicate it with labels.

### 25.2 Fields

#### Status

```text
Inbox
Triage
Ready
In progress
In review
Blocked
Done
```

#### Priority

```text
P0 - immediate/security incident
P1 - next critical work
P2 - planned
P3 - backlog
```

#### Area

```text
Core
Fetch
Store
Policy
Analysis
Shell
PowerShell
YARA-X
Archives
Provenance
Intelligence
Execution
Sandbox
Plugin API
Wrappers
Package managers
CLI/UX
CI/Release
Documentation
Governance
```

#### Effort

```text
XS
S
M
L
XL
```

`XL` means the issue should normally be split into sub-issues.

#### Risk

```text
Low
Medium
High
Critical
```

Risk describes implementation/security risk, not priority.

#### Target release

```text
v0.1
v0.2
v0.3
v0.4
v1.0
Later
```

Use GitHub milestones as the release completion container and the Project field for roadmap filtering. This slight duplication is intentional because milestones provide release progress and close dates, while the field works across views.

#### Additional fields

- Iteration;
- Start date;
- Target date;
- Security impact: None / Low / High;
- Breaking change: Yes / No;
- Public API impact: Yes / No;
- Plugin compatibility impact: Yes / No.

Do not add fields merely because GitHub allows them. Every field must drive a view, query, or decision.

### 25.3 Views

Create:

1. **Inbox and triage** - table grouped by Status.
2. **Current work** - board for Ready through In review.
3. **Roadmap** - roadmap grouped by Target release.
4. **Security** - table filtered to Security impact or Security hardening.
5. **Plugin ecosystem** - grouped by wrapper, shell, detector, and package-manager work.
6. **Release readiness** - grouped by milestone and blocked state.
7. **Research and ADRs** - Research issues and accepted/proposed ADR work.
8. **Blocked** - dependencies and external blockers.
9. **Good first issues** - public contributor entry points.

### 25.4 Agent and automation approval boundary

Automation may inspect and request approval, but the same GitHub App, agent tool, or workflow capability must not fabricate human approval. Plan-bound approval artifacts are created through a protected environment or trusted UI and are non-replayable across changed plans.

### 25.5 Hierarchy and dependencies

Use:

- Epics as parent issues;
- sub-issues for deliverable work;
- issue dependencies for "blocked by" relationships;
- milestones for releases;
- task lists only for very small local checklists.

Example:

```text
Epic: Secure fetch core
  - Define Fetcher trait
  - Implement exact-byte HTTP retrieval
  - Implement redirect policy
  - Implement SSRF address validation
  - Add local adversarial HTTP test server
```

Do not use one enormous issue with 50 checkboxes. Sub-issues provide ownership, status, dependencies, and reporting.

### 25.6 Automations

Built-in Project automation:

- auto-add issues and PRs from the core repository;
- new items -> Inbox;
- merged PR -> Done;
- closed issue -> Done;
- reopened issue -> Triage;
- automatically archive old Done items after a retention period.

A small repository-owned GitHub Action may:

- set PR to In review when marked ready;
- link PRs to issues using closing keywords;
- copy Target release from parent Epic where appropriate;
- flag missing Area or acceptance criteria;
- add release-note requirement for public behavior changes.

Do not create an elaborate synchronization bot before built-in automation proves insufficient.

### 25.7 Iterations

Use two-week iterations only for currently committed work. Do not force the entire backlog into sprints. OSS contributors work asynchronously; a rigid sprint model becomes fake precision quickly.

---

## 26. Labels

Use fields for status, priority, type, area, risk, and effort. Keep labels for semantics and automation that are useful outside Projects:

```text
good first issue
help wanted
needs reproduction
needs decision
blocked: external
security-sensitive
breaking change
no changelog
dependencies
platform: linux
platform: macos
platform: windows
```

Avoid label taxonomies that duplicate Project fields.

---

## 27. Pull request process

PR template should require:

- problem and chosen approach;
- linked issue;
- security impact;
- user-visible behavior;
- tests added;
- documentation/schema changes;
- compatibility impact;
- dependency additions;
- release-note requirement;
- checklist for exact-byte and policy invariants when relevant.

Rules:

- small, reviewable PRs;
- PR title follows conventional format;
- squash merge;
- no unrelated refactoring in security fixes;
- dependency PRs include changelog/security review;
- generated files must be reproducible;
- unsafe code and workflow changes receive security-owner review;
- AI-assisted contributions are allowed, but the contributor remains responsible for correctness, licensing, tests, and disclosure of substantial generated content when project policy requires it.

---

## 28. ADR process

Use Markdown ADRs:

```text
docs/adr/0001-rust-2024-and-toolchain-policy.md
docs/adr/0002-reqwest-behind-fetcher-trait.md
docs/adr/0003-toml-policy-format.md
docs/adr/0004-wasmtime-component-plugins.md
docs/adr/0005-redb-metadata-index.md
docs/adr/0006-update-framework-selection.md
```

States:

```text
Proposed
Accepted
Superseded
Rejected
```

Accepted ADRs are immutable except for factual corrections. A new ADR supersedes an old decision.

Initial ADRs should cover every choice where changing later would be expensive or security-sensitive.

---

## 29. Documentation

Keep developer and user documentation in the monorepo.

Recommended:

- rustdoc for crate APIs;
- mdBook for user/developer guides when content outgrows the README;
- threat model and security invariants as first-class docs;
- generated CLI reference;
- example policies tested in CI;
- plugin WIT documentation;
- architecture diagrams stored as text source where possible.

Publish docs through GitHub Pages only after the documentation structure stabilizes. The repository remains canonical.

---

## 30. Initial GitHub workflow set

```text
.github/workflows/
  ci.yml
  security.yml
  codeql.yml
  fuzz-smoke.yml
  scheduled-full.yml
  coverage.yml
  release-pr.yml
  release.yml
  scorecard.yml
  project-automation.yml
```

Prefer fewer workflows with clear permission boundaries over one giant workflow.

Every workflow should define:

```yaml
permissions: {}

concurrency:
  group: ${{ github.workflow }}-${{ github.ref }}
  cancel-in-progress: true
```

Each job then grants only what it needs.

Never blindly copy action examples that reference floating tags. Pin to full SHA and include a comment with the human-readable release.

---

## 31. Recommended repository bootstrap order

### Stage 1: Governance and skeleton

1. Reserve GitHub organization, repository, crate name, and relevant domains where available.
2. Create public repository with dual license.
3. Add community and security files.
4. Configure rulesets and private vulnerability reporting.
5. Create organization Project and issue types/fields.
6. Add ADRs for the foundational decisions.
7. Commit Rust workspace and toolchain pin.

### Stage 2: CI trust foundation

1. Add format, Clippy, check, nextest, and docs workflows.
2. Add cargo-deny, cargo-audit, dependency review, CodeQL, and secret scanning.
3. Pin every action by SHA.
4. Add Dependabot for Cargo and GitHub Actions.
5. Add release workflow in dry-run mode.
6. Add artifact attestation proof-of-concept.

### Stage 3: Core implementation

1. Domain model and state machine.
2. Capability-rooted staging store.
3. SHA-256 content-addressed commit.
4. exact-byte fetcher.
5. policy model.
6. receipt generation.
7. release invariant tests.

### Stage 4: Analysis and plugins

1. YARA-X detector.
2. shell Tree-sitter analysis.
3. Wasmtime WIT plugin host.
4. curl and wget operation-plan parsers.
5. archive expansion.
6. external AV adapters.

### Stage 5: Package ecosystems

1. common package recipe model;
2. Homebrew research adapter;
3. Arch community package recipe analyzer;
4. clean-build sandbox;
5. paru/yay command wrappers.

---

## 32. Deliberately rejected initial choices

### Scalar risk scores

Deferred from the MVP. Findings, confidence, provenance, detector state, and policy traces are more defensible than a single gameable number.

### Native dynamic plugins

Rejected because they share host memory authority and create ABI and supply-chain risk.

### YAML policy files

Rejected because of implicit typing, parser complexity, and the deprecated state of `serde_yaml`.

### Full curl compatibility in the core

Rejected because the option surface is huge and many operations are not downloads. Wrappers should expose explicit semantic coverage.

### SQLite as the first metadata index

Deferred. SQLite is mature, but Arbitraitor initially needs a small key-value index. `redb` avoids a native C dependency. Keep the abstraction so the decision can change.

### Embedded Sigstore verification as a hard dependency

Deferred until the Rust library API and compatibility surface are judged stable enough. A controlled `cosign` adapter is easier to isolate initially.

### Rego, Cedar, or CEL policy language

Deferred until concrete policy requirements exceed the typed native model.

### Kubernetes, remote control plane, or cloud scanner

Rejected for the initial project. Local-first behavior is a key trust property and keeps the project buildable by a small OSS team.

### Multiple core repositories

Rejected until release cadence or trust boundaries require separation.

---

## 33. Risks requiring prototypes before commitment

1. **Connected-peer validation in reqwest:** prove that SSRF policy can bind DNS resolution to the actual connection on every supported platform. Drop to Hyper or a custom connector if needed.
2. **HTTP content-coding identity:** prove encoded and decoded artifacts are recorded and replayed without ambiguity.
3. **Wasmtime startup and memory cost:** measure plugin-host overhead and caching behavior.
4. **WASI capability leakage:** test every imported capability and deny ambient authority.
5. **TUF delegation:** determine whether `tough` is sufficient for the future plugin registry.
6. **Tree-sitter shell semantics:** measure extraction accuracy against real installers and obfuscated fixtures.
7. **Archive path handling:** build a cross-platform corpus, especially Windows path edge cases.
8. **Package-manager mediation:** determine which Homebrew and Arch lifecycle stages can be reliably controlled without patching upstream tools.
9. **redb crash recovery:** test power-loss and corruption scenarios before storing authoritative approval metadata.
10. **Release reproducibility:** compare artifacts from independent builds and document unavoidable variance.
11. **Execution context:** test environment injection, startup files, interpreter replacement, inherited descriptors, and poisoned PATH.
12. **Platform provenance:** verify quarantine/MOTW creation and propagation.
13. **TUF client:** run current conformance and May 2026 regression tests before library selection.
14. **Package recipes:** prove that Homebrew and PKGBUILD inspection occurs before arbitrary code evaluation.

These should be GitHub Research issues linked to ADRs, not hidden implementation assumptions.

---

## 34. Initial milestone and Project breakdown

### v0.1: Invariant-preserving fetch

Epic issues:

- Repository and security bootstrap;
- Domain model and state machine;
- Content-addressed store;
- Exact-byte HTTP fetch;
- Basic policy evaluator;
- JSON receipt;
- Cross-platform CLI;
- Release pipeline proof-of-concept.

Exit criteria:

- no content can be released before a verdict;
- released digest equals scanned digest;
- redirects and connected addresses are recorded;
- CI and artifact provenance are operational.

### v0.2: Static analysis

- YARA-X;
- shell parser;
- findings and source spans;
- archive limits;
- reputation snapshot;
- interactive review;
- SARIF.

### v0.3: Plugin foundation

- WIT API;
- Wasmtime host;
- signed plugin manifest;
- curl wrapper;
- wget wrapper;
- Bash and PowerShell execution adapters;
- conformance suite.

### v0.4: Package workflows

- common recipe model;
- Homebrew adapter prototype;
- Arch community recipe analyzer;
- paru/yay wrappers;
- sandboxed builds.

### v1.0 prerequisites

- independent security review;
- stable receipt and policy schemas;
- plugin compatibility policy;
- secure update channel;
- documented incident process;
- supported-platform matrix;
- reproducible or independently verifiable releases;
- false-positive governance;
- stable public API limited to what can be maintained.

---

## 35. Source references

Primary documentation used for this recommendation:

- Rust 1.96.0 release: <https://blog.rust-lang.org/releases/latest/>
- Rust 2024 resolver 3: <https://doc.rust-lang.org/stable/edition-guide/rust-2024/cargo-resolver.html>
- reqwest client configuration: <https://docs.rs/reqwest/latest/reqwest/struct.ClientBuilder.html>
- Wasmtime and the Component Model: <https://docs.wasmtime.dev/>
- Wasmtime component API: <https://docs.wasmtime.dev/api/wasmtime/component/>
- WASI implementation: <https://docs.wasmtime.dev/api/wasmtime_wasi/>
- cap-std: <https://docs.rs/cap-std/latest/cap_std/>
- redb: <https://docs.rs/redb/latest/redb/>
- YARA-X Rust API: <https://virustotal.github.io/yara-x/docs/api/rust/>
- Tree-sitter: <https://tree-sitter.github.io/tree-sitter/>
- ShellCheck: <https://github.com/koalaman/shellcheck>
- PSScriptAnalyzer: <https://learn.microsoft.com/powershell/utility-modules/psscriptanalyzer/overview>
- Cargo Vet: <https://mozilla.github.io/cargo-vet/>
- cargo-deny: <https://embarkstudios.github.io/cargo-deny/>
- RustSec cargo-audit: <https://github.com/rustsec/rustsec/tree/main/cargo-audit>
- CodeQL Rust support: <https://codeql.github.com/docs/codeql-overview/supported-languages-and-frameworks/>
- GitHub Actions security hardening: <https://docs.github.com/actions/security-guides/security-hardening-for-github-actions>
- GitHub repository rulesets: <https://docs.github.com/repositories/configuring-branches-and-merges-in-your-repository/managing-rulesets/about-rulesets>
- GitHub Projects best practices: <https://docs.github.com/issues/planning-and-tracking-with-projects/learning-about-projects/best-practices-for-projects>
- GitHub organization issue fields: <https://docs.github.com/issues/tracking-your-work-with-issues/using-issues/managing-issue-fields-in-your-organization>
- GitHub artifact attestations: <https://docs.github.com/actions/how-tos/secure-your-work/use-artifact-attestations/use-artifact-attestations>
- release-plz: <https://release-plz.dev/docs>
- cargo-dist: <https://opensource.axo.dev/cargo-dist/>
- CycloneDX Rust Cargo plugin: <https://github.com/CycloneDX/cyclonedx-rust-cargo>
- GitHub dependency review: <https://docs.github.com/code-security/supply-chain-security/understanding-your-software-supply-chain/configuring-the-dependency-review-action>
- AWS `tough` security bulletin: <https://aws.amazon.com/security/security-bulletins/2026-019-aws/>
- TUF security model: <https://theupdateframework.io/docs/security/>
- Wasmtime host-call interruption limitation: <https://docs.wasmtime.dev/api/wasmtime/struct.Config.html>
- PowerShell parser: <https://learn.microsoft.com/en-us/dotnet/api/system.management.automation.language.parser>
- Homebrew tap trust: <https://docs.brew.sh/Tap-Trust>
- Arch makepkg: <https://wiki.archlinux.org/title/Makepkg>
- Unicode security mechanisms: <https://www.unicode.org/reports/tr39/>
- Windows Zone.Identifier: <https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/6e3f7352-d11c-4d76-8c39-2516a9df36e8>

---

## 36. Final stack decision

The recommended foundation is:

```text
Rust 2024
  + Tokio
  + reqwest/rustls behind Fetcher
  + capability-rooted filesystem APIs
  + SHA-256 content-addressed objects
  + redb metadata index
  + TOML policy and JSON protocols
  + typed native policy engine
  + YARA-X and Tree-sitter analysis
  + Wasmtime Component Model plugins
  + TUF-style signed updates after client conformance review
  + clean, network-denied mediated execution
  + platform provenance preservation
  + GitHub Actions, Projects, attestations, and security tooling
```

The crucial architectural rule is not a library choice: Arbitraitor core owns retrieval, artifact identity, policy, approval, and release. Libraries and plugins provide mechanisms and evidence. None of them gets to silently turn an unknown artifact into an approved execution.

### 36.1 Pre-1.0 release blockers for third-party embedding

Before publishing the `arbitraitor-api` crate to crates.io for third-party
embedding (spec §40.5 / §40.6), the following must be in place:

1. **Workspace crate layout aligned.** The pipeline engine exists as a
   crate separate from the CLI's `pipeline.rs` (ADR-0027 trajectory) and
   from the daemon's socket I/O layer. The MCP gateway is a thin client
   of the engine, not an independent pipeline composition.
2. **Stability contract documented.** The deliberative scope of
   `Arbitraitor`, `ArbitraitorBuilder`, `ArbitraitorApi`, `Config`,
   `InspectResult`, and the error type is recorded (spec §40.6); internal
   adapter crates are not exposed.
3. **MSRV pinned and tracked.** `rust-version = "1.96"` in `Cargo.toml`
   is the working baseline; bumping the MSRV is a release-blocking decision
   evaluated against consumer compatibility.
4. **Feature-flag matrix.** The `yara-x`, `sigstore`, `package-manager`,
   `plugin-host` features gate heavier transitive dependencies; a minimal
   consumer pulling only `inspect` should not transitively depend on
   Wasmtime or Sigstore.
5. **ADR-0037 accepted.** Naming and extraction-vs-rename decision recorded;
   this is the gating ADR for the §3.5 surface.
6. **Type wrapping complete.** `FetchPolicy`, `ReleaseMethod`, `StoreError`,
   and `PolicyEngine` are wrapped in engine-owned types; no internal crate
   types leak through the public API. (This is nontrivial work — see spec
   §40.6 migration note for the full list of currently-leaking types.)
7. **State machine wired.** `PipelineOperation` from `arbitraitor-core` is
   integrated into the engine's `inspect`/`scan`/`release` flow; the engine
   is the single authority for state transitions across retrieval → release.
   Today `PipelineOperation` is fully implemented but not wired into any of
   the three existing compositions (CLI, MCP, daemon) — integration is a
   prerequisite for the single-pipeline principle, not a consequence of it.
8. **Provenance verification in the engine.** The engine owns minisign/cosign
   verification, not the CLI; `ArbitraitorApi::inspect` accepts signature
   inputs and produces signature findings. Today the CLI pipeline does this
   (`crates/arbitraitor-cli/src/pipeline.rs:138, 347-370`) but
   `ArbitraitorApi` does not — they diverge.
9. **conventions.md updated.** The crate responsibility table and boundary
   rules include the engine crate; the security invariants list is reconciled
   with spec §9's full 24 invariants. Today conventions.md lists only 10
   invariants and omits the engine crate from the responsibility table.
