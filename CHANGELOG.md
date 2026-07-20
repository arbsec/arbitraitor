# Changelog

All notable changes to Arbitraitor are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

#### Receipt

- `arbitraitor-receipt::Receipt::to_sarif()` — converts findings to a
  SARIF 2.1.0 report per spec §31.4. Includes rule definitions with
  multi-taxonomy mappings (CWE, CAPEC, OWASP, ATT&CK) per SARIF §3.59.
  Results include artifact hashes in locations for findings inside
  extracted or decoded child artifacts. 12 new public types:
  SarifReport, SarifRun, SarifTool, SarifDriver, SarifRule,
  SarifTaxonomyEntry, SarifMessage, SarifResult, SarifLocation,
  SarifPhysicalLocation, SarifArtifactLocation, SarifRegion.

#### Sandbox

- `arbitraitor-sandbox::windows_adapters` — new public module with five
  Windows sandbox adapter stubs per spec §27.5: `WindowsSandboxAdapter`,
  `AppContainerAdapter`, `JobObjectsAdapter`, `WdacAdapter`,
  `HyperVAdapter`. All `is_available()` methods return `false` on
  non-Windows platforms. 4 tests verify unavailability on Linux.

#### Fetch

- `TlsVerifier::{PlatformVerifier, PinnedWebPki}` and
  `FetchPolicy::tls_verifier` add a policy-selectable TLS verifier type for
  spec §41.4.3. The default is `PlatformVerifier`; transport behavior is
  unchanged until pinned WebPKI enforcement is wired separately.
- `FetchMetadata::tls_cipher_suite` complements the existing TLS protocol
  version and peer leaf-certificate fingerprint metadata. Reqwest 0.13 only
  exposes the peer certificate publicly, so protocol and cipher-suite values
  remain absent when the backend cannot report them. Certificate validity is
  transport metadata, not publisher provenance.
- `FetchPolicy::proxy_url: Option<String>` — configurable proxy support per
  spec §11.2 and ADR-0018. When `None` (default), `.no_proxy()` is called
  to disable all proxy behavior. When `Some`, reqwest is configured with the
  given proxy URL.
- `FetchPolicy::first_byte_timeout: Option<Duration>` — distinct deadline
  for time-to-first-byte per spec §41.4.6. Sits alongside `connect_timeout`
  (TCP/TLS only) and `total_timeout` (whole-operation budget) so callers
  can cap slow-but-connected servers without shortening the global budget.
  Defaults to `None`, preserving existing fail-open semantics.
- `FetchCancellation` — new public type wrapping `Arc<AtomicBool>` for
  spec §41.4.6 cancellation tokens. Carries `new()`, `is_cancelled(&self)`,
  `cancel(&self)`, `Clone`, and `Default`. Clones share state, so any
  handle can signal cancellation that every other handle observes.
- `FetchRequest::cancellation: FetchCancellation` — new field attached by
  default to `FetchCancellation::new()`. New `with_cancellation(token)`
  builder lets callers wire a token they keep outside the fetcher so they
  can cancel an in-flight fetch from another thread without taking
  ownership of the request.
- `FetchPolicy::behind_proxy: bool` — records whether DNS resolution and
  target address selection are performed by the proxy. When `true`,
  .resolve_to_addrs is skipped so reqwest uses the proxy's DNS resolution,
  and receipt metadata records that connected-peer verification observes
  the proxy peer, not the actual target.

#### Antivirus

- `arbitraitor_av::SignatureFreshness` — new public struct for spec §18.3
  signature freshness snapshots. Carries `engine_version`, `signature_version`,
  parsed `last_update: Option<SystemTime>`, and `is_stale: bool` so callers can
  layer policy on top without parsing RFC 3339 themselves.
- `arbitraitor_av::AntivirusAdapter::check_freshness(&self, max_age: Duration)`
  — new trait method with a default implementation that reads the adapter's
  version fields and parses `last_update_time()` as RFC 3339, marking the
  signatures stale when the timestamp exceeds `max_age` or lies in the future.
- `arbitraitor_av::macos::{read_quarantine_xattr, read_spotlight_metadata}` —
  new module per spec §41.13 wrapping the stable macOS facilities `xattr(1)`
  and `mdfind(1)`. The helpers are `cfg(target_os = "macos")` gated and return
  `None` on any other host. `xattr` returns the trimmed
  `com.apple.quarantine` value when present; `mdfind` returns the first
  indexed path line. Endpoint Security is documented but not wrapped because
  it requires a signed system extension.
- `arbitraitor_av::AvDetector` — fail-closed integration of signature
  freshness. When `AvPolicy::required` is `true` and
  `max_signature_age_hours` is set, a stale snapshot emits a critical
  `av.signatures-stale` finding that blocks release per spec §18.3 rather
  than silently treating the scan as clean.

#### Plugin Host

- `arbitraitor_plugin_host::registry::{RegistryMetadata,
  REGISTRY_METADATA_SCHEMA_VERSION, SignatureStatus, ProvenanceStatus,
  SecurityAuditStatus, ConformanceStatus, RevocationStatus,
  RevocationEntry, StagedRollout, PermissionDiffStatus}` — new public
  types for spec §39.20 plugin registry signed metadata, publisher
  revocation, staged rollout, and permission-diff approval. `RegistryMetadata`
  is the document the registry loader evaluates to decide whether an
  update is admissible: signature status, provenance status, security
  audit status, conformance status, revocation status, known
  vulnerabilities, version history, supported platforms, requested
  permissions, and SHA-256 `download_digest` (pinning metadata to the
  artifact prevents metadata-swap attacks). The struct carries a
  `schema_version` field and uses `#[serde(deny_unknown_fields)]` so
  audit consumers reject smuggled fields. `RevocationEntry` records a
  publisher or operator revocation of a `(plugin_id, version)` pair
  with issuer, timestamp, and reason. `StagedRollout` carries the
  rollout percentage and target audience for a phased release.
  `PermissionDiffStatus` is the state machine (`Approved`, `Blocked`,
  `PendingApproval`) for operator review of permission changes between
  the currently installed release and the proposed update.

#### Sandbox

- `arbitraitor-sandbox::linux_adapters` — new public module with four
  Linux sandbox adapters per spec §27.3: `NamespaceAdapter` (user +
  mount + IPC + PID + network namespaces via `unshare`), `BubblewrapAdapter`
  (bwrap subprocess wrapper), `SystemdRunAdapter` (transient scope with
  PrivateNetwork/NoNewPrivileges), and `EBpfObservationAdapter` (stub,
  is_available returns false). 3 tests covering bwrap/systemd-run command
  construction.

#### Sandbox

- `arbitraitor_sandbox::observed::{ObservedEvent, ObservedEventLog,
  FileOperation, OBSERVED_EVENT_SCHEMA_VERSION}` — new public types for
  spec §27.6 dynamic-adapter event reporting. `ObservedEvent` is a
  `serde`-tagged enum covering all ten spec-mandated event classes
  (process tree, file read/write/delete, network connection, DNS
  request, privilege change, persistence creation, credential store
  access, child download with SHA-256, library load with SHA-256,
  attempted security-control modification). `ObservedEventLog` is an
  ordered, append-only log carrying a `schema_version` field and using
  `#[serde(deny_unknown_fields)]` so audit consumers reject smuggled
  fields. `FileOperation` is the read/write/delete label for file
  events, serialized as lowercase strings to stay stable across Rust
  version bumps.

#### YARA-X

- `arbitraitor_yarax::RulePackManager::compile_all_cached` — new method
  that caches compiled `Rules` keyed by a snapshot digest computed from
  all loaded rule pack namespaces, versions, and rule text (spec §17).
  If the packs haven't changed since the last compile, the cached `Rules`
  are returned without recompilation. Also adds `snapshot_digest()` method
  for receipt-recording and a `CompiledRulesCache` internal struct.

#### Update

- `arbitraitor_update::manifest::UpdateChannel::BinaryRelease` — new
  channel variant for binary releases per spec §34.3. Carries SHA-256
  digests, Sigstore bundles, SBOMs, and reproducible-build info.
- `arbitraitor_update::manifest::ReleaseProvenance` — new struct
  with optional SBOM path, optional Sigstore bundle path, and
  reproducible-build flag. Attached to `UpdateTarget` on the
  `BinaryRelease` channel.

#### Provenance

- TOFU pins now record and compare the final redirect destination and
  certificate identity, reporting field-level drift for either value per
  spec §14.4.
- `SignatureSystem` now enumerates the spec §14.2 platform-native signing
  families: `OpenPGP` (planned via Sequoia per §41.12.4), `Authenticode`,
  `AppleCodeSign`, and `LinuxPackage`. Each new variant carries a stable
  lower-case `as_str()` label (`openpgp`, `authenticode`, `apple_code_sign`,
  `linux_package`) for receipts and diagnostics; verification logic for
  these families is tracked in follow-up issues.

#### Exec

- `arbitraitor-exec::native::PlatformProvenance` — new struct recording
  which platform-native provenance attributes were applied during release
  per spec §26.4 and ADR-0010. On Linux this is xattr; on macOS it's
  `com.apple.quarantine`; on Windows it's Mark of the Web (Zone.Identifier).
  macOS quarantine function is conditional on `target_os = "macos"`.
  Windows MOTW function is conditional on `target_os = "windows"`.
  Constants are dead-code-allowed on non-matching platforms.

#### Intel

- `arbitraitor-intel::FeedAdapter` now exposes the spec §21.5 `name`,
  `fetch_indicators`, and `source_class` surface. Offline stubs are available
  for ThreatFox, OpenSSF malicious packages, and OSV with CISA KEV; the new
  `AllowDenyListAdapter` reads non-empty, non-comment indicator lines from a
  local file without network access.
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
- `arbitraitor-intel::duplicate_collapse` — new function that merges feed
  entries describing the same indicator (spec §22 anti-abuse control).
  Two entries are duplicates when their `Indicator` (type and value)
  matches; collapse preserves the earliest `first_seen`, the latest
  `last_seen`, the highest `Confidence`, the latest non-`None`
  `expires_at`, the union of `FeedSource` records (de-duplicated by
  `source_type` + `reference`), and the first non-`None` `malware_family`
  and `notes` in evidence. Order of the output matches the order of
  first appearance in the input.
- `arbitraitor-intel::SignedModerationAction` and
  `arbitraitor_intel::ModerationAction` — new types for moderator-driven
  add/remove/revoke actions over the feed, with a detached
  `FeedSignature` binding the action to the moderator and timestamp
  (spec §22 signed moderation actions).
- `arbitraitor-intel::RevocationEntry` — new public record of an
  indicator revoked from the feed, paired with a `FeedSignature` so the
  public revocation history is tamper-evident (spec §22 revocation
  history).
- `arbitraitor-intel::FeedEntry::source_update_time` — new optional
  RFC 3339 timestamp recording when the originating feed last updated the
  indicator (spec §21.6 freshness). Distinct from `last_seen`, which tracks
  when Arbitraitor last observed the indicator.
- `arbitraitor-intel::FeedEntry::is_expired` — new helper that returns
  `true` when the entry has an `expires_at` strictly before the supplied
  RFC 3339 `now` (spec §21.6 freshness). Replaces `is_expired_at` so the
  strict-less-than semantic matches the spec and the existing
  `IntelStore::purge_expired` / `match_indicator` filters stay consistent.

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

- Python + JavaScript script detector (`arbitraitor_analysis::pyjs::PythonJsDetector`, spec §16.3, #506) — narrow initial coverage for the two dominant scripting ecosystems in untrusted artifact payloads. The detector scans `PythonScript` and `JavaScript` artifact kinds for risky construction patterns (subprocess/shell invocation, eval/exec, arbitrary deserialization, dynamic / native module loading, credential / environment exfiltration, persistence writes, obfuscated / encoded payloads) and emits one finding per match with category, severity, evidence snippet, and a stable tag. Pattern matching uses simple substring scans to keep the crate dependency-free; a future revision may swap in a tokenizer / AST walker once the stub proves out coverage.
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

#### Documentation

- ADR-0022 now references the final SLSA v1.2 Build Provenance URL and
  documents Source Track consumption, including how verified Source L2+
  evidence strengthens Build L1 provenance without raising the Build level
  (#461).

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
