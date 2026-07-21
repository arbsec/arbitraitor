# Changelog

All notable changes to Arbitraitor are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

#### Documentation

- `book/src/cli/wrappers.md` — full rewrite. Previous page documented a
  fictional CLI (claims shims install to `~/.local/bin` with `--path`,
  `--wrappers`, `--mode` flags that do not exist, omits the `init` and
  `init-script` subcommands). New page matches the actual
  implementations in `arbitraitor-cli/src/main.rs` and
  `arbitraitor-wrapper/src/shim.rs`: documents all five `wrappers`
  subcommands (`install`, `uninstall`, `status`, `init`, `init-script`),
  the `--shim-dir` / `--use-scripts` parent flags, every `init` flag
  (`--install`, `--uninstall`, `--detect-shell`, `--dry-run`,
  `--no-backup`), all 11 supported shells (bash, zsh, sh, fish, nu,
  xonsh, powershell, elvish, posix, tcsh, oil), the marker-block
  idempotency pattern, the default-distro `~/.local/bin` PATH matrix, the
  `arbitraitor env` hidden alias, the deprecated `hook init` migration
  path, and the per-verdict output behaviour table. Verified against
  commit `7cb6906`.
- `book/src/getting-started/wrappers.md` — expanded shell-integration
  section. Adds the two-step install pattern (`wrappers install` then
  `wrappers init --install`), lists all 11 supported shells (previously
  missing `oil`), documents the `# >>> arbitraitor wrappers >>>` marker
  convention, explains the `--shim-dir ~/.local/bin` override, and adds
  the Debian/Ubuntu/Fedora `~/.local/bin` default-PATH matrix (with the
  Arch/RHEL/NixOS/Alpine caveat).
- `book/src/cli-reference.md` — `Wrappers command` section now documents
  `init`, `init-script`, `--shim-dir`, `--use-scripts`, and the full
  `init` flag set. `Hook command` section marked deprecated with the
  `wrappers init --install` replacement path. Command overview table
  updated: `wrappers` row now reflects "Install curl/wget shims + render
  shell-integration snippet"; `hook` row marked "Deprecated bash DEBUG
  trap (prefer `wrappers init --install`)".
- `README.md` — "Use wrappers" section now shows the two-step install
  pattern (`wrappers install` + `wrappers init --install`) instead of
  only `wrappers install`. "Shell integration hooks" section renamed to
  "Shell integration" and now documents `wrappers init` /
  `wrappers init --install` with the deprecated `hook init` clearly
  marked.

#### Documentation corrections from adversarial review (PR #613)

- Removed false safety claim that the shim directory is created with
  `0o700` (actual: standard `create_dir_all` with process umask).
- Removed false safety claim that foreign files are never overwritten
  (actual: `wrappers install` removes and replaces any file at the shim
  path; `foreign file` in `wrappers status` is an informational hint,
  not a protection). Added explicit warning that `--shim-dir ~/.local/bin`
  and other shared paths may clobber existing files and should be audited
  first.
- Removed false claim that "any script requiring approval still pauses
  for human input". Actual: wrappers are a strict download gate;
  `Prompt`/`Warn`/`Block`/`Error`/`Incomplete` verdicts all exit
  non-zero with no stdout. Use `arbitraitor run` for interactive approval.
- Corrected the supported-shells list in `README.md` from `nushell` to
  `nu (Nushell)` and added the missing `xonsh` entry, matching
  `arbitraitor_wrapper::init::Shell::ALL` in source.
- Documented that `init-script` is a hidden legacy command, not equivalent
  to `wrappers init` (it prints a generic POSIX snippet with no per-shell
  auto-detection or runtime idempotency).
- Documented that the `arbitraitor env` hidden alias lacks the
  `--shim-dir` and `--use-scripts` parent flags (always uses
  `default_shim_dir()`); use the `wrappers init` form to override the
  directory.
- Added the `fish` / `nu` / `powershell` exception to the marker-block
  idempotency claim — these shells use a dedicated file, not a marked
  block in an existing rcfile.
- Removed fictional `arbitraitor wrap curl -- URL` references (no `wrap`
  command exists).
- Clarified the backup-file naming behaviour: `Path::with_extension`
  appends `.arbitraitor.bak` for files without an extension but
  *replaces* the extension for files with one (e.g. PowerShell
  `profile.ps1` → `profile.arbitraitor.bak`).
- Tightened `wrappers status` state labels: `installed (symlink)` now
  notes target is not validated; `foreign file` now warns the file will
  be overwritten on next `wrappers install`.
- Added the required Unstable stability block to
  `book/src/getting-started/wrappers.md` per `docs/doc-ownership.md`.

### Added

#### Archive

- `FindingCategory::ParserDifferential` and archive `ParserSmelting` hazard
  coverage for spec §19.1/§19.3 parser consensus failures (CWE-436).

#### Intel

- `ossf-malicious-packages` feed adapter for OpenSSF malicious-packages
  `MAL-` IDs returned by OSV.dev `querybatch` responses. Adds typed
  `OsvMalId`, `IndicatorType::OsvMal`, and
  `FeedSourceClass::OssfMaliciousPackages` so malicious npm packages can be
  ingested into the signed local intel store without raw string IDs.

#### Exec

- `ExecError::script_io(stage, source, child_exit_code, child_stderr)`
  — new public constructor for `ExecError::ScriptIo` that pre-renders a
  stable, bounded (≤1 KiB) `child_detail` suffix from the captured child
  state. The `ScriptIo` variant now carries `child_exit_code:
  Option<i32>`, `child_stderr: Vec<u8>`, and `child_detail: String` fields
  so callers see the actual root cause (e.g. `bash: !DOCTYPE: event not
  found`, `unshare: operation not permitted`) when the interpreter exits
  before consuming the streamed script bytes. Fixes the diagnostic-loss
  half of #612: when bash or `unshare` exits early, the user-visible
  error now distinguishes "I fed bash junk" from "kernel denied the user
  namespace" from "Landlock blocked the interpreter path".
- `ExecError::script_io_detail(child_exit_code, child_stderr)` — shared
  public helper that renders the `child_detail` suffix. `PowerShellError::
  ScriptIo` mirrors the new fields and reuses this helper so PowerShell
  execution gets the same diagnostic improvement when wired.
- `spawn::best_effort_capture(child, limit)` — internal drain helper that
  captures a child's exit code and piped stdout/stderr after a prior
  operation (typically `write_all` to the child's stdin) has already
  failed. Swallows secondary `read_with_limit` errors so the original
  I/O error remains the primary signal.

#### MCP

- `RunApprovedArtifactError::NotExecutable { artifact_type }` — new
  variant produced by `RunApprovedArtifactTool::run` when an
  approved-but-non-shell-script artifact's bytes are about to be piped to
  `/bin/bash`. Closes Blocker 4 from the adversarial review of #615: an
  agent can no longer approve an HTML / JSON / XML / archive / Unknown
  artifact via `request_approval` and execute it via
  `run_approved_artifact` — only `ArtifactType::ShellScript(_)` is
  runnable through the MCP approved-execution path. CLI `run` and MCP
  `run_approved_artifact` now enforce the same content-type gate
  (ADR-0036, issue #612).

#### CLI

- `arbitraitor wrap <tool> -- ...` — first-class spec §28.1 wrapper
  command. `curl` and `wget` delegate to the guarded wrapper-fetch
  pipeline, `bash` inspects a local script path without executing it, and
  unimplemented tools warn without releasing content.
- `arbitraitor execute` (the approved-artifact execution command,
  separate from `arbitraitor run`) now gates execution by classified
  `ArtifactType` before piping bytes to `/bin/bash`. Round 2 of the
  adversarial review of #615 found that the round-1 fix only gated the
  `run` and MCP `run_approved_artifact` paths; the `execute` command
  (invoked as `arbitraitor execute <APPROVAL>`) accepted the
  same bash-execution approval file and piped artifact bytes without
  classifying them. The gate mirrors the round-1 fix: only
  `ArtifactType::ShellScript(_)` is permitted; everything else
  (HTML / JSON / XML / archives / `GenericText/Binary` /
  `PowerShellScript` / `PythonScript` / `JavaScript` / `Unknown`) fails
  closed with `miette::bail!("... is not executable via the approved
  execute path; only shell scripts are runnable (ADR-0036, issue #612)")`.
  Native executables are gated out as well because the approval flow
  always binds to the bash interpreter (native execution uses a separate
  release path).

### Changed

#### CLI

- `arbitraitor run` now gates execution by classified `ArtifactType`.
  Only `ShellScript(_)` (`Posix` / `Bash` / `Zsh`) and native executable
  types (`PeExecutable`, `ElfExecutable`, `MachOExecutable`) reach
  `ExecutionMode::Script` / `ExecutionMode::Native`. Every other type —
  `HtmlDocument`, `JsonDocument`, `XmlDocument`, `GenericText`,
  `GenericBinary`, archives (`ZipArchive`, `TarArchive`,
  `*Compressed`), `PowerShellScript`, `PythonScript`, `JavaScript`, and
  `Unknown` — fails closed with `RunFailure::Blocked` (exit code
  `BlockedByPolicy`) before reaching the execution layer. Piping those
  bytes to `/bin/bash` was incorrect (bash doesn't understand them) and
  unsafe (HTML/JSON/XML can incidentally contain bash-parseable
  `$(...)`, redirections, and pipes). Fixes the content-type-gate half
  of #612. See ADR-0036 for the rationale.
- `InspectedArtifact` (private to `arbitraitor-cli/src/run/`) now carries
  `ArtifactType` directly rather than its stringified `{:?}` form, and the
  `is_native: bool` field is dropped in favor of deriving native vs.
  script from `artifact_type` via `execution_mode_for_type`. Receipt
  serialization is unchanged (`format!("{:?}", artifact_type)` is passed
  to `ReceiptBuilder::artifact_type` on demand).

### Fixed

#### Exec

- `ExecError::script_io_detail` is now panic-safe when the captured child
  stderr is attacker-controlled UTF-8 longer than 1 KiB. The previous
  byte-index slice `&str[..1024]` panicked if byte 1024 fell inside a
  multibyte codepoint; the fix truncates the BYTES first, then
  lossy-decodes via `String::from_utf8_lossy`, which replaces any partial
  trailing codepoint with U+FFFD. Found by 3 of the 5 adversarial
  reviewers of #615 (Blocker 1, MEDIUM severity).
- `ExecError::script_io_detail` now escapes Arbitraitor untrusted-data
  markers (`<<ARBITRAITOR_UNTRUSTED_DATA_START>>` /
  `<<ARBITRAITOR_UNTRUSTED_DATA_END>>`) inside the captured child
  stderr, satisfying the Safe Presentation invariant (ADR-0016) that
  untrusted text must be escaped and bounded before display. The
  `{:?}` debug-format at the call site already neutralizes ANSI control
  sequences; the marker escape additionally prevents prompt-injection
  in downstream agent consumers that rely on the markers to fence
  untrusted content. Found by 2 of the 5 adversarial reviewers of #615
  (Blocker 2, MEDIUM severity).
- `ScriptExecution::execute` and `PowerShellExecution::execute` now
  `drop(stdin)` before calling `best_effort_capture` on the write/flush
  failure path. Without this, if the child was still alive (write failed
  due to EPIPE on one write, not because the child exited), the child
  could be blocked on stdin read while the parent was blocked on
  stdout/stderr drain, causing an indefinite deadlock. Found by 2 of 3
  fresh adversarial review lanes (round 3, MAJOR severity).
- The content-type gate in `arbitraitor run`, `arbitraitor execute`, and
  MCP `run_approved_artifact` now restricts to `ShellScript(Posix | Bash)`
  instead of `ShellScript(_)`. `ShellScript(Zsh)` is now blocked because
  `/bin/bash` cannot safely interpret zsh syntax — the same wrong-
  interpreter class that ADR-0036 rejects for Python/PowerShell/JS.
  Found by the fresh adversarial code-quality review (round 3, MAJOR
  severity).
- `arbitraitor execute` now re-verifies the SHA-256 of the loaded CAS
  bytes against the approved digest before classification and execution.
  Closes a TOCTOU gap where a same-UID local attacker could mutate the
  CAS object between ContentStore verification and read_to_end.
  Found by the fresh adversarial security review (round 3, LOW severity).
- MCP `error_response` now sanitizes error messages via
  `sanitize_for_agent` before including them in JSON-RPC responses.
  Attacker-controlled child stderr was reaching the `"error"` field
  without untrusted-data fencing, a Safe Presentation (ADR-0016) gap.
  Found by the fresh adversarial security review (round 3, MEDIUM).
- `ExecError::script_io_detail` message for the `(None, non_empty_stderr)`
  case changed from "child exited before reading stdin" to "child
  produced stderr without an exit code" — the `None` exit-code also
  covers signal termination and wait failure, not just early exit.

### Added

#### Receipt

- `arbitraitor_model::vex` now models the VEX format matrix for receipt
  companion artifacts: OpenVEX 0.2.0 parsing with the current product and
  vulnerability structs, rejection of OpenVEX 0.0.x/0.1.x contexts, CSAF 2.0
  and CSAF 2.1 VEX profile parsing, CSAF 2.1 CVSS v4 vector strings, CSAF
  involvement statements, typed parser errors, and explicit
  `VexFormatVersion` labels.
- `arbitraitor_model::vex::VexLimits` bounds untrusted OpenVEX and CSAF VEX
  parsing by raw bytes, modeled collection counts, map entries, and string
  lengths. VEX hash maps now parse SHA-256 entries into `Sha256Digest`, CSAF
  VEX category matching is exact, timestamps require RFC 3339 timezone text,
  and parser error display avoids echoing attacker-controlled document fields.
- `arbitraitor-receipt::Receipt::to_sarif()` — converts findings to a
  SARIF 2.1.0 report per spec §31.4. Includes rule definitions with
  multi-taxonomy mappings (CWE, CAPEC, OWASP, ATT&CK) per SARIF §3.59.
  Results include artifact hashes in locations for findings inside
  extracted or decoded child artifacts. 12 new public types:
  SarifReport, SarifRun, SarifTool, SarifDriver, SarifRule,
  SarifTaxonomyEntry, SarifMessage, SarifResult, SarifLocation,
  SarifPhysicalLocation, SarifArtifactLocation, SarifRegion.

#### Sandbox

- `arbitraitor_sandbox::LandlockAbiVersion` and
  `probe_landlock_abi_version()` record the running Linux kernel's Landlock ABI
  via `LANDLOCK_CREATE_RULESET_VERSION`, exposing the observed ABI in
  contained-execution receipt controls without changing enforcement policy.
- `arbitraitor-sandbox::windows_adapters` — new public module with five
  Windows sandbox adapter stubs per spec §27.5: `WindowsSandboxAdapter`,
  `AppContainerAdapter`, `JobObjectsAdapter`, `WdacAdapter`,
  `HyperVAdapter`. All `is_available()` methods return `false` on
  non-Windows platforms. 4 tests verify unavailability on Linux.

#### Fetch

- `RedirectCredentialSecrecy` records whether a credential-bearing redirect
  remained secret or would have leaked a bearer token, cookie, or default
  `.netrc` token across a non-HTTP protocol boundary. Fetch now fails closed
  before following `http(s)` redirects into IMAP, LDAP, POP3, SMTP, FTP, file,
  gopher, or SMB destinations when Authorization, Cookie, or caller-declared
  netrc credentials are configured; receipts expose the outcome in retrieval
  metadata.
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

#### Documentation

- [ADR 0034](docs/adr/0034-apple-containerization-ga-strategy.md) —
  Apple Containerization GA strategy for macOS 26+. Documents the
  Containerization framework (open-sourced at WWDC 2025-06-09) as the
  preferred `contained` assurance path on macOS 26+ Apple silicon, with
  per-container lightweight VMs, isolated IP, EXT4 block devices, and
  sub-second cold starts. The Endpoint Security framework remains the
  observation-only path on macOS 13–15, Intel macOS, and any host where
  the `container` CLI is unavailable. Supersedes the GA-replacement
  deferral in [ADR 0024](docs/adr/0024-macos-containment-strategy.md);
  ADR 0024 stays Accepted for the macOS 13–15 / Intel surface until the
  ContainerizationAdapter lands.

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

#### Documentation

- ADR-0030 (`docs/adr/0030-sbom-vex-ingestion-profiles.md`) accepted:
  SBOM/VEX ingestion profiles aligned with the CISA August 2025 *SBOM
  Minimum Elements* update (Component Hash, License, Tool Name,
  Generation Context additions; Software Producer and Coverage renames)
  and the May 2026 CISA+G7 *SBOM for AI: Minimum Elements* guidance
  (System-Level Properties, Data Properties, Model Properties,
  Infrastructure, Security Properties clusters). CycloneDX 1.6+ profile
  supports the CDXA ML/AI and CBOM cryptography extensions; SPDX 2.2.1
  profile uses a per-field mapping to the CISA 2025 minimum elements
  (SPDX Lite is rejected); OpenVEX 0.2.0 is accepted alongside the SBOM
  and indexed by PURL (semantics deferred to ADR-0029); CSAF 2.1
  (ISO/IEC 20153, May 2025) carries signed VEX and security advisory
  content. Decision: Arbitraitor ingests but does not generate SBOM/VEX
  artifacts. EU CRA Annex I Part II mandate effective 11 December 2027
  is informational; CycloneDX and SPDX profiles consume CRA-shaped
  documents unmodified. New user-facing book page
  `book/src/architecture/sbom-and-vex.md` lists the per-format field
  mapping and the AI-cluster ingestion envelope.

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

- `arbitraitor fetch` promoted from hidden wrapper alias to first-class
  subcommand per spec §28.2. Removed `#[command(hide = true)]` and
  `disable_help_flag`; added the full spec-defined flag surface:
  `-o/--output`, `--sha256`, `--signature`, `--cosign-bundle`, `--identity`,
  `--issuer`, `--expected-type`, `--expected-content-type`, `--max-bytes`,
  `--header`, `--policy`, `--recursive`, `--sandbox`, `--non-interactive`,
  `--json`, `--sarif`, `--receipt`, `--no-cache`. Wrapper symlink invocations
  (`curl`/`wget`) continue to work via `--tool` and passthrough args (#477).
- ADR-0030 (SBOM/VEX ingestion profiles) factual corrections from Oracle
  adversarial review: corrected the SBOM-for-AI cluster count from 5 to 7
  (Metadata, System Level Properties, Models, Dataset Properties,
  Infrastructure, Security Properties, KPI) per the G7/CISA source;
  corrected OpenVEX 0.2.0 status mapping to the four spec-defined values
  (`not_affected`, `affected`, `fixed`, `under_investigation`) and marked
  `tooling` as optional with `author`/`version` required; corrected SPDX
  ISO year from `5962:2024` to `5962:2021` with a resolvable ISO
  catalogue URL; corrected CSAF standard status (2.0 = ISO/IEC 20153:2025,
  2.1 = OASIS CSD02 Feb 2026, not yet ISO); corrected SPDX/CycloneDX
  field mappings (SPDX annotations only have `REVIEW`/`OTHER`; CycloneDX
  generation context lives in `metadata.lifecycles[].phase`); replaced
  dead CISA URLs with canonical routes and marked the CISA 2025 SBOM
  page as a public-comment draft; fixed broken book link from
  `book/src/architecture/security.md` (`../sbom-and-vex.md` →
  `./sbom-and-vex.md`); bumped ADR count from 27 to 28 in `AGENTS.md`
  and `README.md`.
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

- Tar archive inspection now checks for parser-smelting PAX `size=` desync
  patterns and records `parser_differential` findings that refuse release;
  `arbitraitor doctor` verifies the locked `tar` crate is at the patched
  0.4.46 floor for GHSA-3pv8-6f4r-ffg2 (#459).
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
