# Changelog

All notable changes to Arbitraitor are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- `arbitraitor-engine` crate (ADR-0038, accepted): the single consolidated
  pipeline engine owning fetch → store → analyze → provenance → receipt →
  verdict → release. Public surface: `Arbitraitor`, `ArbitraitorBuilder`,
  `ArbitraitorApi`, `Config`, `InspectionResult`, `InspectionResultReceipt`
  (engine-owned receipt wrapper, decision 6), and a typed `EngineError`. The
  engine drives the `arbitraitor-core` `PipelineOperation` state machine
  through every inspection (retrieval → storage → identification → analysis
  → expansion → evaluation → verdict) and through
  approval → release → completion on the release path (#747).
- `arbitraitor-engine::FAIL_CLOSED_POLICY_TOML`: the fail-closed policy for
  non-interactive surfaces, exported so the daemon and embedders configure
  identical unattended behavior.
- `arbitraitor-engine::scan_path`: bounded, symlink-rejecting local-file
  scan through the full pipeline (moved from the MCP tool's private
  implementation).
- `arbitraitor-engine::ArbitraitorApi::receipt_summary`: read-only lookup
  of the persisted receipt for a digest. The daemon's `QueryReceipt`
  socket endpoint and any future reader go through this accessor; the
  audit trail is never rewritten by a query.
- `arbitraitor-engine::Config::store_max_bytes`: engine-wide bound on
  bytes accepted into CAS, plumbed to `sink_with_limits` on every
  engine-managed write (inspect, fetch, scan, child-artifact expansion).
  The CLI passes `store.max_bytes` through directly; the daemon and MCP
  keep the engine default of `arbitraitor_store::DEFAULT_MAX_BYTES`
  (1 GiB).
- `arbitraitor_store::DEFAULT_MAX_BYTES` and
  `arbitraitor_store::ContentStore::store_with_metadata_and_limits`: the
  storage crate's default 1 GiB bound is now exported as a public
  constant, and a variant of `store_with_metadata` accepts an explicit
  per-call byte bound so engine consumers can enforce a tighter
  configured limit without a post-write check.
- `arbitraitor-mcp::TransportUnavailablePrompt`: a fail-closed
  `ApprovalPrompt` used by the default stdio MCP server so
  `request_approval` cannot block the JSON-RPC channel trying to read an
  interactive confirmation from stdin.
- The MCP default server now registers all seven tool handlers:
  `request_approval` and `run_approved_artifact` were implemented but never
  registered (ADR-0038 decision 3). Approved execution reads artifact
  bytes from the engine's CAS.
- Headless (non-interactive) plan-bound approval for MCP embedders (#746,
  ADR-0013): `arbitraitor-mcp` gains `HeadlessApprovalPrompt`, a
  `PendingApprovalStore` (one JSON record per canonical plan digest in an
  embedder-chosen directory, conventional default
  `~/.arbitraitor/pending-approvals/`, records `0600` under a `0700`
  directory on Unix), and a trusted-resolution API
  (`PendingApprovalStore::{list_pending, resolve, prune_expired}`). Every
  `request_approval` call persists a time-limited pending record (default
  1-hour TTL) and fails closed; a retry of the same request mints a
  plan-bound token only after a trusted resolver approves the exact
  canonical plan digest, consuming the approval exactly once. Resolution is
  a Rust-only API and is never exposed as an MCP tool, preserving the
  ADR-0013 agent capability separation (H-11) on the headless path. Issued
  tokens record the channel via a new `approval_method` /
  `human_approver_identity` attestation plumbed through the
  `ApprovalPrompt::request_confirmation_attested` defaulted trait method;
  `StdinApprovalPrompt` remains the interactive default and is audit-
  identical to before (`stdin-human-confirmation`). Records are MAC'd
  (HMAC-SHA-256) with an embedder-supplied key; tampered, forged, or
key-less records fail closed. Cross-process consumption is claimed
atomically via an exclusive `.consumed` marker (one approval = one grant
per consumption cycle; the marker is cleared when the next request for
the same digest opens a fresh cycle), with exactly-once holding while
the store directory is not writable by agent-side processes. The store
caps pending record files at
`MAX_PENDING_RECORDS` (1000, freed by
  `PendingApprovalStore::prune_expired`), and `PendingApprovalStore::open`
  refuses group/world-writable store directories on Unix.
- `xtask cleanup` (repo maintenance, `cargo run -p xtask -- cleanup`):
  the `worktrees` phase removes secondary worktrees whose branch maps to
  a merged or closed PR (tracked via `gh`) and deletes those branches; a
  PR is only followed when its
  recorded head SHA matches the branch tip (`headRefOid` vs
  `git rev-parse HEAD`), so a recycled branch name can never delete
  unrelated work. The phase refuses dirty, locked, bare, detached,
  open-PR, name-mismatch, and PR-less trees so in-flight work is never
  touched; stale worktree entries are pruned when `--yes` is passed. The
  `artifacts` phase removes `target/` build directories
  (main checkout plus every unlocked worktree) older than `--days`
  (default 7) and reports reclaimed bytes. Both phases dry-run by
  default; `--yes` applies.
- `xtask mint-github-token` (`cargo run -p xtask -- mint-github-token`):
  contributor/agent tooling that mints a ~1h `arbsec-agent` GitHub App
  installation token so agent-driven GitHub operations attribute to the
  service identity instead of a personal account (see AGENTS.md). The
  token — and only the token — is printed to stdout for
  `GH_TOKEN="$(...)" gh ...`; the App private key is resolved fail-closed
  from `$ARBSEC_APP_PEM`/`$ORCHESTRAITOR_APP_PEM` or the platform keyring,
  secret material never reaches argv, stderr, or files inside the repo,
  and the keyring being unreachable is an error (no fallback). The
  documented commit shape for agent work satisfies `required_signatures`
  without an admin bypass: author = `arbsec-agent[bot]` (via `--author`) +
  DCO `Signed-off-by:`, committer = the ambient local git identity of the
  operator (the identity whose registered SSH signing key GitHub verifies;
  `user.name`/`user.email` stay the operator's — never `-c` them to the
  bot); setting the committer to the bot fails as `UNKNOWN_KEY` (no
  bot-owned signing key).

### Changed

- **CLI, MCP, and daemon now route through `arbitraitor-engine`**
  (ADR-0038): the three divergent pipeline compositions are unified, which
  closes silent coverage holes and changes observable behavior on every
  surface:
  - **CLI `inspect`/`fetch`/`wrap`** now evaluate the configured policy
    (previously skipped entirely). With no policy file and no inline rules
    configured, the built-in verdict derivation applies, preserving the
    default pass-through behavior. CLI inspections now persist a receipt to
    the default receipts directory even without `--receipt`, and record
    store metadata (source URL, content type) for inspected artifacts.
  - **MCP `inspect_url`/`fetch_artifact`/`scan_artifact`** now store fetched
    artifacts in the CAS and persist receipts (previously neither
    happened; `fetch_artifact`'s documented "record its CAS identity" is
    finally true). `fetch_artifact` responses now always include the
    effective final URL instead of `null` when no redirect occurred.
  - **Daemon socket `Inspect`/`Scan`/`QueryReceipt`** now apply the
    daemon's fail-closed policy (an unmatched artifact verdicts `Block`
    instead of the analysis verdict), persist receipts, and bound
    local-file reads (previously unbounded). The daemon's provenance stage
    runs through the engine with an empty default input set (`DaemonOptions`
    exposes no signature inputs), so signature verifications are recorded
    on the receipt only when an embedder supplies inputs; the stage exists
    structurally but produces no minisign/cosign checks in daemon default
    configuration. `QueryReceipt` now
    returns the artifact's actual verdict and finding count instead of the
    existence-only `stored` marker, and is a strict read: it never
    re-runs analysis or rewrites the persisted receipt.
    `Daemon::new`/`with_options` return
    `Result` because the engine opens the CAS eagerly.
  - **`ArbitraitorApi` release gate is now the state machine**: release
    after an `Incomplete` verdict (detector failure) is rejected — the
    previous check only rejected `Block` and `Error` (fail-closed per
    spec §18.3).
  - **Configured `default_action = "prompt"` policies upgrade to `Block`
    on non-interactive surfaces**: the engine evaluates policy with
    `EvalContext::new(false)`, so any unmatched prompt verdict becomes
    `Block` on the daemon, the MCP default stdio server, and the CLI when
    run unattended. Interactive TTY embedders that explicitly want a
    prompt verdict register their own approval channel via
    `RequestApprovalTool::with_prompt`.
  - Receipts are unified on the richer CLI shape (transport metadata,
    signature findings, rule pack versions, detector provenance) and the
    canonical `unix:<secs>.<nanos>Z` timestamp; `query_receipts` parses both
    timestamp forms.
  - `arbitraitor-daemon::api` re-exports the engine surface
    (`ApiError` → `EngineError`); the daemon crate retains only socket I/O,
    the operation queue, capability-token recording, and rate-limiting.
  - `arbitraitor-daemon`'s `Config::default` directories moved with the
    engine to the user cache root (`$XDG_CACHE_HOME/arbitraitor`), no longer
    the working-directory-relative `.arbitraitor`.
- **Spec/tech-stack naming sweep**: the §40 and §3/§3.5 bodies now refer
  to the engine crate as `arbitraitor-engine` everywhere, and the
  "deferred to a focused ADR (proposed ADR-0037)" constructs are replaced
  by "ADR-0038 (accepted)" references. The pre-existing ADR-0037 number is
  the Wasmtime CVE risk register; carrying it in spec §40 was a stale
  cross-reference.

### Fixed

- **url-discovery: template URLs inside a downloaded data document no longer
  reject the caller's static-URL fetch** (#751) — fetching a static, literal
  URL whose response is a data document full of template-shaped URI examples
  (e.g. `curl -o x.json https://docs.renovatebot.com/renovate-schema.json`)
  deterministically failed with `verdict: Warn` and 4×
  `url-discovery.dynamic-url-expression` Medium findings: the detector
  attributed URL-shaped strings found *inside* the downloaded artifact to the
  fetch being wrapped, and the built-in verdict ladder warned on any
  non-Informational finding, so the transfer was hard-rejected (exit 10) and
  the consumer never received the bytes. Two coordinated changes:
  - **Detector severity is scoped by how the artifact is consumed.** On
    executable sources (Python, JavaScript — newly added to
    `UrlDiscoveryDetector`'s supported kinds) a resolved template URL is a
    live second-stage fetch the script will perform, so the finding stays a
    Medium `SuspiciousScriptBehavior` hazard. On data documents (HTML, JSON,
    XML) the URL is inert content of the already-downloaded artifact: the
    finding is now Informational `NetworkBehavior` — still recorded on the
    receipt (mandatory coverage for HTML/JSON is unchanged), but no longer
    gating the fetch of the document itself. `curl URL | bash`-style
    download-to-execute hazards are unaffected: they fire via the AST-based
    shell detector (`download-pipe-execute`, Critical), not via
    url-discovery.
  - **Informational findings are pass-equivalent in the built-in verdict
    ladder** (`AnalysisCoordinator::derive_verdict` and the CLI's
    `verdict_from_findings`), matching the documented severity→action table
    (Medium→Warn). The configured-policy path is untouched: repos that want
    Informational findings to block can express that with a policy rule.
  Regression tests reproduce the #751 scenario (JSON schema fixture with 4
  template URI examples → `Verdict::Pass`, all 4 findings recorded) and the
  negative case (Python/JavaScript script with a dynamic URL construction →
  Medium finding, `Verdict::Warn`). The inspect guide's severity→action
  table now also documents the pre-existing built-in behavior for Low
  (Warn — previously the table claimed Pass, contradicting the shipped
  derivation; no Low-severity producer exists in the default detector set,
  so observed behavior is unchanged) and adds the Informational row.
- **Mediated script execution works again on Landlock-active hosts: the
  network wrapper's user-namespace identity writes are granted
  (`arbitraitor-exec`)** (#754) — `ScriptExecution::bash` (and any mediated
  script run with network isolation enabled, the default) wraps the
  interpreter in `unshare --user --map-current-user --net`, which writes
  `/proc/self/uid_map`, `/proc/self/setgroups`, and `/proc/self/gid_map`
  before exec'ing the interpreter. `landlock_rules_for_script_execution`
  granted no `/proc` access, so on every host where the Landlock LSM is
  active the wrapper died with `unshare: cannot open /proc/self/uid_map:
  Permission denied` and mediated script execution failed exactly where the
  isolation layer was strongest. The mediated ruleset now adds three
  per-file, write-only (`LANDLOCK_ACCESS_FS_WRITE_FILE`) rules for exactly
  those three procfs files, and only for wrapper runs — non-wrapped
  mediated execution receives no `/proc` grants. The grant is not
  leverageable:
  per-file `O_PATH` handles (no directory traversal), write-only (no
  read-back), kernel-validated content (an unprivileged writer can only map
  its own UID/GID to itself; elevating mappings and second writes fail with
  `EPERM`), and `/proc/self/*` resolves to the writing process's own
  namespace files.
- **The effective-controls matrix is derived from the same Landlock probe
  the enforcement hook acts on (`arbitraitor-sandbox`)** (#754) —
  `compute_effective_controls` probed the kernel ABI independently while
  `configure_filesystem_isolation` made its own install/no-op decision, so
  the reported matrix and actual enforcement could diverge. Both now share
  one captured verdict: `capture_landlock_install_plan` records the probe
  (`LandlockProbe::Supported(abi)` / `LandlockProbe::No`) at command
  configuration time, the `pre_exec` hook enforces exactly that verdict
  (`install_landlock_ruleset_plan` reports
  `LandlockInstallOutcome::{Enforced, NoKernelSupport}` — observable
  in-process and in tests; the forked-child hook itself discards it), and
  `compute_effective_controls` maps `Supported` → `Available` / `No` →
  `Unavailable`. The #755 fail-closed behavior is unchanged — a host without
  a Landlock ABI still reports `filesystem_isolation: Unavailable` — but
  the reporting and the hook can no longer disagree.
- **Long-lived MCP server and daemon no longer hold an exclusive lock on the
  CAS metadata store** (#762) — three coordinated fixes for the
  "metadata index failure during open: Database already open. Cannot acquire
  lock." failure that made every fetch through the curl/wget wrapper and the
  CLI fail while `arbitraitor mcp` (or the daemon) was running:
  - The engine now opens the content store **per operation** instead of
    once at API construction: `ArbitraitorApi` opens the store inside each
    inspect/fetch/scan/release/list call and closes it when the call ends,
    so long-lived surfaces (the MCP stdio server, the Unix-socket daemon)
    hold the redb whole-file lock only for the duration of a request and
    never while idle. An MCP server and concurrent CLI fetches now
    coexist; the daemon and MCP server no longer exclude each other.
    Startup no longer fails when the store is briefly locked by another
    process — the failure, if any, moves to the request that actually
    needs the store.
  - A contended metadata-database open (two Arbitraitor processes opening
    the same store within milliseconds, e.g. two concurrent fetches) now
    retries with a short backoff for a bounded window instead of failing
    on the first attempt. If another process still holds the store after
    the retry budget, the operation fails closed with a diagnostic that
    names the situation and how to find the holder
    (`pgrep -af arbitraitor`) instead of the raw redb lock message. The
    same treatment applies to the durable spent-nonce store.
  - `arbitraitor doctor` gains a `legacy_store` check that warns when the
    pre-cache-root store location `~/.arbitraitor/cas` still exists
    alongside the active `$XDG_CACHE_HOME/arbitraitor/cas` store. The
    check is diagnostic only: it never migrates, moves, or deletes the

  a Landlock ABI still reports `filesystem_isolation: Unavailable` — but
  the reporting and the hook can no longer disagree.
- **curl/wget wrapper: scheme-less `host[:port]/path` arguments are
  normalized to `http://`, the wrapper's URL diagnostic states every
  accepted form, and `-f`/`-s` no longer silence the gate's own
  diagnostic** (#763) — three fixes to the wrapper diagnostics path:
  - A scheme-less `host:port/path` argument (the shape of countless health
    checks, `curl localhost:8123/health`) is now defaulted to `http://` by
    the wrapper parsers — the same default real `curl`/`wget` apply — so it
    flows through the normal parse/FetchPolicy/SSRF pipeline instead of
    being rejected as a missing URL. Recognition covers dotted hosts,
    `localhost`, `host:port`, and bracketed IPv6 (`[::1]:8080/x`), and is
    deliberately conservative elsewhere: option values (`-o
    download.log`) are never mistaken for URLs, a scheme-qualified
    positional always outranks an earlier scheme-less one for the
    single-URL accessor, and userinfo form (`user:pass@host`) needs an
    explicit `http://` prefix. Whether plaintext `http` is fetchable
    remains governed entirely by fetch policy; the normalization only
    supplies the default scheme, it does not weaken any policy check
    (`ftp://` and other opaque schemes are still rejected).
  - The wrapper's missing-URL diagnostic no longer self-contradicts: it
    previously demanded "an `http://` or `https://` URL argument" while the
    same invocation's fetch policy refused plaintext `http`. It now states
    the actual accepted forms: `http://host[:port]/path`,
    `https://host[:port]/path`, or `host[:port]/path` (scheme-less defaults
    to `http`).
  - `curl -sf <url>` no longer fails with a bare non-zero exit and an empty
    stderr: the CLI's mapped-exit-code path (`curl` exit 6/7/22/28/60) used
    to call `std::process::exit` before `main`'s error printer ran, so the
    rejection diagnostic vanished exactly when `-s`/`-f` were present. The
    diagnostic is now printed before the mapped exit — quiet flags silence
    the *tool's* output, not a security gate's verdict (same reasoning as
    the unconditional #761 verdict banner).
- **TLS-verification-disabling flags are rejected by the curl/wget
  wrappers** (#769) — `curl -k` / `--insecure` and wget
