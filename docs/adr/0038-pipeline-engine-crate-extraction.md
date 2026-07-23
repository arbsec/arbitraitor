# ADR 0038: Pipeline engine crate extraction and naming

**Status:** Proposed
**Date:** 2026-07-23
**Issue:** TBD (tracking issue to be created before acceptance)

## Context

Three independent compositions of the fetch→store→analyze→provenance→receipt→verdict pipeline exist in the codebase today:

1. **`arbitraitor-cli/src/pipeline.rs`** (ADR-0027) — composes fetcher, ContentStore, AnalysisCoordinator, signature verification, and receipt building. Does **not** do policy evaluation or release.
2. **`arbitraitor-mcp` tool handlers** — `InspectUrlTool` composes fetch+analyze per-call; `FetchArtifactTool` does fetch-only; `ScanArtifactTool` does analyze-only. These three tools do not use ContentStore, PolicyEngine, or receipt building. (Note: `QueryReceiptTool` does use `arbitraitor_receipt::Receipt` for lookups, and `ApprovalTokenIssuer` uses `arbitraitor_store::SpentNonceStore` — the broader MCP crate has store and receipt dependencies, but not for pipeline composition.)
3. **`arbitraitor-daemon::ArbitraitorApi`** — composes fetch+store+analyze+policy+receipt. Does **not** do provenance verification.

Each composition covers a **different subset** of the pipeline. A consumer switching between surfaces (CLI, MCP, daemon) gets different security coverage without knowing it. This is worse than uniform divergence — it is silent coverage holes.

ADR-0027 moved CLI orchestration out of `main.rs` into `pipeline.rs` as an interim step "until the core state machine can own the pipeline more fully." ADR-0027's stated future direction was movement **into `arbitraitor-core`**. However, ADR-0002 keeps `arbitraitor-core` free of I/O, and the pipeline composes I/O-producing crates (fetch, store, analysis, provenance). This ADR redirects ADR-0027's trajectory: the pipeline engine lives in **its own crate**, not in `arbitraitor-core`.

Additionally, third-party products (Rust package managers, IDE plugins, CI binaries) need to embed Arbitraitor's pipeline without shelling out to the CLI. The spec §40 (v0.6, PR #651) describes three integration surfaces — library, daemon, MCP gateway — all over a single pipeline engine.

**Note on spec dependency:** This ADR references invariant numbers and spec sections from `docs/spec/spec.md` (PR #651, pending merge). The invariant numbering below follows the spec's §9 list (24 invariants), which is more granular than `conventions.md`'s 10-invariant summary. If #651 is not merged before this ADR is accepted, inline definitions must be added.

## Decision

### 1. Extract a new pipeline engine crate: `arbitraitor-engine`

Working name: `arbitraitor-engine` (recommended over `arbitraitor-api` to avoid REST/HTTP API confusion and prevent the redundant `arbitraitor_api::ArbitraitorApi` path).

The crate owns:

- `Arbitraitor` — entry-point struct with a fluent builder.
- `ArbitraitorBuilder` — config, policy, signature inputs, detector list, YARA rules.
- `ArbitraitorApi` — the in-process API (moved from `arbitraitor-daemon`).
- `Config` — store path, fetch policy, retention policy, receipts directory.
- `InspectionResult` — typed result carrying verdict, findings, receipt, sha256. (Note: the current code uses `InspectionResult` at `api.rs:84`; this ADR preserves the existing name rather than renaming to `InspectResult`.)
- A typed error derived from `thiserror`.

The engine is the single authority for (spec §9 invariant numbers, pending #651 merge):

- Invariant 1 (no early release)
- Invariant 2 (immutable identity — reverify digest before every release)
- Invariant 3 (single retrieval)
- Invariant 4 (bounded processing)
- §18.3 fail-closed principle (required scanner failure must block or produce `incomplete`)
- Spec invariant 8 (safe temporary storage — CAS; note: `conventions.md` invariant 8 is "monotonic project configuration" — the numbering systems differ)
- Spec invariant 11 (approval integrity — inspection result feeding approval display)
- Spec invariant 12 (deterministic enforcement — detector scheduling)
- Spec invariant 22 (metadata index is non-authoritative)
- Spec invariant 23 (plan-bound approval capability — **ownership gap**: `ApprovalTokenIssuer` and `RequestApprovalTool` currently live in `arbitraitor-mcp`; invariant 23 ownership is claimed but not yet realized, see proposed ADR-0039)
- §26.2 (safe destination release)

State transitions (§38.3) remain owned by `arbitraitor-core` (the value-type state machine `PipelineOperation`). The engine **drives** the state machine through the API. **Note:** `PipelineOperation` is currently fully implemented but not wired into any of the three existing compositions. Integrating the state machine into the engine is a **prerequisite** for the single-pipeline principle, not a consequence of it (tech-stack §36.1 item 7).

### 2. `arbitraitor-daemon` becomes a thin consumer

The daemon crate retains only:

- Unix-socket I/O
- `OperationQueue` (async queue with concurrency limiting, cancellation)
- Capability-token recording (currently records token presence for diagnostics; full verification is a future responsibility)
- Rate-limiting

Pipeline code (fetch, store, analyze, provenance, receipt, verdict) moves to `arbitraitor-engine`.

### 3. `arbitraitor-mcp` becomes a thin consumer

MCP tool handlers translate JSON-RPC parameters into typed `ArbitraitorApi` calls. No pipeline composition is reimplemented in `arbitraitor-mcp`.

The full set of tool handlers:
`InspectUrlTool`, `ScanArtifactTool`, `FetchArtifactTool`, `QueryReceiptTool`, `ExplainVerdictTool`, `RequestApprovalTool`, `RunApprovedArtifactTool`.

**Current-state gap:** `build_default_server()` registers only 5 of 7 tools (`RequestApprovalTool` and `RunApprovedArtifactTool` are implemented but not registered). The migration must also wire these into the default server.

### 4. `arbitraitor-cli` becomes a thin consumer

Per ADR-0027's trajectory (redirected by this ADR), the CLI's `pipeline.rs` becomes a thin adapter that builds an `ArbitraitorBuilder` from CLI args, calls `ArbitraitorApi::inspect`, and formats results through the CLI's presentation helpers.

### 5. Public API stability contract

Before 1.0, `arbitraitor-engine` publishes under SemVer `0.x`:

- Breaking changes tracked in `CHANGELOG.md` and flagged in the release PR.
- The public surface is deliberately narrow: `Arbitraitor`, `ArbitraitorBuilder`, `ArbitraitorApi`, `Config`, `InspectionResult`, and a typed error.
- Feature flags gate heavier integrations (`yara-x`, `sigstore`, `package-manager`, `plugin-host`) so minimal consumers do not pull those transitive dependencies.
- The public API **never** exposes types from `arbitraitor-fetch`, `arbitraitor-store`, `arbitraitor-analysis`, `arbitraitor-receipt`, `arbitraitor-provenance`, or `arbitraitor-exec` verbatim.

### 6. `InspectionResult.receipt` type identity

`InspectionResult` exposes a receipt. To insulate consumers from `arbitraitor-receipt` schema changes (e.g. the envelope restructure in #492), `InspectionResult.receipt` **must be an engine-owned wrapper struct** that maps from internal `arbitraitor-receipt::Receipt` types — not the raw type. This means:

- When `arbitraitor-receipt` schema changes (flat → envelope per #492), the engine crate absorbs the mapping change. Consumers see a stable `InspectionResultReceipt` type.
- The wrapper must expose all fields consumers need (verdict, findings, sha256, retrieval metadata) without leaking `arbitraitor-receipt` types.
- **Review trigger:** if `arbitraitor-receipt` adds a field consumers need, the wrapper must be updated in the same PR.

### 7. Current type leakage migration

The existing `ArbitraitorApi` in `arbitraitor-daemon` leaks internal types:

- `Config.fetch_policy: FetchPolicy` (from `arbitraitor-fetch`)
- `ReleaseResult.method: ReleaseMethod` (from `arbitraitor-exec`)
- `ApiError::Store(StoreError)` (from `arbitraitor-store`)
- `ArbitraitorBuilder::policy(PolicyEngine)` (from `arbitraitor-policy`)

All of these must be wrapped in engine-owned types before the crate publishes to crates.io (tech-stack §36.1 item 6).

## Consequences

- **Single pipeline, one set of invariants.** CLI, MCP, daemon, and third-party embedders all route through the same engine. Silent coverage holes are eliminated.
- **ADR-0027 trajectory redirected.** ADR-0027 envisioned movement into `arbitraitor-core`; this ADR moves to a separate engine crate because the pipeline composes I/O-producing crates and ADR-0002 keeps `arbitraitor-core` free of I/O.
- **`PipelineOperation` must be wired.** The state machine in `arbitraitor-core` is currently unused. Integration is a prerequisite, not a consequence, of the extraction.
- **Provenance verification must be added to the engine.** The CLI pipeline does minisign/cosign verification; `ArbitraitorApi` does not. The engine must own this.
- **Approval flow ownership gap.** `ApprovalTokenIssuer` and `RequestApprovalTool` currently live in `arbitraitor-mcp`. The engine claims invariant 23 (plan-bound approval) but the approval flow is not yet integrated. This gap is explicitly deferred to ADR-0039 (proposed). Until ADR-0039 is accepted, invariant 23 ownership is aspirational, not realized.
- **MCP dependency closure grows.** When `arbitraitor-mcp` depends on `arbitraitor-engine`, it transitively depends on `arbitraitor-store`, `arbitraitor-fetch`, etc. The MCP process's attack surface increases. Feature flags mitigate this but do not eliminate it.
- **New §9 invariant candidate.** The single-pipeline principle ("only the pipeline engine may transition the state machine across retrieval → release") is a security-relevant assertion not yet in §9. If added as invariant 25, the `invariants.yml` CI workflow must test it. Deferred to a separate decision.

## Alternatives considered

- **Move pipeline into `arbitraitor-core`:** Rejected. ADR-0002 keeps `arbitraitor-core` free of I/O. The pipeline composes I/O-producing crates (fetch, store, analysis, provenance). While ADR-0027's "Alternatives considered" called the core move a "better final boundary," the I/O constraint makes it architecturally incompatible. This ADR formally redirects ADR-0027's trajectory rather than perpetuating an unfulfillable plan.

- **Multi-pipeline composition per consumer:** Rejected. Reintroduces the silent coverage holes that motivated the extraction. Each composition omits different invariants.

- **Toolkit crate exposing individual components:** Rejected. Third parties would re-implement invariants (§9 and §26.2) and the security boundary becomes advisory rather than enforced.

- **Library embedding as the only surface (no daemon, no MCP):** Rejected. Non-Rust consumers (Go, Python, Node) need a stable out-of-process surface.

- **Name `arbitraitor-api`:** Rejected. Evokes REST/HTTP APIs, creates the redundant `arbitraitor_api::ArbitraitorApi` path, and conflicts with common expectations of what an "API crate" provides.

- **Name `arbitraitor-runtime`:** Rejected. "Runtime" is overloaded — could mean execution runtime, plugin runtime, or WASM runtime. The codebase already has `arbitraitor-exec` and `arbitraitor-plugin-host`.

## Staged rollout

1. **Stage 0:** `PipelineOperation` wired into at least one composition (prerequisite — must be complete before ADR acceptance).
2. **Stage 1:** This ADR accepted. Spec §40 marked as normative (requires #651 merged).
3. **Stage 2:** Add provenance verification to `ArbitraitorApi` (currently CLI-only).
4. **Stage 3:** Extract `arbitraitor-engine` crate from `arbitraitor-daemon`.
5. **Stage 4:** Make MCP thin (rewrite tool handlers to delegate to `ArbitraitorApi`).
6. **Stage 5:** Make CLI thin (rewrite `pipeline.rs` to delegate to `ArbitraitorApi`).
7. **Stage 6:** Type wrapping (wrap all leaking types in engine-owned structs).
8. **Stage 7:** Feature flags (`yara-x`, `sigstore`, `package-manager`, `plugin-host`).
9. **Stage 8:** Publish to crates.io under `0.x`.

## Dependencies on in-flight issues

- **#651 (spec commit, pending merge):** This ADR references invariant numbers (11, 12, 22, 23) and spec sections (§9, §18.3, §26.2, §38.3, §36.1, §40) from `docs/spec/spec.md`. These do not exist in the codebase until #651 is merged. If #651 is not merged before this ADR is accepted, inline invariant definitions must be added.
- **#492 (receipt envelope, breaking-change):** `InspectionResult.receipt` type identity depends on this. The engine-owned wrapper (decision 6) absorbs the breaking change. Must coordinate.
- **#462 (WASI 0.3 floor):** May override tech-stack §10.1 cautious wording. Reconcile WASI 0.3 status before the `plugin-host` feature flag ships.
- **#503 (mandatory detector coverage) — MERGED:** Coverage-map policy must be exposed through `ArbitraitorBuilder`.
- **#499 (decoded-child artifact) — MERGED:** `InspectionResult` may need a child-identity field beyond single `sha256`.
- **#463 (Wasmtime CVE risk register):** Adds receipt fields (`wasmtime_version`, `compiler_backend`) that flow through `InspectionResult.receipt`. Three-way coordination with #492.

## References

- Spec §40 (`docs/spec/spec.md`, PR #651)
- Tech-stack §3.5 (`docs/spec/tech-stack.md`, PR #651)
- ADR-0002 (workspace structure and crate boundaries)
- ADR-0013 (plan-bound approval capability)
- ADR-0027 (CLI pipeline boundary — redirected by this ADR)
- `conventions.md` (security invariants — note: uses different invariant numbering than spec §9)
