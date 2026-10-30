# ADR 0001: Rust 2024 and toolchain policy

**Status:** Accepted
**Date:** 2026-06-16

## Context

Arbitraitor is a security boundary written in Rust. The language choice,
edition, and toolchain pin affect memory safety, build reproducibility,
dependency compatibility, and CI correctness.

## Decision

- **Language:** Rust, 2024 edition.
- **Bootstrap toolchain:** Rust 1.99.1, pinned in `rust-toolchain.toml` and
  mirrored in `.mise.toml`. The pin history is recorded in the amendment
  history below.
- **Workspace resolver:** Cargo resolver 3 (`resolver = "3"`).
- **Minimum Supported Rust Version (MSRV):** 1.96 for pre-1.0 releases; a
  rolling six-month MSRV will be considered only after public API and
  downstream users exist.
- **Nightly:** prohibited for production features; used only in isolated CI
  jobs (Miri, sanitizer testing).
- **`Cargo.lock`:** committed for all crates in this monorepo.
- **Profiles:**
  - `release`: `codegen-units = 1`, `lto = "thin"`, `panic = "abort"`,
    `strip = "symbols"`.
  - `release-with-debug`: inherits release, `debug = 1`, `strip = "none"`.
- **Lints:** `unsafe_code = "forbid"` workspace-wide. Clippy `all = deny`,
  `pedantic = warn`, `cargo = warn`. `unwrap_used`, `expect_used`, `panic`,
  `dbg_macro`, `print_stdout`, `print_stderr` denied. Local exceptions allowed
  with justification.
- **Staying current:** the pinned toolchain tracks current stable Rust, so
  the pin is bumped as soon as a new stable release is available. A bump is
  a reviewed change: the reviewer re-runs the full gate list under the new
  toolchain and records the fallout in the amendment history below. Lints a
  bump introduces are fixed in the code — never silenced with a blanket
  `#[allow]`.

## Consequences

- Security-sensitive dependencies (Wasmtime, YARA-X, TLS, parsers) can move
  quickly; pinning current stable avoids patch lag.
- `panic = "abort"` is appropriate for the shipped CLI; reusable library
  crates must not rely on process abortion as error handling.
- CI runs an additional job against current stable channel to detect drift.

## Amendment history

Amendments are made in place: the decision above stays the decision, the
current state of the world is updated here, and each amendment is dated.
The MSRV has not moved; only the pinned bootstrap toolchain has.

### 2026-10-30 — Rust 1.98.1 → 1.99.1

- **Change:** the bootstrap pin moves from Rust 1.98.1 to Rust 1.99.1 in
  `rust-toolchain.toml` and `.mise.toml` (Renovate PR #796; this change
  supersedes that PR). The MSRV stays at 1.96.
- **Reason:** the pin tracks current stable, so security-sensitive
  dependencies (Wasmtime, YARA-X, TLS, parsers) do not accumulate patch
  lag, as the consequences above require.
- **Fallout:** two lints, both diagnostics-only — no behavioural change, no
  new dependency, and no blanket `#[allow]`:
  - `clippy::assert_is_empty` (new in Clippy 1.99.0; `pedantic` upstream, so
    it reaches this workspace through `pedantic = "warn"` and CI's
    `-D warnings`). The 160 assertions that only checked emptiness
    (`assert!(x.is_empty())`, `assert!(!x.is_empty())`) now compare against
    an empty value (`assert_eq!` / `assert_ne!`), following the lint's own
    suggestion, so a failure prints the offending contents instead of only
    reporting that the value was not empty. No assertion was weakened.
  - rustc's `semicolon_in_expressions_from_non_local_macros` (a
    future-incompatibility warning that is on by default) fires on four
    `miette::bail!` calls in `arbitraitor-cli` that used the macro in
    expression position. They now use it in statement position (a trailing
    `;`, and one match arm wrapped in a block). `bail!` already diverges, so
    the control flow is unchanged.

### 2026-09-25 — Rust 1.98.0 → 1.98.1

- **Change:** patch-level bump of the bootstrap pin (PR #725).
- **Reason:** patch release; no fallout beyond the version numbers.

### 2026-08-24 — Rust 1.96.0 → 1.98.0

- **Change:** the bootstrap pin moves from Rust 1.96.0 to Rust 1.98.0
  (PR #719).
- **Reason:** the pin tracks current stable, as above.
- **Fallout:** one new Clippy 1.98 lint, `chunks_exact_to_as_chunks`
  (deny-by-default via `clippy::all`), at two call sites; both were
  rewritten to `slice::as_chunks::<2>`, which keeps the previous behaviour
  of silently dropping the remainder.

## Alternatives considered

- **Older MSRV (e.g., 1.80):** Rejected. Creates patch lag for security deps
  with little benefit for a pre-1.0 project.
- **C or C++:** Rejected. Memory safety risk in a security boundary.
- **Go:** Rejected. Less control over memory layout, unsafe code isolation,
  and zero-cost abstractions needed for the analysis pipeline.

## References

- `docs/spec/tech-stack.md` §2 (Language and toolchain policy)
- `rust-toolchain.toml`
- `Cargo.toml` workspace section
