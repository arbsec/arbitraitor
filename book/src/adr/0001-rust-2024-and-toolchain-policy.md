# ADR 0001: Rust 2024 and toolchain policy

**Status:** Accepted
**Date:** 2026-06-16

## Context

Arbitraitor is a security boundary written in Rust. The language choice, edition, and toolchain pin affect memory safety, build reproducibility, dependency compatibility, and CI correctness.

## Decision

- **Language:** Rust, 2024 edition.
- **Bootstrap toolchain:** Rust 1.96.0, pinned in `rust-toolchain.toml`.
- **Workspace resolver:** Cargo resolver 3 (`resolver = "3"`).
- **Minimum Supported Rust Version (MSRV):** 1.96 for pre-1.0 releases; a rolling six-month MSRV will be considered only after public API and downstream users exist.
- **Nightly:** prohibited for production features; used only in isolated CI jobs (Miri, sanitizer testing).
- **`Cargo.lock`:** committed for all crates in this monorepo.
- **Profiles:**
  - `release`: `codegen-units = 1`, `lto = "thin"`, `panic = "abort"`, `strip = "symbols"`.
  - `release-with-debug`: inherits release, `debug = 1`, `strip = "none"`.
- **Lints:** `unsafe_code = "forbid"` workspace-wide. Clippy `all = deny`, `pedantic = warn`, `cargo = warn`. `unwrap_used`, `expect_used`, `panic`, `dbg_macro`, `print_stdout`, `print_stderr` denied. Local exceptions allowed with justification.

## Consequences

- Security-sensitive dependencies (Wasmtime, YARA-X, TLS, parsers) can move quickly; pinning current stable avoids patch lag.
- `panic = "abort"` is appropriate for the shipped CLI; reusable library crates must not rely on process abortion as error handling.
- CI runs an additional job against current stable channel to detect drift.

## Alternatives considered

- **Older MSRV (e.g., 1.80):** Rejected. Creates patch lag for security deps with little benefit for a pre-1.0 project.
- **C or C++:** Rejected. Memory safety risk in a security boundary.
- **Go:** Rejected. Less control over memory layout, unsafe code isolation, and zero-cost abstractions needed for the analysis pipeline.

## References

- `.spec/arbitraitor-tech-stack.md` §2 (Language and toolchain policy)
- `rust-toolchain.toml`
- `Cargo.toml` workspace section
