# ADR 0027: CLI inspect pipeline boundary

**Status:** Accepted
**Date:** 2026-07-19
**Issue:** #436

## Context

`docs/conventions.md` defines `arbitraitor-cli` as responsible for argument
parsing, output formatting, and user interaction. The inspect command had grown
pipeline orchestration directly inside `main.rs`: fetch policy construction,
source parsing, retrieval, CAS storage, analysis coordinator setup, provenance
verification, and receipt assembly.

That made the CLI entry point harder to review against the crate boundary and
mixed dispatch/output concerns with inspect pipeline state transitions.

## Decision

Extract inspect pipeline orchestration from `crates/arbitraitor-cli/src/main.rs`
into `crates/arbitraitor-cli/src/pipeline.rs`.

`main.rs` remains responsible for CLI parsing, command dispatch, and inspect
output formatting helpers. The new `pipeline` module owns the inspect-related
orchestration helpers within the CLI crate until the core state machine can own
the pipeline more fully.

## Consequences

- `main.rs` becomes smaller and easier to audit for CLI-only responsibilities.
- Inspect orchestration has a named module boundary, making future movement into
  `arbitraitor-core` easier.
- Runtime behavior, command-line arguments, receipts, and public CLI output stay
  unchanged.
- Other command business logic (`wrapper_fetch`, `unpack`, `intel`) remains in
  place and requires separate follow-up decisions if moved later.

## Alternatives considered

- **Move orchestration directly to `arbitraitor-core`:** better final boundary,
  but larger than this focused refactor because it would require cross-crate API
  design for CLI output hooks, rule loading, and receipt emission.
- **Leave orchestration in `main.rs`:** preserves status quo, but continues to
  violate the documented CLI crate responsibility and keeps the entry point too
  large.

## References

- `docs/conventions.md` crate responsibility table
- Issue #436
