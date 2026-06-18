# ADR 0019: `catch_unwind` and `panic = "abort"` interaction

**Status:** Accepted
**Date:** 2026-06-18

## Context

The `arbitraitor-analysis` crate uses `catch_unwind(AssertUnwindSafe(|| detector.analyze(ctx)))`
to isolate detector panics — when a detector panics, the coordinator records
`DetectorStatus::Error` and continues running remaining detectors, then derives
an `Incomplete` verdict (fail-closed).

ADR 0001 establishes `panic = "abort"` for the `release` profile. Under
`panic = "abort"`, `catch_unwind` is a **no-op**: a panic aborts the process
rather than unwinding the stack, so the `catch_unwind` closure never returns
`Err` and the `DetectorStatus::Error` path is never reached.

This means detector isolation via `catch_unwind` is functional in debug and
test builds only. In production (release) builds, a detector panic aborts the
entire process.

## Decision

Accept the tension as an intentional two-tier defense:

1. **Debug/test builds** (`panic = "unwind"`): `catch_unwind` provides
   detector isolation. A panicking detector is caught, recorded as
   `DetectorStatus::Error`, and the analysis continues. The verdict is
   `Incomplete`. This enables robust testing of detector error handling.

2. **Release builds** (`panic = "abort"`): Process abort is the fail-closed
   mechanism. A detector panic kills the process, producing no verdict at all.
   The caller observes a non-zero exit and must treat the artifact as
   untrusted. This is strictly more conservative than `Incomplete`.

The workspace `clippy::panic = "deny"` and `unwrap_used = "deny"` lints
minimize the sources of unintentional panics. Remaining panic sources (index
out of bounds in dependencies, stack overflow) are rare and result in process
abort in release — the safest possible outcome for a security boundary.

## Consequences

- `DetectorStatus::Error(panic_message)` and the `Incomplete` verdict for
  panics are **dead code in release builds**. They remain valuable for
  debug/test coverage and are not removed.
- `DetectorStatus::Timeout` is similarly debug-only (see #79 for timeout
  enforcement design).
- Future consumers of the analysis pipeline must distinguish "no verdict due
  to process abort" from an explicit `Incomplete` verdict. The receipt schema
  should account for this in a future revision.
- The `AssertUnwindSafe` wrapper is sound: `analyze(&self, &AnalysisContext)`
  holds only immutable references, so no mutation crosses the unwind boundary.

## Alternatives Considered

1. **`panic = "unwind"` in release**: Rejected by ADR 0001 for binary size,
   compile time, and defense-in-depth reasons. Process abort is the preferred
   fail-closed mechanism for a security boundary.

2. **Spawn each detector in a separate process**: Would provide isolation
   even under `panic = "abort"`, but introduces IPC complexity, serialization
   overhead, and non-determinism — unacceptable for the MVP.

3. **Remove `catch_unwind` entirely**: Would simplify the code but lose
   valuable debug-time detector isolation and error reporting.
