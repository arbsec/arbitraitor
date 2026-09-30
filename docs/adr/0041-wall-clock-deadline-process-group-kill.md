# ADR 0041: Wall-clock deadline and process-group kill for mediated execution

**Status:** Accepted
**Date:** 2026-09-30
**Issue:** #760

## Context

`arbitraitor_exec::ExecutionPolicy` fences mediated execution with CPU-time
and memory limits (`ResourceLimits::cpu_time_secs` via `RLIMIT_CPU`), but a
CPU limit cannot stop a child that sleeps or blocks on I/O. Script execution
(`script.rs::execute`, the mediated bash path) blocked on the child with no
wall-clock deadline and no kill path a caller could drive: a hung child ran
unboundedly, and the only caller recourse was to abandon the task, leaking
both the child and the blocking thread.

The motivating consumers (Orchestraitor bootstrap, per issue #314 /
arbsec/orchestraitor#434) run agents against mediated scripts in practice;
the gap was not only "no caller-driven kill" but that no effective deadline
fired by default. Per the exclusivity rule (spec §40.0 single-pipeline
principle), Orchestraitor will not build a parallel kill path; it needs the
capability in `arbitraitor-exec` itself, reporting expiry as a typed result
so the harness can record "stopped at deadline" (spec §9.24-style
`could not be stopped` semantics) instead of mistaking the kill for a crash.

## Decision

1. **Default-on wall-clock deadline.** `ResourceLimits` gains
   `wall_clock_secs: Option<u64>`, defaulting to `DEFAULT_WALL_CLOCK_SECS`
   = 300 seconds. The value sits above
   every shorter stage timeout in the default configuration
   (`arbitraitor-core::TimeoutConfig` caps at 120s for recursive payload
   graphs; `ExecutionConfig::timeout_secs` defaults to 60) so the fence is a
   backstop, not the binding constraint in normal runs. `None` disables the
   deadline; this escape hatch exists for explicitly trusted, caller-driven
   paths only. A `Some(0)` deadline expires immediately (useful for tests
   and fail-closed probes).
2. **Watchdog thread.** `read_with_limit` spawns a watchdog when a deadline
   is configured. It polls the deadline (50 ms granularity) and is released
   the moment the direct child is reaped, so it never fires against a
   recycled pid.
3. **Process-group kill.** The child is spawned with
   `process_group(0)` (mirroring the plugin host's `configure_process_group`),
   so on expiry the watchdog `SIGKILL`s the child's **process group** —
   shell-spawned grandchildren die with the interpreter instead of surviving
   a bare kill and holding the inherited pipe FDs (spec §9 subprocess
   controls: "process group … timeout and kill-tree behavior"). `ESRCH`
   from the group kill is treated as success (the goal — a dead group — is
   met); any other kill error is surfaced as
   `ExecError::WallClockKillFailed` (fail closed), after a best-effort
   single-process kill of the direct child.
4. **Typed expiry.** Expiry reports `ExecError::WallClockExpired { limit_secs }`
   rather than the child's signal-death exit status, so callers distinguish
   "stopped at deadline" from an ordinary crash. The CLI `run` pipeline maps
   expiry (and kill failure) to `RunFailure::AnalysisIncomplete` — exit code
   34, "analysis incomplete due to resource limit" (spec §29) — because the
   run was aborted by a resource fence, not by the child's own behavior.

## Consequences

- Mediated script and PowerShell execution can no longer run unboundedly by
  default: a hung agent dies at the 300 s fence without caller action.
- Callers can tighten (`wall_clock_secs = Some(n)`), loosen, or disable
  (`None`) the deadline per execution via
  `ScriptExecution::with_resource_limits` / `with_environment_policy`.
- The watchdog adds one thread per in-flight execution for at most the
  deadline duration; it exits immediately when the child is reaped first.
- Existing `OutputExceeded` handling is unchanged; the two fences compose
  (whichever fires first wins).
- Alternatives considered:
  - *Caller-driven kill only* (the issue's minimal ask) — rejected: the
    motivating symptom was hung agents with no caller intervention; a
    default-off capability would not fix it.
  - *Async runtime timers* — rejected: the exec crate is synchronous and
    std-only by design; a thread-per-execution watchdog is simple and
    bounded.
  - *cgroup freezer/timeout* — rejected: requires root or delegated
    cgroup control and is platform-specific; process groups cover the
    grandchild-reaping need portably on Unix.

## References

- spec §9 (subprocess controls: process group, timeout and kill-tree),
  §26.3 ("complete process tree under cancellation and resource control"),
  §29 (exit code 34), §40.0 (single-pipeline / exclusivity principle)
- ADR-0007 (assurance levels), ADR-0008 (execution context security profile)
