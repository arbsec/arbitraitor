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
2. **Watchdog thread.** The watchdog is armed immediately after spawn (it
   covers the parent's blocking `write_all` of the script bytes to the
   child's stdin, not only output collection), polls the deadline
   (50 ms granularity), and is released the moment the direct child is
   reaped, so it never fires against a recycled pid.
3. **Process-group kill.** The child is spawned with
   `process_group(0)` (mirroring the plugin host's `configure_process_group`),
   so on expiry the watchdog `SIGKILL`s the child's **process group** —
   the interpreter and every descendant that remained in its default
   process group die together instead of surviving a bare kill and holding
   the inherited pipe FDs (spec §9 subprocess controls: "process group …
   timeout and kill-tree behavior").
   **Scope, stated honestly:** the group kill covers the direct child and
   the descendants that inherited its default group. A script that
   deliberately calls `setsid(2)`/`setpgid(2)` (or `set -m`) creates a new
   session or group the fence does not reach; such a script opts out of
   the group kill, and doing so is observable malicious behavior worth
   flagging in analysis. Technical completeness (subreaper + tree walk, or
   seccomp denial of `setsid`/`setpgid`) was rejected: the fence's purpose
   is a resource backstop, not containment — filesystem, network, and
   process containment are Landlock/unshare/seccomp's job
   (ADR-0008/0020/0021), and a detached survivor holds no parent resources
   (its inherited pipe FDs close when the reaped parent group dies).
   `ESRCH`
   from the group kill is treated as success (the goal — a dead group — is
   met); any other kill error is surfaced as
   `ExecError::WallClockKillFailed` (fail closed), after a best-effort
   single-process kill of the direct child.
4. **Typed expiry, and kill failure only when death is unconfirmed.**
   Expiry reports `ExecError::WallClockExpired { limit_secs }` rather than
   the child's signal-death exit status, so callers distinguish "stopped at
   deadline" from an ordinary crash. `ExecError::WallClockKillFailed` is
   reserved for the case where the group kill errored (non-ESRCH) **and**
   the child is not confirmed dead (for example the pre-drain zero-deadline
   path): death unconfirmed → fail closed. When the direct child has been
   reaped, death is confirmed and `WallClockExpired` is the accurate
   report. The CLI `run` pipeline maps expiry (and kill failure) to
   `RunFailure::AnalysisIncomplete` — exit code 34, "analysis incomplete
   due to resource limit" (spec §29) — because the run was aborted by a
   resource fence, not by the child's own behavior.

## Consequences

- Mediated script, PowerShell, **and native** execution can no longer run
  unboundedly by default: a hung agent dies at the 300 s fence without
  caller action. The fence is enforced on every Unix platform (the
  watchdog uses only std threads + POSIX `killpg`); only the
  `prlimit`-based CPU/memory/process/fd limits remain Linux-only.
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
    default-group descendant kill portably on Unix.
  - *Seccomp denial of `setsid`/`setpgid` or subreaper + tree-walk kill* —
    rejected for this fence (see Decision 3 scope note): containment
    belongs to the sandbox layer; the fence is a resource backstop. The
    `setsid` escape is observable malicious behavior, in scope for shell
    analysis, not for this deadline.

## References

- spec §9 (subprocess controls: process group, timeout and kill-tree),
  §26.3 ("complete process tree under cancellation and resource control"),
  §29 (exit code 34), §40.0 (single-pipeline / exclusivity principle)
- ADR-0007 (assurance levels), ADR-0008 (execution context security profile)
