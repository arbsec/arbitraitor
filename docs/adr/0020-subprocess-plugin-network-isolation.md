# ADR 0020: Seccomp-BPF network isolation for subprocess plugins

**Status:** Accepted
**Date:** 2026-06-23
**Issue:** #208

## Context

ADR 0006 defines plugin instances as networkless by default. The Wasmtime
Component Model path already withholds WASI networking capabilities, but the
subprocess fallback executes native binaries. A community subprocess plugin could
open sockets directly and exfiltrate artifact contents, environment-derived
metadata, or analysis results.

ADR 0008 also makes runtime network access denied by default because unrestricted
egress defeats transitive payload coverage. Native subprocess plugins therefore
need an operating-system boundary that applies before untrusted code runs.

## Decision

Install a Linux seccomp-BPF filter in the subprocess plugin child via
`pre_exec`, after resource limits are registered and before the general process
sandbox. The filter blocks socket-related syscalls with
`SECCOMP_RET_ERRNO | EPERM`, not `SECCOMP_RET_KILL`, so plugins observe ordinary
permission failures instead of process termination.

The filter denies socket creation, socket pairs, connect, bind, listen, accept,
socket send/receive calls, endpoint inspection, and socket option syscalls. It
first checks `seccomp_data.arch` against the build architecture's `AUDIT_ARCH_*`
value so ABI confusion cannot bypass the syscall-number denylist.
Use raw classic BPF through `libc` rather than `libseccomp` or another C-backed
dependency. The required policy is a short denylist with an allow-by-default
fall-through, and avoiding a new native dependency keeps the sandbox supply-chain
and deployment surface smaller.

Network isolation is enabled by default for `SubprocessExecutor`. Callers may
disable it only when policy explicitly grants a plugin network capability. The
current implementation enforces on Linux `x86_64` and `aarch64`; other platforms
must report this control as unavailable rather than silently claiming isolation.
Landlock filesystem isolation remains separate work (#209).

## Consequences

- Community subprocess plugins can no longer create network sockets under the
  default executor policy on supported Linux architectures.
- Existing filesystem and stdio behavior remains available because the filter is
  scoped to network-related syscalls.
- Plugins that legitimately require network access need an explicit policy grant
  and must use `with_network_isolated(false)`.
- Non-Linux and unsupported Linux architectures still need a platform-specific
  enforcement mechanism before they can claim subprocess plugin network denial.

## Alternatives considered

- **libseccomp-rs:** Rejected. It provides a clearer API but adds a native C
  library dependency to a security boundary.
- **Network namespaces:** Deferred. They are stronger but require namespace setup,
  lifecycle handling, and often privilege/user-namespace considerations.
- **SECCOMP_RET_KILL:** Rejected. Killing plugins obscures policy failures and
  makes graceful capability-denied behavior harder to test and debug.

## References

- [ADR 0006](0006-wasmtime-component-model-plugins.md) — Wasmtime Component
  Model for plugins
- [ADR 0008](0008-execution-context-security-profile.md) — Execution context
  security profile
- Linux `seccomp(2)`
- Linux `seccomp_data` and classic BPF filter ABI
