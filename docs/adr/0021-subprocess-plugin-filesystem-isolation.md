# ADR 0021: Landlock filesystem isolation for subprocess plugins

**Status:** Accepted
**Date:** 2026-06-23
**Issue:** #209

## Context

ADR 0006 defines plugins as capability-bounded components and ADR 0011 treats
community plugins as untrusted until proven otherwise. The Wasmtime Component
Model path withholds ambient WASI filesystem access, but subprocess plugins run
as native binaries under Arbitraitor's user ID. Without an operating-system
filesystem boundary, a subprocess plugin can read any file that user can read,
including configuration, SSH material, token stores, and host metadata.

ADR 0020 added seccomp-BPF network isolation for subprocess plugins. Filesystem
access needs a separate control because network denial does not prevent local
secret discovery or later exfiltration through plugin output.

## Decision

Install a Linux Landlock ruleset in the subprocess plugin child via `pre_exec`,
after resource limits, network isolation, and the general process sandbox have
been registered. The ruleset handles all Landlock filesystem access bits known
to the running kernel ABI and denies governed access by default.

The executor grants read/execute access to the plugin binary's parent directory
and common dynamic-linker runtime directories (`/bin`, `/usr/bin`, `/lib`,
`/lib64`, `/usr/lib`, `/usr/lib64`) so dynamically-linked plugin binaries can
start without allowing `/etc` or user home directories. If the caller supplies a
plugin working directory, the child receives read/write/create/remove/execute
access beneath that directory. All other governed filesystem accesses fail with
the Landlock `EACCES` behavior.

Use raw Linux syscalls through `libc` rather than adding liblandlock, libseccomp,
or another native dependency. The sandbox crate owns the unsafe FFI boundary;
plugin-host remains `forbid(unsafe_code)` and invokes only safe wrappers.

Linux kernels before Landlock support (5.13) degrade gracefully: the hook returns
success without installing a ruleset, and callers must treat filesystem isolation
as unavailable on those hosts rather than claiming enforcement.

## Consequences

- Supported Linux hosts now deny subprocess plugins ambient access to `/etc`,
  home directories, and other undeclared filesystem paths.
- Dynamically-linked plugins still start because read/execute grants cover the
  common ELF interpreter and shared-library search paths.
- Working-directory access becomes explicit and bounded beneath the configured
  directory instead of inheriting all same-UID filesystem privileges.
- Unsupported kernels and non-Linux platforms still require a platform-specific
  enforcement mechanism before they can claim subprocess plugin filesystem
  isolation.

## Alternatives considered

- **Require statically-linked plugins only:** Rejected for now. It would simplify
  Landlock rules but would break existing dynamically-linked subprocess plugins
  and tests.
- **Allow read access to all of `/`:** Rejected. It preserves compatibility but
  fails the security goal by continuing to expose host secrets.
- **Parse ELF dependencies per plugin:** Deferred. It would reduce runtime read
  grants but adds format parsing and linker-policy complexity to the spawn path.
- **liblandlock or a Rust Landlock crate:** Rejected. Raw syscalls are small,
  already consistent with the seccomp sandbox, and avoid a new security-boundary
  dependency.

## References

- [ADR 0006](0006-wasmtime-component-model-plugins.md) — Wasmtime Component
  Model for plugins
- [ADR 0011](0011-plugin-trust-classification.md) — Plugin trust classification
  model
- [ADR 0020](0020-subprocess-plugin-network-isolation.md) — Seccomp-BPF network
  isolation for subprocess plugins
- Linux `landlock_create_ruleset(2)`, `landlock_add_rule(2)`, and
  `landlock_restrict_self(2)`
