# ADR 0009: Privilege separation and no-root invariant

**Status:** Accepted
**Date:** 2026-06-16
**Issue:** #4

## Context

Installers often request `sudo`, `su`, `doas`, `pkexec`, or administrator
rights. Running Arbitraitor itself as root would expose parsers, archive
handlers, AV adapters, and plugin hosts to root-level compromise. The
adversarial review (C-04) identified this as underspecified.

## Decision

### Invariant

> Arbitraitor analysis, parsing, rule evaluation, and plugin execution must
> **never** require elevated privileges.

### Default behavior

1. **Block elevation requests:** `sudo`, `su`, `doas`, `pkexec`, UAC elevation,
   and equivalent operations are blocked during mediated execution by default.
2. **Never inherit elevated tokens:** If Arbitraitor is started with root/admin
   privileges, it refuses to run unless in a narrowly defined diagnostic mode
   (`--allow-root`, explicitly logged).
3. **Main process is unprivileged:** Retrieval, parsing, scanning, plugin
   execution, and policy evaluation run as the normal user.

### Privileged helper (future, specified now)

If a future operation requires system modification (e.g., installing a package
system-wide), a separately installed **minimal privileged helper** is used:

| Property | Requirement |
|----------|-------------|
| Accepted input | Immutable artifact digests + declarative operations only |
| Rejected input | Arbitrary command strings, untrusted archives, scripts, policy, plugin output |
| Network | None |
| Parsers | None |
| Authentication | Authenticated local requests only |
| Revalidation | Immediately before the privileged operation |
| Audit | Every operation recorded in the receipt |
| Scope | No general shell-command endpoint |

The helper receives **declarative operations** (e.g., "install package
`sha256:abc...` to `/usr/local`"), not command strings. It revalidates
authorization immediately before performing the operation.

### Package installation strategy

For package installation, prefer handing an **already built and inspected
package** to the native package manager rather than elevating an arbitrary
installer script:

```text
arbitraitor fetch + inspect package artifact
  → arbitraitor approves the inspected artifact
  → privileged helper invokes: pacman -U <local-package-file>
  → NOT: sudo ./install.sh
```

## Consequences

- A compromise of Arbitraitor's parsers or plugins does not yield root.
- Installer scripts that invoke elevation are detected by script analysis and
  blocked by default in mediated execution.
- The privileged helper, if implemented, has a minimal attack surface (no
  parsers, no network, no plugins).
- Package-manager lifecycle mediation can model the hand-off to the native
  package manager as a "delegated" stage in the coverage report.

## Alternatives considered

- **Run as root with internal sandboxing:** Rejected. Kernel escape from a
  sandbox running as root is catastrophic.
- **setuid binary:** Rejected. Classic privilege-escalation attack vector.
- **No privileged helper ever:** Accepted for MVP. Package installation that
  requires elevation is reported as "delegated, not mediated" in the coverage
  report. The helper is specified but deferred.

## References

- `docs/spec/spec.md` §9.16 (No elevated analysis),
  §26.6 (Privilege boundary)
- `docs/spec/spec.md` C-04
- [ADR 0008](0008-execution-context-security-profile.md) — Execution context
