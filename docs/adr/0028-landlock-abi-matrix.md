# ADR 0028: Landlock ABI Probe and Receipt Recording

**Status:** Accepted
**Date:** 2026-07-20
**Issue:** #466

## Context

Spec §27.3 requires Linux Landlock for contained execution. Current kernels
expose an expanding Landlock UAPI, and receipt consumers need to know which ABI
the host reported when untrusted code executed. Issue #466 tracks adding that
observable signal without changing enforcement semantics in the same step.

Landlock ABI versions relevant to Arbitraitor:

| ABI | Kernel | Added controls |
|-----|--------|----------------|
| v1 | 5.13 | Initial filesystem restrictions |
| v2 | 5.19 | File modes isolation |
| v3 | 6.2 | Truncate / ioctl restrictions |
| v4 | 6.7 | TCP connect/bind |
| v5 | 6.10 | IOCTL device |
| v6 | 6.12 | Signal scope + abstract UNIX socket |
| v7 | 6.15 | Audit log |
| v8 | 7.0-rc | `LANDLOCK_RESTRICT_SELF_TSYNC` |
| v9 | 6.13+ downstream patches | `RESOLVE_UNIX` |
| v10 | 6.16 | UDP connect/bind |

## Decision

Arbitraitor probes the running kernel at runtime with
`landlock_create_ruleset(NULL, 0, LANDLOCK_CREATE_RULESET_VERSION)`. The return
value is represented as `LandlockAbiVersion` and may be copied into
contained-execution effective-control receipts when filesystem isolation is
backed by Landlock.

This ADR is record-only. It does not set minimum acceptable ABI versions, change
verdict downgrades, or claim TCP/UDP/signal/audit enforcement. Current
enforcement remains limited to the filesystem access rights already installed by
the sandbox crate; ABI v4+ semantics are recorded only until a follow-up policy
matrix defines and tests sub-control behavior.

## Consequences

- Receipt consumers can audit whether a contained run observed Landlock v1-v10
  or a future non-zero ABI.
- Future Landlock controls can be represented before Arbitraitor claims their
  enforcement semantics.
- Linux hosts without Landlock report no ABI, forcing callers to treat
  filesystem isolation as unavailable when containment is mandatory.
- macOS and Windows report no Landlock ABI; their platform strategies remain
  governed by their dedicated ADRs.
- A follow-up ADR or issue must define the Landlock ABI policy matrix before
  Arbitraitor uses ABI v4+ features for assurance-level decisions.

## Alternatives considered

- **Kernel release parsing.** Rejected because backports and downstream patches
  make release strings less authoritative than the Landlock UAPI probe.
- **Compile-time ABI constants only.** Rejected because the host kernel, not the
  build machine, determines the effective sandbox controls.
- **Failing on ABI below v6 unconditionally.** Rejected for this change because
  issue #466 only introduces probing and receipt exposure; minimum-version
  policy belongs in the planned matrix.

## References

- Linux `landlock_create_ruleset(2)`
- Spec §27.3, §27.7
- ADR-0007: Assurance levels model
- ADR-0021: Landlock filesystem isolation for subprocess plugins
