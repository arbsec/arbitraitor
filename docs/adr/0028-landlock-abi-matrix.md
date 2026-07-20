# ADR 0028: Landlock ABI Matrix and Receipt Recording

**Status:** Accepted
**Date:** 2026-07-20
**Issue:** #466

## Context

Spec §27.3 requires Linux Landlock for contained execution but previously did
not enumerate the ABI features behind that label. Current kernels expose an
expanding Landlock UAPI, and receipt consumers need to know which controls were
actually available on the host that executed untrusted code.

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
value is stored as `LandlockAbiVersion` and propagated through sandbox state so
contained-execution receipts can record the effective ABI.

Sandbox policy targets Landlock ABI v6 or newer when available because v6 adds
signal and abstract UNIX socket scope. Hosts with ABI v4 or v5 remain acceptable
for pre-6.10 kernels but are recorded as lower-assurance: TCP connect/bind is
available, while newer signal, audit, TSYNC, and UDP controls are absent. Hosts
with ABI lower than v4 do not enforce TCP connect/bind through Landlock;
receipts must record the network port-constraint sub-control as unavailable and
the verdict downgrades according to spec §27.7.

The probe is observational and does not itself install a sandbox. Enforcement
code still masks requested access rights to the ABI that the kernel reports
before creating rulesets.

## Consequences

- Receipt consumers can audit whether a contained run used Landlock v1-v10 or a
  future non-zero ABI.
- Future Landlock controls can be represented before the policy matrix learns
  their full semantics.
- Linux hosts without Landlock report no ABI, forcing callers to treat
  filesystem isolation as unavailable when containment is mandatory.
- macOS and Windows report no Landlock ABI; their platform strategies remain
  governed by their dedicated ADRs.

## Alternatives considered

- **Kernel release parsing.** Rejected because backports and downstream patches
  make release strings less authoritative than the Landlock UAPI probe.
- **Compile-time ABI constants only.** Rejected because the host kernel, not the
  build machine, determines the effective sandbox controls.
- **Failing on ABI below v6 unconditionally.** Rejected for compatibility with
  pre-6.10 hosts; receipts and verdict downgrades communicate the weaker
  control set without pretending it is fully contained.

## References

- Linux `landlock_create_ruleset(2)`
- Spec §27.3, §27.7
- ADR-0007: Assurance levels model
- ADR-0021: Landlock filesystem isolation for subprocess plugins
