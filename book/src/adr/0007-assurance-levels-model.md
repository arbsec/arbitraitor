# ADR 0007: Assurance levels model

**Status:** Accepted
**Date:** 2026-06-16
**Issue:** #2

## Context

The original specification protected artifact identity (SHA-256, single retrieval, immutable CAS) but did not sufficiently protect the execution context. A benign scanned script can be turned malicious by inherited environment variables, shell startup files, a poisoned `PATH`, a replaced interpreter, inherited file descriptors, unrestricted network access, or an attacker-controlled working directory.

The adversarial review (C-01, C-02) identified this as the most critical gap: artifact integrity is stronger than execution-context integrity.

## Decision

Define three user-visible **assurance levels**. Every `run` operation must record which level was in effect. Receipts record each effective control independently.

### Level 1: Inspect

Retrieval, hashing, identification, scanning, and reporting. **No execution.**

Guarantees:

- Complete buffering before verdict.
- Exact artifact identity (SHA-256).
- Configured static and reputation checks.
- Payload graph discovery.

No runtime claim is made. The artifact was never executed.

### Level 2: Mediated execution

The exact approved artifact is executed in a deliberately constructed process context.

**Mandatory controls:**

| Control | Requirement |
|---------|-------------|
| Artifact | Approved immutable CAS object |
| Interpreter | Pinned or revalidated immediately before invocation |
| Environment | Allowlisted (not inherited) |
| Interpreter profiles | Disabled (`--noprofile --norc`, `-NoProfile`) |
| Home directory | Temporary |
| Working directory | Temporary |
| Inherited descriptors | Closed |
| Privilege elevation | Denied |
| Network | Denied by default |
| PATH | Controlled |
| Platform provenance | Preserved or added |

This **reduces risk but is not a sandbox guarantee.** If any control is unavailable or relaxed by policy, the assurance level must be reported as degraded — never presented as equivalent to full mediation.

### Level 3: Contained execution

Mediated execution **plus** a verified platform isolation profile.

**Additional mandatory controls:**

| Control | Requirement |
|---------|-------------|
| Filesystem isolation | Enforced (chroot, namespace, AppContainer, etc.) |
| Process-tree containment | Enforced |
| Network policy | Enforced (namespace, filter, broker) |
| Resource limits | Enforced |
| Privilege suppression | `no-new-privileges` or platform equivalent |
| Capability probe | Proves required controls are active |
| Fail-closed | When requested containment is unavailable |

**Platform capability matrix** (recorded per-control in receipt):

```
filesystem isolation:   enforced | partial | unavailable
network isolation:      enforced | partial | unavailable
process-tree control:   enforced | partial | unavailable
privilege suppression:  enforced | partial | unavailable
system-call filtering:  enforced | partial | unavailable
registry/settings iso:  enforced | partial | unavailable
```

This is **never** collapsed into a single `sandboxed = true` boolean.

### Verdict language

The verdict must reference the effective assurance level. Examples:

```
PASS (inspect) — static analysis complete, no execution performed.
PASS (mediated) — executed with clean environment, network denied.
WARN (mediated) — executed with network enabled (policy exception).
INCOMPLETE (contained) — requested Landlock unavailable; fell back to mediated.
```

The label **"safe"** is prohibited. Recommended labels: `low observed risk`, `elevated observed risk`, `high observed risk`, `blocked by policy`, `analysis incomplete`, `unrestricted runtime`.

## Consequences

- Users and automation can distinguish static inspection from controlled execution from contained execution.
- A clean static scan with unrestricted network is **not** presented as equivalent to contained, network-denied execution.
- Receipts carry the capability matrix, enabling downstream auditors to verify what controls were actually in effect.
- macOS initially supports inspect and mediated only (no contained parity claim) — see ADR 0008.

## Alternatives considered

- **Binary safe/unsafe verdict:** Rejected. Same content may be appropriate in a disposable container and unacceptable on a workstation with SSH keys.
- **Single sandboxed boolean:** Rejected. Hides which controls were effective.
- **Numeric risk score:** Rejected for MVP. Easy to game, encourages false equivalence. Presentation-only score may be reconsidered after calibration data exists.

## References

- `.spec/arbitraitor-comprehensive-spec-v0.4.md` §3.11 (Assurance levels)
- `.spec/arbitraitor-adversarial-review-and-gap-analysis.md` §2 (Recommended assurance model), C-01, C-02
- `.spec/arbitraitor-tech-stack.md` §9 (Execution-context security)
