# Architecture Decision Records

An ADR captures a decision that is architecturally significant, security-sensitive,
or expensive to change later. Each ADR is immutable once accepted; a new ADR must
supersede it.

## States

- **Proposed** — draft, open for discussion
- **Accepted** — decision is final and binding
- **Superseded** — replaced by a later ADR (reference included)
- **Rejected** — considered but not adopted (reasons recorded)

## Index

### Foundational

| ADR | Title | Status | Issue |
|-----|-------|--------|-------|
| [0001](0001-rust-2024-and-toolchain-policy.md) | Rust 2024 and toolchain policy | Accepted | — |
| [0002](0002-workspace-structure-and-crate-boundaries.md) | Workspace structure and crate boundaries | Accepted | — |
| [0003](0003-reqwest-behind-fetcher-trait.md) | reqwest behind Fetcher trait | Accepted | — |
| [0004](0004-toml-for-configuration-and-policy.md) | TOML for configuration and policy | Accepted | — |
| [0005](0005-redb-non-authoritative-metadata-index.md) | redb as non-authoritative metadata index | Accepted | #12 |
| [0006](0006-wasmtime-component-model-plugins.md) | Wasmtime Component Model for plugins | Accepted | — |

### Security architecture (P0 from adversarial review)

| ADR | Title | Status | Issue |
|-----|-------|--------|-------|
| [0007](0007-assurance-levels-model.md) | Assurance levels model (inspect/mediated/contained) | Accepted | #2 |
| [0008](0008-execution-context-security-profile.md) | Execution context security profile | Accepted | #3 |
| [0009](0009-privilege-separation-no-root-invariant.md) | Privilege separation and no-root invariant | Accepted | #4 |
| [0010](0010-platform-provenance-preservation.md) | Platform provenance preservation | Accepted | #5 |
| [0011](0011-plugin-trust-classification.md) | Plugin trust classification model | Accepted | #6 |
| [0012](0012-tuf-implementation-selection.md) | TUF implementation selection | Accepted | #7 |
| [0013](0013-plan-bound-approval-capability.md) | Plan-bound approval capability model | Accepted | #8 |
| [0014](0014-receipt-canonicalization-rfc-8785-jcs.md) | Receipt canonicalization (RFC 8785 JCS) | Accepted | #9 |
| [0015](0015-safe-destination-release-semantics.md) | Safe destination release semantics | Accepted | #10 |
| [0016](0016-terminal-and-unicode-sanitization.md) | Terminal and Unicode sanitization renderer | Accepted | #11 |
| [0017](0017-monotonic-project-configuration.md) | Monotonic project configuration | Accepted | #13 |
| [0018](0018-ssrf-proxy-connected-peer-verification.md) | SSRF, proxy, and connected-peer verification | Accepted | #14 |
| [0019](0019-catch-unwind-and-panic-abort.md) | catch_unwind and panic=abort interaction | Accepted | #80 |

## Format

```markdown
# ADR NNNN: Title

**Status:** Accepted | Proposed | Superseded by ADR-XXXX | Rejected
**Date:** YYYY-MM-DD
**Issue:** #NN (GitHub issue this ADR resolves, if applicable)

## Context

Why this decision is needed.

## Decision

What was decided.

## Consequences

What follows from the decision.

## Alternatives considered

Options that were evaluated and rejected.

## References

Spec sections, advisories, standards, library docs.
```
