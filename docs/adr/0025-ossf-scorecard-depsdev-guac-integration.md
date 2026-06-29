# ADR 0025: OpenSSF Scorecard, deps.dev, and GUAC as optional integrations

**Status:** Proposed
**Date:** 2026-06-29
**Issue:** #275

## Context

Spec v0.5 §21.8 and §21.9 describe project-posture signals (OpenSSF
Scorecard, deps.dev) and supply-chain graph query (GUAC) as optional
enterprise integrations. These tools provide independent signals about a
project's security posture that complement artifact-level signals (hash,
signature, reputation).

GUAC (Graph for Understanding Artifact Composition) v1.1.0 aggregates SBOM,
DSSE, deps.dev, in-toto ITE-6, Scorecard, OSV, SLSA, SPDX, CSAF VEX, and
OpenVEX into a queryable graph. It is a separate service, not a library.

## Decision

These are **proposed optional enterprise integrations**, not implemented or
required core Arbitraitor capabilities:

1. **OpenSSF Scorecard** — Arbitraitor would consume Scorecard results as a
   detector input (advisory, never authoritative). This requires the
   artifact's source repository to be resolvable. When unresolvable, the
   signal would be `unavailable` — never `passing`.

2. **deps.dev** — provides license info, package deprecation, and
   dependency resolution depth. Consumed as a supplementary signal alongside
   OSV/KEV (§18.5).

3. **GUAC** — Arbitraitor receipts (via the optional in-toto export,
   ADR-0023) are **ingestible by GUAC** as DSSE-wrapped in-toto Statements.
   An enterprise deploys GUAC separately and queries it across all
   supply-chain artifacts. Arbitraitor does not embed or require GUAC.

Arbitraitor operates fully without any of these integrations. Receipts do
not depend on their availability (§3.10: "fail closed for enforcement, fail
explainably for tooling").

## Consequences

- No new hard dependencies. Scorecard/deps.dev data is fetched via HTTP when
  policy opts in; GUAC is an external service.
- Enterprise users gain supply-chain graph queryability without Arbitraitor
  embedding the tooling.
- Scorecard posture is one signal among many — it never authorizes release
  (invariant 5, invariant 22) and never overrides malware findings
  (invariant 21).

## Alternatives considered

- **Embed GUAC as a library:** would add significant dependency surface and
  architectural coupling for a feature that only benefits enterprise users.
- **Require Scorecard for all artifacts:** most artifacts' source repos are
  unresolvable; would produce `incomplete` verdicts for legitimate downloads.

## References

- OpenSSF Scorecard: <https://scorecard.dev/>
- deps.dev API: <https://docs.deps.dev/api/>
- GUAC: <https://github.com/guacsec/guac>
- Spec §21.8, §21.9, §46.1
