# ADR 0026: EU CRA / NIST SSDF informational compliance mapping

**Status:** Proposed
**Date:** 2026-06-29
**Issue:** #276

## Context

The EU Cyber Resilience Act (Reg 2024/2847) enters force December 2024
with vulnerability reporting obligations applying from September 2026 and
full applicability from December 2027. Annex I Part II requires a
machine-readable SBOM of top-level dependencies. Article 14 mandates
24h/72h/14d vulnerability reporting to CSIRTs/ENISA.

The US Executive Order 14028, OMB M-22-18, and OMB M-23-09 require federal
software vendors to self-attest to NIST SSDF (SP 800-218) conformance.

Arbitraitor's spec §44.1 describes an informational compliance mapping,
not a normative self-attestation. Normative claims require legal and
process evidence the spec cannot define.

## Decision

Arbitraitor provides an **informational evidence matrix** mapping current
controls to CRA and SSDF language. The matrix documents what Arbitraitor
**does** (not what it _satisfies_):

### EU CRA mapping (informational)

| CRA Requirement | Arbitraitor Control |
|---|---|
| Annex I Part II: SBOM in machine-readable format | CycloneDX 1.6 SBOM generated via `cargo-cyclonedx` for Arbitraitor releases (§44) |
| Article 14: 24h/72h/14d vulnerability reporting | `SECURITY.md` directs reports to GitHub private vulnerability reporting; reporting cadence is an operational responsibility, not a code feature |
| Recital 77: SBOM need not be public | SBOM is attached to releases but not published to a public registry |

### NIST SSDF mapping (informational)

| SSDF Practice | Arbitraitor Control |
|---|---|
| PO.5.1 (define security requirements) | Spec §9 security invariants; ADRs for every security-relevant decision |
| PS.1.1 (protect components from tampering) | SHA-256 CAS with invariant 2 (immutable identity) |
| PS.2.1 (automated build) | GitHub Actions with pinned actions by SHA; OIDC trusted publishing |
| PS.3.2 (provenance) | GitHub artifact attestations; SLSA Build L2 target (ADR-0022) |
| PW.4.4 (review human-readable code) | CODEOWNERS with security-owner review for sensitive paths |
| PW.5.1 (code-based configuration) | TOML configuration with `deny_unknown_fields` (ADR-0004) |
| PW.6.2 (test cases) | 900+ tests across unit, property, integration, invariant, and fuzz layers |
| PW.7.1 (build from separate environment) | `--locked` release builds from protected tags |
| PW.8.2 (static analysis) | Clippy with `-D warnings`; CodeQL; YARA-X for artifact content |
| RV.1.1 (identify vulnerabilities) | `cargo-audit`, `cargo-deny`, GitHub dependency review |
| RV.3.2 (root-cause analysis) | Receipts provide full audit trail; ADRs document decisions |

This mapping is **informational**, not a procurement self-attestation. The
word "satisfies" is deliberately avoided.

## Consequences

- Arbitraitor can be cited in federal procurement context as having SSDF
  controls mapped, but the mapping is not a legal self-attestation.
- The matrix must be maintained as controls evolve.
- CRA vulnerability-reporting cadence (Article 14) is an operational
  responsibility, not a code feature — the mapping notes this explicitly.

## Alternatives considered

- **Normative self-attestation:** requires legal review and process
  evidence; premature for a pre-1.0 project.
- **No mapping at all:** limits enterprise adoption credibility.

## References

- EU CRA: <https://eur-lex.europa.eu/eli/reg/2024/2847/oj/eng>
- NIST SSDF: <https://csrc.nist.gov/pubs/sp/800/218/final>
- OMB M-23-09: <https://www.whitehouse.gov/wp-content/uploads/2022/09/M-23-09-Memo-on-Self-Attestation.pdf>
- Spec §44.1
