# ADR 0023: in-toto Statement receipt envelope

**Status:** Proposed
**Date:** 2026-06-29
**Issue:** #273

## Context

Arbitraitor receipts are RFC 8785 JCS canonicalized JSON (ADR-0014). For
interoperability with supply-chain tools (GUAC, Sigstore, in-toto verifylib,
dependency-management platforms), receipts should be exportable as in-toto
Statements per ITE-6 (`_type: https://in-toto.io/Statement/v1`).

Changing the canonical receipt format would be a breaking change and risk
schema churn. The question is whether to wrap receipts in in-toto Statements
canonically or as an optional derived export.

## Decision

The canonical Arbitraitor receipt format is RFC 8785 JCS JSON
(ADR-0014). This ADR proposes adding an optional derived export as an
in-toto Statement:

```json
{
  "_type": "https://in-toto.io/Statement/v1",
  "subject": [{ "name": "sha256:...", "digest": { "sha256": "..." } }],
  "predicateType": "https://arbitraitor.dev/verdict/v1",
  "predicate": { /* full Arbitraitor receipt object */ }
}
```

Two predicate types are defined:

- `https://arbitraitor.dev/verdict/v1`: the verdict receipt
- `https://arbitraitor.dev/payload-graph/v1`: the payload graph alone

The Statement is signed via DSSE (Dead Simple Signing Envelope) per in-toto
conventions, using the same key/capability as the canonical receipt.

The export is requested via `arbitraitor inspect --receipt receipt.json
--export-intoto statement.json` or the daemon library API.

Anti-forgery: the in-toto export includes the canonical receipt's own
signature in `predicate.provenance.receipt_signature` so downstream
consumers can detect mismatch between Statement and receipt.

## Consequences

- Receipts remain backward-compatible (no schema change).
- GUAC and other in-toto-compatible tools can ingest Arbitraitor receipts
  natively.
- The export is a separate code path that must be maintained and tested.
- DSSE signature verification adds a dependency or requires manual
  verification logic.

## Alternatives considered

- **Canonical in-toto envelope (replacing JCS):** breaking change, high risk.
- **No in-toto support:** limits interoperability with supply-chain platforms.

## References

- ITE-6 Attestation Framework: <https://github.com/in-toto/attestation/blob/main/spec/v1/README.md>
- DSSE: <https://github.com/secure-systems-lab/dsse>
- ADR-0014 (receipt canonicalization), Spec §31.3.1
