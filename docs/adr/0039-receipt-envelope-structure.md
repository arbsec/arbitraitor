# ADR 0039: Receipt envelope structure (spec §31.1)

**Status:** Accepted
**Date:** 2026-07-23
**Issue:** #492

## Context

The receipt schema (v1) used a flat structure where all fields lived at the
top level of the `Receipt` struct. As the receipt grew to include
provenance, detector, policy, and release metadata, the flat structure
became difficult to navigate and did not match the spec §31.1 top-level
envelope shape:

```json
{
  "schema_version": 1,
  "request": {},
  "artifact": {},
  "retrieval": {},
  "provenance": {},
  "payload_graph": {},
  "detectors": [],
  "findings": [],
  "policy": {},
  "verdict": {},
  "release": {},
  "timestamps": {}
}
```

Issue #492 flagged this as a HIGH-severity spec gap.

## Decision

Adopt the spec §31.1 envelope structure as schema v2. The `Receipt` struct
is reorganized into grouped sub-structs:

| Bucket | Sub-struct | Fields moved from v1 top-level |
|--------|-----------|-------------------------------|
| `request` | `RequestInfo` | `arbitraitor_version`, `config_digest` |
| `artifact` | `ArtifactInfo` | `artifact_sha256` → `sha256`, `artifact_size` → `size`, `artifact_type` |
| `retrieval` | `Option<RetrievalInfo>` | unchanged |
| `provenance` | `ProvenanceInfo` | `verifier_identity`, `detector_provenance`, `signature`, `signatures` |
| `payload_graph` | `Option<PayloadGraph>` | unchanged (now always present as key, null when None) |
| `detectors` | `Vec<DetectorVersion>` | `detector_versions` |
| `findings` | `Vec<FindingSummary>` | unchanged |
| `policy` | `PolicyInfo` | `policy_digest`, `allow_rule_metadata`, `audit_trail` |
| `verdict` | `VerdictInfo` | unchanged |
| `release` | `Option<ReleaseInfo>` | `approval` and `effective_controls` moved from top-level into `ReleaseInfo` |
| `timestamps` | `ReceiptTimestamps` | unchanged |

### Migration path

`Receipt::parse(json)` accepts both v1 (flat) and v2 (envelope) JSON. v1
receipts are deserialized into `ReceiptV1` and converted to v2 via
`Receipt::from_v1()`. This allows existing receipt files on disk to be
read transparently.

### Canonicalization

`unsigned_canonical_bytes()` clears `provenance.signature` and
`provenance.signatures` before canonicalization (ADR-0014). The signature
fields moved from top-level to `provenance.*` but the canonicalization
logic is unchanged — signatures are still excluded to prevent
self-reference.

### Builder API

`ReceiptBuilder` method signatures are unchanged. The builder internally
constructs the nested structure and handles the `approval` and
`effective_controls` fields via pending state that is merged into `release`
on `build()`.

## Consequences

- **Breaking change:** any code that directly accesses `receipt.artifact_sha256`,
  `receipt.policy_digest`, etc. must update to `receipt.artifact.sha256`,
  `receipt.policy.policy_digest`, etc.
- `schema_version` bumped from 1 to 2.
- All 12 top-level keys are always present in serialized JSON (spec §31.1
  acceptance criterion).
- v1 receipts on disk are automatically migrated when read via
  `Receipt::parse()`.
- in-toto Statement export (ADR-0023) and SARIF export (§31.4) continue to
  work — they read from the nested `artifact.sha256` field.
- The `ReceiptBuilder` API is source-compatible — downstream callers that
  use the builder do not need changes.

## Alternatives considered

- **Keep flat structure, add envelope as a wrapper type:** rejected because
  the spec §31.1 explicitly requires the top-level keys to be the envelope
  buckets. A wrapper would add an extra nesting level not in the spec.
- **Make all fields always present (non-Option):** rejected because
  `retrieval`, `payload_graph`, and `release` are genuinely optional (not
  all flows produce them). They serialize as `null` when absent, which
  satisfies the "all top-level keys present" requirement.

## References

- Spec §31.1 (top-level envelope structure)
- ADR-0014 (receipt canonicalization, RFC 8785 JCS)
- ADR-0023 (in-toto Statement receipt envelope)
- Issue #492
