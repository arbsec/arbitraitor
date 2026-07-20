# ADR 0029: VEX format support matrix

**Status:** Accepted
**Date:** 2026-07-20
**Issue:** #468

## Context

Arbitraitor consumes VEX companion artifacts as provenance evidence for package-risk findings. The supported formats must be explicit because older OpenVEX drafts used different product and vulnerability shapes, CSAF 2.0 is now ISO/IEC 20153, and CSAF 2.1 adds fields such as CVSS v4 and company involvements.

## Decision

Arbitraitor supports this matrix for VEX companion artifacts:

| Format | Status | Notes |
|--------|--------|-------|
| OpenVEX 0.0.x | Rejected | Missing or legacy context defaults are ambiguous and predate the 0.2.0 product/vulnerability structs. |
| OpenVEX 0.1.x | Deprecated/rejected | Consumers must publish 0.2.0 documents for Arbitraitor ingestion. |
| OpenVEX 0.2.0 | Supported | Required `@context` is `https://openvex.dev/ns/v0.2.0`; products use the `products` array with product structs; vulnerabilities use the expanded vulnerability struct. |
| CSAF 1.x | Rejected | Legacy CSAF documents are outside the VEX profile support boundary. |
| CSAF 2.0 | Supported | CSAF VEX profile documents are accepted as ISO/IEC 20153-compatible input. |
| CSAF 2.1 | Preferred | CSAF VEX profile documents are accepted with CVSS v4 vector strings and involvement statements. |

The model crate exposes typed format-version labels so downstream policy can distinguish accepted and rejected formats without relying on raw strings.

## Consequences

- Unknown fields in security-critical VEX input structs are rejected by serde where the external schemas are modeled.
- Older OpenVEX documents fail closed with a clear unsupported-context error.
- CSAF VEX feeds are first-class intelligence sources for §21.4 source-class policy.
- CSAF 2.1 can preserve CVSS v4 and company-involvement evidence for receipts and future policy decisions.

## Alternatives considered

- Accept OpenVEX 0.0.x/0.1.x and normalize legacy `product` string fields. Rejected because it would preserve ambiguous drafts after a breaking schema update.
- Treat CSAF VEX as a generic authoritative feed. Rejected because §21.4 needs a first-class CSAF source class for auditability.
- Add a full CSAF schema dependency. Rejected for this change because the workspace already has serde and the issue only requires the VEX profile subset.

## References

- OpenVEX 0.2.0 specification: <https://github.com/openvex/spec/blob/main/OPENVEX-SPEC.md>
- CSAF 2.1 specification: <https://docs.oasis-open.org/csaf/csaf/v2.1/csaf-v2.1.html>
- CSAF 2.0 ISO/IEC 20153 approval announcement: <https://www.oasis-open.org/2025/05/20/csaf-2-0-approved-as-iso-iec-20153/>
