# ADR 0014: Receipt canonicalization (RFC 8785 JCS)

**Status:** Proposed
**Date:** 2026-06-16
**Issue:** #9

## Context

Signed receipts require a canonical byte representation for the signature
input. "Canonical JSON or binary" is too vague for interoperability. Different
JSON serializers produce different byte output (key ordering, whitespace,
number formatting, Unicode escaping), which breaks signature verification
across implementations.

The adversarial review (H-06) recommended RFC 8785 JSON Canonicalization
Scheme (JCS) and warned against the abandoned `serde_jcs` crate.

## Decision (proposed)

### Receipt format

1. **User-facing receipts** remain normal JSON (pretty-printed, human-readable).
2. **Signature input** uses **RFC 8785 JSON Canonicalization Scheme (JCS)**.
3. **Algorithm and key ID** are included **outside** the signed payload (in a
   wrapper or detached signature).

### Canonicalization rules (RFC 8785)

Before canonicalization, reject:

- Duplicate JSON keys in any object.
- Non-I-JSON numbers (NaN, Infinity, excessive precision).
- Invalid Unicode (unpaired surrogates, non-characters).
- Excessive nesting depth (limit: 128).
- Oversized values (string limit: 1 MiB, total document limit: 16 MiB).

RFC 8785 mandates:
- **Lexicographic key ordering** at every object level (UTF-16 code unit
  comparison).
- **Number serialization** in the shortest round-trippable form (no trailing
  zeros, scientific notation with lowercase `e` when shorter).
- **String serialization** with required escape sequences (`\"`, `\\`,
  control characters as `\u00XX`).
- **No whitespace** between tokens.
- **No trailing newline.**

### Library evaluation

| Candidate | Status | Notes |
|-----------|--------|-------|
| `serde_json_canonicalizer` | **Recommended (pending conformance tests)** | Maintained; purpose-built for RFC 8785 |
| `serde_jcs` | **Rejected** | Maintenance concerns; known conformance divergences |
| Custom implementation | Fallback | Last resort; high risk of subtle bugs |

**Selection criteria:**
1. Passes official RFC 8785 test vectors.
2. Rejects duplicate keys, invalid Unicode, non-I-JSON numbers.
3. Deterministic output across platforms and architectures.
4. Maintained and responsive to issues.
5. No unsafe code.

### Signature envelope

```json
{
  "receipt": { ... },
  "signature": {
    "algorithm": "ed25519",
    "key_id": "sha256:abc123...",
    "value": "base64:...",
    "canonicalization": "rfc8785"
  }
}
```

The `receipt` object is canonicalized per RFC 8785, then the canonical bytes
are signed. The `signature` object is **not** part of the signed payload.

### Test vectors

Arbitraitor publishes official canonicalization test vectors covering:
- Key ordering (including UTF-16 ordering edge cases).
- Number formatting (integers, floats, scientific notation).
- String escaping (control chars, surrogates, non-ASCII).
- Nesting and empty containers.
- Duplicate key rejection.
- Receipt-sized realistic examples.

## Consequences

- Receipt signatures are verifiable by any RFC 8785-compliant implementation,
  not just Arbitraitor.
- The canonicalization is deterministic: the same receipt always produces the
  same signature.
- Large receipts (deep payload graphs, many findings) are bounded by the
  nesting and size limits.
- The canonicalization library is a critical-path dependency for receipt
  signing — it must be audited and fuzzed.

## Alternatives considered

- **CBOR canonical encoding:** Considered. More compact binary format with a
  well-defined canonical form (RFC 7049 §3.1). However, receipts are JSON-first
  for human readability and tooling interoperability. CBOR could be used for the
  signature input while keeping JSON for display, but this adds complexity.
- **TLS-style signed JSON (custom):** Rejected. Custom canonicalization is a
  well-known source of signature bypass vulnerabilities.
- **JWT/JWS:** Rejected. Base64url-encoded, not human-readable, and the claims
  model doesn't map cleanly to receipts.

## References

- `.spec/arbitraitor-adversarial-review-and-gap-analysis.md` H-06
- `.spec/arbitraitor-tech-stack.md` §6.4 (Signed receipt canonicalization)
- [RFC 8785 — JSON Canonicalization Scheme](https://www.rfc-editor.org/rfc/rfc8785.html)
- [RFC 8259 — The JSON Data Interchange Syntax](https://www.rfc-editor.org/rfc/rfc8259)
- [I-JSON (RFC 7493)](https://www.rfc-editor.org/rfc/rfc7493.html)
