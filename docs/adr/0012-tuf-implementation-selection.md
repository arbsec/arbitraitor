# ADR 0012: TUF implementation selection

**Status:** Accepted
**Date:** 2026-06-16
**Issue:** #7

## Context

Arbitraitor needs signed update channels for rule packs, intelligence feeds,
trust-root metadata, and plugin registry metadata. The Update Framework (TUF)
provides the right security model: offline root keys, threshold signatures,
role separation, rollback protection, expiration, freeze-attack resistance,
and consistent snapshots.

AWS security bulletin 2026-019 disclosed multiple vulnerabilities in `tough`
(the Rust TUF implementation) before version 0.22.0:

- Delegated-role signature threshold bypass.
- Missing delegated metadata validation.
- Path traversal in metadata handling.

This demonstrates that update clients are themselves high-risk parsers and
authorization engines. The selection cannot be made casually.

## Decision

**No Rust TUF library is selected normatively** until the evaluation criteria
below are satisfied. The initial implementation uses a narrowly scoped
TUF-compatible first-party channel with minisign-signed metadata, behind an
internal `UpdateVerifier` trait.

### Evaluation criteria

Any selected implementation must pass ALL of the following:

1. **Current security advisories:** All known vulnerabilities fixed. If `tough`
   is selected, minimum version 0.22.0.
2. **Official TUF conformance suite:** Pass the official test vectors from the
   TUF specification.
3. **Adversarial tests:** Duplicate signatures, delegated metadata length/hash/
   expiry validation, cyclic delegation, path traversal, symlink targets,
   rollback, freeze, mix-and-match, endless data.
4. **Cache corruption behavior:** Corrupted local cache fails closed (denial of
   service), not silently treated as valid.
5. **Root bootstrap and recovery:** Documented procedure for initial root trust
   and out-of-band key recovery.
6. **Key separation and threshold policy:** Separate root, targets, snapshot,
   and timestamp keys. Root and preferably targets/snapshot keys offline with
   threshold signatures.

### Candidates

| Candidate | Status | Notes |
|-----------|--------|-------|
| `tough` >= 0.22.0 | Primary candidate (pending evaluation) | AWS-maintained; 2026-019 fixes applied in 0.22.0; must pass `tuf-conformance` suite + adversarial tests before adoption |
| `rust-tuf` | Deprioritized | Community-maintained; confirmed limited maintenance activity as of 2026-06 |
| Custom scoped implementation | Fallback | Narrower scope, easier to audit, but must implement TUF spec correctly |
| `go-tuf` (subprocess) | Not preferred | Adds Go runtime dependency; cross-language boundary |

### Interim approach

For the MVP, Arbitraitor uses:

```text
signed manifest (minisign)
  → verify against pinned public key
  → parse versioned metadata
  → fetch targets with declared SHA-256
  → reject older snapshot versions (rollback protection)
  → check expiration timestamps
```

This provides:

- Signed updates (minisign).
- Version rollback protection.
- Expiration checking.
- Target integrity verification.

It does NOT provide the full TUF delegation model. Full TUF is deferred until
the ADR is finalized with conformance results.

### Separation of trust roots

| Channel | Trust root | Key type |
|---------|-----------|----------|
| Binary releases | Sigstore/cosign + GitHub attestation | Per-release OIDC |
| Built-in rule packs | TUF/minisign | Offline project key |
| Intelligence feeds | TUF/minisign | Per-feed signing key |
| Trust-root metadata | TUF root role | Offline threshold keys |
| Plugin registry | TUF/minisign | Project-controlled |

### Trusted time

Update metadata depends on time for expiration and freshness:

- **Monotonic timers** for operation deadlines (not affected by clock changes).
- **Wall-clock sanity checks:** detect large backward jumps.
- **Offline grace policy:** explicit grace period for expired metadata when
  offline, not silent acceptance.
- **Optional trusted-time source** for managed environments.

## Consequences

- Update security is not blocked on TUF library selection.
- The `UpdateVerifier` trait allows swapping the implementation when a library
  passes evaluation.
- Community registry (delegated trust) is deferred until full TUF is available.
- The interim minisign approach is simpler to audit but lacks delegation.

## Alternatives considered

- **Use `tough` immediately (pre-evaluation):** Rejected. The 2026-019
  advisory demonstrates the risk of unaudited TUF implementations.
- **No signed updates (unsigned HTTPS only):** Rejected. HTTPS alone is
  insufficient for update integrity (CDN compromise, MITM with corporate CA).
- **Custom full TUF from scratch:** Deferred. High implementation risk without
  conformance suite verification.

## References

- `.spec/arbitraitor-adversarial-review-and-gap-analysis.md` C-06
- `.spec/arbitraitor-tech-stack.md` §13.1 (TUF metadata)
- `.spec/arbitraitor-comprehensive-spec-v0.4.md` §34 (Update security)
- [AWS Security Bulletin 2026-019](https://aws.amazon.com/security/security-bulletins/2026-019-aws/)
- [TUF Security](https://theupdateframework.io/docs/security/)
- [TUF FAQ](https://theupdateframework.io/docs/faq/)
- [TUF Conformance Suite](https://github.com/theupdateframework/tuf-conformance)
- [ADR 0013](0013-plan-bound-approval-capability.md) — Plan-bound approval
