# ADR 0003: reqwest behind Fetcher trait

**Status:** Accepted
**Date:** 2026-06-16

## Context

Arbitraitor needs an HTTP client for artifact retrieval. The choice affects TLS
trust, redirect handling, decompression behavior, proxy semantics, and the
ability to bind security policy to the actual connection (SSRF defense). No
reqwest types should cross crate boundaries.

## Decision

Use **reqwest with Tokio and rustls** for the MVP, hidden behind an internal
`Fetcher` trait:

```rust
#[async_trait::async_trait]
pub trait Fetcher: Send + Sync {
    async fn fetch(
        &self,
        request: FetchRequest,
        sink: &mut dyn ArtifactSink,
    ) -> Result<FetchReceipt, FetchError>;
}
```

**Exact-byte semantics:**

- Send `Accept-Encoding: identity`.
- Disable reqwest's automatic gzip, Brotli, deflate, and zstd response
  decoding.
- Hash and store the HTTP representation bytes received after transfer framing.
- If wrapper semantics request content decoding, store the encoded artifact
  and create a separately hashed decoded child artifact. Scan and execute the
  decoded child. Record both identities and the transformation edge.

**TLS:**

- rustls with a policy-selectable verifier.
- TLS 1.2 and 1.3 only.
- Certificate validation mandatory; hostname validation mandatory.
- No user-facing "ignore all TLS errors" shortcut.
- Insecure modes require explicit policy and cannot be used for execution in
  enforcement mode.
- Record peer certificate fingerprints and negotiated protocol.
- A valid certificate is **not** publisher provenance.

**Redirects:** implemented in Arbitraitor policy, not accepted as reqwest
defaults. See [ADR 0018](0018-ssrf-proxy-connected-peer-verification.md) for
full redirect, SSRF, and proxy semantics.

## Consequences

- Preserves the option to use Hyper directly for a lower-level connector if
  reqwest cannot bind policy to the actual connection in the future.
- No reqwest types cross crate boundaries.
- Exact-byte identity is well-defined: what was hashed is what was scanned is
  what was executed.

## Alternatives considered

- **Hyper direct:** More control over connectors but more boilerplate. Deferred;
  the `Fetcher` trait allows migration.
- **ureq:** Simpler, synchronous. Rejected—Tokio async is needed for streaming
  into CAS while hashing.
- **isahc (libcurl bindings):** Rejected. C FFI in a security boundary adds
  attack surface.

## References

- `.spec/arbitraitor-tech-stack.md` §4 (HTTP and transport stack)
- `.spec/arbitraitor-comprehensive-spec-v0.4.md` §11 (Retrieval subsystem)
- [ADR 0018](0018-ssrf-proxy-connected-peer-verification.md) — SSRF and proxy
