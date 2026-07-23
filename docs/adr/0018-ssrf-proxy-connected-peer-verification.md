# ADR 0018: SSRF, proxy, and connected-peer address verification

**Status:** Accepted
**Date:** 2026-06-16
**Issue:** #14

## Context

The adversarial review (H-03) identified that ambient proxy settings, system
proxy configuration, cookie jars, netrc files, and custom cert stores can
influence reqwest behavior. With a proxy, Arbitraitor may not resolve or
directly connect to the target host, changing SSRF and peer-address guarantees.

A URL allow/deny check before DNS resolution is insufficient because DNS
rebinding can return different addresses on consecutive queries.

## Decision

### Address verification pipeline

Every HTTP request follows this pipeline. The pipeline repeats for every
redirect and retry:

```
1. Parse and normalize the hostname.
2. Resolve all candidate addresses via DNS.
3. Reject disallowed address classes:
     - Private (RFC 1918): 10/8, 172.16/12, 192.168/16
     - Loopback: 127/8, ::1
     - Link-local: 169.254/16, fe80::/10
     - Multicast: 224/4, ff00::/8
     - Cloud metadata: 169.254.169.254, fd00:ec2::254 (AWS), and known
       equivalent endpoints for GCP/Azure/Oracle
     - Unspecified: 0.0.0.0, ::
4. Connect ONLY to an approved resolved address.
5. Verify the connected peer address where the platform exposes it
   (getpeername after connect).
6. Apply policy to IPv4-mapped IPv6 and unusual textual representations.
7. If the connected address differs from the resolved address (e.g., DNS
   rebinding), abort and report.
```

### Ambient configuration disabled by default

| Setting | Default | Override |
|---------|---------|----------|
| HTTP proxy (`HTTP_PROXY`) | Ignored | Explicit in operation plan |
| HTTPS proxy (`HTTPS_PROXY`) | Ignored | Explicit in operation plan |
| ALL proxy (`ALL_PROXY`) | Ignored | Explicit in operation plan |
| Cookie jar | Disabled | Explicit scoped jar |
| netrc | Disabled | Explicit credential reference |
| Credential helpers | Disabled | Explicit credential reference |
| No-proxy (`NO_PROXY`) | Ignored | Explicit bypass list |

### Proxy semantics

When a proxy is explicitly configured in the operation plan:

| Question | Answer |
|----------|--------|
| Who performs DNS resolution? | Documented per proxy type |
| Who connects to the target? | The proxy, not Arbitraitor |
| Can we verify the target IP? | **No** — only the proxy peer |
| What does the receipt say? | "Connected to proxy, target IP unverified" |

**Never claim connected-target-IP verification when only the proxy peer is
observable.** The receipt must record:

```json
{
  "connection": {
    "proxy": { "type": "https_connect", "address": "proxy.example.com:443" },
    "target_resolution": "proxy_performed",
    "target_address_verified": false
  }
}
```

### Redirect handling

On every redirect:

1. Normalize and re-evaluate the new URL.
2. Enforce maximum redirect count (default: 5).
3. Block HTTPS-to-HTTP downgrade by default.
4. Remove authorization headers and cookies on cross-origin redirects.
5. Re-run IP-range and network-boundary policy on the new hostname.
6. Record the chain.
7. Detect redirect loops and suspicious origin changes.
8. Findings for: unexpected cross-origin, URL shortener, raw IP redirect,
   low-reputation domain redirect, content-disposition filename change,
   content-type mismatch.

### TLS trust backend

Use a **policy-selectable** trust backend:

| Mode | Use case | Risk |
|------|----------|------|
| WebPKI roots (default) | Hermetic CI, reproducible builds | Root set must be kept current |
| Platform verifier | Workstation mode, enterprise trust | Larger parsing surface; enterprise roots |
| Custom root set | Testing, specific trust domains | Manual management |

The `rustls-platform-verifier` project notes that a pure Rust verifier can be
preferable for applications that deliberately connect to many untrusted TLS
endpoints. Use a policy-selectable backend rather than one universal default.

### Implementation approach

**Phase 1 (MVP):** Use reqwest with explicit configuration:

- Disable auto-decompression, ambient proxy, cookies, netrc.
- Custom `resolve` callback that performs address filtering.
- Redirect policy set to `none` — Arbitraitor handles redirects manually.
- Connect callback (if available) to verify peer address.

**Phase 2 (if reqwest is insufficient):** Custom Hyper connector that:

- Resolves DNS through Arbitraitor's filtered resolver.
- Binds policy to the actual connection.
- Verifies connected peer address post-connect.
- Supports Hickory DNS behind a resolver trait for deterministic resolution and
  DNSSEC-aware experiments.

### DNS rebinding defense

The connector must:

1. Resolve the hostname.
2. Connect to a specific resolved address.
3. Verify (via `getpeername`) that the connected address matches.
4. If they differ (rebinding occurred between resolve and connect), abort.

This check is meaningful only when Arbitraitor performs the connection, not
when a proxy does.

## Consequences

- SSRF attacks (redirecting to internal services, cloud metadata) are blocked.
- DNS rebinding attacks are detected and rejected.
- Proxy mode honestly reports reduced verification capability.
- Ambient configuration cannot leak credentials or bypass address policy.
- The implementation may require a custom Hyper connector, adding complexity
  to the fetch layer.

## Alternatives considered

- **Trust reqwest defaults:** Rejected. Ambient proxy, cookies, and netrc
  create credential leakage and SSRF bypass.
- **URL allow/deny before resolution only:** Rejected. DNS rebinding defeats
  this.
- **Block all proxies:** Rejected. Enterprise environments require explicit
  proxy support with honest reporting.

## References

- `docs/spec/spec.md` H-03
- `docs/spec/tech-stack.md` §4.4 (Redirects and credentials), §4.5
  (SSRF and DNS rebinding)
- `docs/spec/spec.md` §11.2 (HTTP behavior)
- [rustls-platform-verifier](https://github.com/rustls/rustls-platform-verifier)
- [ADR 0003](0003-reqwest-behind-fetcher-trait.md) — Fetcher trait
