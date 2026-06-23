# Security Policy

## Reporting a Vulnerability

**Do not report vulnerabilities through public GitHub issues.**

Use [GitHub private vulnerability reporting](https://github.com/arbsec/arbitraitor/security/advisories/new) to disclose security issues responsibly.

Please include:

- Description of the vulnerability and its impact
- Steps to reproduce or proof of concept
- Affected versions or commits
- Suggested fix if available

We acknowledge within 72 hours and aim to provide an initial assessment within 7 days.

## Security invariants

Arbitraitor enforces these non-negotiable security invariants. Any change that weakens them will be rejected:

1. **No early release** — No artifact byte reaches a downstream consumer before scanning and policy evaluation complete.
2. **Immutable identity** — Released bytes hash to exactly the SHA-256 recorded in the verdict.
3. **Single retrieval** — The primary network response is not re-fetched between approval and execution.
4. **Bounded processing** — Every parser, decompressor, scanner, and recursive operation has explicit limits.
5. **Fail closed** — When enforcement is mandatory, inability to complete a required check blocks release.
6. **Plan-bound approval** — Approval binds the full execution plan, not just the artifact digest.

## Supported versions

| Version | Supported |
|---------|-----------|
| < 1.0 | Security fixes only on latest `main` |

Arbitraitor is pre-1.0. Only the latest `main` branch receives security fixes. Backports are not provided.

## Threat model

Arbitraitor assumes:

- **Network is adversarial.** SSRF, DNS rebinding, TLS downgrade, and CDN compromise are real threats.
- **Content publishers may be compromised.** A legitimate domain can serve malicious content.
- **Human operators make mistakes.** Arbitraitor enforces policy even when users intend to bypass it.

For the full threat model, see the threat model documentation in `docs/threat-model/`.

## Security boundaries

```
Untrusted input
       │
       ▼
┌──────────────────────────────────────┐
│ FETCH: SSRF protection, TLS verify   │
└──────────────────────────────────────┘
       │
       ▼
┌──────────────────────────────────────┐
│ STORE: Immutable CAS, SHA-256 identity │
└──────────────────────────────────────┘
       │
       ▼
┌──────────────────────────────────────┐
│ ANALYSIS: Detection pipeline           │
└──────────────────────────────────────┘
       │
       ▼
┌──────────────────────────────────────┐
│ POLICY: Verdict computation           │
└──────────────────────────────────────┘
       │
       ▼
┌──────────────────────────────────────┐
│ APPROVAL: Plan-bound human approval    │
└──────────────────────────────────────┘
       │
       ▼
┌──────────────────────────────────────┐
│ EXECUTE: Mediated, sandboxed          │
└──────────────────────────────────────┘
```

Bytes flow through these boundaries in one direction. Only handles (digests) cross boundaries after initial retrieval.

## Plugin security

Plugins are isolated using Wasmtime Component Model or subprocess protocols:

- WASM plugins have no filesystem, network, or environment access by default
- Subprocess plugins run with closed descriptors, clean environment, and resource limits
- Native dynamic libraries (`.so`, `.dylib`) are not supported

See the [Plugins](../plugins/overview.md) documentation for details.

## Disclosure policy

| Timeline | Action |
|----------|--------|
| 0 days | Vulnerability reported |
| 3 days | Acknowledgment sent |
| 7 days | Initial assessment provided |
| 30 days | Fix developed and tested |
| 60 days | Security advisory published |

Critical vulnerabilities may follow an accelerated timeline.
