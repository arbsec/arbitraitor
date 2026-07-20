# Security Model

Arbitraitor enforces explicit policy at every boundary between retrieval, analysis, and execution.

## Security invariants

These are non-negotiable. Any change that weakens them will be rejected.

### 1. No early release

> No artifact byte reaches a downstream consumer before scanning and policy evaluation complete.

Detection and policy evaluation are not advisory. They are enforced. A detector that fails produces an `incomplete` verdict, not a clean result.

### 2. Immutable identity

> Released bytes must hash to exactly the SHA-256 recorded in the verdict.

Re-verify the digest immediately before every release. If the stored digest does not match the on-disk bytes, block.

### 3. Single retrieval

> The primary network response is not re-fetched between approval and execution.

Once the artifact is buffered in CAS, it stays there. Execution reads from CAS using the verified digest, not a new network request.

### 4. Bounded processing

> Every parser, decompressor, scanner, and recursive operation has explicit time, memory, file-count, depth, and byte limits.

A maliciously crafted archive cannot exhaust memory or hang the analyzer. Limits are enforced in the store, the analysis coordinator, and each individual detector.

### 5. No implicit trust from location

> HTTPS, a popular domain, or a successful download does not imply trust.

A script from `github.com` is treated the same as one from an unknown server. Trust comes from provenance (signatures, pinned digests) or explicit policy, not from the source URL.

### 6. Fail closed

> When enforcement is mandatory, inability to complete a required check blocks release.

A detector that errors is not treated as passing. The verdict becomes `incomplete` and release is blocked until the issue is resolved or human override approves.

### 7. Plan-bound approval

> Approval binds the artifact digest, interpreter, arguments, environment, filesystem/network grants, destination, policy snapshot, detector snapshots, expiry, and nonce.

Digest-only approval is replayable and forbidden. Changing any parameter of the execution plan requires fresh approval.

### 8. Monotonic project configuration

> A project `.arbitraitor.toml` may only tighten inherited policy. It cannot add trust roots, enable plugins, permit uploads, or weaken execution controls.

Local configuration can restrict but cannot expand privileges. This prevents a malicious project configuration from weakening global policy.

### 9. Preserve platform provenance

> Never silently remove macOS quarantine attributes or Windows Mark of the Web.

Platform provenance markers indicate the origin of downloaded content. Arbitraitor records them in receipts but does not strip them, preserving Gatekeeper and SmartScreen context.

### 10. Safe presentation

> All untrusted text must be escaped and bounded before display. Plugins return structured data, never terminal control sequences.

Plugin output is never echoed to the terminal raw. Content from network responses is displayed through a renderer that escapes control characters and limits output length.

## Threat model summary

Arbitraitor assumes:

- **Network is adversarial.** SSRF, DNS rebinding, TLS downgrade, and CDN compromise are real threats.
- **Content publishers may be compromised.** A legitimate domain can serve malicious content.
- **Human operators make mistakes.** Arbitraitor enforces policy even when users intend to bypass it.

Arbitraitor does not assume:

- **That detection is complete.** New malware variants may evade existing detectors.
- **That a scan means safe.** The label is about what was observed, not a guarantee.
- **That approval implies safety.** Approval binds context, but the artifact must still be inspected.

## Assurance levels

<!-- markdownlint-disable-next-line MD057 -->
Every operation reports which assurance level was in effect. These are documented in detail in [ADR 0007](../adr/0007-assurance-levels-model.md).

| Level | Name | What it means |
|-------|------|---------------|
| 1 | Inspect | Analysis only. No execution. |
| 2 | Mediated | Executed with clean environment. Network denied by default. |
| 3 | Contained | Mediated plus verified platform isolation. |

The verdict always includes the level: `PASS (inspect)`, `WARN (mediated)`, etc.

## Plan-bound approval

When approval is required, it binds the entire execution context, not just the artifact digest.

The approval capability contains:

```text
Artifact digest:      sha256:7c...
Operation:            run
Release mode:         execute
Interpreter:          /bin/bash sha256:a1b2...
Arguments:            [--prefix=/usr/local]
Environment digest:   sha256:b2c3...
Working directory:    /tmp/arbitraitor-xyz
Filesystem grants:     [/tmp/arbitraitor-xyz]
Network grants:       []
Sandbox requirements: mediated
Policy snapshot:      sha256:c3d4...
Detector snapshot:     sha256:d4e5...
Expiry:               2026-06-23T12:00:00Z
Nonce:                op-12345
```

Any change to these fields invalidates the approval. If the script is modified, the network policy changes, or the interpreter shifts, fresh approval is required.

<!-- markdownlint-disable-next-line MD057 -->
See [ADR 0013](../adr/0013-plan-bound-approval-capability.md) for the full approval model.

## No-root invariant

Arbitraitor analysis, parsing, rule evaluation, and plugin execution **never** require elevated privileges. Running Arbitraitor as root is blocked by default.

Elevation requests (`sudo`, `su`, `doas`, `pkexec`, UAC) within a script are detected by shell analysis and blocked during mediated execution.

<!-- markdownlint-disable-next-line MD057 -->
See [ADR 0009](../adr/0009-privilege-separation-no-root-invariant.md) for the full privilege separation model.

## Sandbox capabilities

When Level 3 (Contained) execution is requested, the following controls are verified:

| Control | Requirement |
|---------|-------------|
| Filesystem isolation | Enforced (Landlock, chroot, or equivalent) |
| Process-tree containment | Enforced |
| Network policy | Enforced |
| Resource limits | Enforced (memory, CPU, file size) |
| Privilege suppression | `no-new-privileges` or platform equivalent |
| Capability probe | Proves controls are active |

These are reported per-control in the receipt, not as a single boolean.

## Receipt integrity

Receipts are signed using RFC 8785 JCS canonical JSON. The signature covers:

- Artifact digest
- All findings
- Verdict and assurance level
- Policy and detector snapshots
- Execution context (for run operations)
- Capability matrix (for contained execution)

Receipts can be verified independently and used as audit evidence.

## SBOM and VEX ingestion

Arbitraitor consumes SBOM and VEX documents at the policy and provenance boundary but never produces, signs, or republishes them. Ingestion covers four formats: CycloneDX 1.6+ (with the CDXA ML/AI and CBOM cryptography extensions), SPDX 2.2.1, OpenVEX 0.2.0, and CSAF 2.1 (ISO/IEC 20153, May 2025). The expected shape is the CISA 2025 *SBOM Minimum Elements* revision (the four new fields Component Hash, License, Tool Name, Generation Context, plus the Software Producer and Coverage renames) and, when an SBOM declares AI content, the five SBOM-for-AI clusters (System-Level Properties, Data Properties, Model Properties, Infrastructure, Security Properties). Documents missing required fields are rejected with a typed error; AI clusters are surfaced into receipt metadata and treated as advisory signals (never verdict inputs). EU CRA Annex I Part II becomes effective for products placed on the EU market from 11 December 2027; the CycloneDX and SPDX profiles here consume CRA-shaped SBOMs unmodified.

<!-- markdownlint-disable-next-line MD057 -->
See [ADR 0030](./adr/0030-sbom-vex-ingestion-profiles.md) for the per-format field mapping and [SBOM and VEX ingestion](./sbom-and-vex.md) for the user-facing reference.
