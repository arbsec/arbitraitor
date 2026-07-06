# Arbitraitor

> **Pre-alpha software.** The CLI flags, configuration format, receipt schemas,
> and policy syntax are subject to breaking changes. Do not use in production.

Arbitraitor is a policy-enforced download, inspection, provenance verification, and execution gate for untrusted content. It replaces the `curl | sh` pattern with a controlled pipeline that makes trust decisions explicit and provides explainable findings.

## Why Arbitraitor?

Commands like `curl -fsSL https://example.com/install.sh | sh` collapse four distinct operations into one:

1. **Retrieval** — fetching bytes from a network location
2. **Trust** — deciding whether those bytes are acceptable
3. **Inspection** — analyzing content for threats
4. **Execution** — running the retrieved code

When any of these fails, the failure is invisible. Arbitraitor separates these concerns and enforces explicit policy at each boundary.

## Key principles

**Inspect before execute.** No artifact byte reaches a downstream consumer before scanning and policy evaluation complete. This is not a preference — it is a security invariant.

**Evidence over scores.** Arbitraitor produces findings with categorical detections and capability matrices, not a single risk score that obscures what was actually checked.

**Provenance outranks detection.** A cryptographically signed attestation from a trusted publisher weighs more than a static analysis finding. Digest pinning, minisign/cosign signatures, and TUF metadata are first-class concepts.

## The pipeline

```
resolve policy
  -> retrieve once
  -> record transport metadata
  -> buffer immutable bytes
  -> identify content
  -> hash and verify provenance
  -> inspect reputation
  -> scan content
  -> recursively inspect contained payloads
  -> calculate verdict
  -> request approval when required
  -> release or execute the exact inspected bytes
  -> emit a signed receipt
```

## Threat model

Arbitraitor assumes:

- The network is adversarial. HTTPS does not imply trust.
- Content publishers may be compromised. A popular download endpoint is an attractive attack surface.
- Human operators make mistakes. Arbitraitor enforces policy even when users intend to do the right thing.

Arbitraitor does not assume:

- That a successful download means the content is safe
- That shell scripts are harmless without network access
- That any single detector is authoritative

## Assurance levels

Every operation runs at a defined assurance level:

| Level | Name | What it guarantees |
|-------|------|-------------------|
| 1 | Inspect | Retrieval, hashing, identification, scanning, reporting. No execution. |
| 2 | Mediated | Approved artifact in a deliberately constructed process context. Network denied by default. |
| 3 | Contained | Mediated plus verified platform isolation (filesystem, process, network). |

The verdict always states which level was in effect. A clean static scan with network access is labeled as **Inspect**, not as safe.

## Architecture

Arbitraitor is a Rust monorepo organized into focused crates:

```
arbitraitor-cli               CLI entry point (23 subcommands)
arbitraitor-core              Config, metrics, health checks, state machine
arbitraitor-model             Domain types, receipts, findings (newtypes)
arbitraitor-fetch             HTTP retrieval with SSRF protection + truncation detection
arbitraitor-store             Content-addressed storage (CAS)
arbitraitor-artifact           Content classification (ELF, PE, Mach-O, shebang)
arbitraitor-analysis          Detection pipeline coordinator
arbitraitor-shell             Shell script analyzer (bash/dash)
arbitraitor-powershell        PowerShell AST analyzer
arbitraitor-yarax             YARA-X scanner
arbitraitor-archive           Archive inspection (6 formats, 15 hazards)
arbitraitor-av                Antivirus adapters (ClamAV, Defender)
arbitraitor-provenance        Signature and attestation verification
arbitraitor-intel             Threat intelligence feeds
arbitraitor-policy            TOML policy engine
arbitraitor-receipt           RFC 8785 canonicalized receipts
arbitraitor-exec              Mediated execution (script + native + PowerShell)
arbitraitor-sandbox           Process hardening
arbitraitor-mcp               MCP server
arbitraitor-plugin-api        Plugin trait hierarchy
arbitraitor-plugin-host       Plugin runtime (Wasmtime + subprocess)
arbitraitor-wrapper           curl/wget wrapper translators + per-shell init
arbitraitor-daemon            Unix socket daemon with background queue
arbitraitor-package-manager   Registry adapters (cargo, npm, uv, pnpm, yarn, bun)
arbitraitor-update            Signed update manifest verification
arbitraitor-testkit           Test infrastructure
```

## Current status

**Pre-alpha.** The API, CLI, receipts, and policy schemas will change. 1103+ tests pass in the current suite. Do not use in production.

## Next steps

- [Getting Started](./getting-started.md) — install and run your first inspection
- [CLI Reference](./cli-reference.md) — full command documentation
- [Architecture](./architecture/overview.md) — how the pieces fit together
- [Plugins](./plugins/overview.md) — extending Arbitraitor
