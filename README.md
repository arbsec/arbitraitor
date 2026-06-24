# Arbitraitor

**[Documentation](https://arbsec.github.io/arbitraitor/)** | **[ADRs](docs/adr/README.md)** | **[Contributing](CONTRIBUTING.md)**

A policy-enforced download, inspection, provenance verification, and execution gate for untrusted content.

[![CI](https://github.com/arbsec/arbitraitor/actions/workflows/ci.yml/badge.svg)](https://github.com/arbsec/arbitraitor/actions/workflows/ci.yml)
[![Security](https://github.com/arbsec/arbitraitor/actions/workflows/security.yml/badge.svg)](https://github.com/arbsec/arbitraitor/actions/workflows/security.yml)

Arbitraitor separates retrieval, trust, inspection, and execution into a controlled pipeline:

```text
resolve policy
  -> retrieve once
  -> record transport metadata
  -> buffer immutable bytes
  -> identify content
  -> hash and verify provenance
  -> inspect reputation
  -> scan content
  -> recursively inspect contained and referenced payloads
  -> calculate verdict
  -> request approval when required
  -> release or execute the exact inspected bytes
  -> emit a signed receipt
```

## Why?

Commands like `curl -fsSL https://example.com/install.sh | sh` collapse retrieval, trust, inspection, and execution into one operation. Arbitraitor makes trust decisions explicit, prevents premature streaming execution, and provides explainable findings.

## How it compares

| | Arbitraitor | Tirith | safesh | ShellCheck | cosign | Firejail |
|---|---|---|---|---|---|---|
| Download gate | Yes | No | Yes | No | No | No |
| Script analysis | Yes | No | Yes | Yes | No | No |
| Signature verification | Yes | No | No | No | Yes | No |
| Execution sandbox | Yes | No | No | No | No | Yes |
| Audit receipts | Yes | No | No | No | No | No |
| Policy engine | Yes | No | No | No | No | No |
| Plugin system | Yes | No | No | No | No | No |

See the [full comparison](book/src/comparison.md) for details and complementary tools.

## Quick start

### Install

```sh
git clone https://github.com/arbsec/arbitraitor.git
cd arbitraitor
cargo install --path crates/arbitraitor-cli
```

### Inspect a script

```sh
# Fetch and inspect without executing
arbitraitor inspect https://example.com/install.sh
```

Output shows the artifact's SHA-256, content type, detection findings, and a verdict (Pass, Warn, Prompt, or Block).

### Run with approval

```sh
# Fetch, inspect, and execute after human approval
arbitraitor run https://example.com/install.sh

# Execute as a native binary (requires --native gate)
arbitraitor run https://example.com/binary --native
```

### Use wrappers

Install shell shims so `curl` and `wget` route through Arbitraitor automatically:

```sh
arbitraitor wrappers install
arbitraitor wrappers status
```

## Features

- **Mediated execution** — Scripts run in a sandboxed bash with network isolation, resource limits, and output capping
- **Content-addressed storage** — All artifacts stored by SHA-256 with quarantine, retention policies, and garbage collection
- **Threat detection** — Shell analysis (28+ categories), YARA-X rules, PowerShell AST parsing, archive inspection
- **Provenance verification** — Digest pinning, minisign/cosign signatures, TUF metadata, TOFU mode
- **Plan-bound approval** — ADR-0013 approval tokens bind artifact + interpreter + network + policy snapshot
- **MCP integration** — Model Context Protocol tools for AI agent inspection, scanning, and approved execution
- **Plugin system** — Subprocess protocol, Wasmtime Component Model, plugin registry with trust tiers
- **Community intelligence** — Feed submission, review workflow, transparency log, URLhaus adapter
- **Receipts** — RFC 8785 JCS canonicalized receipts with full audit trail

## Architecture

```text
arbitraitor-cli         Command-line interface
├── arbitraitor-fetch    HTTP retrieval with SSRF protection
├── arbitraitor-store    Content-addressed storage (CAS) with retention/GC
├── arbitraitor-analysis Detection pipeline coordinator
│   ├── arbitraitor-shell       Shell script analyzer (bash/dash)
│   ├── arbitraitor-powershell  PowerShell AST analyzer
│   ├── arbitraitor-yarax       YARA-X scanner integration
│   ├── arbitraitor-archive     Archive inspection (6 formats, 15 hazard types)
│   └── arbitraitor-av          Antivirus adapters (ClamAV, Microsoft Defender)
├── arbitraitor-provenance Signature/attestation verification
├── arbitraitor-intel    Threat intelligence feeds
├── arbitraitor-policy   TOML policy engine with rule evaluation
├── arbitraitor-receipt  RFC 8785 canonicalized receipts
├── arbitraitor-exec     Mediated execution (script + native + PowerShell)
├── arbitraitor-sandbox  Process hardening (prctl, close_range, setrlimit)
├── arbitraitor-mcp      MCP server (inspect, scan, approve, execute)
├── arbitraitor-plugin-api    Plugin trait hierarchy
├── arbitraitor-plugin-host   Plugin runtime (subprocess + Wasmtime)
├── arbitraitor-wrapper  curl/wget wrapper translators
├── arbitraitor-daemon   Unix socket daemon with background queue
└── arbitraitor-core     Config, metrics, health checks
```

See the [Architecture Decision Records](docs/adr/README.md) for design rationale.

## Configuration

Arbitraitor uses layered TOML configuration:

```toml
# ~/.arbitraitor/config.toml

[fetch]
timeout = 30
max_redirects = 10

[policy]
default_action = "prompt"
non_interactive_prompt_action = "block"

[detectors]
shell_analysis = true
powershell_analysis = true
max_archive_depth = 10
```

Secrets can be referenced from environment or files:

```toml
[intel]
urlhaus_key = "secret://env/URLHAUS_API_KEY"
```

See [conventions](docs/conventions.md) for the full configuration reference.

## Documentation

- [Architecture Decision Records](docs/adr/README.md) — 21 accepted ADRs
- [Development conventions](docs/conventions.md) — coding rules, security invariants
- [MVP roadmap](docs/mvp-roadmap.md) — milestone breakdown
- Crate documentation: `cargo doc --workspace --open`

## Status

**Pre-alpha.** Not ready for production use. The API, CLI, receipts, and policy schemas will change. 867+ tests passing.

## License

Dual-licensed under [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE).

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). All contributions are made under the Developer Certificate of Origin.

## Security

See [SECURITY.md](SECURITY.md). **Do not report vulnerabilities through public GitHub issues.**
