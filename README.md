# Arbitraitor

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

## Status

**Pre-alpha.** Not ready for production use. The API, CLI, receipts, and policy schemas will change.

## License

Dual-licensed under [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE).

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). All contributions are made under the Developer Certificate of Origin.

## Security

See [SECURITY.md](SECURITY.md). **Do not report vulnerabilities through public GitHub issues.**
