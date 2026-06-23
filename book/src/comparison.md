# Comparison with Other Tools

## How Arbitraitor differs

Arbitraitor is the only tool that combines **content inspection + provenance verification + policy enforcement + execution gating + receipt trail** in a single system. Other tools solve pieces of this pipeline but none provide the full chain from "downloaded something" to "executed it with known, approved risk."

## Direct alternatives

These tools target the same "download → inspect → execute" problem space.

| Tool | What it does | License | Key difference |
|------|-------------|---------|----------------|
| **Arbitraitor** | Full pipeline: download → inspect → verify provenance → policy gate → sandboxed execution → receipt | MIT/Apache-2.0 | Only tool with all six stages integrated |
| **[Tirith](https://tirith.sh/)** | Terminal security gate that intercepts shell commands in real-time, detects 200+ threat categories | AGPL-3.0 | Guards the terminal layer — inspects the command, not the artifact content. Complementary. |
| **[safesh](https://safesh.sh/)** | Drop-in replacement for `bash` in `curl \| bash` — buffers script, runs static analysis, prompts | MIT | Pipe-intercept level only. Simpler scope, easier adoption. |
| **[SafeInstall](https://github.com/forloopcodes/safeinstall)** | Inspects installer scripts, queries URLhaus/VirusTotal, scores risk | MIT | Rust-based, integrated threat intel. Lacks provenance verification and execution sandbox. |
| **[sfetch](https://github.com/3leaps/sfetch)** | Secure downloader with signature verification and trust scoring | Apache-2.0 | Focuses on acquisition integrity, not content inspection. Pairs with shellsentry. |
| **[lgtmit](https://github.com/mitsuru/lgtmit)** | Uses Claude AI to review scripts before execution | MIT | LLM-powered review — requires Claude CLI. Different inspection approach. |

## Feature comparison

| Feature | Arbitraitor | Tirith | safesh | ShellCheck | cosign | Firejail | URLhaus |
|---------|-------------|--------|--------|------------|--------|----------|---------|
| Download interception | Yes | No | Yes | No | No | No | No |
| Content inspection | Yes | No | Yes | Yes (shell) | No | No | No |
| Provenance verification | Yes | No | No | No | Yes | No | No |
| Human approval gate | Yes | No | Yes | No | No | No | No |
| Sandboxed execution | Yes | No | No | No | No | Yes | No |
| Audit receipts | Yes | No | No | No | No | No | No |
| Policy engine | Yes | No | No | No | No | No | No |
| Plugin system | Yes | No | No | No | No | No | No |
| MCP integration | Yes | No | No | No | No | No | No |

## Complementary tools

Arbitraitor is designed to integrate with existing security tools, not replace them:

### Static analysis

| Tool | Scope | Integration |
|------|-------|-------------|
| [ShellCheck](https://www.shellcheck.net/) | Shell script linting (280+ checks) | Arbitraitor produces ShellCheck-compatible JSON output via `--explain --format shellcheck` |
| [Semgrep](https://semgrep.dev/) | Multi-language static analysis (3000+ rules) | Can run as a detector plugin |
| [Bandit](https://bandit.readthedocs.io/) | Python security linter | Python-specific AST analysis |

### Provenance

| Tool | Scope | Integration |
|------|-------|-------------|
| [cosign](https://github.com/sigstore/cosign) | Container/image signing (Sigstore) | Arbitraitor verifies cosign bundles as a provenance signal |
| [TUF](https://theupdateframework.github.io/) | Secure update framework | Supported as a trust root per ADR-0012 |
| [in-toto](https://in-toto.io/) | Supply chain attestation | Attestation format compatible with receipt system |

### Runtime sandboxing

| Tool | Approach | Integration |
|------|----------|-------------|
| [Bubblewrap](https://github.com/containers/bubblewrap) | Unprivileged namespace sandbox | Can wrap Arbitraitor's executed artifacts |
| [gVisor](https://gvisor.dev/) | Userspace kernel | Stronger isolation — run Arbitraitor inside gVisor container |
| [Firecracker](https://firecracker-microvm.github.io/) | MicroVM hypervisor | VM-level boundary for highest-trust workloads |

### Threat intelligence

| Tool | Scope | Integration |
|------|-------|-------------|
| [URLhaus](https://urlhaus.abuse.ch/) | 300K+ malicious URLs | Built-in adapter — queried before inspection |
| [VirusTotal](https://www.virustotal.com/) | 70+ AV engines | API integration as intelligence plugin |
| [urlscan.io](https://urlscan.io/) | URL behavioral analysis | Submit URLs for sandboxed browsing analysis |
