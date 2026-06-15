# ADR 0002: Workspace structure and crate boundaries

**Status:** Accepted
**Date:** 2026-06-16

## Context

Arbitraitor spans retrieval, storage, analysis, policy, execution, plugins,
receipts, updates, and CLI presentation. Clear crate boundaries enforce the
security invariant that no detector, parser, or plugin can call the release or
execution layer directly.

## Decision

Single monorepo with 25 workspace crates under `crates/`:

| Crate | Responsibility | I/O |
|-------|---------------|-----|
| `arbitraitor-model` | Serializable domain types (newtypes, enums, structs) | None |
| `arbitraitor-core` | State machine orchestrator, invariant enforcement | None |
| `arbitraitor-policy` | TOML policy → internal AST → verdict | Policy files only |
| `arbitraitor-fetch` | HTTP retrieval behind `Fetcher` trait | Network |
| `arbitraitor-store` | Content-addressed quarantine store (CAS) | Filesystem |
| `arbitraitor-artifact` | Content type identification and classification | Read-only |
| `arbitraitor-analysis` | Detector coordination | Read-only |
| `arbitraitor-shell` | POSIX shell / Bash / Zsh static analysis | Read-only |
| `arbitraitor-powershell` | PowerShell static analysis | Read-only |
| `arbitraitor-yarax` | YARA-X in-process scanning | Read-only |
| `arbitraitor-av` | ClamAV / Defender adapters | Subprocess |
| `arbitraitor-archive` | Archive extraction under resource limits | Filesystem |
| `arbitraitor-intel` | Intelligence feed matching | Local files |
| `arbitraitor-provenance` | Digest pinning, signature verification | Crypto + subprocess |
| `arbitraitor-exec` | Mediated execution broker | Process spawning |
| `arbitraitor-sandbox` | Platform isolation adapters | Platform APIs |
| `arbitraitor-receipt` | Receipt creation, signing, query | Filesystem |
| `arbitraitor-update` | TUF-style signed update channel | Network |
| `arbitraitor-plugin-api` | Plugin ABI types, WIT definitions | None |
| `arbitraitor-plugin-host` | Wasmtime host + subprocess fallback | Subprocess + WASM |
| `arbitraitor-wrapper` | Downloader argument translation | None |
| `arbitraitor-package-manager` | Homebrew / Arch lifecycle mediation | Subprocess |
| `arbitraitor-cli` | Argument parsing and presentation only | Terminal |
| `arbitraitor-testkit` | Test fixtures, mock servers, generators | Test-only |
| `arbitraitor-mcp` | MCP server for AI agent gateway | Network |

**Boundary rules:**

1. `arbitraitor-model` contains serializable domain types and **no I/O**.
2. `arbitraitor-core` owns state transitions and invariants, **not presentation**.
3. `arbitraitor-fetch` knows networking but **not policy syntax**.
4. `arbitraitor-policy` consumes normalized facts and **produces decisions only**.
5. `arbitraitor-cli` performs argument parsing and presentation **only**.
6. Platform-specific code lives behind traits in dedicated modules.
7. Plugin ABI types live in `arbitraitor-plugin-api` and WIT definitions.
8. **No detector may call the release or execution layer directly.**
9. No wrapper plugin may directly perform network I/O unless a narrowly
   documented mode requires it.

**Publishing:** most crates use `publish = false`. Only the CLI and (later)
the plugin SDK will be published before 1.0.

## Consequences

- Compile-time enforcement of dependency direction (Cargo cannot prevent all
  cycles, but the boundary rules create clear review checkpoints).
- `unsafe_code = "forbid"` in core policy, receipt, model, and state-machine
  crates. Required unsafe isolated in platform/FFI crates.
- Cross-crate communication uses typed domain types from `arbitraitor-model`,
  never raw strings for hashes, URLs, paths, or policy IDs.

## Alternatives considered

- **Multi-repo:** Rejected for pre-1.0. Makes atomic security changes, versioning,
  and cross-platform CI harder.
- **Fewer, larger crates:** Rejected. Weakens boundary enforcement and makes
  parallel development harder.
- **Dynamic plugin ABI (.so/.dylib/.dll):** Rejected. Equivalent to core
  compromise. Plugins use Wasmtime or subprocess protocol only.

## References

- `.spec/arbitraitor-tech-stack.md` §3 (Workspace and crate boundaries)
- `.spec/arbitraitor-comprehensive-spec-v0.4.md` §38.1 (Rust workspace layout)
- `Cargo.toml` workspace members
