# Development Conventions

This document defines the architecture, coding conventions, and security invariants for the Arbitraitor project. All contributors — human and automated — must follow these rules.

## Architecture and crate boundaries

The workspace is a monorepo. Each crate has a strict responsibility:

| Crate | Owns | Must not do |
|---|---|---|
| `arbitraitor-model` | Serializable domain types, newtypes | I/O, logic, side effects |
| `arbitraitor-core` | State machine, invariants | Presentation, I/O details |
| `arbitraitor-policy` | Rule evaluation, verdicts | Network, retrieval |
| `arbitraitor-fetch` | HTTP retrieval, transport policy | Policy syntax |
| `arbitraitor-store` | Content-addressed storage | Authorization decisions |
| `arbitraitor-cli` | Argument parsing, output formatting | Business logic |
| `arbitraitor-analysis` | Detector coordination | Direct release/execution |
| `arbitraitor-exec` | Execution broker | Scanning logic |
| `arbitraitor-plugin-host` | Wasmtime/subprocess plugin runtime | Native ABI loading |

### Boundary rules (never violate)

- No detector may call the release or execution layer directly. Detectors produce findings; policy produces verdicts; only the core orchestrates release.
- No crate may re-fetch the primary artifact after approval. Single retrieval for execution is a security invariant.
- The metadata database (`redb`) is a non-authoritative cache. It cannot independently authorize release. CAS digest + receipts are authoritative.
- Do not expose `reqwest` types across crate boundaries. All HTTP interaction goes through the `Fetcher` trait.
- Use newtypes (`Sha256Digest`, `ArtifactId`, `PluginId`, `OperationId`) — never pass raw `String` for hashes, URLs, paths, or signer identities.

---

## Security invariants (non-negotiable)

A change that weakens any of these will be rejected.

1. **No early release:** No artifact byte reaches a downstream consumer before scanning and policy evaluation complete.
2. **Immutable identity:** Released bytes must hash to exactly the SHA-256 recorded in the verdict. Re-verify the digest immediately before every release.
3. **Single retrieval:** The primary network response is not re-fetched between approval and execution.
4. **Bounded processing:** Every parser, decompressor, scanner, and recursive operation has explicit time, memory, file-count, depth, and byte limits.
5. **No implicit trust from location:** HTTPS, a popular domain, or a successful download does not imply trust.
6. **Fail closed:** When enforcement is mandatory, inability to complete a required check blocks release. A detector error is never "clean."
7. **Plan-bound approval:** Approval binds the artifact digest, interpreter, arguments, environment, filesystem/network grants, destination, policy snapshot, detector snapshots, expiry, and nonce. Digest-only approval is replayable and forbidden.
8. **Monotonic project configuration:** A project `.arbitraitor.toml` may only tighten inherited policy. It cannot add trust roots, enable plugins, permit uploads, or weaken execution controls.
9. **Preserve platform provenance:** Never silently remove macOS quarantine attributes or Windows Mark of the Web.
10. **Safe presentation:** All untrusted text (URLs, headers, filenames, source snippets, plugin output) must be escaped and bounded before display. Plugins return structured data, never terminal control sequences.

When writing tests, include assertions that verify these invariants hold. The `invariants.yml` CI workflow runs property tests for state-machine transitions, exact-byte identity, and no-release-before-verdict.

---

## Language and toolchain

- **Rust 2024 edition**, pinned toolchain in `rust-toolchain.toml`.
- Do not change the toolchain pin without an ADR.
- Do not introduce nightly-only features in production code.
- `Cargo.lock` is committed. Review lockfile changes as security-relevant.
- Build with `--locked` in release contexts.

### Lint policy (workspace-wide)

```toml
[workspace.lints.rust]
unsafe_code = "forbid"
missing_docs = "warn"

[workspace.lints.clippy]
all = "deny"
pedantic = "warn"
unwrap_used = "deny"
expect_used = "deny"
panic = "deny"
unimplemented = "deny"
dbg_macro = "deny"
print_stdout = "deny"
print_stderr = "deny"
```

- Do not add blanket `#[allow(...)]` attributes to silence lints. Fix the code or add a narrowly scoped, explained exception.
- `unwrap`/`expect` are denied outside tests. In tests, they are acceptable where failure context is clear.
- `println!`/`eprintln!` are denied in library crates. Use `tracing` for diagnostics. The CLI crate may use structured output functions.

### Unsafe code

- `unsafe_code` is `forbid` in core crates (`arbitraitor-model`, `arbitraitor-core`, `arbitraitor-policy`, `arbitraitor-receipt`, `arbitraitor-store`).
- Required unsafe code lives in dedicated platform/FFI crates (`arbitraitor-fetch` low-level connectors, sandbox adapters).
- Every unsafe block requires a safety comment documenting the invariant.
- Unsafe changes require two maintainer approvals.

---

## Coding conventions

### Error handling

- `thiserror` for typed library errors.
- `miette` at the CLI boundary for user-facing reports with source spans.
- `tracing` for structured operational events.
- Never place secrets, authorization headers, cookies, or signed URLs in error strings.
- Errors include: stage, artifact/operation ID, retryability, policy consequence, and safe diagnostic context.

### Secrets

- Use `secrecy` wrappers and `zeroize` for sensitive values.
- Secret types must not implement `Debug`, `Display`, or `Serialize` by default.
- Pass secret references through plugin plans, not values. Core resolves references at the last responsible moment.
- Redact URL credentials, query parameters, and authorization headers in all logs and receipts.

### Serialization

- **TOML** for human-authored configuration and policy. Never YAML for Arbitraitor policy (deprecated `serde_yaml`, implicit typing, parser complexity).
- **JSON** for machine protocols, receipts, findings, and plugin messages.
- Use `#[serde(deny_unknown_fields)]` on security-critical input structures.
- Include explicit `schema_version` on all versioned JSON.
- Receipt signatures use RFC 8785 JSON Canonicalization Scheme.

### Concurrency

- Tokio for async I/O and orchestration.
- CPU-bound work (hashing, parsing, decompression, scanning) runs on bounded worker pools, not Tokio executor threads.
- Cancellation propagates through a shared token. No detached tasks outlive the operation receipt.
- Use `loom` tests for critical state machines (commit/lease, approval-to-release, cancellation races).

---

## Testing

### What every PR needs

- **Unit tests** for new logic in the same crate.
- **Property tests** (`proptest`) for: URL/path normalization, redaction, policy monotonicity, receipt round-trips, state-machine transitions, and any function with many input permutations.
- **Integration tests** for cross-crate interactions.
- Tests are deterministic and parallel-safe.

### Test layers

| Layer | Tool | Scope |
|---|---|---|
| Unit | `cargo-nextest` | Per-crate logic |
| Property | `proptest` | Invariants and edge cases |
| Snapshot | `insta` | Human-facing diagnostics, receipts (sparingly) |
| Fuzz | `cargo-fuzz` | Parsers, decoders, normalizers |
| Concurrency | `loom` | State machines, races |
| Invariant | Custom + CI `invariants.yml` | No-early-release, exact-byte, SSRF, archive traversal |

### What tests must cover

For security-critical code, tests must verify:

- No content is released before a verdict.
- Released digest equals scanned digest.
- Bounded operations actually enforce their limits (time, memory, depth, count).
- Failure paths produce `error`/`incomplete`/`block` — never "clean."
- Secrets are redacted in all output.
- Archive path traversal is rejected.

---

## Dependencies

Adding a production dependency is a security-relevant decision.

### Admission checklist

Before proposing a new dependency, verify and document:

- Exact capability needed and why std or an existing dependency cannot provide it.
- Maintenance activity and owner concentration.
- Release and security history.
- Unsafe code content.
- Native dependencies and build scripts (build scripts and proc macros are executable supply-chain dependencies).
- Network behavior.
- License (must be `MIT OR Apache-2.0` compatible).
- MSRV impact.
- Transitive dependency increase.

Significant dependency decisions require an ADR in `docs/adr/`.

### Automated controls (enforced by CI)

- `cargo-deny`: advisories, licenses, bans, sources, duplicates.
- `cargo-audit`: RustSec advisory checks.
- GitHub dependency review blocks vulnerable additions in PRs.
- No Git dependencies without a pinned commit and explicit approval.
- No unknown registries.

### Lockfile

`Cargo.lock` is committed for all crates. Treat lockfile changes as security-relevant — review transitive additions and version downgrades.

---

## Security-sensitive paths

Changes to these paths require security-owner review (per CODEOWNERS) and extra scrutiny:

- `crates/arbitraitor-core/` — state machine and invariants.
- `crates/arbitraitor-fetch/` — transport, SSRF, redirect, TLS policy.
- `crates/arbitraitor-store/` — CAS, digest verification, release.
- `crates/arbitraitor-exec/` — execution broker, environment construction.
- `crates/arbitraitor-update/` — TUF metadata, update verification.
- `crates/arbitraitor-plugin-host/` — Wasmtime runtime, capability enforcement.
- `wit/` — plugin interface definitions.
- `rules/` — YARA-X rule packs.
- `Cargo.lock` — dependency supply chain.
- `deny.toml` — dependency policy.
- `.github/workflows/` — CI/release trust boundaries.

When in doubt about whether a change is security-sensitive, treat it as security-sensitive.

---

## Things to avoid

| Do not | Why |
|---|---|
| Use `unwrap()`/`expect()` in production code | Masks errors, violates lints |
| Add `#[allow(clippy::all)]` or blanket allows | Defeats quality gates; fix the lint instead |
| Use YAML for Arbitraitor configuration or policy | Implicit typing, parser complexity, deprecated ecosystem |
| Introduce native dynamic plugins (`.so`, `.dylib`, `.dll`) | Equivalent to core compromise |
| Remove platform quarantine attributes silently | Disables Gatekeeper/SmartScreen defenses |
| Pass raw `String` for hashes, URLs, or identities | Use newtypes |
| Fetch the primary artifact again after approval | Violates single-retrieval invariant |
| Treat metadata DB rows as authorization | Only CAS + receipts are authoritative |
| Let plugin output reach the terminal unescaped | Terminal injection / log injection |
| Mix refactoring into security fixes | Makes review harder; keep PRs focused |
| Add dependencies without the admission checklist | Supply chain risk |
| Disable or weaken CI checks to make a PR pass | Fix the code, not the gate |

---

## Decision records (ADRs)

Architecturally significant decisions go in `docs/adr/NNNN-title.md`:

```text
docs/adr/0001-rust-2024-and-toolchain-policy.md
docs/adr/0002-reqwest-behind-fetcher-trait.md
```

States: `Proposed`, `Accepted`, `Superseded`, `Rejected`.

Write an ADR when:

- Adding or changing a production dependency with security implications.
- Changing the trust model, plugin capability model, or execution context.
- Choosing between competing approaches where reversal is expensive.
