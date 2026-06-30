# Contributing to Arbitraitor

Thank you for your interest in contributing to Arbitraitor! This project is a security boundary — every contribution is part of the attack surface.

## Developer Certificate of Origin

All contributions must be signed off with the Developer Certificate of Origin (DCO). Use `git commit -s` or add `Signed-off-by: Your Name <your.email@example.com>` to your commit.

## Getting Started

### Prerequisites

This project uses [mise](https://mise.jdx.dev/) for tool management. Install it and all tools with:

```sh
mise install
```

This installs the correct versions of Rust, lefthook, cocogitto, and all other tools.

### Setup

1. Fork and clone the repository.
2. Run `mise install` to install pinned tool versions (Rust, lefthook, cocogitto, rumdl, nextest, deny, audit, mdbook).
3. Run `lefthook install` to set up git hooks.
4. Run `cargo build` to verify the workspace compiles.

### Workflow

1. **Work in a temporary worktree** — never commit directly to `main`:

   ```sh
   git fetch origin
   git worktree add ../arbitraitor-<task-slug> main
   ```

2. **Create a branch** using Conventional Commits format:

   ```sh
   git checkout -b feat/my-feature
   ```

3. **Write code and tests.** Follow the [development conventions](docs/conventions.md) for architecture boundaries, coding style, security invariants, and testing requirements.

4. **Run pre-PR checks** — all must pass:

   ```sh
   cargo fmt --check
   cargo clippy --workspace --all-targets --all-features -- -D warnings
   cargo check --workspace --all-targets --all-features
   cargo nextest run
   rumdl check .
   ```

5. **Open a PR** with a Conventional Commits title, security impact assessment, and linked issue.

6. **Clean up** after merge:

   ```sh
   git worktree remove ../arbitraitor-<task-slug>
   ```

## Conventional Commits

This project enforces [Conventional Commits](https://www.conventionalcommits.org/) via [cocogitto](https://github.com/cocogitto/cocogitto). PR titles must follow:

```text
feat(fetch): enforce connected-peer address policy
fix(store): prevent release from stale artifact handle
security(plugin): reject undeclared WASI imports
docs(spec): define encoded HTTP artifact identity
```

Branch names: `<type>/<short-slug>` (e.g. `feat/fetcher-trait`, `fix/store-digest-race`).

## Code Style

- **Rust 2024 edition.** Follow `rustfmt` and `clippy` — both are enforced in CI and git hooks.
- No `unwrap()`/`expect()` in production code. Use proper error handling.
- No `unsafe` in core crates. `unsafe` in platform crates requires a safety comment and two maintainer approvals.
- Use newtypes for security-relevant values (hashes, URLs, identities).

See [development conventions](docs/conventions.md) for the full coding rules, architecture boundaries, and security invariants.

## Testing

Every PR must include:

- Unit tests for new logic.
- Property tests (`proptest`) for functions with many input permutations.
- Tests that verify security invariants hold.

## Dependencies

Adding a production dependency is a security-relevant decision. See the [dependency admission checklist](docs/conventions.md#dependencies) before proposing any new dependency. Never add a dependency without justification.

## Questions?

Open a [Discussion](https://github.com/arbsec/arbitraitor/discussions) for general questions.
