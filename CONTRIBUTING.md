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

The agent-skill shell gate also needs [ShellCheck](https://www.shellcheck.net/)
**v0.11.0** — the version CI pins and installs. Rule sets change between
releases, so a different version can report findings CI does not.

### Setup

1. Fork and clone the repository.
2. Run `mise install` to install pinned tool versions (Rust, lefthook, cocogitto, rumdl).
3. Install CI tools: `cargo install cargo-nextest cargo-deny cargo-audit mdbook mdbook-mermaid --locked`
4. Install ShellCheck v0.11.0 (`shellcheck --version` must print `version: 0.11.0`).
5. Run `lefthook install` to set up git hooks.
6. Run `cargo build` to verify the workspace compiles.

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

   Changes under `.agents/**`, or to `.shellcheckrc`, also run the agent-skill
   shell gate in CI (`.github/workflows/agents.yml`):

   ```bash
   failed=0
   # One `bash -n` per file — `bash -n a b` parses only `a`.
   while IFS= read -r script; do
     bash -n "$script" || failed=1
   done < <(
     find .agents -type f \( -name '*.sh' -o -name '*.bash' \) -print
     find .agents/skills -type f -path '*/scripts/*' ! -name '*.*' -print
   )
   for suite in .agents/skills/*/scripts/tests/*.bash; do
     bash "$suite" || failed=1
   done
   [ "$failed" -eq 0 ]

   # Same file selection and severity as the CI shellcheck step.
   # `-S warning` is required: SC2155 (masked `export X="$(cmd)"` status)
   # is a warning, not an error.
   # ShellCheck v0.11.0 — the version CI pins; other versions can report
   # findings CI does not.
   mapfile -t shell_files < <(
     find .agents -type f \( -name '*.sh' -o -name '*.bash' \) -print
     find .agents/skills -type f -path '*/scripts/*' ! -name '*.*' -print
   )
   # Empty selection: `shellcheck` with no files prints usage and exits
   # non-zero, which would read as a lint hit instead of a regression. The
   # workflow makes this fatal (`exit 1`); pasted interactively (no `set -e`)
   # `false` only sets `$?`, so the `shellcheck` line below is what fails.
   [ "${#shell_files[@]}" -gt 0 ] || { echo "no shell files selected" >&2; false; }
   shellcheck -x -P SCRIPTDIR -S warning "${shell_files[@]}"
   ```

5. **Open a PR** with a Conventional Commits title, security impact assessment, and linked issue. The PR template's `arb:*` checklist markers are verified by the [pr-lifecycle skill](.agents/skills/github-pr-lifecycle/SKILL.md) based on evidence — check them only when the underlying fact holds.

6. **Clean up** after merge:

   ```sh
   cargo run -p xtask -- cleanup worktrees --yes
   ```

## Agent-assisted contributions

Agent-driven delivery rules — scheduling, review domains, service identity, ownership
boundaries — live in the [workflow policy](.agents/project/arbitraitor-workflow.md). The
[github-pr-lifecycle](.agents/skills/github-pr-lifecycle/SKILL.md) and
[github-project-workflow](.agents/skills/github-project-workflow/SKILL.md) skills define
the PR and issue mechanics. Human contributions follow the same gates: no merge on red,
adversarial review before merge, docs updated in the same PR.

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
