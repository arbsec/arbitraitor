# AGENTS.md

Guidelines for AI agents and automated contributors working in the Arbitraitor repository.

Arbitraitor is a **security boundary** — a policy-enforced download, inspection, provenance verification, and execution gate for untrusted content. Every contribution is part of the attack surface.

**Before writing any code**, read:
- [Development conventions](docs/conventions.md) — architecture boundaries, security invariants, coding rules, testing requirements.
- `.spec/` — full product specification, technology stack, and adversarial review (gitignored, local only).

---

## 1. Workflow: worktrees and pull requests

### 1.1 Always work in a temporary worktree

Never commit directly to `main`. Every task starts by creating an isolated git worktree from the latest `main`:

```sh
git fetch origin
git worktree add ../arbitraitor-<task-slug> main
```

Work exclusively in that worktree. When the PR is merged, clean up:

```sh
git worktree remove ../arbitraitor-<task-slug>
```

This keeps the main checkout clean, allows multiple parallel tasks, and prevents accidental cross-contamination between changes.

### 1.2 Every change gets its own PR

- One PR per logical change. No batching unrelated work.
- Branch name: `<type>/<short-slug>` (e.g. `feat/fetcher-trait`, `fix/store-digest-race`, `docs/adr-0007`).
- PR title uses Conventional Commits format:

  ```text
  feat(fetch): enforce connected-peer address policy
  fix(store): prevent release from stale artifact handle
  security(plugin): reject undeclared WASI imports
  docs(spec): define encoded HTTP artifact identity
  ```

- Squash merge is the only merge strategy. The PR title becomes the commit message.
- Small, reviewable PRs. If a change touches more than a few hundred lines, split it into stacked PRs.
- No unrelated refactoring in security fixes. A bug fix PR contains only the fix.

### 1.3 Before opening a PR

Run these locally. All must pass:

```sh
cargo fmt --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo check --workspace --all-targets --all-features
cargo nextest run
```

If the change affects schemas or WIT bindings, also verify generated output is current (CI will diff-check these).

### 1.4 PR description

Include:

- Problem and chosen approach.
- Linked issue (GitHub closing keyword).
- Security impact assessment.
- Tests added.
- Compatibility impact (public API, plugin protocol, receipt schema).
- Dependency additions (if any, with justification — see [dependency admission checklist](docs/conventions.md#dependencies)).

### 1.5 Commit hygiene

While individual contributor commits are not required to follow Conventional Commits (squash merge uses the PR title), keep commits clean and focused for easier review. Do not mix whitespace changes, formatting, and logic in the same commit.

---

## 2. Quick reference

```sh
# Create an isolated worktree
git fetch origin
git worktree add ../arbitraitor-<task-slug> main

# Pre-PR checks (all must pass)
cargo fmt --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo check --workspace --all-targets --all-features
cargo nextest run

# Branch and PR
git checkout -b <type>/<short-slug>
git push -u origin <type>/<short-slug>
# Open PR with conventional title, security impact, tests, linked issue

# Cleanup after merge
git worktree remove ../arbitraitor-<task-slug>
```
