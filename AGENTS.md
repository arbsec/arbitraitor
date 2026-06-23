# AGENTS.md

Guidelines for AI agents and automated contributors working in the Arbitraitor repository.

Arbitraitor is a **security boundary** — a policy-enforced download, inspection, provenance verification, and execution gate for untrusted content. Every contribution is part of the attack surface.

**Before writing any code**, read:
- [Development conventions](docs/conventions.md) — architecture boundaries, security invariants, coding rules, testing requirements.
- [Architecture Decision Records](docs/adr/README.md) — all accepted and proposed ADRs. Every architecturally significant or security-sensitive decision must be recorded as an ADR.
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
- **Adversarial review required for sub-agent PRs.** Every PR created by a sub-agent must be reviewed and approved by a different sub-agent before merging. The reviewer must attempt to break the implementation, verify security invariants hold, and check for edge cases the author missed. Self-merge by the same agent that authored the PR is forbidden.

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
- Documentation updated (see §1.6).
- Compatibility impact (public API, plugin protocol, receipt schema).
- Dependency additions (if any, with justification — see [dependency admission checklist](docs/conventions.md#dependencies)).

### 1.5 Commit hygiene

While individual contributor commits are not required to follow Conventional Commits (squash merge uses the PR title), keep commits clean and focused for easier review. Do not mix whitespace changes, formatting, and logic in the same commit.

### 1.6 Documentation requirements

Every PR must update documentation to reflect the changes made:

- **Public API changes** (new public types, functions, traits): add or update rustdoc comments. All crates use `#![warn(missing_docs)]` — no undocumented public items.
- **New features** (new CLI commands, new config sections, new protocol messages): update the relevant section in the user guide (`docs/guide/` or `README.md`).
- **Architecture changes** (new crates, new ADRs, changed boundaries): update [Architecture Decision Records](docs/adr/README.md) and [conventions](docs/conventions.md).
- **Security changes** (sandboxing, policy, approval flow): update the threat model in `docs/threat-model/` and note the change in the PR description.
- **New dependencies**: document justification in the PR description per the [dependency admission checklist](docs/conventions.md#dependencies).

**README.md** must accurately reflect the current state of the project. If a PR changes what the user sees (CLI output, config format, installation), the README must be updated in the same PR.

---

## 2. Project board

Tasks are tracked on the **[Arbitraitor Kanban](https://github.com/orgs/arbsec/projects/1)** board (GitHub Projects v2, project ID `1`).

### 2.1 Commands

```sh
# View the board
gh project view 1 --owner arbsec

# List items
gh project item-list 1 --owner arbsec

# Add an issue to the board
gh project item-add 1 --owner arbsec --url https://github.com/arbsec/arbitraitor/issues/<number>

# Edit a field (e.g. move to "In Progress")
gh project item-edit --id <item-id> --field-id <field-id> --project-id PVT_kwDOEYXhr84BawZd --text "In Progress"
```

### 2.2 Workflow rules

- Every issue or task should be on the board. If it isn't, add it.
- Move items through columns as work progresses: **Backlog** → **Todo** → **In Progress** → **Review** → **Done**.
- Link PRs to their corresponding issue so the board updates automatically on merge.

---

## 3. Tooling: MCP servers

Agents have access to Model Context Protocol (MCP) servers that provide capabilities beyond plain file I/O and shell commands. **Prefer MCP tools over manual alternatives** when the task matches.

### 3.1 Codegraph — cross-file code exploration

Codegraph indexes the entire workspace and provides symbol-level search, caller/callee traversal, and verbatim source retrieval across files in a single call.

**Use for:**
- `codegraph_explore` — the primary tool. Pass a natural-language question or a bag of symbol/file names. Returns verbatim source code (line-numbered, Read-equivalent) plus the call path between symbols. Use this BEFORE Reading files or grepping.
- `codegraph_search` — quick symbol name lookup. Returns locations only (no source). Good for "where is X defined?" when there might be multiple definitions.
- `codegraph_node` — read one symbol's full body with its caller/callee trail. Pass `file` alone to read an entire file like Read.
- `codegraph_callers` — find every call site of a function/method. Use before refactoring or deleting.

**Prefer over:** `grep` for "how does X work?", `read` for multiple files at once, manual cross-file symbol tracing.

**Key advantage over Serena:** Codegraph works across the entire workspace in one call, while Serena is scoped to a single file/session. For "how does the plugin system work end-to-end?", use Codegraph. For "what are the compiler errors in this file?", use Serena.

### 3.2 Serena — LSP-powered code analysis

Serena wraps a language server (rust-analyzer) to provide semantic code intelligence.

**Use for:**
- `serena_find_symbol` / `serena_get_symbols_overview` — locate types, functions, traits without grepping.
- `serena_find_referencing_symbols` — find all call sites before refactoring or deleting.
- `serena_find_implementations` — check trait impls, locate concrete implementations.
- `serena_get_diagnostics_for_file` — get compiler errors/warnings for a file (faster than full `cargo check`).
- `serena_rename_symbol` — workspace-wide rename with LSP precision (no regex misses).
- `serena_replace_symbol_body` — replace a function/method body with semantic awareness.

**Prefer over:** `grep` for symbol searches within a file, manual find-and-replace for renames, full `cargo check` for single-file diagnostics.

### 3.3 Sequential thinking — structured problem decomposition

Multi-step reasoning tool for complex analysis with revision and branching.

**Use for:**
- Breaking down ambiguous requirements into concrete steps.
- Architecture decisions with multiple viable approaches.
- Root-cause analysis when debugging fails after the first attempt.
- Any task where the full scope isn't clear upfront.

**How:** Start with an initial thought count estimate, revise as understanding deepens, branch into alternative approaches when needed.

### 3.4 Tavily — web research and content extraction

Web search, page extraction, site crawling, and multi-source research.

**Use for:**
- `tavily_search` — quick lookups: library versions, API changes, CVE details.
- `tavily_extract` — pull documentation or blog posts from specific URLs.
- `tavily_research` — deep multi-source research for unfamiliar domains.
- `tavily_map` / `tavily_crawl` — map or crawl documentation sites for API references.

**Prefer over:** Manual web browsing, guessing library APIs from memory.

### 3.5 Context7 — library documentation

Resolve and query up-to-date documentation for any library or framework.

**Use for:**
- `context7_resolve-library-id` — find the Context7 ID for a crate or library.
- `context7_query-docs` — query specific API docs, configuration, or best practices.

**Typical workflow:** resolve ID → query docs → apply findings. Skip the resolve step if the user provides an ID in `/org/project` format.

**Prefer over:** Reading vendored docs, relying on potentially outdated training data.

### 3.6 Priority order

When multiple tools could serve a task:

1. **Codegraph** for "how does X work?", cross-file exploration, and understanding architecture before making changes.
2. **Serena** for code symbols, references, diagnostics, and renames within a specific file.
3. **Context7** for external library/framework documentation.
4. **Tavily** for web research, CVE lookups, or non-documentation web content.
5. **Sequential thinking** for complex multi-step reasoning before any implementation.
6. **Plain tools** (`grep`, `read`, `bash`) only when no MCP tool covers the task or adds unnecessary overhead.

---

## 4. Quick reference

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

# Project board
gh project view 1 --owner arbsec
gh project item-list 1 --owner arbsec
gh project item-add 1 --owner arbsec --url https://github.com/arbsec/arbitraitor/issues/<number>
```
