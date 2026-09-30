# Arbitraitor workflow policy

Project-specific delivery rules for the Arbitraitor repository. The reusable
[github-project-workflow](../skills/github-project-workflow/SKILL.md) and
[github-pr-lifecycle](../skills/github-pr-lifecycle/SKILL.md) skills hold the generic
mechanism; this file holds Arbitraitor's choices.

This file is **project-specific**. Do not leak Arbitraitor's concrete values into the
generic skill instructions. The skills read mutable configuration (organization, project
number, field names) from [`github-project.example.toml`](github-project.example.toml) or the
local equivalent, never from hardcoded values.

Arbitraitor is a security boundary: every contribution is attack surface. Where a
generic-skill default and this policy disagree, this policy wins.

## Scheduling: the auto-continuation queue

Only issues that satisfy **all** of the following may be implemented:

- `Type` is `Task` or `Bug` (Epics and Features MUST be decomposed into leaf issues first).
- `Status` = `Ready` (Definition of Ready met — see
  [`../skills/github-project-workflow/references/definitions-of-ready-and-done.md`](../skills/github-project-workflow/references/definitions-of-ready-and-done.md)).
- No unresolved `Blocked by` dependencies (native issue dependencies).
- No conflicting in-flight PR touching the same spec section, crate, or invariant
  (`AGENTS.md` "Workflow" step 2). The spec at `docs/spec/spec.md` is the single source
  of truth — two agents editing the same section independently is a defect.

Arbitraitor is a post-MVP project: there is no MVP gate. When a task completes (PR
merged) or exits via the review-loop limit, pick the next task from this priority
order and do not wait for human input:

1. **Pending adversarial reviews** for other agents' open PRs (the pre-merge gate
   obligates reviewing others' work).
2. **Own PRs with review feedback** to address (CI green + unresolved review comments).
3. **Open issues** on the board — P0/P1 `Priority` first, then lowest-numbered issue.
4. **Stale open PRs** (>48 hours with no activity, no review, not draft) — review them
   or ping the author.
5. **Codebase sweep** if nothing else is available:
   - Search for `TODO`/`FIXME`/`unwrap()` in production code and file issues for findings.
   - Run `cargo deny check`, `cargo audit`, `rumdl check .` on the full repo.
   - Check for stale Renovate PRs.
   - Verify `cargo run -p xtask -- docs-check` passes on `main`.
   - Reclaim disk: `cargo run -p xtask -- cleanup artifacts --yes` removes `target/`
     dirs older than 7 days across the checkout and its worktrees.

### Stale PR detection

```sh
gh pr list --repo arbsec/arbitraitor --state open --draft=false \
  --json number,title,updatedAt,reviewDecision \
  --search "updated:<48-hours-ago>"
```

- No review comments → review it (adversarial review per the pre-merge gate).
- Unresolved comments addressed to you → address them.
- Unresolved comments to the author, unanswered >48h → ping the author.
- CI failing → investigate the root cause; fix it or file an issue.

### Claiming and abandoning work

- Before starting an issue, assign it: `gh issue edit <number> --repo arbsec/arbitraitor --add-assignee @me`.
- When abandoning (blocked, deprioritized): unassign and leave a comment explaining why.
- When blocked by another issue or PR: link the blocker, set the `blockedBy` edge, and
  label cross-repo blockers `blocked:orchestraitor`.

## Parallel delivery lanes

Independent leaf work runs in parallel lanes instead of serializing behind the
one-claim guard:

- Only leaf Tasks/Bugs with **file-disjoint** scopes run in parallel. Lanes that touch the same
  spec section, crate, or invariant stay serialized, in which case the orchestrator keeps the
  default one-claim behavior.
- One worktree and one branch per lane (`git worktree add -b <type>/<slug>
  ../arbitraitor-<slug> origin/main`); lanes never share a checkout and never write to
  `main`. Claims are taken deliberately with `claim-issue --allow-parallel` (up to 4 concurrent
  claims), which keeps the one-claim guard active for every caller that omits the flag.
- Each lane rebases onto the updated `origin/main` before its PR opens, and merge order onto
  `main` is serialized by the orchestrator — never by whichever lane happens to finish first.
- A merged or abandoned lane releases its claim (`release-issue`) before another lane
  claims that issue.

## GitHub service identity

All agent-driven GitHub operations — board writes, issue lifecycle, PRs, reviews — run as
the `arbsec-agent` GitHub App service identity, never a personal account. The App is
org-owned and installation-scoped; tokens are minted from the App private key
(fail-closed, ~1h expiry). Personal owner auth remains an explicitly labelled fallback
only when the App identity is unavailable, never an equal option.

Assignee fields accept user accounts only, so the bot cannot carry ownership: board
Status + run-state do. The ready queue excludes items assigned to humans and keeps
items assigned to a declared service identity schedulable
(`[service_identities].slugs` in the project config, default `arbsec-agent`;
overridable via `$ARB_SERVICE_IDENTITIES`).

### Token minting mechanics

- **Every `gh` invocation in agent sessions MUST be prefixed**
  `GH_TOKEN="$(cargo run -q -p xtask -- mint-github-token)"` — mint fresh per batch of
  calls (tokens live ~1 hour; never cached on disk). Bare `gh` defaults to the
  operator's personal auth and is the labelled-fallback ONLY; an unprefixed `gh ...`
  command in agent work is a defect, not a shortcut.
- Mint per operation (tokens expire after ~1 hour; never cached on disk):
  `GH_TOKEN="$(cargo run -p xtask -- mint-github-token)" gh ...`. The subcommand prints
  only the token to stdout; diagnostics go to stderr and never carry secret material.
  PATH caveat: a `curl` shim on PATH (arbitraitor wrappers) can intercept the minting
  POST and swallow the response — invoke a real curl (`/usr/bin/curl`) or bypass the
  shim for that command if the token request fails with no detail.
- PEM resolution order (fail-closed — no token, no fallback attempt inside the tool):
  `$ARBSEC_APP_PEM` / `$ORCHESTRAITOR_APP_PEM`, then the platform keyring entry
  `secret://keyring/orchestraitor-app-pem` (service `orchestraitor`). Installation id
  defaults to the arbsec org installation (`165043398`); override with
  `$ARBSEC_INSTALLATION_ID`.
- Minting follows the runbook (orchestraitor `.omo/drafts/github-app-setup.md` §5):
  RS256 JWT, claims `{ iat, exp: iat+10min, iss: <client ID> }` — the **client ID**
  (`Iv23linxUDbcc53QbFVK`) is the issuer; the App ID (`5082653`) is rejected with 401
  (verified 2026-09-26). The JWT is exchanged at
  `POST /app/installations/<id>/access_tokens`.
- Verification limits: installation tokens are **not** user tokens — REST `GET /user`
  returns 403 ("not accessible by integration") even though attribution works; check
  identity via GraphQL `viewer.login` (returns `arbsec-agent[bot]`).
- Git identity for commits from agent worktrees: **author** = `arbsec-agent[bot]`
  (set via `--author='arbsec-agent[bot] <334074867+arbsec-agent[bot]@users.noreply.github.com>'`
  — bot user id `334074867`, verified against real bot commits; the App id is not part
  of the noreply address) plus the DCO `Signed-off-by:` trailer (`-s`); **committer**
  = the ambient local git identity of the operator (its `user.name`/`user.email` must
  remain the operator's personal identity — NEVER pass `-c user.name`/`-c user.email`
  set to the bot, since git derives the committer from those and the bot owns no
  signing key).
- **Commit shape under required_signatures** (verified live; the org ruleset requires
  verified signatures): GitHub verifies SSH signatures against keys registered to the
  **committer's** identity when committer ≠ author. The working shape:
  - **author** = `arbsec-agent[bot]` + DCO `Signed-off-by:` trailer (`-s`),
  - **committer** = the ambient local git identity of the operator — the personal
    `user.name`/`user.email` whose registered SSH signing key
    (`SHA256:TwGlTWKwN7VjHbONYK7mJN11fFqWvDYT3/qmKsYpXBk`, mekwall) GitHub marks
    `verification: valid` → the ruleset passes with **no** admin bypass. (The push
    credential itself is the bot installation token and is unrelated to commit
    identity; do not conflate the two.)
  - **NEVER set committer to the bot**: no bot-owned signing key exists, so GitHub
    yields `UNKNOWN_KEY` and blocks merge (verified: PR #776 initially needed
    `--admin` because both author and committer were the bot). Concretely:
    `user.name`/`user.email` MUST remain the operator's — never pass
    `-c user.name='arbsec-agent[bot]'`/`-c user.email='...bot...'` to `git commit`,
    because git derives the committer from those values.
  - Git command (ambient identity untouched → committer = the operator; only the
    author is overridden, and `-s` adds the DCO trailer):

    ```sh
    git commit \
        --author='arbsec-agent[bot] <334074867+arbsec-agent[bot]@users.noreply.github.com>' \
        -s -m "..."
    ```

  - Squash merges via the GitHub API merge endpoint carry GitHub's own web-flow
    signature (committer `GitHub <noreply@github.com>`), so merged squashes verify
    regardless of the branch commits' shape. That is a merge-time exception only —
    the shape above is what branch commits must follow. API-created commits are
    **not** signed by GitHub at creation time.
  - Precedent: the author=bot + DCO convention originates from `arbsec/orchestraitor`
    (`delivery.rs commit_all` + SKILL.md "Service identity") — note `commit_all` sets
    GIT_AUTHOR_* and GIT_COMMITTER_* from one caller identity, so used verbatim it
    would also produce committer=bot and fail; it is the origin of the author=bot
    convention, not the committer mechanics. The only verified live commit-shape
    example (author=bot + DCO, committer=pusher, passes `required_signatures`) is
    orchestraitor commit `734f17c8`. (`06a07ea4` and `61a656df` are squash merges —
    committer=GitHub web-flow, i.e. squash-exception evidence, not committer=pusher
    examples.)

## Security-first review

- **Arbitraitor implements every security primitive in the arbsec stack.** Changes to
  the [security-sensitive paths](../../docs/conventions.md#security-sensitive-paths) —
  `crates/arbitraitor-core/`, `-fetch/`, `-store/`, `-exec/`, `-update/`, `-plugin-host/`,
  `wit/`, `rules/`, `Cargo.lock`, `deny.toml`, `.github/workflows/` — require **human
  review before release** and are routed to `@arbsec/security` via
  [`CODEOWNERS`](../../.github/CODEOWNERS). When in doubt, treat a change as
  security-sensitive.
- Changes that weaken a §9 security invariant of `docs/spec/spec.md` are stop-and-ask,
  not implement-and-see (see "When to stop and ask" below).
- Adversarial review continues until one full review generation against the current HEAD finds
  no new noteworthy findings and all earlier blocking findings are resolved (PR convergence;
  see the pr-lifecycle skill's `pr-convergence` reference). Reaching a loop/cost/time limit
  produces `blocked` / `needs-human` — never silent approval.

## Ownership boundaries

Arbitraitor owns the entire security stack. Cross-repo blockers point the other way —
orchestration and model-routing belong in Orchestraitor:

| Concern | Owner | Action if missing here |
|---|---|---|
| Sandboxing, process hardening, mediated execution | Arbitraitor (`arbitraitor-sandbox`, `-exec`) | Implement here |
| Policy engine, rule evaluation | Arbitraitor (`arbitraitor-policy`) | Implement here |
| Retrieval, SSRF protection, single-fetch invariant | Arbitraitor (`arbitraitor-fetch`) | Implement here |
| CAS storage, digest verification, receipts | Arbitraitor (`arbitraitor-store`, `-receipt`) | Implement here |
| Detection, provenance, intel feeds | Arbitraitor (`-analysis` crates, `-provenance`, `-intel`) | Implement here |
| Plugin protocol + host | Arbitraitor (`-plugin-api`, `-plugin-host`, `wit/`) | Implement here |
| MCP surface for agent inspection/execution | Arbitraitor (`arbitraitor-mcp`) | Implement here |
| Agent loop, orchestration, model routing, provider transports | Orchestraitor | Open Orchestraitor issue; Arbitraitor Task stays `Blocked` |

Cross-repository blocker handling: an Arbitraitor issue blocked on Orchestraitor MUST link the
canonical Orchestraitor issue and carry the `blocked:orchestraitor` label. The ready-queue script
excludes any issue with an unresolved `blockedBy` edge, so the issue stays out of the queue
until the upstream PR lands. Do not retry such a Task as if it were transiently blocked;
wait on the upstream PR.

## Required review domains

Reviewer selection is based on changed areas. The required
reviewer domains, when the corresponding area is touched, are:

| Touched area | Required reviewer domain |
|---|---|
| [Security-sensitive paths](../../docs/conventions.md#security-sensitive-paths), any policy/verdict/approval wiring | `security` (analysis) + human security-owner review |
| `crates/arbitraitor-{analysis,intel,provenance,package-manager}/` | `security` + `backend` |
| `crates/arbitraitor-{core,model,policy,engine,store}/` non-security-sensitive changes | `backend` |
| `crates/arbitraitor-cli/`, `crates/arbitraitor-wrapper/` | `backend` / `documentation` |
| `book/**`, `docs/**`, `AGENTS.md`, governance | `documentation` + maintainer |
| Tests, fixtures, invariant suites | `testing` |

The `security` domain is **analysis only** — it never implements enforcement.

## Documentation expectations

Any change to public behavior updates human-facing docs in the same PR (`AGENTS.md`
"Documentation is current" and the [doc-ownership](../../docs/doc-ownership.md) map).
For Arbitraitor "public behavior" includes: CLI commands and flags, wrapper/shim surface,
config and policy TOML schema, environment variables, receipt schema, MCP tools, daemon
protocol, plugin protocol, package-manager policies, security guarantees, error/exit-code
behavior, and installation/migration/removal. `CHANGELOG.md` `[Unreleased]` carries an
entry per public-behavior change and serves consumers of Arbitraitor only — it is release
notes, not a development log. Internal development notes (spec-section bookkeeping,
repository tooling, agent workflows, review process, issue/task tracking) stay in PR
descriptions, spec documents, and evidence files.

## Testing expectations

- Test Arbitraitor's behavior, not third-party internals.
- Security-sensitive behavior gets negative + adversarial tests asserting the forbidden effect
  did **not** occur. Never claim a sandbox/verdict test passed because an error occurred —
  assert the forbidden effect did not happen.
- Every defect found during work gains a regression test when practical.
- CI never depends on live network intel feeds — fixtures and the testkit
  (`arbitraitor-testkit`) provide deterministic transport doubles.
- Retries must not convert a flake into a passing gate (see "Failure classification").

## Failure classification

- **Transient** (timeout, 429, 5xx, runner OOM) → bounded retry.
- **Real failure** → fix root cause; do NOT reroll. Do not re-run hoping for a transient
  pass (`AGENTS.md` "CI is fully green").
- **Flake** → identify + file an issue; do NOT rerun until green.
- A policy/Orchestraitor blocker is never retried as if it were transient.

## Discovered work

Never hide newly discovered work. Create a separate issue for independently testable or
revertible follow-up work. Security or correctness defects **needed for safe completion**
may NOT be deferred merely to shrink a PR — in Arbitraitor every contribution is attack
surface, so this rule is absolute. See
[`../skills/github-project-workflow/references/discovered-work.md`](../skills/github-project-workflow/references/discovered-work.md)
for blocker vs. follow-up handling.

## PR convergence requirements

A PR merges only when (re-stating `AGENTS.md` in operational terms the pr-lifecycle skill
enforces):

1. all required and non-optional checks pass (current HEAD);
2. all actionable review threads are resolved;
3. all noteworthy findings are fixed or formally resolved with recorded reasoning;
4. one full adversarial-review generation against the current HEAD finds no new noteworthy
   findings;
5. required documentation is updated;
6. the managed PR-checklist items are checked based on evidence.

## Forbidden administrative shortcuts

- No merge on red. No admin-merge bypass.
- No re-running a flaky check until it passes by chance.
- No implementer approving their own security-sensitive change.
- No treating a loop/cost/time limit as successful convergence — it produces `blocked` /
  `needs-human`.
- No deferring a security/correctness defect needed for safe completion merely to shrink a PR.
- No suppressing errors (`unwrap()`, blanket `#[allow(...)]`) to make a check pass.

## Housekeeping

- After a PR merges (or is closed/handed off): remove the worktree and branch —
  `cargo run -p xtask -- cleanup worktrees --yes` (removes secondary worktrees whose
  branch has a merged/closed PR, deletes the branch, refuses dirty/locked trees;
  dry-run by default). Never leave merged worktrees on disk.
- Reclaim build artifacts regularly: `cargo run -p xtask -- cleanup artifacts --yes`
  (`--days <n>` to tune); stale `target/` directories are pure build cache and must not
  accumulate across worktrees.
- Before removing a worktree, verify it is clean (`git status --porcelain` empty) and its
  work is landed (merged PR or explicit handoff); a dirty or unmerged worktree is kept
  and reported, never force-removed.

## When to stop and ask

Only stop and request human input when:

1. **Security-sensitive design decision** — new trust root, new execution context, new
   invariant, or a change that weakens an existing §9 invariant of `docs/spec/spec.md`.
2. **Cross-issue design conflict** — two in-flight PRs propose contradictory designs and
   the conflict cannot be resolved by reading the spec.
3. **Review-loop hard ceiling hit** — human reviewer added, remaining findings posted.
4. **No available tasks** — the entire auto-continuation queue is empty and the codebase
   sweep found nothing actionable.
5. **Destructive or irreversible action** — deleting a branch, force-pushing to `main`,
   merging with failing CI, publishing to crates.io.

Everything else (naming, defaults, implementation approach, test structure, doc placement)
is the agent's decision. Note the choice in the PR description and move on.
