# Definitions of Ready and Done

Two gates, both enforced. `Ready` controls whether an issue may be claimed; `Done` controls whether a PR may merge.

## Definition of Ready (an issue may be claimed)

An issue is `Ready` only when ALL of:

- `Type ∈ {Task, Bug}` (leaf — Epics/Features must be decomposed first).
- Queue priority per the auto-continuation queue in `arbitraitor-workflow.md` (pending reviews → own PRs → P0/P1 issues → stale PRs → sweep).
- `Risk` is set (zero unset values — never schedule a "guess").
- No unresolved `blockedBy` (native issue dependency).
- No conflicting in-flight PR touching the same spec section / crate (AGENTS.md "Workflow" step 2).
- The body has:
  - a **single, bounded objective**;
  - an explicit **specification reference** (`docs/spec/spec.md §N`) or ADR (`docs/adr/NNNN-*.md`);
  - **acceptance criteria** that are observable and testable;
  - **explicit non-goals** (what is deliberately out of scope);
  - **security impact** declared;
  - **testing requirements** identified (unit/property/integration; negative/adversarial for security-sensitive);
  - **documentation impact** identified;
  - **dependencies** listed (blocking issues, Orchestraitor upstream);
  - **rollback implications** noted.

If any field is unset or a criterion is missing, the issue stays `Backlog`, not `Ready`. Never guess a value to force `Ready` — escalate per `arbitraitor-workflow.md` "When to stop and ask".

## Definition of Done (a PR may merge)

A PR may merge only when ALL of (AGENTS.md "Pre-merge gate"):

- All required and non-optional CI checks pass against the **current HEAD**. A missing/skipped check is a failure, not a pass (AGENTS.md "CI is fully green").
- All actionable review threads are resolved.
- All noteworthy findings (CRITICAL/HIGH/MEDIUM) are fixed or formally resolved with recorded reasoning. LOW findings may be deferred only with an explicit justification comment on the finding.
- Adversarial review converges against the current HEAD: one full review generation finds no new noteworthy findings AND all earlier blocking findings are resolved (see the pr-lifecycle skill's `pr-convergence` reference).
- Required documentation is updated in the same PR for any public-behavior change (AGENTS.md "Documentation is current"; [doc-ownership](../../../../docs/doc-ownership.md)). Generated API docs alone do not count.
- The PR checklist items (the `<!-- arb:* -->` markers) are checked based on **evidence**, not intentions.

## Limits are safety valves, not convergence

Reaching a configured `max_review_loops`, cost, or elapsed-time limit produces a `blocked` or `needs-human` state (arbitraitor-workflow.md "PR convergence requirements"). It **never** counts as successful convergence. The implementer adds a human reviewer and moves on; the issue/PR is not silently approved.

This rule is the difference between "an agent that ships when green" and "an agent that ships when it gives up". Arbitraitor requires the former — a security boundary never ships on a guessed pass.
