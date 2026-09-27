# Task decomposition

## Rule

Epics and Features are **not directly implementable**. They MUST be decomposed into leaf Tasks/Bugs before any work starts (arbitraitor-workflow.md "Discovered work"; prefer thin vertical slices).

## Mechanism

Decomposition uses **native GitHub sub-issues** — the `parent` / `subIssues` relationship (GA Apr 2025; gh v2.94.0+). Each child is a first-class issue with its own Type, Target, Status, assignee, and acceptance criteria; the parent tracks `subIssuesSummary`.

### Creating a sub-issue

```sh
gh issue create --parent <parent-num-or-URL> [issue-flags]
```

### Listing the children of a parent

```sh
gh issue view <parent> --json subIssues   # { nodes: [...], totalCount }
```

### Removing the parent link (e.g. on a split)

```sh
gh issue edit <child> --remove-parent
```

## What makes a decomposition good

- Each child is **independently testable and revertible** (arbitraitor-workflow.md "Discovered work"). If two children cannot be tested apart, they are one Task, not two.
- Each child traces to a **specification requirement** (`docs/spec/spec.md §N`) or an ADR (`docs/adr/NNNN-*.md`).
- Dependencies are explicit: use native `blockedBy` to encode the DAG edge ("child B needs child A's API first"). Dependencies are NOT free-text prose in the body.
- Thin vertical slices over horizontal layers. A "add provider-proxy chat-completions endpoint" slice that compiles + tests + reviews end-to-end beats a "add HTTP layer everywhere" slice that touches every crate and proves nothing.
- The parent's acceptance criteria decompose into the children's acceptance criteria. The parent "Done" = all children "Done".

## What a decomposition is NOT

- Not a clone of the parent (each child has its own bounded objective).
- Not a TODO list inside one issue — TODOs in the body hide work from the board ("Never hide newly discovered work" — arbitraitor-workflow.md).
- Not a one-shot. If a child reveals further work, open a NEW leaf issue and link it (see `discovered-work.md`).

## Ownership boundary

Arbitraitor owns all security behavior (sandboxing, policy, approvals, receipts, inspection). A sub-issue only becomes cross-repo when its prerequisite is orchestration or model-routing work that belongs in `arbsec/orchestraitor` — see the arbitraitor workflow policy's "Ownership boundaries" table. The Arbitraitor child may track integration work but does not start until the Orchestraitor capability lands.

## Dry-run first

`decompose-issue --dry-run` prints the sub-issues it would create (with proposed titles, bodies, types, dependencies) and writes nothing. Review the plan before applying — decomposition mistakes propagate to every downstream Task.
