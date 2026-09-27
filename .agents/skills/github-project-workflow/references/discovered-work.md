# Discovered work

Never hide newly discovered work. Create a separate issue for independently testable or revertible follow-up work (arbitraitor-workflow.md "Discovered work"). This reference defines the three categories and where each one goes.

## Three kinds of discovered work

| Kind | What it is | Where it goes |
|---|---|---|
| **Blocker** | Work that MUST land before the current issue/PR can safely complete. The current work cannot proceed without it. | Native `blockedBy` edge. Current issue → `Status = Blocked`. If the blocker is orchestration or model-routing capability, the canonical issue lives in `arbsec/orchestraitor`. |
| **Follow-up** | Independently testable/revertible work discovered during the current task, but NOT required to complete it safely. | A NEW leaf issue, linked from the current PR's "Newly discovered follow-up work" section. The current work may merge without it. |
| **Hidden work** (forbidden) | Discovered work stuffed into the current PR to avoid opening an issue. | **Never.** Open a Follow-up instead. |

## The non-deferral rule

Security or correctness defects **needed for safe completion** may NOT be deferred merely to shrink a PR. In Arbitraitor every contribution is attack surface — this rule is absolute. If the defect blocks safe completion, it is a **blocker**, not a follow-up — it must land in this PR (or block the PR).

The rule of thumb: if the PR would be unsafe to merge without the fix, it is a blocker. If the PR is safe with or without it, it may be a follow-up.

## `create-blocker` (for blockers)

Opens an issue (optionally in `arbsec/orchestraitor` for cross-repo orchestration prerequisites), creates a `blockedBy` edge from the current issue, and sets the current issue's `Status = Blocked`.

```sh
scripts/create-blocker --repo arbsec/orchestraitor \
  --title "Expose replayable harness event stream" \
  --blocked-issue <current-arbitraitor-issue>
```

## `create-follow-up` (for follow-ups)

Opens a separate leaf issue, linked from the current PR's body. The follow-up carries its own spec reference, acceptance criteria, and non-goals. It is never silently absorbed.

```sh
scripts/create-follow-up --from-pr <pr> --title "..." --spec-ref "docs/spec/spec.md §40"
```

## Why this matters

Hidden work causes:

- merged PRs that do more than their title says (reviewers miss things);
- "I'll fix it later" issues that never get filed;
- security-correctness gaps deferred into a backlog that nobody revisits;
- merge conflicts when the hidden work touches the same files as a later PR.

The skill enforces: discovered work is visible work.
