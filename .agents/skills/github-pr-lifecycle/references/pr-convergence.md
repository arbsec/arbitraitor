# PR convergence

Convergence is the gate between "review is happening" and "review is done". Getting it wrong ships bugs or security holes. Getting it honestly right is the difference between "an agent that ships when green" and "an agent that ships when it gives up".

## The rule

A PR has converged ONLY when ALL hold, checked against the **current HEAD** (not a prior commit):

1. One full adversarial-review generation against the current HEAD finds **no new noteworthy findings**.
2. All earlier **blocking** findings (CRITICAL/HIGH/MEDIUM) are fixed or formally resolved with recorded reasoning.
3. LOW findings may be deferred only with an explicit justification comment on the finding.

**Every new commit invalidates earlier convergence.** A review generation run against commit A says nothing about commit A+1. The next generation re-examines the full diff at the new HEAD.

## What "noteworthy" means

CRITICAL, HIGH, and MEDIUM findings are noteworthy. They MUST be resolved before merge. A finding is "resolved" when:

- the code is fixed AND the reviewer confirms the fix, OR
- the finding is formally accepted with recorded reasoning in the review thread (e.g. "This is a known limitation; tracking in #N; accepted because X").

LOW findings are not blocking but MUST be tracked. A PR with 50 unacknowledged LOW findings has NOT converged — the reviewer must explicitly defer each one.

## Fresh contexts (AGENTS.md "Pre-merge gate")

Each review generation runs in a **fresh agent context** — never the implementer's session. The implementer may not approve their own security-sensitive changes (arbitraitor-workflow.md "Forbidden administrative shortcuts"). Fresh context prevents:

- accumulated authority leakage (the reviewer inherits the implementer's tool grants);
- context poisoning from prior review loops;
- confirmation bias from reviewing one's own reasoning.

## The loop

```text
review generation N (fresh context, current HEAD)
  → collect findings (deduplicated — see review-findings.md)
  → fix all CRITICAL/HIGH/MEDIUM in a fresh implementer context
  → push (new commit → HEAD moved → prior convergence invalidated)
  → review generation N+1 (fresh context, new HEAD)
  → ...
  → STOP when generation N finds no new noteworthy findings
    AND all earlier blocking findings are resolved
```

## Limits are safety valves, not convergence

Reaching `max_review_loops` (default 3), a cost budget, or an elapsed-time limit produces a **`blocked`** or **`needs-human`** state (arbitraitor-workflow.md "PR convergence requirements"). It NEVER counts as successful convergence. The implementer:

1. Adds a human reviewer (`gh pr edit <num> --add-reviewer <human>`)
2. Posts a comment summarizing remaining findings and what was tried
3. Moves to the next task in the queue

The PR stays open, unmerged, in `blocked` state until a human resolves the remaining findings.

## What does NOT count as convergence

- "No findings reported" when no review actually ran (missing generation = not converged).
- "All findings resolved" against a prior HEAD after new commits pushed (stale = not converged).
- Reviewer and implementer agree the PR is "basically fine" without a full generation (opinion ≠ evidence).
- Hitting the loop limit (giving up ≠ converging).
- The implementer approving their own PR (forbidden for security-sensitive changes — see arbitraitor-workflow.md "Forbidden administrative shortcuts").
- An admin using `--admin` to bypass a red check (forbidden — AGENTS.md "Never merge w/ failing CI").

## How `convergence-status` computes the verdict

The script combines:

- `pr-checks` — all required + non-optional checks pass at current HEAD;
- `review-threads` — all actionable threads resolved (`isResolved = true`);
- `reconcile-checklist` — the managed marker set is present and all checked based on evidence (a marker-less body is `checklist_missing`, not converged);
- the review-generation state (has a generation run against the current HEAD? did it find new noteworthy findings?).

The script also blocks when the review-thread page is truncated (`has_next_page: true`) — an undercounted thread list is not evidence of resolution.

The script exits `0` only when all of these are true. Exit `5` (`ARB_ERR_BLOCKED`) means the loop limit was hit — `blocked`/`needs-human`, not mergeable.
