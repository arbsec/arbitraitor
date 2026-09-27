# Review findings

How adversarial-review findings are classified, deduplicated, and tracked across remediation loops.

## Severity taxonomy

| Severity | Blocks merge? | Action |
|---|---|---|
| CRITICAL | Yes | MUST fix before merge. Security vulnerability, data loss, invariant violation. |
| HIGH | Yes | MUST fix before merge. Correctness bug, missing security control, unhandled edge case. |
| MEDIUM | Yes (unless explicitly deferred) | MUST fix or formally resolve with recorded reasoning. Code quality issue with correctness implications. |
| LOW | No, but MUST be tracked | May be deferred with explicit justification comment. Stylistic, minor improvement, non-blocking. |

## Finding structure

Every finding MUST include:

```json
{
  "id": "gen2-thread-3-finding-1",
  "severity": "HIGH",
  "evidence": "src/auth.rs:42 calls unwrap() on a user-controlled value",
  "affected_paths": ["crates/arbitraitor-core/src/state.rs"],
  "violated_rule": "AGENTS.md: no unwrap() in production code",
  "proposed_remediation": "Replace with proper error propagation using thiserror",
  "generation": 2,
  "thread_id": "PRRT_kw...",
  "status": "open|fixed|resolved-with-reasoning|deferred"
}
```

## Deduplication across loops

Review generations re-examine the full diff. Findings recur. The skill deduplicates by:

1. **Path + line + rule** — if generation N+1 reports the same finding at the same path/rule as generation N, and the finding was already fixed, it is stale (mark `status: stale`, do not re-block).
2. **Same finding, new location** — if the same rule violation moved to a new line (e.g. after a reformat), the old finding is closed (`status: fixed`) and the new one is tracked fresh.
3. **Same finding, different wording** — if two findings describe the same issue at the same path, the later one is a duplicate (mark `status: duplicate-ref: <earlier-id>`).

The `convergence-status` script counts only `status: open` findings with severity ≥ MEDIUM when computing the blocking count.

## Tracking across loops

The skill does NOT rely on GitHub's review-thread state alone for tracking — threads can be resolved by the implementer without the reviewer confirming the fix. The authoritative tracking is:

1. **Review threads** (GraphQL `reviewThreads` with `isResolved`) — the GitHub-native state.
2. **Finding deduplication state** — local to the skill session, keyed by `(path, line, rule)`.

When the implementer marks a thread "resolved" but the reviewer has not confirmed the fix in a subsequent generation, the finding stays `status: open` in the skill's tracking until confirmed.

## What "resolved" means

- `fixed`: the code changed and the reviewer's next generation confirms the finding is gone.
- `resolved-with-reasoning`: the reviewer accepts the finding with recorded reasoning (e.g. "This is a known limitation accepted because X; tracking in #N").
- `deferred`: LOW severity, explicitly deferred with justification.
- `stale`: HEAD moved and the affected path/line no longer exists (auto-detected).
- `duplicate-ref`: same as an earlier finding (auto-detected during dedup).

A thread being "resolved" on GitHub is necessary but not sufficient. The skill's `convergence-status` requires finding-level resolution, not just thread-level resolution.
