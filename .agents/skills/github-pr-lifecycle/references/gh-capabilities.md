# `gh` CLI capabilities for PR lifecycle (verified 2026-07-23)

Source: <https://cli.github.com/manual/> and gh CLI v2.94.0+.

## Minimum version

**gh v2.94.0+** (same as the project-workflow skill). Scripts check at runtime and exit `2` if older.

## `gh pr view` JSON fields

These are the ONLY valid `--json` field names (verified 2026-07-23):

`additions`, `assignees`, `author`, `autoMergeRequest`, `baseRefName`, `baseRefOid`, `body`, `changedFiles`, `closed`, `closedAt`, `closingIssuesReferences`, `comments`, `commits`, `createdAt`, `deletions`, `files`, `fullDatabaseId`, `headRefName`, `headRefOid`, `headRepository`, `headRepositoryOwner`, `id`, `isCrossRepository`, `isDraft`, `labels`, `latestReviews`, `maintainerCanModify`, `mergeCommit`, `mergeStateStatus`, `mergeable`, `mergedAt`, `mergedBy`, `milestone`, `number`, `potentialMergeCommit`, `projectCards`, `projectItems`, `reactionGroups`, `reviewDecision`, `reviewRequests`, `reviews`, `state`, `statusCheckRollup`, `title`, `updatedAt`, `url`.

### IMPORTANT: `reviewThreads` DOES NOT EXIST

`gh pr view --json reviewThreads` is **not a valid field**. Confirmed by maintainers in <https://github.com/cli/cli/issues/11477> and the official manual page. Review threads are GraphQL-only — see [`graphql.md`](graphql.md).

Use `review-threads` script (which calls `gh api graphql`) instead.

## `gh pr checks` (<https://cli.github.com/manual/gh_pr_checks>)

Flags: `--watch`, `--required`, `--fail-fast`, `--interval`, `--json`, `--jq`, `--template`, `--web`.

`--json` fields: `bucket`, `completedAt`, `description`, `event`, `link`, `name`, `startedAt`, `state`, `workflow`.

- `bucket` maps check state to: `pass`, `fail`, `pending`, `skipping`, `cancel`.
- Exit code `8` = checks pending (not a failure, not a pass).
- `--required` filters to only required checks (from rulesets/branch protection).

The `pr-checks` script wraps this and classifies each failure (transient vs. real vs. flake).

## `gh pr review` (<https://cli.github.com/manual/gh_pr_review>)

Flags: `--approve`, `--comment`, `--request-changes`, `--body`, `--body-file`.

This skill does NOT perform reviews — it tracks them. But `pr-state` uses `reviewDecision` from `gh pr view --json` to report whether the PR has approval, changes requested, or no review yet.

## `gh pr merge` (<https://cli.github.com/manual/gh_pr_merge>)

```text
gh pr merge [<num>|<url>|<branch>] [flags]
  -s, --squash              squash merge (the shared arbsec strategy)
  -d, --delete-branch        delete the branch after merge
  --auto                     enable auto-merge (waits for checks)
  --disable-auto             disable auto-merge
  --admin                    BYPASS requirements — FORBIDDEN by this skill (AGENTS.md "Never merge w/ failing CI")
  --match-head-commit <sha>  refuse merge if head moved since gate check
  -t, --subject <text>       merge commit subject
  -b, --body <text>          merge commit body
  -F, --body-file <file>     read body from file
  -A, --author-email <text>  merge commit author email
```

The `merge-gate` script always uses `--squash --delete-branch --match-head-commit <sha>`. It NEVER passes `--admin`.

## `gh pr list` (for stale-PR detection)

```text
gh pr list --state open --draft=false \
  --json number,title,updatedAt,reviewDecision
```

## `gh pr edit` (for adding reviewers)

```text
gh pr edit <num> --add-reviewer <login>
```

## `gh pr close` / `gh pr ready` (draft → ready)

```text
gh pr ready <num>     # marks a draft PR as ready for review
gh pr close <num>     # closes a PR (without merging)
```

## `gh pr diff` (for doc-impact classification)

```text
gh pr diff <num>            # unified diff
gh pr diff <num> --name-only   # changed file paths only
```

The `classify-docs-impact` script uses `--name-only` + the diff body to match against public-behavior surface patterns.
