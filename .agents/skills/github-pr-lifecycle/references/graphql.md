# GraphQL for PR review threads

`gh pr view --json reviewThreads` DOES NOT EXIST (verified 2026-07-23; see [`gh-capabilities.md`](gh-capabilities.md)). Use `gh api graphql` with the `pullRequest.reviewThreads` connection.

## Fetch all review threads

```sh
gh api graphql -f query='
  query($owner: String!, $name: String!, $number: Int!) {
    repository(owner: $owner, name: $name) {
      pullRequest(number: $number) {
        reviewThreads(first: 100) {
          pageInfo { hasNextPage endCursor }
          nodes {
            id
            isResolved
            isOutdated
            isCollapsed
            path
            line
            startLine
            diffSide
            comments(first: 50) {
              nodes {
                databaseId
                body
                path
                line
                createdAt
                author { login }
                url
              }
            }
          }
        }
      }
    }
  }' -F owner="$OWNER" -F name="$REPO" -F number="$PR_NUMBER"
```

## Pagination

`reviewThreads(first: 100)` may not return all threads on large PRs. The `review-threads` script handles pagination:

```text
fetch first 100 → if pageInfo.hasNextPage → fetch next 100 with after: endCursor → repeat
```

## Resolving a thread

```sh
gh api graphql -f query='
  mutation resolveReviewThread($threadId: ID!) {
    resolveReviewThread(input: { threadId: $threadId }) {
      thread { id isResolved }
    }
  }' -F threadId="$THREAD_ID"
```

The skill does NOT auto-resolve threads — only reviewers resolve them. The `review-threads` script is read-only.

## Key fields

| Field | Type | Meaning |
|---|---|---|
| `id` | `ID!` | GraphQL global ID (`PRRT_...`), stable. |
| `isResolved` | `Boolean!` | Thread marked resolved on GitHub. |
| `isOutdated` | `Boolean!` | The diff hunk the thread is on has changed since the comment. |
| `isCollapsed` | `Boolean!` | Thread is collapsed in the UI (not meaningful for automation). |
| `path` | `String!` | File path the thread is on. |
| `line` / `startLine` | `Int` | Line range (may be null for file-level comments). |
| `diffSide` | `DiffSide` | `LEFT` (base) or `RIGHT` (head). |
| `comments` | connection | The review comments on the thread. |

## What "actionable" means for convergence

A thread is **actionable** (blocks merge) when:

- `isResolved = false` AND
- `isOutdated = false` (outdated threads on changed hunks are not blocking — the reviewer re-examines the new code).

An **outdated, unresolved** thread indicates the diff changed since the comment. The reviewer must re-examine at the new HEAD. If the finding still applies, a new thread is opened; the old one is stale.

## Auth

`gh api graphql` uses the same OAuth token as the `gh` CLI. No additional scope is required for reading review threads. Resolving threads requires repo write access (default scope). Agent-driven operations authenticate as the GitHub App service identity (see SKILL.md "Safety conditions"); these personal-account scope notes describe the labelled owner fallback only.
