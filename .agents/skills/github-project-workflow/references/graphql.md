# GraphQL for GitHub Projects, sub-issues, and dependencies

Use `gh api graphql` only where first-class `gh` commands are insufficient (verified 2026-07-23; see `gh-capabilities.md`).

## Resolving a Project's node ID and fields

The skill never hardcodes project node IDs (`PVT_...`) in committed files. It resolves at runtime:

```sh
gh api graphql -f query='
  query($org: String!, $num: Int!) {
    organization(login: $org) {
      projectV2(number: $num) { id title }
    }
  }' -F org="$ORG" -F num="$PROJECT_NUMBER"
```

Then list fields + single-select options:

```sh
gh api graphql -f query='
  query($id: ID!) {
    node(id: $id) {
      ... on ProjectV2 {
        fields(first: 50) {
          nodes {
            ... on ProjectV2Field         { id name dataType }
            ... on ProjectV2IterationField { id name }
            ... on ProjectV2SingleSelectField { id name options { id name } }
          }
        }
      }
    }
  }' -F id="$PROJECT_ID"
```

Cache the field→node-ID map **outside the repo** (e.g. `~/.cache/arbitraitor/gh-project-fields.json` or `$XDG_CACHE_HOME/orchestraitor/...`) keyed by `(org, project_number, field_name, option_name)`. Never commit it.

Field node-ID prefixes: `PVTF_` (text/number/date fields), `PVTSSF_` single-select options, `PVTIF_` iteration fields. These IDs are stable for the lifetime of the field/option.

## Setting a single-select field on a project item

```sh
gh project item-edit \
  --id "$ITEM_ID" \
  --field "$FIELD_ID" \
  --project "$PROJECT_NUMBER" \
  --owner "$ORG" \
  --single-select-option "$OPTION_ID"
```

Where `OPTION_ID` came from the runtime resolution above.

## Sub-issues (GraphQL mutation)

When `gh issue create --parent` is insufficient (e.g. you have node IDs already and want one round-trip):

```graphql
mutation addSubIssue($issueId: ID!, $subIssueId: ID!) {
  addSubIssue(input: { issueId: $issueId, subIssueId: $subIssueId }) {
    issue { number }
    subIssue { number }
  }
}
```

Remove: `removeSubIssue(input: { issueId, subIssueId })`.

Reorder priority: `updateSubIssue(input: { issueId, subIssueId, priority })`.

## Blocked-by (GraphQL mutation)

```graphql
mutation addBlockedBy($issueId: ID!, $blockingIssueId: ID!) {
  addBlockedBy(input: { issueId: $issueId, blockingIssueId: $blockingIssueId }) {
    issue { number }
    blockingIssue { number }
  }
}
```

Remove: `removeBlockedBy(input: { issueId, blockingIssueId })`.

`--blocking` (the CLI flag) swaps the two arguments under the hood; the skill scripts always construct the input with the explicit roles.

## Cross-repo blockers (Orchestraitor)

A `blockedBy` edge from an Arbitraitor issue to an Orchestraitor issue is NOT supported by `gh issue --blocked-by <num>` (that flag works same-repo only). Two patterns:

1. **GraphQL across repos (preferred; both repos are in the same org):** the `addBlockedBy` mutation takes node IDs which are cross-repo within an org. Resolve both issues' `ID!` via `gh issue view --json id` and pass them. This is what `create-blocker` does: `create-blocker --repo arbsec/orchestraitor --title "..." --blocked-issue <arbitraitor-issue>` opens the upstream issue in `arbsec/orchestraitor`, labels it, and adds the `blockedBy` edge to the Arbitraitor issue.

2. **Body link (fallback only):** in the Arbitraitor issue body, link `Blocked by arbsec/orchestraitor#<num>` and label the issue `blocked:orchestraitor`. If `addBlockedBy` fails, the blocker edge does NOT exist — the issue is NOT excluded from the ready queue — so `create-blocker` fails loudly instead of leaving a silent gap.

## Auth

`gh api graphql` uses the same auth as the `gh` CLI default scope. No extra scope is required for read mutations on Projects, but setting Project fields still needs the `project` scope (`gh auth refresh -s project`). Agent-driven operations authenticate as the GitHub App service identity (see SKILL.md "Safety conditions"); these personal-account scope notes describe the labelled owner fallback only.

## Schema drift

GitHub's GraphQL schema is versioned per `X-GraphQL-Name`. The skill scripts assert the schema reports `addBlockedBy` and `addSubIssue` as available before calling; if missing (older GHES, enterprise feature flag off), exit `2` with the detected schema version and the missing mutation name.
