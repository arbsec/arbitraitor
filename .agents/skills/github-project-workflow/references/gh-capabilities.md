# `gh` CLI capabilities (verified 2026-07-23)

Source: <https://cli.github.com/manual/> and
<https://github.blog/changelog/2026-06-10-manage-sub-issues-types-and-dependencies-from-github-cli/>

## Minimum version

**gh v2.94.0+** is required for issue types, sub-issues, and issue dependencies. The skill's scripts check this at runtime and exit `2` with an actionable message if the installed `gh` is older.

## Issue types (org-level, GA Apr 2025; gh support v2.94.0+)

- `gh issue create --type <name>`
- `gh issue list --type <name>` / `gh issue list --json issueType`
- `gh issue edit <num> --add-type <name> | --remove-type`
- Org-configured type names; GitHub ships no universal default list.

## Sub-issues (GA Apr 2025; gh support v2.94.0+)

- `gh issue create --parent <num-or-URL>`
- `gh issue edit <num> --set-parent <num> | --remove-parent | --add-sub-issue <nums> | --remove-sub-issue <num>`
- `gh issue list`/`gh issue view --json` exposes `parent`, `subIssues`, `subIssuesSummary`.
- `subIssues` returns `{ nodes: [...], totalCount: N }` — NOT a flat array. Consumers must handle pagination.

## Issue dependencies — blocked-by / blocking (GA Aug 2025; gh support v2.94.0+)

- `gh issue create --blocked-by <num[,num,...]> --blocking <num[,num,...]>`
- `gh issue edit <num> --add-blocked-by <num> | --remove-blocked-by <num> | --add-blocking <num> | --remove-blocking <num>`
- `gh issue list`/`gh issue view --json` exposes `blockedBy`, `blocking`.
- Returned as `{ nodes: [...], totalCount: N }` — same pagination caveat as sub-issues.
- **GHES gating**: requires GHES 3.19+. The CLI detects org-level support via `IssueRelationshipsSupported`. On older GHES, exit `2` with a clear message.
- **Cross-repo**: `--blocked-by` accepts a number for an issue in the SAME repo only. Cross-repo (Arbitraitor) blockers are linked differently — see `graphql.md`.

## `gh issue list` JSON fields (Issues 2.0)

`assignees`, `author`, `blockedBy`, `blocking`, `body`, `closed`, `closedAt`, `closedByPullRequestsReferences`, `comments`, `createdAt`, `id`, `isPinned`, `issueType`, `labels`, `milestone`, `number`, `parent`, `projectCards`, `projectItems`, `reactionGroups`, `state`, `stateReason`, `subIssues`, `subIssuesSummary`, `title`, `updatedAt`, `url`.

The fields WITHOUT a native `gh` flag (e.g. `projectItems` with field values) require GraphQL — see `graphql.md`.

## `gh issue create` flags of interest

`-t/--title`, `-b/--body`, `-F/--body-file`, `-e/--editor`, `-a/--assignee` (`@me`, `@copilot`), `-l/--label` (repeatable; comma-OK), `-m/--milestone`, `--type`, `--parent`, `--blocked-by`, `--blocking`, `-p/--project <title>` (requires the `project` OAuth scope: `gh auth refresh -s project`), `-T/--template`, `--recover`, `-w/--web`, `-R/--repo`.

## `gh issue view` flags

`--json <fields>`, `--jq`, `--template`, `--comments`, `--web`.

## Projects (v2) — what `gh` CAN do

- `gh project --help` lists item-list/item-add/item-edit/item-archive/item-copy/field-list/markdown-create/template-list/template-view/template-create.
- `gh project item-add --owner <org> --project <number> --url <issue-or-pr-url>`
- `gh project item-edit --field <name> --project <number> --owner <org>` (with `--id` for the item and `--text`/`--single-select-option`/etc.)

Node IDs from Projects queries are stable (`PVT_` items, `PVTF_` fields, `PVTSSF_` single-select options), but the skill resolves them at runtime via `field-list` + `item-list` and caches outside the repo — never in a committed file.

## Projects (v2) — what `gh` CANNOT do

- **Rulesets:** `gh ruleset` has only `check`, `list`, `view`. There is **no `gh ruleset create`/`edit`**. Configure required-status-checks via REST/GraphQL or the GitHub UI. Source: <https://cli.github.com/manual> — only those three subcommands exist.

## Auth scopes

- Default `gh auth login` scopes are sufficient for read.
- Setting Project single-select fields requires the **`project`** OAuth scope: `gh auth refresh -s project`.
- Creating cross-org issues requires normal repo write access to the target repo.
- Agent-driven board/issue operations MUST run as the GitHub App service identity, not a personal account (see SKILL.md "Safety conditions"). The personal-account scope notes above describe the explicitly labelled owner fallback only.
