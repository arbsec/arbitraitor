# Local CodeRabbit CLI review contract

The review mechanism for Arbitraitor PRs is the **local CodeRabbit CLI**, driven by
[`scripts/pr-review-local`](../scripts/pr-review-local). This page records the verified
v0.9.0 contract. Project policy that forbids bot review-trigger comments lives in
`.agents/project/arbitraitor-workflow.md` and `AGENTS.md`.

## Why the local binary

- The GitHub App check (`CodeRabbit`) auto-skips in this repo. The check name observed via
  `gh pr checks --json name,state,bucket` is exactly `CodeRabbit` (`bucket: skipping`), and
  it is listed in `[checks].optional` in `.agents/project/github-project.example.toml`.
  `pr-checks` exempts only `bucket == "skipping"`, so a CodeRabbit run that actually
  **failed** still blocks the gate.
- **Never post `@coderabbitai review`** (or any other bot review-trigger comment). Bot
  comment triggers are no-ops during plan pauses and burn review quota. The local CLI is
  the mechanism.
- If the CLI is missing or unusable, the task is **BLOCKED** and must be escalated. Never
  fall back to a comment trigger.

## Binary and authentication

| Item | Verified value |
|---|---|
| Binary | `coderabbit` (operator machine: `~/.local/bin/coderabbit`; override with `CODERABBIT_BIN`) |
| Version | v0.9.0. **Not** mise/npm/cargo-managed, so the script asserts `coderabbit --version` parses and is `>= 0.9.0` at runtime (unparseable or older → exit `2`). |
| Auth | `~/.coderabbit/auth.json`, created by browser OAuth (`coderabbit auth login`, org `arbsec`). No API-key environment variable is used in automation. |
| Inline key | `--api-key <key>` / `--region us\|eu` exist for key-based runs; not used by the script. |

Check the version before blaming a review result:

```sh
coderabbit --version   # must be >= 0.9.0
```

## Review flags (v0.9.0, from `coderabbit review --help`)

Real flags:

- `--agent` — emit structured findings for agent workflows (what this skill uses).
- `--base <branch>` / `--base-commit <commit>` — comparison base.
- `--dir <path>`, `-c, --config <files...>`, `--committed`, `--uncommitted`,
  `--include-untracked`, `--fresh`, `--deep [focus]`, `--show-prompts`.
- `--remote <owner/repo>` + `--source-branch <ref>` — server-side review without a clone.
- `--use-credits`, `--api-key <key>`, `--region us|eu`, `--usage`.
- Subcommand: `coderabbit review findings [--dir <path>] [--clear]`.

Footguns — flags that **do not exist** in 0.9.0:

- `--plain` hard-errors. The script never passes it.
- `--json`, `--type`, `--path` are **silently ignored** (not in `--help`). A run that
  accepts them looks successful while reviewing something else. Always verify a flag with
  `coderabbit review --help` before adding it to automation.

Quota and cloud behaviour:

- `coderabbit usage` (or `review --usage`) talks to the cloud and can fail transiently. It
  **must not gate** anything: the script never calls it.
- `--use-credits` spends money when included reviews are exhausted. Never use it in
  automation.

## Invocation

```sh
bash .agents/skills/github-pr-lifecycle/scripts/pr-review-local --pre-push --base origin/main
```

The script runs exactly one command from the worktree root:

```text
<coderabbit> review --agent --base <base>
```

`--pre-push` is the default when `--pr` is absent. Modes and gates:

- `--pre-push` — no `gh` calls. Detached HEAD → exit `2`. Best-effort
  `git fetch origin <base>` (warns and continues on failure, using the local
  `origin/<base>`). No resolvable base → exit `1`. Dirty **tracked** tree → exit `4`
  (untracked files are deliberately ignored).
- `--pr <N|URL>` — resolves the PR head/base with `gh`, then compares **tree OIDs**, not
  commit SHAs (see below). Tree mismatch → exit `4`; conflicting PR → exit `5`;
  mergeability not yet computed (`UNKNOWN`) → exit `2` (retry).
- `--from-raw <file>` — re-derives a record from a stored raw file without another review
  (no quota spend). The raw file must live under `.arbitraitor/reviews/` and its recorded
  head OID must equal the current `git rev-parse HEAD`.

**Tree equality, never SHA equality.** `xtask push-branch` lands a new GitHub-signed
commit (committer `web-flow`) with the same tree but a different commit OID, so a local
HEAD and the PR head can never share a SHA. The script compares
`git rev-parse <local HEAD>^{tree}` with the tree of `headRefOid` (resolved locally when
present, else via `gh api repos/<repo>/git/commits/<oid> --jq .tree.sha`).

### CLI output capture

stdout, stderr, and the CLI exit code are captured verbatim. A non-zero CLI exit surfaces
stderr and exits `1`. Raw evidence is always written **first**:

```text
.arbitraitor/reviews/<short-head>-<timestamp>.raw.txt
```

with header lines `# command:`, `# head OID:`, `# tree OID:`, `# base ref:`, `# base OID:`,
`# exit:`, then `# --- stdout ---` and `# --- stderr ---` sections.

## Record format

After a successful CLI run the script writes
`.arbitraitor/reviews/<short-head>-<timestamp>.md` — **script-generated**, never
hand-written. Minimum fields:

```text
- verdict: CLEAN|FINDINGS|UNKNOWN   # UNKNOWN only when no --verdict was supplied
- head OID: <sha>        # git rev-parse HEAD
- tree OID: <sha>        # git rev-parse HEAD^{tree}
- base OID: <sha>        # git rev-parse <base>^{commit}
- cli exit: <n>
- raw file: <relative name>
- raw sha256: <hex>
- generated: <ISO-8601 UTC>
```

All OIDs come from `git rev-parse`, never from caller input. `--pr` mode adds
`- pr head OID:` / `- pr tree OID:`.

## Verdict derivation (never guess)

`coderabbit review --agent` emits **NDJSON** — one JSON object per line. Observed record
types on v0.9.0 are `review_context` (emitted first) and `error`. A *successful* review's
finding/count record was **not** observed (stage 0 failed auth), so the script does not
infer anything from a successful stdout.

The verdict is therefore accepted only from an explicit `--verdict CLEAN|FINDINGS`
supplied by the agent/operator. Without it the record carries `verdict: UNKNOWN`, the raw
file stays the evidence, and the script warns. It never prints or records `findings: 0`
unless one was observed.

A new push changes the tree, so the record is invalidated: re-run the review after each
push (see `SKILL.md` step 6).

### Observed on v0.9.0

Stage 0 — the single real CLI run used to validate this contract — was executed as:

```sh
bash .agents/skills/github-pr-lifecycle/scripts/pr-review-local --pre-push --base origin/main
```

Observed captured output (NDJSON on stdout, exit `1`):

```text
{"type":"review_context","reviewType":"all","currentBranch":"<branch>","baseBranch":"origin/main","workingDirectory":"<abs-path>","expectedDuration":"Reviews usually take 2-6 minutes and can take up to 15. Keep this command running for at least 15 minutes or run it in the background; stopping it early discards the review."}
{"type":"error","errorType":"review","message":"Review failed: Your CodeRabbit session or Git provider access could not be authenticated. Run `coderabbit auth login`, then retry the review.\nPrevious local review has no stored findings.","recoverable":false,"details":{}}
```

and the same message on stderr. `coderabbit auth status` and `coderabbit doctor` both
reported the account and the `arbsec` organization as signed in, so the cause is
unconfirmed — `auth status`/`doctor` report signed-in while the review call rejected
authentication. The remedy is the interactive browser OAuth flow
(`coderabbit auth login`), after which the review must be re-run — a re-run is a real
(quota-using) review, so it is a separate authorized step, not a retry loop.

The raw transcript stays at `.arbitraitor/reviews/<short-head>-<timestamp>.raw.txt`; a
failed CLI run writes no `.md` record (exit `1` before verdict derivation).

## Exit codes

| Code | Meaning |
|---|---|
| `0` | Review ran (or `--dry-run` printed the argv) |
| `1` | CLI/network/quota failure; also no resolvable base |
| `2` | Config/state: missing CLI, bad version, detached HEAD, unknown flag, missing config, unusable `--from-raw` file |
| `4` | Dirty tracked tree, or PR tree mismatch |
| `5` | PR is conflicting (not mergeable) |

Codes `4`/`5` deliberately differ from the generic `_lib.sh` meanings (`4` concurrent
edit, `5` blocked); this script's contract is the table above.
