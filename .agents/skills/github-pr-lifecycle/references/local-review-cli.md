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

### Auth failure modes (observed)

Two distinct failures look alike at the review call. Probe with `coderabbit usage` — never
with `auth status`/`doctor` (see the false-negative rule below).

**Dead session** (the browser OAuth session expired or was revoked — a login minted on
2026-10-07 was still on disk and never refreshed). The server answers `401 UNAUTHORIZED`
and `usage` exits `1` with:

```text
Error: 401 UNAUTHORIZED — CLI session expired or revoked. Sign in again.
```

The review call itself only reports:

```text
Your CodeRabbit session or Git provider access could not be authenticated. Run `coderabbit auth login`, then retry the review.
```

Action: `coderabbit auth login` (interactive browser OAuth), or pass `--api-key` for a
key-based run.

**Seat/quota** (latent — it resurfaces after a successful re-login, because the account is
authenticated but not entitled):

```text
You've used all 3 included reviews ... this Git provider account isn't linked to an assigned seat
```

Action: assign a CodeRabbit seat to the Git provider account, or use an Agentic API key
(`--api-key`). Never pass `--use-credits`.

Rules learned the hard way:

- `coderabbit auth status` and `coderabbit doctor` are **false negatives** — both exit `0`
  and print "Signed in" on a dead session. `auth status` swallows the seat-query `401` into
  a log-only WARN, and `doctor` only checks local metadata presence plus unauthenticated
  reachability. Neither may be used as an auth health check.
- `coderabbit usage` is the only cheap probe that reflects real auth state (`usage` exits
  `1` with the server message). It is **diagnostic-only**: `pr-review-local` runs it after
  every review invocation (bounded by `timeout 15`), records the result in the raw file's
  `# auth probe:` header, and — when the review itself failed — prints the verdict plus a
  concrete operator hint on stderr. A probe failure must never gate: a successful review
  stays exit `0`, and a failed probe never replaces the review's own exit code.
- The CLI serializes these errors as `{}` in its structured output, destroying the server
  message; only the free-text stderr/human line survives.
- Auto-update stalled at `0.9.0` (a `0.9.2` update is pending). The runtime gate stays
  `>= 0.9.0`; do not assume a newer binary is installed.
- A dead session leaves the task **BLOCKED/escalated**. Never fall back to
  `@coderabbitai review` or any other bot review-trigger comment.

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

- `coderabbit usage` (or `review --usage`) talks to the cloud and can fail transiently. The
  script runs it only as a **diagnostic auth probe** after each review invocation and records
  the result in the raw evidence; it **must not gate** anything — a probe failure never
  changes the review's exit code (see "Auth failure modes").
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
stderr plus the bounded `coderabbit usage` auth probe (verdict and, when it matches a known
failure, the operator action) and exits `1`. Raw evidence is always written **first**:

```text
.arbitraitor/reviews/<short-head>-<timestamp>.raw.txt
```

with header lines `# command:`, `# head OID:`, `# tree OID:`, `# base ref:`, `# base OID:`,
`# exit:`, `# auth probe:`, then `# --- stdout ---` and `# --- stderr ---` sections.

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
reported the account and the `arbsec` organization as signed in — they are false negatives.
The cause was later confirmed with `coderabbit usage` as a dead session
(`401 UNAUTHORIZED`, "CLI session expired or revoked"); see "Auth failure modes (observed)".
The remedy is the interactive browser OAuth flow (`coderabbit auth login`), after which the
review must be re-run — a re-run is a real (quota-using) review, so it is a separate
authorized step, not a retry loop.

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
