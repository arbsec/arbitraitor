# Verified-commit path (App-API landing via `xtask push-branch`)

Arbitraitor's `main` ruleset enforces `required_signatures`: a commit shows
`verified: true` only when GitHub itself can attest to it. A locally-created
commit carrying the bot identity in author/committer name+email is **always**
unverified — attribution metadata is not a signature, and the bot owns no
signing key. Verified commits come from exactly two sources:

1. **App-API-created commits.** Commits created via GraphQL
   `createCommitOnBranch` by the `arbsec-agent` App installation are signed by
   GitHub (committer `GitHub <noreply@github.com>`, shown as `web-flow`) and
   verify as `reason=valid`. The REST
   `git/commits` endpoint does **not** sign, even with an installation token
   (verified empirically in orchestraitor, 2026-10-01).
2. **Real GPG/SSH signatures** from a key registered to the committing
   identity. The operator's SSH key (`SHA256:TwGlTWKw…`, mekwall) satisfies the
   ruleset when the **committer** is the operator — that is why the audited
   local commit shape (author=bot + DCO, committer=operator) passes at merge
   time for squash-merged history. Branch-tip commits landed by agents use the
   App-API path instead.

## The landing path: `xtask push-branch`

```sh
cargo run -p xtask -- push-branch \
    --message "feat(scope): conventional subject" \
    [--body-file <path>] [--branch <local>] [--remote-branch <name>] \
    [--base <ref>] [--owner <o>] [--repo <name|owner/name>] [--dry-run]
```

Behavior (mirrors `orc github push-branch` in orchestraitor):

1. Resolves `(owner, repo)` from flags or the `origin` remote; the local
   branch from HEAD.
2. Mints a fresh installation token in memory (never cached, never logged).
3. Reads the remote branch head; computes the change set between the remote
   head tree (existing branch) or base tree (new branch) and the local
   branch's **committed** tree — never the index or working directory.
4. Lands via a unique temp branch (`push-branch/tmp-<nanos>`) so the gates run
   BEFORE the real ref moves:
   - **tree equality** — the landed commit's tree must byte-identically match
     the local branch tree;
   - **verification** — `signature.isValid` must be true.
   The temp ref is deleted on every path (success, gate failure, mutation
   failure).
5. Moves the real ref with an exact-head CAS precondition
   (`updateRefs`/`RefUpdate.beforeOid` = observed head, `force=false`), then
   re-reads the ref to confirm the move outcome (the payload carries only a
   nullable `clientMutationId`; a spurious error envelope after a successful
   move is downgraded to a warning after a provable re-read).

### Deltas from the orchestraitor implementation

This is a scoped port of `orc github push-branch`; the following are NOT
ported: `--re-land` (deliberate re-landing of an already-landed tree) and
stdin `-` support for `--body-file`; the typed detached-HEAD error of the
original IS ported (a detached HEAD with no `--branch` bails before any API
call). Consequence: a branch that was rebased onto
another commit but whose TREE equals the remote head exits with "nothing to
land" - the change set is tree-based, so there is nothing to re-create. If
that state genuinely needs re-landing, re-create the branch tip with a
follow-up commit (e.g. an empty commit made through the landing path) or land
the tree-identical re-sign manually; plain `git push` stays forbidden in
every case.

## Why plain `git push` is forbidden for PR branches

- **Credential misattribution (incident 2026-10-13, PR #801):** the ambient
  credential helper (`gh auth git-credential`) prefers the keyring account.
  A `git push` executed without `GH_TOKEN` exported authenticated as the
  operator's personal account; GitHub attributed the ref update to `mekwall`
  ("mekwall force-pushed"). The token-scoped path (`xtask push-branch`) carries
  the installation token only in the Authorization header of the API call —
  the helper is never invoked.
- **Unverifiable commits:** a local bot-identity commit has no registered
  signing key; `required_signatures` rejects it at merge time (PR #776 needed
  an admin bypass before this path existed — the bypass is forbidden now).

## Commit identity for local commits

`bash .agents/skills/github-pr-lifecycle/scripts/commit-identity check`
checks that a local `git commit` would be **authored** as
`arbsec-agent[bot] <334074867+arbsec-agent[bot]@users.noreply.github.com>`
(`--author=`) and that the **committer** stays the operator identity (never
the bot); it also prints a DCO convention hint - the commit command must
carry `-s` - which is informational, not a verification. To validate the
exact command you are about to run, pass the planned author explicitly:
`commit-identity check . --author "$ARBITRAITOR_BOT_AUTHOR"` (without
`--author`, the check reads the ambient GIT_AUTHOR_* env / user.name /
user.email config, which fails by design when the commit will carry an
explicit `--author=` override). Local chains are
landed
tree-identically by `push-branch`; the local commit metadata stays for audit.

## What NOT to do

- Never `git push` a PR branch — not even once, not even "just the first push".
- Never reset a PR branch through an ancestor-of-`main` state (GitHub
  auto-closes the PR).
- Never bypass the gates (tree equality, verification) or the CAS precondition.
- Never persist, echo, or log the installation token; never route API calls
  through the arbitraitor curl shim (`/usr/bin/curl` is invoked directly, as in
  `github_mint.rs`).
