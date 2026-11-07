#!/usr/bin/env bash
# Regression tests for the local CodeRabbit review enforcement in
# scripts/convergence-status and scripts/merge-gate (PR B).
#
# Fully offline and self-contained: GH_BIN and CODERABBIT_BIN are stubs, and
# each fixture repo has a real `file://` origin so the ancestor/overlap checks
# run against real git objects. Sub-checks (pr-checks/review-threads/
# reconcile-checklist) are stubbed in a temp scripts dir that symlinks the real
# convergence-status, so this suite tests the gate logic and not the network.
#
# The head commit is built in a second clone (LAND) and pushed, exactly like
# `xtask push-branch`: the landed commit object does NOT exist in WORK. That is
# the regression this suite must keep honest — a bare `rev-parse HEAD^{tree}`
# would hard-fail and brick every merge.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCRIPTS_REAL="$(cd "$HERE/.." && pwd)"
EXAMPLE_TOML="$(cd "$HERE/../../../../project" && pwd)/github-project.example.toml"
ROOT="$(mktemp -d)"
trap 'rm -rf "$ROOT"' EXIT

# --- hermetic git ---------------------------------------------------------------
# The fixtures build real commits, so they must not inherit the operator's git
# configuration. This repository's workflow expects operators to have SSH
# commit signing configured: with `commit.gpgsign=true` in the global config,
# every fixture `git commit` tries to sign and can fail or block on a key
# prompt. Other global settings change the fixtures too — `diff.renames`
# decides whether a move is reported as `R` or as a delete plus an add, and
# cases 14, 25, 28 and 29 depend on rename detection being ON.
#
# `GIT_CONFIG_*` entries are applied AFTER every config file, so a
# `git config diff.renames false` written into the fixture repo config has
# no effect — only an explicit `git -c` overrides them. Rename detection is
# therefore ON in every fixture, which is what those cases need.
#
# `GIT_CONFIG_GLOBAL`/`GIT_CONFIG_NOSYSTEM` need git 2.32; the git floor for
# this repository is higher (the base fetch uses `git rev-parse --verify` and
# the CI images ship git 2.4x). `GIT_CONFIG_COUNT` would be the 2.31 fallback,
# but it cannot blank the global config, only override single keys.
export GIT_CONFIG_GLOBAL=/dev/null
export GIT_CONFIG_NOSYSTEM=1
# Be explicit about the one global setting the fixtures rely on, instead of
# inheriting it from a default: rename detection ON.
export GIT_CONFIG_COUNT=1
export GIT_CONFIG_KEY_0=diff.renames
export GIT_CONFIG_VALUE_0=true

pass=0; fail=0
ok()  { pass=$((pass + 1)); echo "PASS $1"; }
bad() { fail=$((fail + 1)); echo "FAIL $1${2:+: $2}" >&2; }

# --- stub scripts dir: real convergence-status + stubbed sub-checks -----------
SCRIPTS="$ROOT/scripts"
mkdir -p "$SCRIPTS"
ln -s "$SCRIPTS_REAL/convergence-status" "$SCRIPTS/convergence-status"
cp "$SCRIPTS_REAL/_lib.sh" "$SCRIPTS/_lib.sh"
cat > "$SCRIPTS/pr-checks" <<'STUB'
#!/usr/bin/env bash
printf '%s\n' '{"all_passed":true,"any_pending":false,"missing_required":[]}'
STUB
cat > "$SCRIPTS/review-threads" <<'STUB'
#!/usr/bin/env bash
printf '%s\n' '{"unresolved_actionable":0,"has_next_page":false}'
STUB
cat > "$SCRIPTS/reconcile-checklist" <<'STUB'
#!/usr/bin/env bash
printf '%s\n' '{"all_checked":true,"unchecked":[]}'
STUB
chmod +x "$SCRIPTS/pr-checks" "$SCRIPTS/review-threads" "$SCRIPTS/reconcile-checklist"

# --- mutant of the gate script -------------------------------------------------
# `evaluate_local_review` sets LR_STATUS on every blocking path, and the
# caller falls back to `local_review_evaluation_failed` when a path forgets.
# The mutant removes one such assignment, so the fallback is the only thing
# that keeps an unnamed failure from leaving the verdict mergeable.
MUTANT_SCRIPTS="$ROOT/scripts-mutant"
build_mutant() {
  mkdir -p "$MUTANT_SCRIPTS"
  cp -p "$SCRIPTS/pr-checks" "$SCRIPTS/review-threads" "$SCRIPTS/reconcile-checklist" \
    "$MUTANT_SCRIPTS/"
  cp -p "$SCRIPTS_REAL/_lib.sh" "$MUTANT_SCRIPTS/_lib.sh"
  awk '
    $0 == "  if [ ! -d \"$REVIEW_DIR\" ]; then" { marker = 1; print; next }
    marker && $0 == "    LR_STATUS=\"local_review_missing\"" { marker = 0; next }
    { print }
  ' "$SCRIPTS_REAL/convergence-status" > "$MUTANT_SCRIPTS/convergence-status"
  chmod +x "$MUTANT_SCRIPTS/convergence-status"
  if grep -q 'LR_STATUS="local_review_missing"' "$MUTANT_SCRIPTS/convergence-status"; then
    if [ "$(grep -c 'LR_STATUS="local_review_missing"' \
      "$MUTANT_SCRIPTS/convergence-status")" -eq 1 ]; then
      return 0
    fi
  fi
  echo "mutant: the mutation did not apply" >&2
  return 1
}

# --- gh stub -------------------------------------------------------------------
cat > "$ROOT/gh" <<'STUB'
#!/usr/bin/env bash
case "${1:-}" in
  auth) exit 0 ;;
  pr)
    case "${2:-}" in
      checks) cat "${GH_CHECKS:?}" ;;
      diff)
        # GH_DIFF_FAIL=1 simulates an unreadable/oversized diff.
        if [ "${GH_DIFF_FAIL:-0}" = "1" ]; then
          echo "gh: failed to read diff" >&2
          exit 1
        fi
        printf '%s\n' "${GH_FILES:-}" ;;
      view)   cat "${GH_PR_VIEW:?}" ;;
      *) exit 2 ;;
    esac ;;
  api) printf '%s\n' "${GH_API_TREE:-}" ;;
  *) exit 2 ;;
esac
STUB
chmod +x "$ROOT/gh"

# --- coderabbit stub (integration case only) -----------------------------------
cat > "$ROOT/coderabbit" <<'STUB'
#!/usr/bin/env bash
case "${1:-}" in
  --version) printf '0.9.2\n' ;;
  usage) exit 0 ;;
  review) printf '%s\n' '{"type":"review_context","reviewType":"all"}' ;;
  *) exit 2 ;;
esac
STUB
chmod +x "$ROOT/coderabbit"

# --- jq stub: simulates a jq runtime error --------------------------------------
# `jq -e` exits 1 for a false/null result and >= 2 for a runtime or system
# error. The gate must not read the second as "false": that would turn a jq
# failure into "no spec path", "no non-docs path", or "no overlap" — and each
# of those waives the local review. The stub fails for ONE filter (exact match
# on the last argument, or a substring) and delegates everything else to the
# real jq.
# Intentional masking: a missing `jq` surfaces per-assertion through
# `${JQ_REAL:?}` instead of aborting the whole suite at this export.
JQ_REAL="$(command -v jq)" || true
export JQ_REAL
cat > "$ROOT/jq" <<'STUB'
#!/usr/bin/env bash
filter="${!#}"
if [ -n "${JQ_FAIL_EXACT:-}" ] && [ "$filter" = "$JQ_FAIL_EXACT" ]; then
  echo "jq: simulated runtime error" >&2
  exit 2
fi
if [ -n "${JQ_FAIL_SUBSTR:-}" ] && [[ "$filter" == *"$JQ_FAIL_SUBSTR"* ]]; then
  echo "jq: simulated runtime error" >&2
  exit 2
fi
exec "${JQ_REAL:?}" "$@"
STUB
chmod +x "$ROOT/jq"

# run_conv_with_jq_failure <name> <exact-filter|substr-filter> <args...>
# Runs the gate with the jq stub on PATH and the given filter failing.
run_conv_jq_fails() { # run_conv_jq_fails <exact|exact-or-substr> <match> <args...>
  local mode="$1" match="$2"; shift 2
  local saved_path="$PATH"
  PATH="$ROOT:$PATH"
  export JQ_FAIL_EXACT="" JQ_FAIL_SUBSTR=""
  if [ "$mode" = "exact" ]; then export JQ_FAIL_EXACT="$match"; else export JQ_FAIL_SUBSTR="$match"; fi
  GOT=0
  ( cd "$WORK" && GH_BIN="$ROOT/gh" bash "$SCRIPTS/convergence-status" "$@" ) \
    > "$ROOT/out" 2> "$ROOT/err" || GOT=$?
  OUT="$(cat "$ROOT/out")"
  ERR="$(cat "$ROOT/err")"
  PATH="$saved_path"
  export JQ_FAIL_EXACT="" JQ_FAIL_SUBSTR=""
}

GH_CHECKS="$ROOT/checks.json"
printf '[]\n' > "$GH_CHECKS"
export GH_CHECKS

sha256_of() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  else
    shasum -a 256 "$1" | awk '{print $1}'
  fi
}

# --- fixtures ------------------------------------------------------------------
new_case() { # new_case [disabled]
  local dir
  dir="$(mktemp -d "$ROOT/case.XXXXXX")"
  ORIGIN="$dir/origin.git"
  WORK="$dir/work"
  LAND="$dir/land"
  git init -q --bare --initial-branch=main "$ORIGIN"
  git init -q "$WORK"
  mkdir -p "$WORK/.agents/project" "$WORK/docs"
  if [ "${1:-}" = "disabled" ]; then
    awk '{ print } /^\[review\][[:space:]]*$/ && !done { print "local_review_required = false"; done = 1 }' \
      "$EXAMPLE_TOML" > "$WORK/.agents/project/github-project.local.toml"
  else
    cp "$EXAMPLE_TOML" "$WORK/.agents/project/github-project.local.toml"
  fi
  printf 'hello\n' > "$WORK/file.txt"
  printf '# old\n' > "$WORK/docs/old.md"
  git -C "$WORK" add -A
  git -C "$WORK" -c user.email=t@t -c user.name=t commit -q -m init
  git -C "$WORK" branch -M main
  git -C "$WORK" remote add origin "file://$ORIGIN"
  git -C "$WORK" push -q origin main
  git -C "$WORK" update-ref refs/remotes/origin/main "$(git -C "$WORK" rev-parse HEAD)"
  BASE_OID="$(git -C "$WORK" rev-parse HEAD)"
}

start_feature() {
  git -C "$WORK" checkout -q -b feature main
}

commit_work() { # commit_work <message>
  git -C "$WORK" add -A
  git -C "$WORK" -c user.email=t@t -c user.name=t commit -q -m "$1"
}

# land_pr: push WORK's branch, then rebuild the head commit in a second clone so
# the landed SHA exists only on the remote (same tree, different OID — the
# push-branch shape). Sets PR_HEAD and PR_TREE.
land_pr() {
  git -C "$WORK" push -q origin "HEAD:refs/heads/feature"
  rm -rf "$LAND"
  git clone -q "file://$ORIGIN" "$LAND"
  git -C "$LAND" checkout -q feature
  GIT_COMMITTER_DATE="2001-01-01T00:00:00Z" \
    git -C "$LAND" -c user.email=land@t -c user.name=land commit -q --amend --no-edit
  git -C "$LAND" push -q -f origin feature
  PR_HEAD="$(git -C "$LAND" rev-parse HEAD)"
  PR_TREE="$(git -C "$LAND" rev-parse 'HEAD^{tree}')"
}

# land_pr_fork: the shape of a PR from a FORK. The head branch lives on the
# fork, so the base repository carries the head commit ONLY as
# `refs/pull/<N>/head` -- GitHub publishes every PR head there, same-repo
# and fork alike. The head branch is removed from the base repository, so
# the head-branch fetch cannot deliver the object either. Sets PR_HEAD and
# PR_TREE.
land_pr_fork() {
  land_pr
  git -C "$ORIGIN" update-ref refs/pull/42/head "$PR_HEAD"
  git -C "$ORIGIN" update-ref -d refs/heads/feature
}

set_pr_view() {
  GH_PR_VIEW="$ROOT/pr-view.json"
  printf '{"number":42,"reviewDecision":"","headRefOid":"%s","isDraft":false,"baseRefName":"main","headRefName":"feature"}\n' \
    "$PR_HEAD" > "$GH_PR_VIEW"
  export GH_PR_VIEW
}

# A head whose branch cannot be fetched and whose API lookup returns nothing:
# the tree ladder finds no tree, so the gate must refuse to merge.
set_pr_view_unresolvable() {
  GH_PR_VIEW="$ROOT/pr-view.json"
  printf '{"number":42,"reviewDecision":"","headRefOid":"%s","isDraft":false,"baseRefName":"main","headRefName":"no-such-head-branch"}\n' \
    "$PR_HEAD" > "$GH_PR_VIEW"
  export GH_PR_VIEW
  GH_API_TREE=""
  export GH_API_TREE
}

set_files() {
  GH_FILES="$(printf '%s\n' "$@")"
  export GH_FILES
}

# write_review <stem> <verdict> [options via env-ish args]
# Positional: stem verdict cli-exit raw-exit tree base command tamper
write_review() {
  local stem="$1" verdict="$2" cli_exit="${3:-0}" raw_exit="${4:-0}"
  local tree="${5:-$PR_TREE}" base="${6:-$BASE_OID}"
  local command="${7:-coderabbit review --agent --base origin/main}" tamper="${8:-}"
  local dir raw rec sha
  dir="$WORK/.arbitraitor/reviews"
  raw="$dir/$stem.raw.txt"
  rec="$dir/$stem.md"
  mkdir -p "$dir"
  {
    echo "# command: $command"
    echo "# head OID: $(git -C "$WORK" rev-parse HEAD)"
    echo "# tree OID: $tree"
    echo "# base ref: origin/main"
    echo "# base OID: $base"
    echo "# exit: $raw_exit"
    echo "# --- stdout ---"
    echo '{"findings": []}'
    echo "# --- stderr ---"
  } > "$raw"
  sha="$(sha256_of "$raw")"
  {
    echo "# Local CodeRabbit review record"
    echo
    echo "- verdict: $verdict"
    echo "- head OID: $(git -C "$WORK" rev-parse HEAD)"
    echo "- tree OID: $tree"
    echo "- base OID: $base"
    echo "- cli exit: $cli_exit"
    echo "- raw file: $stem.raw.txt"
    echo "- raw sha256: $sha"
    echo "- generated: 2026-01-01T00:00:00Z"
  } > "$rec"
  # Tamper AFTER hashing so the digest no longer matches the transcript.
  [ "$tamper" != "mutate" ] || printf 'tampered\n' >> "$raw"
}

# run_conv <args...>; exported GH_* variables drive the stub.
run_conv() {
  GOT=0
  ( cd "$WORK" && GH_BIN="$ROOT/gh" bash "$SCRIPTS/convergence-status" "$@" ) \
    > "$ROOT/out" 2> "$ROOT/err" || GOT=$?
  OUT="$(cat "$ROOT/out")"
  ERR="$(cat "$ROOT/err")"
}

# run_conv_mutant <args...>; same, but against the mutated gate script.
run_conv_mutant() {
  GOT=0
  ( cd "$WORK" && GH_BIN="$ROOT/gh" bash "$MUTANT_SCRIPTS/convergence-status" "$@" ) \
    > "$ROOT/out" 2> "$ROOT/err" || GOT=$?
  OUT="$(cat "$ROOT/out")"
  ERR="$(cat "$ROOT/err")"
}

expect_exit() { # expect_exit <name> <want>
  if [ "$GOT" -eq "$2" ]; then ok "$1"; else bad "$1" "expected exit $2, got $GOT (stderr: $ERR)"; fi
}

expect_json() { # expect_json <name> <jq-filter> <want>
  local got
  got="$(printf '%s' "$OUT" | jq -r "$2" 2>/dev/null || true)"
  if [ "$got" = "$3" ]; then ok "$1"; else bad "$1" "jq '$2' => '$got', want '$3' (stderr: $ERR)"; fi
}

expect_reason() { # expect_reason <name> <reason>
  if printf '%s' "$OUT" | jq -e --arg r "$2" '.reasons | index($r) != null' >/dev/null 2>&1; then
    ok "$1"
  else
    bad "$1" "reason '$2' missing from: $OUT (stderr: $ERR)"
  fi
}

expect_err_contains() { # expect_err_contains <name> <text>
  if grep -q -- "$2" <<<"$ERR"; then
    ok "$1"
  else
    bad "$1" "stderr lacks '$2': $ERR"
  fi
}

# A negative check on the same captured stderr: some strings must NOT appear.
expect_err_not_contains() { # expect_err_not_contains <name> <text>
  if grep -qF -- "$2" <<<"$ERR"; then
    bad "$1" "stderr offers '$2': $ERR"
  else
    ok "$1"
  fi
}

# ==============================================================================
# 1. Accepted record: tree match, ancestor base, no overlap, hash+exit+command
#    verify, CLEAN verdict. The head object is NOT local before the run.
# ==============================================================================
new_case
start_feature
mkdir -p "$WORK/src"
printf 'fn f() {}\n' > "$WORK/src/lib.rs"
commit_work "feature change"
land_pr
set_pr_view
set_files "src/lib.rs"
write_review "abc1234-20260101T000000Z" CLEAN

if ! git -C "$WORK" cat-file -e "$PR_HEAD" 2>/dev/null; then
  ok "landed head commit is absent locally before the gate (push-branch shape)"
else
  bad "landed head commit is absent locally before the gate" "PR_HEAD exists in WORK"
fi

run_conv 42 --repo arbsec/arbitraitor --json
expect_exit "accepted record exits 0" 0
expect_json "accepted status" '.local_review.status' "accepted"
expect_json "accepted record_file" '.local_review.record_file' "abc1234-20260101T000000Z.md"
expect_json "accepted record_tree_oid" '.local_review.record_tree_oid' "$PR_TREE"
expect_json "accepted record_base_oid" '.local_review.record_base_oid' "$BASE_OID"
expect_json "accepted raw hash verified" '.local_review.raw_sha256_verified' "true"
expect_json "accepted PR is mergeable" '.mergeable' "true"
if git -C "$WORK" cat-file -e "$PR_HEAD" 2>/dev/null; then
  ok "head-tree ladder fetched the landed head object"
else
  bad "head-tree ladder fetched the landed head object" "still missing $PR_HEAD"
fi

# ==============================================================================
# 2. Missing reviews dir -> local_review_missing, exit 5 (never exit 1).
# ==============================================================================
new_case
start_feature
mkdir -p "$WORK/src"
printf 'fn f() {}\n' > "$WORK/src/lib.rs"
commit_work "feature change"
land_pr
set_pr_view
set_files "src/lib.rs"
run_conv 42 --repo arbsec/arbitraitor --json
expect_exit "missing records exit 5 (blocked), not 1" 5
expect_json "missing records status" '.local_review.status' "local_review_missing"
expect_reason "missing records reason" "local_review_missing"
expect_err_contains "missing records names the dir" ".arbitraitor/reviews"
# The stderr reaches agents, who act on it. Project policy forbids the waiver
# without operator approval and a PR-description reason, and a missing record is
# normally fixed by running pr-review-local -- so the message must not present
# `--skip-local-review` as the remedy. It may only name the conditions.
expect_err_contains "missing records names the real remedy" "run pr-review-local"
expect_err_contains "missing records bounds the waiver" "emergency valve only"
expect_err_not_contains "missing records does not offer the waiver as an override" \
  "pass --skip-local-review to override"

# ==============================================================================
# 3. No tree-matching record -> local_review_stale_tree.
# ==============================================================================
new_case
start_feature
mkdir -p "$WORK/src"
printf 'fn f() {}\n' > "$WORK/src/lib.rs"
commit_work "feature change"
land_pr
set_pr_view
set_files "src/lib.rs"
write_review "abc1234-20260101T000000Z" CLEAN 0 0 "1111111111111111111111111111111111111111"
run_conv 42 --repo arbsec/arbitraitor --json
expect_exit "stale tree exits 5" 5
expect_json "stale tree status" '.local_review.status' "local_review_stale_tree"

# ==============================================================================
# 4. Recorded base is not an ancestor of the current base.
# ==============================================================================
new_case
git -C "$WORK" checkout -q main
printf 'side\n' >> "$WORK/file.txt"
git -C "$WORK" add -A
git -C "$WORK" -c user.email=t@t -c user.name=t commit -q -m side
SIDE_OID="$(git -C "$WORK" rev-parse HEAD)"
git -C "$WORK" reset -q --hard "$BASE_OID"
start_feature
mkdir -p "$WORK/src"
printf 'fn f() {}\n' > "$WORK/src/lib.rs"
commit_work "feature change"
land_pr
set_pr_view
set_files "src/lib.rs"
write_review "abc1234-20260101T000000Z" CLEAN 0 0 "$PR_TREE" "$SIDE_OID"
run_conv 42 --repo arbsec/arbitraitor --json
expect_exit "non-ancestor base exits 5" 5
expect_json "non-ancestor base status" '.local_review.status' "local_review_base_advanced"

# ==============================================================================
# 5. Base advanced but only over files the PR does NOT change -> accepted
#    (ancestor + disjoint path). This documents the residual risk: a semantic
#    conflict on untouched files is invisible to path intersection.
# ==============================================================================
new_case
start_feature
mkdir -p "$WORK/src"
printf 'fn f() {}\n' > "$WORK/src/lib.rs"
commit_work "feature change"
land_pr
set_pr_view
set_files "src/lib.rs"
# advance origin/main on a different file, after the review's base was recorded
git -C "$LAND" checkout -q main
printf 'advanced\n' >> "$LAND/file.txt"
git -C "$LAND" add -A
git -C "$LAND" -c user.email=t@t -c user.name=t commit -q -m "advance main"
git -C "$LAND" push -q origin main
git -C "$WORK" fetch -q origin main
write_review "abc1234-20260101T000000Z" CLEAN
run_conv 42 --repo arbsec/arbitraitor --json
expect_exit "advance over disjoint files still accepted" 0
expect_json "advance over disjoint files status" '.local_review.status' "accepted"

# ==============================================================================
# 6. Base advanced over a file the PR changes -> local_review_base_overlap.
# ==============================================================================
new_case
start_feature
mkdir -p "$WORK/src"
printf 'fn f() {}\n' > "$WORK/src/lib.rs"
commit_work "feature change"
land_pr
set_pr_view
set_files "src/lib.rs"
git -C "$LAND" checkout -q main
mkdir -p "$LAND/src"
printf 'fn f() { /* advanced */ }\n' > "$LAND/src/lib.rs"
git -C "$LAND" add -A
git -C "$LAND" -c user.email=t@t -c user.name=t commit -q -m "advance main over same file"
git -C "$LAND" push -q origin main
git -C "$WORK" fetch -q origin main
write_review "abc1234-20260101T000000Z" CLEAN
run_conv 42 --repo arbsec/arbitraitor --json
expect_exit "base overlap exits 5" 5
expect_json "base overlap status" '.local_review.status' "local_review_base_overlap"

# ==============================================================================
# 7. Raw transcript absent.
# ==============================================================================
new_case
start_feature
mkdir -p "$WORK/src"
printf 'fn f() {}\n' > "$WORK/src/lib.rs"
commit_work "feature change"
land_pr
set_pr_view
set_files "src/lib.rs"
write_review "abc1234-20260101T000000Z" CLEAN
rm -f "$WORK/.arbitraitor/reviews/abc1234-20260101T000000Z.raw.txt"
run_conv 42 --repo arbsec/arbitraitor --json
expect_exit "raw missing exits 5" 5
expect_json "raw missing status" '.local_review.status' "local_review_raw_missing"

# ==============================================================================
# 8. Raw transcript tampered after hashing -> local_review_hash_mismatch.
# ==============================================================================
new_case
start_feature
mkdir -p "$WORK/src"
printf 'fn f() {}\n' > "$WORK/src/lib.rs"
commit_work "feature change"
land_pr
set_pr_view
set_files "src/lib.rs"
write_review "abc1234-20260101T000000Z" CLEAN 0 0 "$PR_TREE" "$BASE_OID" \
  "coderabbit review --agent --base origin/main" mutate
run_conv 42 --repo arbsec/arbitraitor --json
expect_exit "hash mismatch exits 5" 5
expect_json "hash mismatch status" '.local_review.status' "local_review_hash_mismatch"
expect_json "hash mismatch leaves verified=false" '.local_review.raw_sha256_verified' "false"

# ==============================================================================
# 9. Raw `# exit:` non-zero -> local_review_cli_exit_nonzero.
# ==============================================================================
new_case
start_feature
mkdir -p "$WORK/src"
printf 'fn f() {}\n' > "$WORK/src/lib.rs"
commit_work "feature change"
land_pr
set_pr_view
set_files "src/lib.rs"
write_review "abc1234-20260101T000000Z" CLEAN 1 1
run_conv 42 --repo arbsec/arbitraitor --json
expect_exit "CLI exit nonzero exits 5" 5
expect_json "CLI exit nonzero status" '.local_review.status' "local_review_cli_exit_nonzero"

# ==============================================================================
# 10. Recorded argv does not name this base -> local_review_command_mismatch.
# ==============================================================================
new_case
start_feature
mkdir -p "$WORK/src"
printf 'fn f() {}\n' > "$WORK/src/lib.rs"
commit_work "feature change"
land_pr
set_pr_view
set_files "src/lib.rs"
write_review "abc1234-20260101T000000Z" CLEAN 0 0 "$PR_TREE" "$BASE_OID" \
  "coderabbit review --agent --base origin/develop"
run_conv 42 --repo arbsec/arbitraitor --json
expect_exit "command mismatch exits 5" 5
expect_json "command mismatch status" '.local_review.status' "local_review_command_mismatch"

# ==============================================================================
# 11. FINDINGS and UNKNOWN both block (verdict is agent-attested).
# ==============================================================================
new_case
start_feature
mkdir -p "$WORK/src"
printf 'fn f() {}\n' > "$WORK/src/lib.rs"
commit_work "feature change"
land_pr
set_pr_view
set_files "src/lib.rs"
write_review "abc1234-20260101T000000Z" FINDINGS
run_conv 42 --repo arbsec/arbitraitor --json
expect_exit "FINDINGS verdict exits 5" 5
expect_json "FINDINGS verdict status" '.local_review.status' "local_review_verdict_not_clean"
rm -rf "$WORK/.arbitraitor/reviews"
write_review "abc1234-20260101T000000Z" UNKNOWN
run_conv 42 --repo arbsec/arbitraitor --json
expect_exit "UNKNOWN verdict exits 5" 5
expect_json "UNKNOWN verdict status" '.local_review.status' "local_review_verdict_not_clean"

# ==============================================================================
# 12. Newest record wins in both directions (timestamp, not whole filename).
# ==============================================================================
new_case
start_feature
mkdir -p "$WORK/src"
printf 'fn f() {}\n' > "$WORK/src/lib.rs"
commit_work "feature change"
land_pr
set_pr_view
set_files "src/lib.rs"
# Older CLEAN with a lexically SMALLER name, newer FINDINGS with a lexically
# LARGER name: both whole-name and timestamp sorts agree -> FINDINGS blocks.
write_review "aaaaaaa-20260101T000000Z" CLEAN
write_review "zzzzzzz-20260201T000000Z" FINDINGS
run_conv 42 --repo arbsec/arbitraitor --json
expect_json "newest FINDINGS record blocks" '.local_review.status' "local_review_verdict_not_clean"
# Reverse: newer CLEAN has the lexically SMALLER name, older FINDINGS the larger.
# A whole-filename sort would pick the older FINDINGS; timestamp sort picks CLEAN.
rm -rf "$WORK/.arbitraitor/reviews"
write_review "zzzzzzz-20260101T000000Z" FINDINGS
write_review "aaaaaaa-20260201T000000Z" CLEAN
run_conv 42 --repo arbsec/arbitraitor --json
expect_json "newest CLEAN record wins on timestamp" '.local_review.status' "accepted"

# ==============================================================================
# 13. Docs-only allowlist: positive and negatives.
# ==============================================================================
new_case
start_feature
printf '# readme\n' > "$WORK/README.md"
printf '# changelog\n' > "$WORK/CHANGELOG.md"
mkdir -p "$WORK/book"
printf '# book\n' > "$WORK/book/x.md"
printf '# guide\n' > "$WORK/docs/guide.md"
commit_work "docs only"
land_pr
set_pr_view
set_files "README.md" "CHANGELOG.md" "book/x.md" "docs/guide.md"
run_conv 42 --repo arbsec/arbitraitor --json
expect_exit "docs-only allowlist exits 0 without a record" 0
expect_json "docs-only status" '.local_review.status' "docs_only_exempt"
expect_json "docs-only is mergeable" '.mergeable' "true"
expect_err_contains "docs-only note" "docs-only diff"

# One fixture per path. The case commits ONLY that path, so a negative case
# fails for the stated reason. A shared fixture that also carries a non-docs
# file (e.g. src/lib.rs) makes every iteration fail for that other reason,
# and the loop would then prove nothing about the path under test.
docs_only_case() { # docs_only_case <path> <docs_only_exempt|accepted>
  local path="$1" want="$2"
  new_case
  start_feature
  mkdir -p "$WORK/$(dirname "$path")"
  printf '# fixture\n' > "$WORK/$path"
  commit_work "add $path"
  land_pr
  set_pr_view
  set_files "$path"
  write_review "abc1234-20260101T000000Z" CLEAN
  run_conv 42 --repo arbsec/arbitraitor --json
  expect_exit "docs-only case $path exits 0" 0
  expect_json "docs-only case $path status" '.local_review.status' "$want"
}

# Allowlist members: exempt on their own.
docs_only_case "README.md" "docs_only_exempt"
docs_only_case "CHANGELOG.md" "docs_only_exempt"
docs_only_case "book/x.md" "docs_only_exempt"
docs_only_case "docs/guide.md" "docs_only_exempt"

# Negatives: every one must go through enforcement (accepted record), never
# docs_only_exempt. Anchoring matters: `README.md` must not match a nested
# README, `book/**` must not match a non-markdown book asset, and the
# `docs/spec/` exclusion is checked before the allowlist.
docs_only_case ".agents/skills/x/README.md" "accepted"
docs_only_case "mybook/x.rs" "accepted"
docs_only_case "book/mermaid.min.js" "accepted"
docs_only_case "docs/spec/spec.md" "accepted"
docs_only_case "AGENTS.md" "accepted"
docs_only_case ".github/workflows/code.yml" "accepted"

# 13b. The allowlist is a NAME check; the head tree must also show a REGULAR
#      FILE (mode 100644) at every changed path. A symlink, a gitlink, or an
#      executable bit at a docs path carries a payload the docs allowlist must
#      not exempt from adversarial review. Each fixture below is enforced and
#      accepted through a real CLEAN record.
docs_only_type_case() { # docs_only_type_case <name> <path> <make-change-fn>
  local name="$1" path="$2" make="$3"
  new_case
  start_feature
  mkdir -p "$WORK/$(dirname "$path")"
  "$make" "$path"
  land_pr
  set_pr_view
  set_files "$path"
  write_review "abc1234-20260101T000000Z" CLEAN
  run_conv 42 --repo arbsec/arbitraitor --json
  expect_exit "$name exits 0" 0
  expect_json "$name is enforced, not exempt" '.local_review.status' "accepted"
}

# Each maker stages its own entry and commits, because `git add -A` would
# re-read a gitlink path as a deletion and a mode change from the worktree.
fixture_commit() {
  git -C "$WORK" -c user.email=t@t -c user.name=t commit -q -m "$1"
}
make_symlink() {
  ln -s ../scripts/run.sh "$WORK/$1"
  git -C "$WORK" add -A
  fixture_commit "add $1"
}
make_gitlink() {
  git -C "$WORK" update-index --add --cacheinfo "160000,$BASE_OID,$1"
  fixture_commit "add $1"
}
make_executable() {
  printf '# guide\n' > "$WORK/$1"
  chmod +x "$WORK/$1"
  git -C "$WORK" add -A
  fixture_commit "add $1"
}

# A 120000 symlink at an allowlisted path (`docs/evil.md -> ../scripts/run.sh`).
docs_only_type_case "docs-only symlink at an allowlisted path" "docs/evil.md" make_symlink
expect_err_contains "symlink enforcement names the mode" "mode 120000"
# A 160000 gitlink at an allowlisted path (a real gitlink entry, no submodule).
docs_only_type_case "docs-only gitlink at an allowlisted path" "docs/vendor.md" make_gitlink
expect_err_contains "gitlink enforcement names the mode" "mode 160000"
# A 100755 executable at an allowlisted path.
docs_only_type_case "docs-only mode change at an allowlisted path" "docs/guide.md" make_executable
expect_err_contains "mode-change enforcement names the mode" "mode 100755"
# Positive control: a plain 100644 content change is still exempt.
new_case
start_feature
printf '# guide\n' > "$WORK/docs/guide.md"
commit_work "docs only"
land_pr
set_pr_view
set_files "docs/guide.md"
run_conv 42 --repo arbsec/arbitraitor --json
expect_exit "regular 100644 docs change exits 0" 0
expect_json "regular 100644 docs change is exempt" '.local_review.status' "docs_only_exempt"
# The type check runs only for would-be exemptions: an allowlist-negative path
# is enforced regardless of mode (here, a symlink).
new_case
start_feature
ln -s docs/old.md "$WORK/AGENTS.md"
commit_work "symlink at a non-allowlisted path"
land_pr
set_pr_view
set_files "AGENTS.md"
write_review "abc1234-20260101T000000Z" CLEAN
run_conv 42 --repo arbsec/arbitraitor --json
expect_exit "non-allowlisted symlink exits 0" 0
expect_json "non-allowlisted symlink is enforced by the name check" '.local_review.status' "accepted"

# ==============================================================================
# 14. Rename -> fail closed (gh pr diff reports only the new path).
# ==============================================================================
new_case
start_feature
git -C "$WORK" mv docs/old.md docs/new.md
commit_work "rename doc"
land_pr
set_pr_view
set_files "docs/new.md"
write_review "abc1234-20260101T000000Z" CLEAN
run_conv 42 --repo arbsec/arbitraitor --json
expect_exit "rename is enforced" 0
expect_json "rename status is not docs_only_exempt" '.local_review.status' "accepted"

# ==============================================================================
# 15. >50 changed files -> fail closed.
# ==============================================================================
new_case
start_feature
mkdir -p "$WORK/docs"
i=1
while [ "$i" -le 51 ]; do
  printf '# doc %s\n' "$i" > "$WORK/docs/page$i.md"
  i=$((i + 1))
done
commit_work "many docs"
land_pr
set_pr_view
files=()
i=1
while [ "$i" -le 51 ]; do
  files+=("docs/page$i.md")
  i=$((i + 1))
done
set_files "${files[@]}"
write_review "abc1234-20260101T000000Z" CLEAN
run_conv 42 --repo arbsec/arbitraitor --json
expect_exit ">50 files is enforced" 0
expect_json ">50 files status is not docs_only_exempt" '.local_review.status' "accepted"

# ==============================================================================
# 16. --skip-local-review in both argv positions; env equivalent.
# ==============================================================================
new_case
start_feature
mkdir -p "$WORK/src"
printf 'fn f() {}\n' > "$WORK/src/lib.rs"
commit_work "feature change"
land_pr
set_pr_view
set_files "src/lib.rs"

run_conv --skip-local-review 42 --repo arbsec/arbitraitor --json
expect_exit "flag before PR exits 0" 0
expect_json "flag before PR status" '.local_review.status' "skipped"
expect_json "flag before PR stays mergeable" '.mergeable' "true"
expect_reason "flag before PR records the skip" "local_review_skipped"
expect_err_contains "flag before PR warns" "WARNING: local CodeRabbit review skipped"

run_conv 42 --skip-local-review --repo arbsec/arbitraitor --json
expect_exit "flag after PR exits 0" 0
expect_json "flag after PR status" '.local_review.status' "skipped"
expect_json "flag after PR stays mergeable" '.mergeable' "true"
expect_reason "flag after PR records the skip" "local_review_skipped"

export ARB_SKIP_LOCAL_REVIEW=1
run_conv 42 --repo arbsec/arbitraitor --json
unset ARB_SKIP_LOCAL_REVIEW
expect_exit "env skip exits 0" 0
expect_json "env skip status" '.local_review.status' "skipped"
expect_reason "env skip records the skip" "local_review_skipped"

# 17. Two positionals -> config error (the flag must never become the PR).
run_conv 42 43 --repo arbsec/arbitraitor --json
expect_exit "two positionals exit 2" 2

# 17b. The valve flag twice is a caller bug, not a stronger waiver: reject it
#      with the config exit code instead of silently accepting both.
run_conv 42 --skip-local-review --skip-local-review --repo arbsec/arbitraitor --json
expect_exit "--skip-local-review twice exits 2" 2
expect_err_contains "--skip-local-review twice is named" "--skip-local-review given twice"

# ==============================================================================
# 18. [review].local_review_required = false -> disabled_by_config (loud).
# ==============================================================================
new_case disabled
start_feature
mkdir -p "$WORK/src"
printf 'fn f() {}\n' > "$WORK/src/lib.rs"
commit_work "feature change"
land_pr
set_pr_view
set_files "src/lib.rs"
run_conv 42 --repo arbsec/arbitraitor --json
expect_exit "disabled by config exits 0" 0
expect_json "disabled status" '.local_review.status' "disabled_by_config"
expect_err_contains "disabled note is loud" "local_review_required = false"

# ==============================================================================
# 19. Integration: a record genuinely produced by pr-review-local with a stubbed
#     CODERABBIT_BIN is accepted (catches writer/reader drift).
# ==============================================================================
new_case
start_feature
mkdir -p "$WORK/src"
printf 'fn f() {}\n' > "$WORK/src/lib.rs"
commit_work "feature change"
land_pr
set_pr_view
set_files "src/lib.rs"
GOT_PR=0
( cd "$WORK" && CODERABBIT_BIN="$ROOT/coderabbit" GH_BIN="$ROOT/gh" \
    bash "$SCRIPTS_REAL/pr-review-local" --pre-push --base origin/main --verdict CLEAN ) \
  > "$ROOT/pr-out" 2> "$ROOT/pr-err" || GOT_PR=$?
if [ "$GOT_PR" -eq 0 ]; then
  ok "pr-review-local wrote a real record"
else
  bad "pr-review-local wrote a real record" "exit $GOT_PR: $(cat "$ROOT/pr-err")"
fi
run_conv 42 --repo arbsec/arbitraitor --json
expect_exit "pr-review-local record is accepted" 0
expect_json "integration status" '.local_review.status' "accepted"
expect_json "integration hash verified" '.local_review.raw_sha256_verified' "true"

# ==============================================================================
# 20. merge-gate forwards --skip-local-review and prints the success-path note.
# ==============================================================================
MERGE_SCRIPTS="$ROOT/merge-scripts"
mkdir -p "$MERGE_SCRIPTS"
ln -s "$SCRIPTS_REAL/merge-gate" "$MERGE_SCRIPTS/merge-gate"
cp "$SCRIPTS_REAL/_lib.sh" "$MERGE_SCRIPTS/_lib.sh"
cat > "$MERGE_SCRIPTS/convergence-status" <<'STUB'
#!/usr/bin/env bash
printf '%s\n' "$*" > "${CONV_ARGS_FILE:?}"
printf '%s\n' '{"mergeable":true,"reasons":["local_review_skipped"],"head_sha":"deadbeef"}'
STUB
chmod +x "$MERGE_SCRIPTS/convergence-status"

export CONV_ARGS_FILE="$ROOT/conv-args"
GOT=0
( cd "$WORK" && GH_BIN="$ROOT/gh" bash "$MERGE_SCRIPTS/merge-gate" \
    42 --repo arbsec/arbitraitor --dry-run --skip-local-review ) \
  > "$ROOT/out" 2> "$ROOT/err" || GOT=$?
OUT="$(cat "$ROOT/out")"; ERR="$(cat "$ROOT/err")"
expect_exit "merge-gate with skip exits 0" 0
if grep -q -- "--skip-local-review" "$CONV_ARGS_FILE"; then
  ok "merge-gate forwards --skip-local-review to convergence-status"
else
  bad "merge-gate forwards --skip-local-review" "args: $(cat "$CONV_ARGS_FILE")"
fi
expect_err_contains "merge-gate prints the success-path note" \
  "note: merge gate passed with waivers: local_review_skipped"

# The other argv order: the flag BEFORE the PR number must forward identically.
CONV_ARGS_FILE="$ROOT/conv-args-before"
GOT=0
: > "$CONV_ARGS_FILE"
( cd "$WORK" && GH_BIN="$ROOT/gh" CONV_ARGS_FILE="$CONV_ARGS_FILE" \
    bash "$MERGE_SCRIPTS/merge-gate" --skip-local-review 42 --repo arbsec/arbitraitor --dry-run ) \
  > "$ROOT/out" 2> "$ROOT/err" || GOT=$?
OUT="$(cat "$ROOT/out")"; ERR="$(cat "$ROOT/err")"
expect_exit "merge-gate with the flag before the PR exits 0" 0
if grep -q -- "--skip-local-review" "$CONV_ARGS_FILE"; then
  ok "merge-gate forwards the flag from the leading position"
else
  bad "merge-gate forwards the flag from the leading position" "args: $(cat "$CONV_ARGS_FILE")"
fi

# A repeated flag is rejected with the config exit code, not accepted twice.
GOT=0
( cd "$WORK" && GH_BIN="$ROOT/gh" bash "$MERGE_SCRIPTS/merge-gate" \
    42 --repo arbsec/arbitraitor --dry-run --skip-local-review --skip-local-review ) \
  > "$ROOT/out" 2> "$ROOT/err" || GOT=$?
OUT="$(cat "$ROOT/out")"; ERR="$(cat "$ROOT/err")"
expect_exit "merge-gate rejects --skip-local-review twice" 2
expect_err_contains "merge-gate names the duplicate flag" "--skip-local-review given twice"
unset CONV_ARGS_FILE

# ==============================================================================
# 20b. The ENV equivalent reaches merge-gate too, with no argv flag: the
#      forwarded args and the success-path waiver note must match case 20.
#      Self-contained: its own args file, and both variables are unset after,
#      so a leaked export from an earlier case cannot make this pass.
# ==============================================================================
CONV_ARGS_FILE="$ROOT/conv-args-env"
ENV_ARGS_FILE="$CONV_ARGS_FILE"
export CONV_ARGS_FILE
: > "$CONV_ARGS_FILE"
GOT=0
( cd "$WORK" && GH_BIN="$ROOT/gh" ARB_SKIP_LOCAL_REVIEW=1 \
    bash "$MERGE_SCRIPTS/merge-gate" 42 --repo arbsec/arbitraitor --dry-run ) \
  > "$ROOT/out" 2> "$ROOT/err" || GOT=$?
OUT="$(cat "$ROOT/out")"; ERR="$(cat "$ROOT/err")"
unset CONV_ARGS_FILE
expect_exit "merge-gate with the env skip exits 0" 0
if grep -q -- "--skip-local-review" "$ENV_ARGS_FILE"; then
  ok "merge-gate forwards the env skip as --skip-local-review"
else
  bad "merge-gate forwards the env skip as --skip-local-review" "args: $(cat "$ENV_ARGS_FILE")"
fi
expect_err_contains "merge-gate prints the env-skip waiver note" \
  "note: merge gate passed with waivers: local_review_skipped"

# ==============================================================================
# 21. Regression: an empty digest on EITHER side is a mismatch, never a match.
#     `sha256_of` used to `exit` inside a command substitution (which ends only
#     the subshell) and `set -e` is suspended under `||`, so an unavailable
#     digest tool yielded "" on both sides and `"" != ""` is false -> fail-open.
# ==============================================================================
new_case
start_feature
mkdir -p "$WORK/src"
printf 'fn f() {}\n' > "$WORK/src/lib.rs"
commit_work "feature change"
land_pr
set_pr_view
set_files "src/lib.rs"
write_review "abc1234-20260101T000000Z" CLEAN

# 21a. The RECORD has no `raw sha256` line -> the recorded digest is empty.
REC="$WORK/.arbitraitor/reviews/abc1234-20260101T000000Z.md"
grep -v '^- raw sha256:' "$REC" > "$REC.tmp" && mv "$REC.tmp" "$REC"
run_conv 42 --repo arbsec/arbitraitor --json
expect_exit "empty recorded digest blocks" 5
expect_json "empty recorded digest status" '.local_review.status' "local_review_hash_mismatch"
expect_json "empty recorded digest is not verified" '.local_review.raw_sha256_verified' "false"

# 21b. The digest TOOL yields nothing -> the computed digest is empty.
new_case
start_feature
mkdir -p "$WORK/src"
printf 'fn f() {}\n' > "$WORK/src/lib.rs"
commit_work "feature change"
land_pr
set_pr_view
set_files "src/lib.rs"
write_review "abc1234-20260101T000000Z" CLEAN
mkdir -p "$ROOT/emptybin"
cat > "$ROOT/emptybin/sha256sum" <<'STUB'
#!/usr/bin/env bash
# A digest tool that produces no output at all.
# It must NOT read stdin: `cat` would consume the test runner's stdin and
# block on a terminal until the developer presses Ctrl-D (CI does not hang,
# because its stdin is not a terminal).
exit 0
STUB
chmod +x "$ROOT/emptybin/sha256sum"
export PATH="$ROOT/emptybin:$PATH"
run_conv 42 --repo arbsec/arbitraitor --json
export PATH="${PATH#"$ROOT/emptybin:"}"
expect_exit "empty computed digest blocks" 5
expect_json "empty computed digest status" '.local_review.status' "local_review_hash_mismatch"
expect_json "empty computed digest is not verified" '.local_review.raw_sha256_verified' "false"

# ==============================================================================
# 22. Regression: EVERY waiver is recorded in `reasons`. `merge-gate` prints
#     only `reasons` on the success path, so a waiver missing there would leave
#     no visible trace in its output.
# ==============================================================================
new_case disabled
start_feature
mkdir -p "$WORK/src"
printf 'fn f() {}\n' > "$WORK/src/lib.rs"
commit_work "feature change"
land_pr
set_pr_view
set_files "src/lib.rs"
run_conv 42 --repo arbsec/arbitraitor --json
expect_exit "config-disabled waiver exits 0" 0
expect_json "config-disabled waiver status" '.local_review.status' "disabled_by_config"
expect_reason "config-disabled waiver is recorded in reasons" "local_review_disabled_by_config"
expect_json "config-disabled waiver stays mergeable" '.mergeable' "true"

new_case
start_feature
printf '# guide\n' > "$WORK/docs/guide.md"
commit_work "docs only"
land_pr
set_pr_view
set_files "docs/guide.md"
run_conv 42 --repo arbsec/arbitraitor --json
expect_exit "docs-only waiver exits 0" 0
expect_json "docs-only waiver status" '.local_review.status' "docs_only_exempt"
expect_reason "docs-only waiver is recorded in reasons" "local_review_docs_only_exempt"
expect_json "docs-only waiver stays mergeable" '.mergeable' "true"

# ==============================================================================
# 23. Regression: the emergency valves do not depend on the evidence inputs.
#     The diff, the base fetch, and the head-tree lookup used to run BEFORE the
#     valve branches and `exit 1` on failure, so a valve could not open when
#     the very inputs it waives were unavailable.
# ==============================================================================
new_case
start_feature
mkdir -p "$WORK/src"
printf 'fn f() {}\n' > "$WORK/src/lib.rs"
commit_work "feature change"
land_pr
set_pr_view
set_files "src/lib.rs"

export GH_DIFF_FAIL=1
run_conv 42 --skip-local-review --repo arbsec/arbitraitor --json
expect_exit "skip valve works when the diff fails" 0
expect_json "skip valve status when the diff fails" '.local_review.status' "skipped"
expect_reason "skip valve reason when the diff fails" "local_review_skipped"
unset GH_DIFF_FAIL

# Without a valve the same failure must be loud, never silent. An infrastructure
# failure is exit 1 (unrecoverable), not the exit 5 (blocked) used for evidence
# failures -- the distinction is deliberate and already covered above.
export GH_DIFF_FAIL=1
run_conv 42 --repo arbsec/arbitraitor --json
expect_exit "diff failure without a valve is unrecoverable" 1
expect_err_contains "diff failure without a valve is loud" "failed to read the PR diff"
unset GH_DIFF_FAIL

# The config valve opens under the same failure.
new_case disabled
start_feature
mkdir -p "$WORK/src"
printf 'fn f() {}\n' > "$WORK/src/lib.rs"
commit_work "feature change"
land_pr
set_pr_view
set_files "src/lib.rs"
export GH_DIFF_FAIL=1
run_conv 42 --repo arbsec/arbitraitor --json
expect_exit "config valve works when the diff fails" 0
expect_json "config valve status when the diff fails" '.local_review.status' "disabled_by_config"
expect_reason "config valve reason when the diff fails" "local_review_disabled_by_config"
unset GH_DIFF_FAIL

# The base fetch failing must not close the valve either.
new_case
start_feature
mkdir -p "$WORK/src"
printf 'fn f() {}\n' > "$WORK/src/lib.rs"
commit_work "feature change"
land_pr
set_pr_view
set_files "src/lib.rs"
git -C "$WORK" remote set-url origin "file://$ROOT/no-such-origin.git"
run_conv 42 --skip-local-review --repo arbsec/arbitraitor --json
expect_exit "skip valve works when the base fetch fails" 0
expect_json "skip valve status when the base fetch fails" '.local_review.status' "skipped"
run_conv 42 --repo arbsec/arbitraitor --json
expect_exit "base fetch failure without a valve is unrecoverable" 1
expect_err_contains "base fetch failure without a valve is loud" "cannot fetch origin main"

# ==============================================================================
# 24. Regression: the base is fetched with an EXPLICIT refspec. `git fetch
#     origin -- <base>` updates refs/remotes/origin/<base> only when the remote's
#     configured fetch refspec covers that branch; in a single-branch or
#     narrow-refspec clone the tracking ref stays STALE, and the ancestor and
#     overlap checks then run against an old base tip — the gate accepts a
#     record whose base has advanced over a file this PR changes.
# ==============================================================================
new_case
start_feature
mkdir -p "$WORK/src"
printf 'fn f() {}\n' > "$WORK/src/lib.rs"
commit_work "feature change"
# The base advances over a file this PR changes.
git -C "$WORK" checkout -q main
mkdir -p "$WORK/src"
printf 'fn f() { /* base */ }\n' > "$WORK/src/lib.rs"
git -C "$WORK" add -A
git -C "$WORK" -c user.email=t@t -c user.name=t commit -q -m "base advance over src/lib.rs"
git -C "$WORK" push -q origin main
git -C "$WORK" checkout -q feature
# Narrow the fetch refspec: `git fetch origin -- main` can no longer update
# refs/remotes/origin/main, so only an explicit refspec refreshes it.
git -C "$WORK" config --replace-all remote.origin.fetch \
  "+refs/heads/feature:refs/remotes/origin/feature"
# `git push` opportunistically updates the tracking ref — reset it to the stale
# base so the clone really looks like one that never refreshed it.
git -C "$WORK" update-ref refs/remotes/origin/main "$BASE_OID"
land_pr
set_pr_view
set_files "src/lib.rs"
write_review "abc1234-20260101T000000Z" CLEAN
run_conv 42 --repo arbsec/arbitraitor --json
expect_exit "stale base tracking ref is refreshed" 5
expect_json "stale base tracking ref status" '.local_review.status' "local_review_base_overlap"

# ==============================================================================
# 25. Regression: a non-docs file moved to a docs path must not slip into the
#     docs-only exemption. `gh pr diff --name-only` lists only the new path,
#     and git's rename heuristics (diff.renames, 50% similarity) can report the
#     move as a delete plus an add, so no `R*` line appears.
# ==============================================================================
new_case
# The moved file must exist in the BASE, otherwise the diff against the base
# shows only its final path and there is no hidden source to expose.
mkdir -p "$WORK/src"
printf 'fn f() {}\n' > "$WORK/src/lib.rs"
git -C "$WORK" add -A
git -C "$WORK" -c user.email=t@t -c user.name=t commit -q -m "base source"
git -C "$WORK" push -q origin main
git -C "$WORK" update-ref refs/remotes/origin/main "$(git -C "$WORK" rev-parse HEAD)"
BASE_OID="$(git -C "$WORK" rev-parse HEAD)"
start_feature
mkdir -p "$WORK/docs"
git -C "$WORK" mv src/lib.rs docs/lib.md
printf '# unrelated content\n' > "$WORK/docs/lib.md"
commit_work "move the source into a docs path"
land_pr
set_pr_view
set_files "docs/lib.md"   # the API reports only the new path
write_review "abc1234-20260101T000000Z" CLEAN
run_conv 42 --repo arbsec/arbitraitor --json
expect_exit "move into a docs path is enforced" 0
expect_json "move into a docs path is not docs_only_exempt" '.local_review.status' "accepted"

# ==============================================================================
# 26. Regression: the head tree must be resolvable. The reason
#     `local_review_head_unresolvable` is documented but was untested: a
#     head branch that cannot be fetched and an API lookup that returns
#     nothing must BLOCK, never fall through to "no record".
# ==============================================================================
new_case
start_feature
mkdir -p "$WORK/src"
printf 'fn f() {}\n' > "$WORK/src/lib.rs"
commit_work "feature change"
land_pr
set_pr_view_unresolvable
set_files "src/lib.rs"
write_review "abc1234-20260101T000000Z" CLEAN
run_conv 42 --repo arbsec/arbitraitor --json
expect_exit "unresolvable head tree blocks" 5
expect_json "unresolvable head tree status" '.local_review.status' "local_review_head_unresolvable"
expect_err_contains "unresolvable head tree is loud" "cannot resolve the tree of PR head"

# 26b. The head TREE resolves (through the API), but the head OBJECT is
#      neither local nor fetchable: the changed-path union cannot be
#      computed, so the gate must block instead of reading it as "no
#      overlap" and waiving the review.
new_case
start_feature
mkdir -p "$WORK/src"
printf 'fn f() {}\n' > "$WORK/src/lib.rs"
commit_work "feature change"
land_pr
set_pr_view_unresolvable
GH_API_TREE="$PR_TREE"
export GH_API_TREE
set_files "src/lib.rs"
write_review "abc1234-20260101T000000Z" CLEAN
run_conv 42 --repo arbsec/arbitraitor --json
expect_exit "unavailable head object blocks" 5
expect_json "unavailable head object status" '.local_review.status' "local_review_head_object_unavailable"
expect_err_contains "unavailable head object is loud" "cannot compute the PR's changed paths"

# ==============================================================================
# 27. Regression: the transcript's own tree/base headers must agree with the
#     record. The `raw sha256` digest covers only the `.raw.txt`; the
#     record's `tree OID`, `base OID` and `verdict` live in the un-hashed
#     `.md` file. A stale transcript could therefore be relabelled as
#     current by editing the record alone — the digest would still match.
# ==============================================================================
relabel_record_as_current() { # relabel_record_as_current <record> <tree> <base>
  local rec="$1" tree="$2" base="$3" sha raw
  raw="$WORK/.arbitraitor/reviews/$(basename "${rec%.md}").raw.txt"
  sha="$(sha256_of "$raw")"
  awk -v tree="$tree" -v base="$base" -v sha="$sha" '
    /^- tree OID:/   { print "- tree OID: " tree;   next }
    /^- base OID:/   { print "- base OID: " base;   next }
    /^- raw sha256:/ { print "- raw sha256: " sha; next }
    { print }
  ' "$rec" > "$rec.tmp" && mv "$rec.tmp" "$rec"
}

# 27a. The record is relabelled with the current tree; the transcript still
#      carries the stale tree.
new_case
start_feature
mkdir -p "$WORK/src"
printf 'fn f() {}\n' > "$WORK/src/lib.rs"
commit_work "feature change"
land_pr
set_pr_view
set_files "src/lib.rs"
STALE_TREE="$(git -C "$WORK" rev-parse 'main^{tree}')"
write_review "abc1234-20260101T000000Z" CLEAN 0 0 "$STALE_TREE" "$BASE_OID"
relabel_record_as_current \
  "$WORK/.arbitraitor/reviews/abc1234-20260101T000000Z.md" "$PR_TREE" "$BASE_OID"
run_conv 42 --repo arbsec/arbitraitor --json
expect_exit "relabelled transcript tree blocks" 5
expect_json "relabelled transcript tree status" '.local_review.status' "local_review_transcript_mismatch"
expect_json "relabelled transcript tree passes the digest check (the header cross-check blocks)" '.local_review.raw_sha256_verified' "true"
expect_err_contains "relabelled transcript tree is loud" "does not match the record's tree OID"

# 27b. Same, for the base: the record claims the current base, the transcript
#      was taken against a different one.
new_case
start_feature
mkdir -p "$WORK/src"
printf 'fn f() {}\n' > "$WORK/src/lib.rs"
commit_work "feature change"
land_pr
set_pr_view
set_files "src/lib.rs"
STALE_BASE="$(git -C "$WORK" rev-parse 'main^{tree}')"
write_review "abc1234-20260101T000000Z" CLEAN 0 0 "$PR_TREE" "$STALE_BASE"
relabel_record_as_current \
  "$WORK/.arbitraitor/reviews/abc1234-20260101T000000Z.md" "$PR_TREE" "$BASE_OID"
run_conv 42 --repo arbsec/arbitraitor --json
expect_exit "relabelled transcript base blocks" 5
expect_json "relabelled transcript base status" '.local_review.status' "local_review_transcript_mismatch"
expect_err_contains "relabelled transcript base is loud" "does not match the record's base OID"

# ==============================================================================
# 28. Regression: the base-overlap check must see the path a file moved FROM.
#     `gh pr diff --name-only` lists only the NEW path of a move, so a base
#     advance over the OLD path looked like an advance over an untouched file
#     and the gate accepted a review that predates that base change. The
#     comparison set is now the union of the API path list and the local
#     `--no-renames` list.
# ==============================================================================
new_case
# The moved file must exist in the BASE, otherwise the diff against the base
# shows only its final path and there is no hidden source to expose.
mkdir -p "$WORK/src"
printf 'fn a() {}\n' > "$WORK/src/a.rs"
git -C "$WORK" add -A
git -C "$WORK" -c user.email=t@t -c user.name=t commit -q -m "base source"
git -C "$WORK" push -q origin main
git -C "$WORK" update-ref refs/remotes/origin/main "$(git -C "$WORK" rev-parse HEAD)"
BASE_OID="$(git -C "$WORK" rev-parse HEAD)"
start_feature
git -C "$WORK" mv src/a.rs src/b.rs
commit_work "rename the source"
# The base advances over the file the PR moved FROM.
git -C "$WORK" checkout -q main
printf 'fn a() { /* base */ }\n' > "$WORK/src/a.rs"
git -C "$WORK" add -A
git -C "$WORK" -c user.email=t@t -c user.name=t commit -q -m "base advance over the old path"
git -C "$WORK" push -q origin main
git -C "$WORK" checkout -q feature
land_pr
set_pr_view
set_files "src/b.rs"   # the API reports only the new path
write_review "abc1234-20260101T000000Z" CLEAN
run_conv 42 --repo arbsec/arbitraitor --json
expect_exit "base advance over the old path of a move is detected" 5
expect_json "base advance over the old path of a move status" '.local_review.status' "local_review_base_overlap"

# ==============================================================================
# 29. Regression: the base-advance path list must see the path a file moved
#     FROM on the BASE side. Git's rename detection (`diff.renames`, 50%
#     similarity) reports a move by its NEW path only, so a base that renamed
#     `src/a.rs` to `src/c.rs` produced a list holding only `src/c.rs` -- and a
#     PR that edits `src/a.rs` looked like it touched no file the base
#     advanced over. The gate accepted a review that predates that base
#     change. The base-side diff now uses `--no-renames` too.
# ==============================================================================
new_case
# The renamed file must exist in the BASE, otherwise the base-side diff has
# no old path to report.
mkdir -p "$WORK/src"
printf 'fn a() {}\n' > "$WORK/src/a.rs"
git -C "$WORK" add -A
git -C "$WORK" -c user.email=t@t -c user.name=t commit -q -m "base source"
git -C "$WORK" push -q origin main
git -C "$WORK" update-ref refs/remotes/origin/main "$(git -C "$WORK" rev-parse HEAD)"
BASE_OID="$(git -C "$WORK" rev-parse HEAD)"
start_feature
printf 'fn a() { /* pr change */ }\n' > "$WORK/src/a.rs"
commit_work "modify the source"
# The base advances by RENAMING that file. Rename detection is on (the
# default), so the old path disappears from the list without --no-renames.
git -C "$WORK" checkout -q main
git -C "$WORK" mv src/a.rs src/c.rs
git -C "$WORK" -c user.email=t@t -c user.name=t commit -q -m "base renames the source"
git -C "$WORK" push -q origin main
git -C "$WORK" checkout -q feature
land_pr
set_pr_view
set_files "src/a.rs"
write_review "abc1234-20260101T000000Z" CLEAN
run_conv 42 --repo arbsec/arbitraitor --json
expect_exit "base rename over a path this PR changes is detected" 5
expect_json "base rename over a path this PR changes status" '.local_review.status' "local_review_base_overlap"

# ==============================================================================
# 30. Regression: a jq failure must never be read as "false".
#     `jq -e` exits 1 for a false/null result and >= 2 for a runtime or system
#     error. A bare `if jq -e ...; then` treats BOTH as false, so a jq failure
#     read as "no spec path", "no non-docs path" or "no overlap" would WAIVE
#     the local review. Every path-set check now fails closed.
# ==============================================================================

# 30a. The `docs/spec/` exclusion cannot be evaluated -> the diff is not
#       exempt -> the review is enforced (before the fix: docs_only_exempt).
new_case
start_feature
printf '# readme\n' > "$WORK/README.md"
commit_work "docs only"
land_pr
set_pr_view
set_files "README.md"
write_review "abc1234-20260101T000000Z" CLEAN
run_conv_jq_fails exact 'any(.[]; test("^docs/spec/"))' 42 --repo arbsec/arbitraitor --json
expect_exit "a failing docs/spec check does not block the PR" 0
expect_json "a failing docs/spec check enforces the review" '.local_review.status' "accepted"

# 30b. The allowlist check cannot be evaluated -> the diff is not exempt ->
#       the review is enforced (before the fix: docs_only_exempt).
new_case
start_feature
printf '# readme\n' > "$WORK/README.md"
commit_work "docs only"
land_pr
set_pr_view
set_files "README.md"
write_review "abc1234-20260101T000000Z" CLEAN
run_conv_jq_fails exact "map(select(test(\$re) | not)) | length > 0" 42 --repo arbsec/arbitraitor --json
expect_exit "a failing allowlist check does not block the PR" 0
expect_json "a failing allowlist check enforces the review" '.local_review.status' "accepted"

# 30c. The changed-file count cannot be evaluated -> the 50-file limit cannot
#       be applied -> the diff is not exempt -> the review is enforced
#       (before the fix: docs_only_exempt).
new_case
start_feature
printf '# readme\n' > "$WORK/README.md"
commit_work "docs only"
land_pr
set_pr_view
set_files "README.md"
write_review "abc1234-20260101T000000Z" CLEAN
run_conv_jq_fails exact 'length' 42 --repo arbsec/arbitraitor --json
expect_exit "a failing file-count check does not block the PR" 0
expect_json "a failing file-count check enforces the review" '.local_review.status' "accepted"

# 30d. The base-overlap check cannot be evaluated -> the gate cannot prove the
#       base is compatible -> it BLOCKS (before the fix: accepted, because a
#       jq failure read as "no overlap").
new_case
mkdir -p "$WORK/src"
printf 'fn f() {}\n' > "$WORK/src/lib.rs"
git -C "$WORK" add -A
git -C "$WORK" -c user.email=t@t -c user.name=t commit -q -m "base source"
git -C "$WORK" push -q origin main
git -C "$WORK" update-ref refs/remotes/origin/main "$(git -C "$WORK" rev-parse HEAD)"
BASE_OID="$(git -C "$WORK" rev-parse HEAD)"
start_feature
printf 'fn f() { /* pr */ }\n' > "$WORK/src/lib.rs"
commit_work "feature change"
# The base advances over the file this PR changes.
git -C "$WORK" checkout -q main
printf 'fn f() { /* base */ }\n' > "$WORK/src/lib.rs"
git -C "$WORK" add -A
git -C "$WORK" -c user.email=t@t -c user.name=t commit -q -m "base advance"
git -C "$WORK" push -q origin main
git -C "$WORK" checkout -q feature
land_pr
set_pr_view
set_files "src/lib.rs"
write_review "abc1234-20260101T000000Z" CLEAN
run_conv_jq_fails substr 'any($' 42 --repo arbsec/arbitraitor --json
expect_exit "a failing overlap check blocks the PR" 5
expect_json "a failing overlap check status" '.local_review.status' "local_review_overlap_check_failed"
expect_err_contains "a failing overlap check is loud" "the base-overlap check failed to run"

# ==============================================================================
# 31. Regression: a record with NO base OID is a malformed record, not an
#     infrastructure error. The gate used to exit ARB_ERR_UNRECOVERABLE (1)
#     with the message "infrastructure error, not a base advance" -- so
#     automation could read a hand-edited record as a transient failure and
#     retry it, and the message blamed the infrastructure. Every other record
#     defect produces a `local_review_*` reason and the blocked exit (5).
# ==============================================================================
new_case
start_feature
mkdir -p "$WORK/src"
printf 'fn f() {}\n' > "$WORK/src/lib.rs"
commit_work "feature change"
land_pr
set_pr_view
set_files "src/lib.rs"
write_review "abc1234-20260101T000000Z" CLEAN
# Drop the base OID line from the RECORD only (the transcript keeps its own).
# Portable form: BSD sed (macOS) reads `-i '<expr>'` as a backup suffix.
REC="$WORK/.arbitraitor/reviews/abc1234-20260101T000000Z.md"
grep -v '^- base OID: ' "$REC" > "$REC.tmp" && mv "$REC.tmp" "$REC"
run_conv 42 --repo arbsec/arbitraitor --json
expect_exit "a record with no base OID blocks" 5
expect_json "a record with no base OID status" '.local_review.status' "local_review_record_malformed"
expect_err_contains "a record with no base OID is loud" "records no base OID"

# ==============================================================================
# 32. A base OID that is PRESENT but absent from the repository stays exit 1:
#     there the repository (a shallow clone, a missing object) is the plausible
#     cause, and that IS an infrastructure error. This pins the distinction
#     between the two cases.
# ==============================================================================
new_case
start_feature
mkdir -p "$WORK/src"
printf 'fn f() {}\n' > "$WORK/src/lib.rs"
commit_work "feature change"
land_pr
set_pr_view
set_files "src/lib.rs"
write_review "abc1234-20260101T000000Z" CLEAN 0 0 "$PR_TREE" \
  "0000000000000000000000000000000000000000"
run_conv 42 --repo arbsec/arbitraitor --json
expect_exit "a base OID absent from the repository is unrecoverable" 1
expect_err_contains "a base OID absent from the repository is loud" "not present in this repository"

# ==============================================================================
# 33. Regression: a failure that names no reason must still block. The caller
#     used to read `evaluate_local_review || LOCAL_REVIEW_REASON="$LR_STATUS"`,
#     which fails OPEN if a return path forgets to set LR_STATUS: the reason
#     stays empty, no entry is added to REASONS, and MERGEABLE stays true.
#     Every current path sets LR_STATUS, but the safety of this gate depends
#     on every FUTURE edit keeping that property -- so the caller now falls
#     back to `local_review_evaluation_failed` (docs/conventions.md, security
#     invariant 6: "Fail closed").
#
#     The mutation removes ONE LR_STATUS assignment from the gate, so the
#     fallback is the only thing that can keep the verdict blocked.
# ==============================================================================
new_case
start_feature
mkdir -p "$WORK/src"
printf 'fn f() {}\n' > "$WORK/src/lib.rs"
commit_work "feature change"
land_pr
set_pr_view
set_files "src/lib.rs"
# No review record at all: the reviews directory does not exist, so the gate
# takes the "no local review records" branch.
build_mutant
run_conv_mutant 42 --repo arbsec/arbitraitor --json
expect_exit "an unnamed evaluation failure blocks" 5
expect_json "an unnamed evaluation failure status" '.local_review.status' \
  "local_review_evaluation_failed"
expect_reason "an unnamed evaluation failure is a reason" \
  "local_review_evaluation_failed"
expect_json "an unnamed evaluation failure is not mergeable" '.mergeable' "false"

# ==============================================================================
# 34. Regression: a PR from a FORK must not block. The head branch of a fork
#     PR lives on the fork, so `origin -- <head branch>` cannot deliver the
#     head object; only `refs/pull/<N>/head` -- which GitHub publishes for
#     EVERY PR head on the BASE repository -- can. The API still answers with
#     the tree, so the tree resolved while the head OBJECT stayed missing:
#     every `git diff <base>...<head>` then failed and the PR blocked with
#     `local_review_head_object_unavailable`. The only way out was
#     `--skip-local-review`, a valve reserved for emergencies.
#
#     The fixture removes the head branch from the base repository and
#     publishes the head only as `refs/pull/42/head`.
# ==============================================================================
new_case
start_feature
mkdir -p "$WORK/src"
printf 'fn f() {}\n' > "$WORK/src/lib.rs"
commit_work "feature change"
land_pr_fork
# GitHub knows the tree of a fork head even when the object is not local.
GH_API_TREE="$PR_TREE"
export GH_API_TREE
set_pr_view
set_files "src/lib.rs"
write_review "abc1234-20260101T000000Z" CLEAN
run_conv 42 --repo arbsec/arbitraitor --json
expect_exit "a fork PR with a pull-ref head is accepted" 0
expect_json "a fork PR with a pull-ref head status" '.local_review.status' "accepted"
expect_json "a fork PR with a pull-ref head is mergeable" '.mergeable' "true"

echo "convergence-status local-review fixtures: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
