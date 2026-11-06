#!/usr/bin/env bash
# Regression tests for scripts/pr-review-local (PR A: local CodeRabbit CLI
# review mechanism). Fully offline and self-contained: CODERABBIT_BIN and
# GH_BIN are stubs, git repositories live under a temp dir, and the canned
# output exercises the state gates without spending review quota.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCRIPT="$HERE/../pr-review-local"
EXAMPLE_TOML="$(cd "$HERE/../../../../project" && pwd)/github-project.example.toml"
ROOT="$(mktemp -d)"
trap 'rm -rf "$ROOT"' EXIT

pass=0; fail=0
ok()  { pass=$((pass + 1)); echo "PASS $1"; }
bad() { fail=$((fail + 1)); echo "FAIL $1${2:+: $2}" >&2; }

# --- coderabbit stub -----------------------------------------------------------
# `--version` -> $CR_VERSION; `review ...` appends one line to $CR_INVOKED and
# prints $CR_OUTPUT. $CR_FAIL makes the review exit 1 with $CR_STDERR.
cat > "$ROOT/coderabbit" <<'STUB'
#!/usr/bin/env bash
case "${1:-}" in
  --version) printf '%s\n' "${CR_VERSION:-0.9.0}" ;;
  review)
    if [ -n "${CR_INVOKED:-}" ]; then printf '%s\n' "$*" >> "$CR_INVOKED"; fi
    if [ -n "${CR_FAIL:-}" ]; then
      printf '%s\n' "${CR_STDERR:-boom}" >&2
      exit 1
    fi
    if [ -n "${CR_OUTPUT:-}" ]; then
      printf '%s\n' "$CR_OUTPUT"
    else
      printf '%s\n' '{"findings": []}'
    fi
    ;;
  *) exit 2 ;;
esac
STUB
chmod +x "$ROOT/coderabbit"

# --- gh stub (only --pr mode touches it) --------------------------------------
cat > "$ROOT/gh" <<'STUB'
#!/usr/bin/env bash
case "${1:-}" in
  auth) exit 0 ;;
  pr)
    case "${2:-}" in
      view) printf '%s\n' "${PR_JSON:?}" ;;
      *) exit 2 ;;
    esac ;;
  api) printf '%s\n' "${PR_TREE:?}" ;;
  *) exit 2 ;;
esac
STUB
chmod +x "$ROOT/gh"

# --- fixture repositories ------------------------------------------------------
# One repo per scenario so detached/dirty state cannot leak between cases.
make_repo() { # make_repo [no-local-config]
  local dir
  dir="$(mktemp -d "$ROOT/repo.XXXXXX")"
  git -C "$dir" init -q
  mkdir -p "$dir/.agents/project"
  if [ "${1:-}" != "no-local-config" ]; then
    cp "$EXAMPLE_TOML" "$dir/.agents/project/github-project.local.toml"
  fi
  printf 'hello\n' > "$dir/file.txt"
  git -C "$dir" add -A
  git -C "$dir" -c user.email=t@t -c user.name=t commit -q -m init
  # remote-tracking base and an unreachable remote: fetch must warn + continue
  git -C "$dir" update-ref refs/remotes/origin/main HEAD
  git -C "$dir" remote add origin "$ROOT/does-not-exist.git"
  printf '%s\n' "$dir"
}

# run() -> sets GOT (exit code), OUT, ERR for the last invocation
run() {
  local dir="$1"; shift
  GOT=0
  ( cd "$dir" && CODERABBIT_BIN="${CODERABBIT_BIN:-$ROOT/coderabbit}" \
      GH_BIN="$ROOT/gh" bash "$SCRIPT" "$@" ) > "$ROOT/out" 2> "$ROOT/err" || GOT=$?
  OUT="$(cat "$ROOT/out")"
  ERR="$(cat "$ROOT/err")"
}

expect_exit() { # expect_exit <name> <want>
  if [ "$GOT" -eq "$2" ]; then ok "$1"; else bad "$1" "expected exit $2, got $GOT (stderr: $ERR)"; fi
}

# 1. Happy path: raw + record written with OIDs taken from git rev-parse; the
#    offline fetch warns but does not block.
REPO="$(make_repo)"
export CR_VERSION="0.9.0" CR_OUTPUT='{"findings": []}'
unset CR_FAIL CR_INVOKED
export CR_INVOKED="$ROOT/invoked.happy"
run "$REPO" --pre-push --base origin/main --verdict CLEAN
expect_exit "happy path exits 0" 0
if grep -q "warning: git fetch origin main failed" <<<"$ERR"; then
  ok "offline fetch warns and continues"
else
  bad "offline fetch warns and continues" "stderr: $ERR"
fi
HEAD_OID="$(git -C "$REPO" rev-parse HEAD)"
TREE_OID="$(git -C "$REPO" rev-parse 'HEAD^{tree}')"
BASE_OID="$(git -C "$REPO" rev-parse 'origin/main^{commit}')"
RAW="$(find "$REPO/.arbitraitor/reviews" -name '*.raw.txt' | head -n 1)"
RECORD="$(find "$REPO/.arbitraitor/reviews" -name '*.md' | head -n 1)"
if [ -n "$RAW" ] && grep -q '^# exit: 0$' "$RAW" && grep -q '{"findings": \[\]}' "$RAW"; then
  ok "raw file persisted first with exit header and stdout"
else
  bad "raw file persisted first with exit header and stdout" "raw=$RAW"
fi
if [ -n "$RECORD" ] \
  && grep -qx -- "- verdict: CLEAN" "$RECORD" \
  && grep -qx -- "- head OID: $HEAD_OID" "$RECORD" \
  && grep -qx -- "- tree OID: $TREE_OID" "$RECORD" \
  && grep -qx -- "- base OID: $BASE_OID" "$RECORD" \
  && grep -qx -- "- cli exit: 0" "$RECORD" \
  && grep -q -- '- raw sha256: [0-9a-f]\{64\}$' "$RECORD" \
  && grep -q -- '- generated: [0-9]\{4\}-[0-9]\{2\}-[0-9]\{2\}T' "$RECORD"; then
  ok "record carries verdict, git-derived OIDs, raw sha256, timestamp"
else
  bad "record carries verdict, git-derived OIDs, raw sha256, timestamp" "record=$RECORD"
fi
if grep -q 'review --agent --base origin/main' "$CR_INVOKED"; then
  ok "CLI invoked as 'review --agent --base <base>'"
else
  bad "CLI invoked as 'review --agent --base <base>'" "invocations: $(cat "$CR_INVOKED" 2>/dev/null)"
fi

# 1b. Without --verdict the record never invents a verdict (the v0.9.0 success
#     schema was not observed, so no stdout heuristic is used).
REPO_NOVERDICT="$(make_repo)"
run "$REPO_NOVERDICT" --pre-push --base origin/main
expect_exit "no --verdict still exits 0" 0
NOREC="$(find "$REPO_NOVERDICT/.arbitraitor/reviews" -name '*.md' | head -n 1)"
if grep -qx -- "- verdict: UNKNOWN" "$NOREC"; then
  ok "no --verdict records UNKNOWN (never a guessed CLEAN)"
else
  bad "no --verdict records UNKNOWN (never a guessed CLEAN)" "record=$NOREC"
fi

# 2. Dirty TRACKED tree -> exit 4 and the CLI is never invoked.
REPO_DIRTY="$(make_repo)"
printf 'dirty\n' >> "$REPO_DIRTY/file.txt"
export CR_INVOKED="$ROOT/invoked.dirty"
run "$REPO_DIRTY" --pre-push --base origin/main
expect_exit "dirty tracked tree exits 4" 4
if [ ! -s "$CR_INVOKED" ]; then
  ok "dirty tree never invokes the CLI"
else
  bad "dirty tree never invokes the CLI" "invocations: $(cat "$CR_INVOKED")"
fi

# 2b. Untracked files are deliberately ignored.
REPO_UNTRACKED="$(make_repo)"
printf 'new\n' > "$REPO_UNTRACKED/untracked.txt"
export CR_INVOKED="$ROOT/invoked.untracked"
run "$REPO_UNTRACKED" --pre-push --base origin/main
expect_exit "untracked-only tree still reviews" 0

# 3. PR mode: tree mismatch -> exit 4 (commit SHAs differ by design).
REPO_PR="$(make_repo)"
export PR_JSON='{"headRefOid":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","headRefName":"feature","baseRefName":"main","mergeable":"MERGEABLE"}'
export PR_TREE='bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb'
run "$REPO_PR" --pr 42
expect_exit "PR tree mismatch exits 4" 4

# 4. PR mode: conflicting PR -> exit 5.
export PR_JSON='{"headRefOid":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","headRefName":"feature","baseRefName":"main","mergeable":"CONFLICTING"}'
run "$REPO_PR" --pr 42
expect_exit "conflicting PR exits 5" 5

# 5. Missing CLI -> exit 2.
REPO_NOCLI="$(make_repo)"
export CODERABBIT_BIN="$ROOT/no-such-coderabbit"
run "$REPO_NOCLI" --pre-push --base origin/main
expect_exit "missing CLI exits 2" 2
unset CODERABBIT_BIN

# 6. Unknown flag -> exit 2.
run "$REPO_NOCLI" --pre-push --base origin/main --frobnicate
expect_exit "unknown flag exits 2" 2

# 7. Unparseable version -> exit 2.
export CR_VERSION="definitely-not-semver"
run "$REPO_NOCLI" --pre-push --base origin/main
expect_exit "unparseable version exits 2" 2

# 7b. Version below the 0.9.0 contract -> exit 2.
export CR_VERSION="0.8.9"
run "$REPO_NOCLI" --pre-push --base origin/main
expect_exit "old version exits 2" 2
export CR_VERSION="0.9.0"

# 8. Detached HEAD -> exit 2.
REPO_DETACHED="$(make_repo)"
git -C "$REPO_DETACHED" checkout -q --detach
run "$REPO_DETACHED" --pre-push --base origin/main
expect_exit "detached HEAD exits 2" 2

# 9. CLI failure -> exit 1 with raw evidence and stderr surfaced.
REPO_FAIL="$(make_repo)"
export CR_FAIL=1 CR_STDERR="quota exhausted"
run "$REPO_FAIL" --pre-push --base origin/main
expect_exit "CLI failure exits 1" 1
if grep -q "quota exhausted" <<<"$ERR"; then
  ok "CLI stderr surfaced on failure"
else
  bad "CLI stderr surfaced on failure" "stderr: $ERR"
fi
if [ -n "$(find "$REPO_FAIL/.arbitraitor/reviews" -name '*.raw.txt' 2>/dev/null)" ]; then
  ok "raw evidence persisted on CLI failure"
else
  bad "raw evidence persisted on CLI failure"
fi
if [ -z "$(find "$REPO_FAIL/.arbitraitor/reviews" -name '*.md' 2>/dev/null)" ]; then
  ok "CLI failure writes no .md record (raw only)"
else
  bad "CLI failure writes no .md record (raw only)" \
    "records: $(find "$REPO_FAIL/.arbitraitor/reviews" -name '*.md' 2>/dev/null)"
fi
unset CR_FAIL CR_STDERR

# 10. --dry-run prints the argv and never invokes the CLI.
export CR_INVOKED="$ROOT/invoked.dry"
run "$REPO_NOCLI" --pre-push --base origin/main --dry-run
expect_exit "--dry-run exits 0" 0
if grep -q 'coderabbit review --agent --base origin/main' <<<"$OUT" && [ ! -s "$CR_INVOKED" ]; then
  ok "--dry-run prints argv without invoking the CLI"
else
  bad "--dry-run prints argv without invoking the CLI" "out: $OUT"
fi

# 11. --from-raw must not accept a path that escapes .arbitraitor/reviews/
#     (a `..` segment resolves outside while still matching the string prefix).
REPO_RAW="$(make_repo)"
mkdir -p "$REPO_RAW/.arbitraitor/reviews"
{
  echo "# head OID: $(git -C "$REPO_RAW" rev-parse HEAD)"
  echo "# base ref: origin/main"
  echo "# base OID: $(git -C "$REPO_RAW" rev-parse 'origin/main^{commit}')"
  echo "# exit: 0"
  echo "# --- stdout ---"
  echo '{"verdict":"CLEAN"}'
  echo "# --- stderr ---"
} > "$REPO_RAW/evil.raw.txt"
run "$REPO_RAW" --from-raw ".arbitraitor/reviews/../../evil.raw.txt"
expect_exit "--from-raw path traversal exits 2" 2

# write_raw <repo> <file-name> <cli-exit> -> a well-formed raw transcript at HEAD
write_raw() {
  local dir="$1" name="$2" code="$3"
  mkdir -p "$dir/.arbitraitor/reviews"
  {
    echo "# command: coderabbit review --agent --base origin/main"
    echo "# head OID: $(git -C "$dir" rev-parse HEAD)"
    echo "# tree OID: $(git -C "$dir" rev-parse 'HEAD^{tree}')"
    echo "# base ref: origin/main"
    echo "# base OID: $(git -C "$dir" rev-parse 'origin/main^{commit}')"
    echo "# exit: $code"
    echo "# --- stdout ---"
    echo '{"findings": []}'
    echo "# --- stderr ---"
  } > "$dir/.arbitraitor/reviews/$name"
}

# 12. --pre-push is a mode, not a modifier: combining it with another mode is
#     ambiguous and must be rejected instead of silently picking one. A valid raw
#     file is used so only the mode conflict can be the cause.
write_raw "$REPO_RAW" "ccccccc-20260101T000000Z.raw.txt" 0
RAW_OK=".arbitraitor/reviews/ccccccc-20260101T000000Z.raw.txt"
run "$REPO_RAW" --pre-push --from-raw "$RAW_OK"
expect_exit "--pre-push --from-raw exits 2" 2
run "$REPO_RAW" --pre-push --pr 42
expect_exit "--pre-push --pr exits 2" 2
# Reverse argv order must be rejected too: whichever flag wins the mode race,
# mixing a mode with --pre-push is a configuration error, never a silent pick.
run "$REPO_RAW" --pr 42 --pre-push
expect_exit "--pr --pre-push exits 2" 2
run "$REPO_RAW" --from-raw "$RAW_OK" --pre-push
expect_exit "--from-raw --pre-push exits 2" 2

# 13. --from-raw happy path: the raw headers supply head/base OIDs, the CLI is
#     never invoked, and an explicit --base is ignored with a warning.
REPO_FROMRAW="$(make_repo)"
write_raw "$REPO_FROMRAW" "aaaaaaa-20260101T000000Z.raw.txt" 0
FROMRAW_BASE="$(git -C "$REPO_FROMRAW" rev-parse 'origin/main^{commit}')"
export CR_INVOKED="$ROOT/invoked.fromraw"
run "$REPO_FROMRAW" --from-raw ".arbitraitor/reviews/aaaaaaa-20260101T000000Z.raw.txt" \
  --base origin/main
expect_exit "--from-raw healthy raw exits 0" 0
if grep -q "ignored in --from-raw mode" <<<"$ERR"; then
  ok "--from-raw warns when --base is ignored"
else
  bad "--from-raw warns when --base is ignored" "stderr: $ERR"
fi
FROMRAW_REC="$REPO_FROMRAW/.arbitraitor/reviews/aaaaaaa-20260101T000000Z.md"
if [ -f "$FROMRAW_REC" ] \
  && grep -qx -- "- base OID: $FROMRAW_BASE" "$FROMRAW_REC" \
  && grep -qx -- "- cli exit: 0" "$FROMRAW_REC" \
  && grep -qx -- "- verdict: UNKNOWN" "$FROMRAW_REC"; then
  ok "--from-raw writes a record from the raw file's headers"
else
  bad "--from-raw writes a record from the raw file's headers" "record=$FROMRAW_REC"
fi
if [ ! -s "$CR_INVOKED" ]; then
  ok "--from-raw never invokes the CLI"
else
  bad "--from-raw never invokes the CLI" "invocations: $(cat "$CR_INVOKED")"
fi

# 14. --from-raw must refuse a raw transcript from a failed run (exit != 0).
REPO_FROMRAW_FAIL="$(make_repo)"
write_raw "$REPO_FROMRAW_FAIL" "bbbbbbb-20260101T000000Z.raw.txt" 1
run "$REPO_FROMRAW_FAIL" --from-raw ".arbitraitor/reviews/bbbbbbb-20260101T000000Z.raw.txt"
expect_exit "--from-raw failed run exits 1" 1
if [ -z "$(find "$REPO_FROMRAW_FAIL/.arbitraitor/reviews" -name '*.md' 2>/dev/null)" ]; then
  ok "--from-raw failed run writes no .md record"
else
  bad "--from-raw failed run writes no .md record" \
    "records: $(find "$REPO_FROMRAW_FAIL/.arbitraitor/reviews" -name '*.md' 2>/dev/null)"
fi

# 15. --pr tree match: identical tree under a different commit SHA (what a
#     pre-commit-tree / push-branch landing looks like) is accepted and the record
#     keeps both the local and PR OIDs apart.
REPO_PR_OK="$(make_repo)"
PR_LOCAL_HEAD="$(git -C "$REPO_PR_OK" rev-parse HEAD)"
PR_LOCAL_TREE="$(git -C "$REPO_PR_OK" rev-parse 'HEAD^{tree}')"
PR_HEAD_OID="ffffffffffffffffffffffffffffffffffffffff"
export PR_JSON="{\"headRefOid\":\"$PR_HEAD_OID\",\"headRefName\":\"feature\",\"baseRefName\":\"main\",\"mergeable\":\"MERGEABLE\"}"
export PR_TREE="$PR_LOCAL_TREE"
export CR_INVOKED="$ROOT/invoked.pr.ok"
run "$REPO_PR_OK" --pr 42 --base main --verdict CLEAN
expect_exit "PR mode tree match exits 0" 0
if grep -q "ignored in --pr mode" <<<"$ERR"; then
  ok "--pr warns when --base is explicitly supplied"
else
  bad "--pr warns when --base is explicitly supplied" "stderr: $ERR"
fi
PR_OK_REC="$(find "$REPO_PR_OK/.arbitraitor/reviews" -name '*.md' | head -n 1)"
if [ -n "$PR_OK_REC" ] \
  && grep -qx -- "- head OID: $PR_LOCAL_HEAD" "$PR_OK_REC" \
  && grep -qx -- "- tree OID: $PR_LOCAL_TREE" "$PR_OK_REC" \
  && grep -qx -- "- pr head OID: $PR_HEAD_OID" "$PR_OK_REC" \
  && grep -qx -- "- pr tree OID: $PR_LOCAL_TREE" "$PR_OK_REC" \
  && grep -qx -- "- verdict: CLEAN" "$PR_OK_REC"; then
  ok "PR mode record keeps local and PR head/tree OIDs distinct"
else
  bad "PR mode record keeps local and PR head/tree OIDs distinct" "record=$PR_OK_REC"
fi

# 16. --pr + explicit --repo is a read-only path: it must not need the local
#     project config (which is gitignored and absent on a fresh checkout).
REPO_PR_NOCFG="$(make_repo no-local-config)"
PR_TREE="$(git -C "$REPO_PR_NOCFG" rev-parse 'HEAD^{tree}')"
export PR_TREE
export PR_JSON='{"headRefOid":"dddddddddddddddddddddddddddddddddddddddd","headRefName":"feature","baseRefName":"main","mergeable":"MERGEABLE"}'
run "$REPO_PR_NOCFG" --pr 42 --repo arbsec/arbitraitor --verdict CLEAN
expect_exit "--pr with --repo needs no local project config" 0
if grep -q "ignored in --pr mode" <<<"$ERR"; then
  bad "--pr without --base does not warn" "stderr: $ERR"
else
  ok "--pr without --base does not warn"
fi

# 17. --pr with a differing tree is a content change: exit 4.
REPO_PR_DIFF="$(make_repo)"
DIFF_PR_HEAD="eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
export PR_JSON="{\"headRefOid\":\"$DIFF_PR_HEAD\",\"headRefName\":\"feature\",\"baseRefName\":\"main\",\"mergeable\":\"MERGEABLE\"}"
export PR_TREE="1111111111111111111111111111111111111111"
run "$REPO_PR_DIFF" --pr 42
expect_exit "PR mode content change exits 4" 4

echo "pr-review-local fixtures: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
