#!/usr/bin/env bash
# Regression tests for scripts/pr-checks (arbsec/arbitraitor PR #757 review).
# Runs pr-checks against a stubbed gh (GH_BIN) in a temp git repo with a local
# project config copied from the committed example, asserting the JSON verdicts:
# skip-exemption (single-line + multi-line config arrays), path-gate exemption
# for **/*.rs / Cargo.lock / workflow-file diffs, missing-required failure, and
# the empty-rollup + hard-failure exit contract.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PR_CHECKS="$HERE/../pr-checks"
EXAMPLE_TOML="$(cd "$HERE/../../../../project" && pwd)/github-project.example.toml"
STUB="$(mktemp -d)"
trap 'rm -rf "$STUB"' EXIT

# --- stub gh: `gh pr checks` -> $FIXTURE, `gh pr diff --name-only` -> $FAKE_FILES
cat > "$STUB/gh" <<'STUB'
#!/usr/bin/env bash
cmd="$1"; shift
case "$cmd" in
  pr)
    sub="$1"; shift
    case "$sub" in
      checks) cat "${FIXTURE:?}" ;;
      diff)   printf '%s\n' "${FAKE_FILES:-AGENTS.md}" ;;
      *) exit 2 ;;
    esac ;;
  auth) echo "logged in" ;;
  *) exit 2 ;;
esac
STUB
chmod +x "$STUB/gh"

# temp repo with a local project config (mutating/read scripts require it)
REPO="$(mktemp -d)"
trap 'rm -rf "$STUB" "$REPO"' EXIT
mkdir -p "$REPO/.agents/project"
cp "$EXAMPLE_TOML" "$REPO/.agents/project/github-project.local.toml"
git -C "$REPO" init -q
git -C "$REPO" -c user.email=t@t -c user.name=t commit -q --allow-empty -m init

FIXTURE="$STUB/raw.json"
pass=0; fail=0
run_case() {
  local name="$1" fixture="$2" files="$3" expect="$4"
  printf '%s' "$fixture" > "$FIXTURE"
  export FIXTURE
  local got want
  got="$(cd "$REPO" && FAKE_FILES="$files" GH_BIN="$STUB/gh" bash "$PR_CHECKS" 1 --json 2>/dev/null \
    | jq -c '{all_passed, any_failing, any_pending, missing_required}')"
  want="$(printf '%s' "$expect" | jq -c '{all_passed, any_failing, any_pending, missing_required}')"
  if [ "$got" != "$want" ]; then
    echo "FAIL $name: expected $want, got $got" >&2
    fail=$((fail + 1))
    return
  fi
  pass=$((pass + 1))
  echo "PASS $name"
}

assert_classification() {
  local name="$1" fixture="$2" check="$3" want="$4"
  printf '%s' "$fixture" > "$FIXTURE"
  local got
  got="$(cd "$REPO" && FAKE_FILES="AGENTS.md" GH_BIN="$STUB/gh" bash "$PR_CHECKS" 1 --json 2>/dev/null \
    | jq -r --arg c "$check" '.checks[] | select(.name == $c) | .classification')"
  if [ "$got" != "$want" ]; then
    echo "FAIL $name: expected $check classification=$want, got $got" >&2
    fail=$((fail + 1))
    return
  fi
  pass=$((pass + 1))
  echo "PASS $name"
}

ALL_PASS='[
 {"name":"Check & Lint","state":"SUCCESS","bucket":"pass","workflow":"Code","link":"","startedAt":null,"completedAt":null},
 {"name":"Workspace Hack (ubuntu-latest)","state":"SUCCESS","bucket":"pass","workflow":"Code","link":"","startedAt":null,"completedAt":null},
 {"name":"Workspace Hack (macos-latest)","state":"SUCCESS","bucket":"pass","workflow":"Code","link":"","startedAt":null,"completedAt":null},
 {"name":"Test (ubuntu-latest)","state":"SUCCESS","bucket":"pass","workflow":"Code","link":"","startedAt":null,"completedAt":null},
 {"name":"Test (macos-latest)","state":"SUCCESS","bucket":"pass","workflow":"Code","link":"","startedAt":null,"completedAt":null},
 {"name":"Invariant Property Tests","state":"SUCCESS","bucket":"pass","workflow":"Security Invariants","link":"","startedAt":null,"completedAt":null},
 {"name":"Markdown Lint","state":"SUCCESS","bucket":"pass","workflow":"Markdown","link":"","startedAt":null,"completedAt":null},
 {"name":"Book Build","state":"SUCCESS","bucket":"pass","workflow":"Markdown","link":"","startedAt":null,"completedAt":null},
 {"name":"Docs Consistency","state":"SUCCESS","bucket":"pass","workflow":"Markdown","link":"","startedAt":null,"completedAt":null},
 {"name":"Dependency Policy","state":"SUCCESS","bucket":"pass","link":"","startedAt":null,"completedAt":null},
 {"name":"Advisory Check","state":"SUCCESS","bucket":"pass","link":"","startedAt":null,"completedAt":null},
 {"name":"CodeQL Analysis","state":"SUCCESS","bucket":"pass","link":"","startedAt":null,"completedAt":null},
 {"name":"Agent Skills Tests","state":"SUCCESS","bucket":"pass","link":"","startedAt":null,"completedAt":null},
 {"name":"Documentation","state":"SKIPPED","bucket":"skipping","workflow":"Code","link":"","startedAt":null,"completedAt":null},
 {"name":"qlty check","state":"SUCCESS","bucket":"pass","workflow":"qlty","link":"","startedAt":null,"completedAt":null}
]'
FULL_JSON='{"all_passed":true,"any_failing":false,"any_pending":false,"missing_required":[]}'

# 1. Full rollup, docs-only diff, Documentation skipping -> exempt via optional
#    (regression: the single-line-array parser bug kept the leading "[" on the
#    first optional element, so the skip-exemption never fired)
run_case "full rollup + docs diff + skipping Documentation exempt" "$ALL_PASS" "AGENTS.md" "$FULL_JSON"

# 2. Rust diff -> path-gated checks covered by **/*.rs
assert_classification "Documentation skipping is not-applicable (single-line optional parse)" "$ALL_PASS" "Documentation" "not-applicable"

run_case "rust diff covers path-gated checks" "$ALL_PASS" "crates/arbitraitor-core/src/lib.rs" "$FULL_JSON"

# 3. Cargo.lock diff -> covers all three path-gated checks
run_case "Cargo.lock diff covers path-gated checks" "$ALL_PASS" "Cargo.lock" "$FULL_JSON"

# 4. security.yml diff -> Dependency Policy + Advisory covered by its paths AND
#    Invariants exempt (security.yml is not in the invariants paths filter) ->
#    nothing missing. The discriminator case: .mise.toml is in the invariants
#    paths but not the security paths, so only Invariants becomes non-exempt.
SEC_YML_FIXTURE="$(printf '%s' "$ALL_PASS" | jq 'del(.[5])')"
run_case "security.yml diff exempts all path-gated checks" "$SEC_YML_FIXTURE" ".github/workflows/security.yml" \
  '{"all_passed":true,"any_failing":false,"any_pending":false,"missing_required":[]}'
run_case ".mise.toml diff leaves only Invariants missing" "$SEC_YML_FIXTURE" ".mise.toml" \
  '{"all_passed":false,"any_failing":false,"any_pending":false,"missing_required":["Invariant Property Tests"]}'

# 5. A required check absent from the rollup with no path coverage -> gate fails
NO_AST_FIXTURE="$(printf '%s' "$ALL_PASS" | jq 'del(.[12])')"
run_case "absent required check fails the gate" "$NO_AST_FIXTURE" "README.md" \
  '{"all_passed":false,"any_failing":false,"any_pending":false,"missing_required":["Agent Skills Tests"]}'

# 6. A failing check -> any_failing + all_passed false
FAILING_FIXTURE="$(printf '%s' "$ALL_PASS" | jq '.[0].bucket = "fail" | .[0].state = "FAILURE"')"
run_case "failing check blocks the gate" "$FAILING_FIXTURE" "AGENTS.md" \
  '{"all_passed":false,"any_failing":true,"any_pending":false,"missing_required":[]}'

# 7. Pending checks -> any_pending, exit 0
PENDING_FIXTURE="$(printf '%s' "$ALL_PASS" | jq '.[0].bucket = "pending" | .[0].state = "PENDING"')"
run_case "pending checks report via JSON" "$PENDING_FIXTURE" "AGENTS.md" \
  '{"all_passed":false,"any_failing":false,"any_pending":true,"missing_required":[]}'

# 8. Empty rollup -> all_passed false (a missing check is a failure, not a pass)
run_case "empty rollup fails closed" "[]" "AGENTS.md" \
  '{"all_passed":false,"any_failing":false,"any_pending":false,"missing_required":[]}'

# 9. Hard gh failure (empty output, non-8 exit) -> exit 1
printf '' > "$FIXTURE"
if (cd "$REPO" && GH_BIN="$STUB/gh" bash -c "GH_BIN='$STUB/gh' FAKE_EXIT=1 true") 2>/dev/null; then :; fi
# stub with failing checks command
cat > "$STUB/gh-fail" <<'STUB'
#!/usr/bin/env bash
case "$1 $2" in
  "pr checks") exit 1 ;;
  "pr diff") printf 'AGENTS.md\n' ;;
  auth) echo "logged in" ;;
esac
STUB
chmod +x "$STUB/gh-fail"
got_code=0
(cd "$REPO" && GH_BIN="$STUB/gh-fail" bash "$PR_CHECKS" 1 --json >/dev/null 2>&1) || got_code=$?
if [ "$got_code" -eq 1 ]; then
  pass=$((pass + 1)); echo "PASS hard gh failure exits 1"
else
  fail=$((fail + 1)); echo "FAIL hard gh failure: expected exit 1, got $got_code" >&2
fi

echo "pr-checks fixtures: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
