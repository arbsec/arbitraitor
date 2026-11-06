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
ok() { pass=$((pass + 1)); echo "PASS $1"; }
bad() { fail=$((fail + 1)); echo "FAIL $1${2:+: $2}" >&2; }
run_case() {
  local name="$1" fixture="$2" files="$3" expect="$4"
  printf '%s' "$fixture" > "$FIXTURE"
  export FIXTURE
  local got want
  got="$(cd "$REPO" && FAKE_FILES="$files" GH_BIN="$STUB/gh" bash "$PR_CHECKS" 1 --json \
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
  got="$(cd "$REPO" && FAKE_FILES="AGENTS.md" GH_BIN="$STUB/gh" bash "$PR_CHECKS" 1 --json \
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
 {"name":"qlty check","state":"SUCCESS","bucket":"pass","workflow":"qlty","link":"","startedAt":null,"completedAt":null},
 {"name":"CodeRabbit","state":"SKIPPED","bucket":"skipping","workflow":"CodeRabbit","link":"","startedAt":null,"completedAt":null}
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
run_case "absent required check fails the gate" "$NO_AST_FIXTURE" "crates/arbitraitor-core/src/lib.rs" \
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

# 8b. CodeRabbit: the App check auto-skips; the local CLI is the mechanism.
#     A skipping CodeRabbit (listed in [checks].optional) is exempt.
run_case "CodeRabbit skipped is exempt" "$ALL_PASS" "README.md" "$FULL_JSON"

# 8c. ...but a CodeRabbit run that actually FAILED still blocks. The exemption
#     requires bucket == "skipping" — a failure is never a pass.
CODERABBIT_FAIL_FIXTURE="$(printf '%s' "$ALL_PASS" | jq '.[] |= (if .name == "CodeRabbit" then .bucket = "fail" | .state = "FAILURE" else . end)')"
run_case "CodeRabbit failed still blocks" "$CODERABBIT_FAIL_FIXTURE" "README.md" \
  '{"all_passed":false,"any_failing":true,"any_pending":false,"missing_required":[]}'

# 8d. `Agent Skills Shell Suites` is `required`, and a FAILING suite still
#     blocks the gate: `all_passed` requires every reported check to be a pass
#     or exempt, so a red suite run is never a pass.
AGENT_SUITES_FAIL_FIXTURE="$(printf '%s' "$ALL_PASS" | jq '. + [{"name":"Agent Skills Shell Suites","state":"FAILURE","bucket":"fail","workflow":"Agent Skills","link":"","startedAt":null,"completedAt":null}]')"
run_case "failing Agent Skills Shell Suites blocks the gate" "$AGENT_SUITES_FAIL_FIXTURE" ".agents/skills/github-pr-lifecycle/SKILL.md" \
  '{"all_passed":false,"any_failing":true,"any_pending":false,"missing_required":[]}'

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

# 10. code.yml path-gate mirror (arbsec/arbitraitor PR B). The workflow is
#     Rust/Cargo-scoped, so an `.agents`-only diff legitimately never reports its
#     six checks. A `wit/**`, `.config/hakari.toml`, or `Cargo.lock` diff DOES
#     reach the workflow, so the checks are not exempt and their absence blocks.
NO_CODE_FIXTURE="$(printf '%s' "$ALL_PASS" | jq '[.[] | select((.name == "Check & Lint"
  or .name == "Workspace Hack (ubuntu-latest)"
  or .name == "Workspace Hack (macos-latest)"
  or .name == "Test (ubuntu-latest)"
  or .name == "Test (macos-latest)"
  or .name == "Agent Skills Tests") | not)]
  + [{"name":"Agent Skills Shell Suites","state":"SUCCESS","bucket":"pass","workflow":"Agent Skills","link":"","startedAt":null,"completedAt":null}]')"
CODE_MISSING='{"all_passed":false,"any_failing":false,"any_pending":false,
 "missing_required":["Check & Lint","Workspace Hack (ubuntu-latest)",
 "Workspace Hack (macos-latest)","Test (ubuntu-latest)","Test (macos-latest)",
 "Agent Skills Tests"]}'
run_case ".agents-only diff exempts the six code.yml checks" "$NO_CODE_FIXTURE" \
  ".agents/skills/x/SKILL.md" "$FULL_JSON"
run_case "wit/** diff does not exempt the code.yml checks" "$NO_CODE_FIXTURE" \
  "wit/arbitraitor.wit" "$CODE_MISSING"
run_case ".config/hakari.toml diff does not exempt the code.yml checks" "$NO_CODE_FIXTURE" \
  ".config/hakari.toml" "$CODE_MISSING"
run_case "Cargo.lock diff does not exempt the code.yml checks" "$NO_CODE_FIXTURE" \
  "Cargo.lock" "$CODE_MISSING"

# 11. markdown.yml path-gate mirror. A `**/*.md` diff reaches the workflow, so
#     the three checks are NOT exempt (their absence fails closed). A Rust-only
#     diff never reaches markdown.yml, so its three checks are exempt.
NO_MD_FIXTURE="$(printf '%s' "$ALL_PASS" | jq '[.[] | select((.name == "Markdown Lint"
  or .name == "Book Build"
  or .name == "Docs Consistency") | not)]')"
MD_MISSING='{"all_passed":false,"any_failing":false,"any_pending":false,
 "missing_required":["Markdown Lint","Book Build","Docs Consistency"]}'
run_case "docs/*.md diff keeps the markdown three required" "$NO_MD_FIXTURE" "docs/guide.md" \
  "$MD_MISSING"
run_case "rust-only diff exempts the markdown three" "$NO_MD_FIXTURE" \
  "crates/arbitraitor-core/src/lib.rs" "$FULL_JSON"

# 12. agents.yml path-gate mirror (arbsec/arbitraitor#862). `Agent Skills Shell
#     Suites` is `required` and has a PATH_GATED row, so it is required exactly
#     for the diffs that trigger agents.yml (`.agents/**`,
#     `.github/workflows/agents.yml`) and exempt for every other diff. The
#     suite that never reports is the dangerous case: `missing_required` is
#     derived from `required` alone, so a check listed only in `optional` can
#     never be missing, and an `.agents/**` diff whose suites never ran would
#     pass the gate.
NO_SUITE_FIXTURE="$(printf '%s' "$ALL_PASS" | jq '[.[] | select(.name != "Agent Skills Shell Suites")]')"
SUITE_MISSING='{"all_passed":false,"any_failing":false,"any_pending":false,
 "missing_required":["Agent Skills Shell Suites"]}'
run_case ".agents/** diff requires the Agent Skills Shell Suites" "$NO_SUITE_FIXTURE" \
  ".agents/skills/github-pr-lifecycle/SKILL.md" "$SUITE_MISSING"
run_case "agents.yml diff requires the Agent Skills Shell Suites" "$NO_SUITE_FIXTURE" \
  ".github/workflows/agents.yml" "$SUITE_MISSING"
run_case "a Rust-only diff exempts the Agent Skills Shell Suites" "$NO_SUITE_FIXTURE" \
  "crates/arbitraitor-core/src/lib.rs" "$FULL_JSON"
run_case "a docs-only diff exempts the Agent Skills Shell Suites" "$NO_SUITE_FIXTURE" \
  "docs/guide.md" "$FULL_JSON"

# 13. The PATH_GATED table mirrors the workflows it claims to mirror.
#
#     A row that OMITS a trigger path of its workflow is unsafe: a diff that
#     touches only that path starts the workflow, and until the run is queued
#     the check is not reported -- while a row that does not match the diff
#     exempts the check. The gate could then pass before CI reported.
#     An extra path in a row is the opposite error: the check is required for
#     a diff that never triggers the workflow, so it can never be satisfied
#     and the gate blocks forever. The row must therefore list the workflow's
#     trigger paths exactly -- in BOTH directions.
#
#     The ownership rule is per JOB, not per workflow: the exemption is looked
#     up by check NAME, so a row that names the workflow does not exempt the
#     other required jobs of that workflow. A required job with no row of its
#     own is never exempt, and it blocks every diff that does not trigger the
#     workflow -- forever.
#
#     The rows are read out of the script under test, so this test cannot
#     drift from it.
REPO_ROOT="$(cd "$HERE/../../../../.." && pwd)"
WORKFLOWS_DIR="$REPO_ROOT/.github/workflows"

# The table: a single-quoted JSON array in the script.
path_gated_json() {
  awk '/^PATH_GATED=/{f=1} f{print} /^\]/{f=0}' "$PR_CHECKS" \
    | tr -d "'" | sed '1s/^PATH_GATED=//'
}

# The trigger paths of a workflow: every entry of every `paths:` list in the
# file. The workflows declare the list once and alias it (`&code_paths` /
# `*code_paths`), and agents.yml declares it twice; the union is the same set.
workflow_paths() {
  awk '
    /^[[:space:]]*paths:/ { f = 1; next }
    f && /^[[:space:]]*-[[:space:]]*/ {
      line = $0
      sub(/^[[:space:]]*-[[:space:]]*/, "", line)
      print line
      next
    }
    f && /^[[:space:]]*$/ { next }
    f { f = 0 }
  ' "$1" | tr -d "\"'" | sort -u
}

# The job names of a workflow (exactly four spaces of indentation -- the
# workflow-level `name:` has none and a step-level `name:` has more).
workflow_job_names() {
  awk '/^    name:[[:space:]]*/ {
    line = $0
    sub(/^    name:[[:space:]]*/, "", line)
    print line
  }' "$1" | tr -d "\"'"
}

# A check name reduced to the part before the matrix suffix: the YAML job is
# named `Test (${{ matrix.os }})` and reports as `Test (ubuntu-latest)`.
check_base() {
  printf '%s' "${1%% (*}"
}

# The required checks, read out of the project config.
required_checks() {
  awk '
    /^required[[:space:]]*=[[:space:]]*\[/ { f = 1; next }
    f && /\]/ { exit }
    f {
      line = $0
      gsub(/[",]/, "", line)
      gsub(/^[[:space:]]+|[[:space:]]+$/, "", line)
      if (length) print line
    }
  ' "$EXAMPLE_TOML"
}

GATED="$(path_gated_json)"
REQUIRED="$(required_checks)"

for wf in "$WORKFLOWS_DIR"/*.yml; do
  base="$(basename "$wf" .yml)"
  marker=".github/workflows/$base.yml"
  paths="$(workflow_paths "$wf")"
  if [ -z "$paths" ]; then
    continue   # unfiltered workflow: every check of it always reports
  fi

  # A `paths-ignore` filter would make the trigger set the complement of the
  # list, and the row could not mirror it.
  if grep -q 'paths-ignore' "$wf"; then
    bad "workflow $base has no paths-ignore filter" "paths-ignore changes the trigger set"
  else
    ok "workflow $base has no paths-ignore filter"
  fi

  rows="$(printf '%s' "$GATED" | jq -c --arg m "$marker" '[.[] | select(.paths | index($m))]')"
  jobs="$(workflow_job_names "$wf")"

  # Does this workflow own a REQUIRED check? If it does and no row names it,
  # its checks are never exempt -- and a required check that never reports
  # blocks the gate forever.
  owns_required=false
  while IFS= read -r job; do
    [ -n "$job" ] || continue
    while IFS= read -r req; do
      [ -n "$req" ] || continue
      if [ "$(check_base "$job")" = "$(check_base "$req")" ]; then
        owns_required=true
      fi
    done <<< "$REQUIRED"
  done <<< "$jobs"

  if [ "$owns_required" = true ] && [ "$(printf '%s' "$rows" | jq 'length')" -eq 0 ]; then
    bad "workflow $base is named by a PATH_GATED row" "it owns a required check but no row names it"
  fi

  # Per JOB, not per workflow: the exemption is looked up by check NAME, so a
  # row that names the workflow does not exempt the OTHER required jobs of
  # that workflow. Every required job of a path-filtered workflow needs its
  # OWN row -- a second required job without one is never exempt and blocks
  # every diff that does not trigger the workflow, forever.
  while IFS= read -r req; do
    [ -n "$req" ] || continue
    owned=false
    while IFS= read -r job; do
      [ -n "$job" ] || continue
      if [ "$(check_base "$job")" = "$(check_base "$req")" ]; then
        owned=true
      fi
    done <<< "$jobs"
    [ "$owned" = true ] || continue
    if printf '%s' "$rows" | jq -e --arg n "$req" 'any(.[]; .name == $n)' >/dev/null; then
      ok "PATH_GATED has a row for the required check '$req' ($base.yml)"
    else
      bad "PATH_GATED has a row for the required check '$req' ($base.yml)" \
        "no row names it, so the check is never exempt"
    fi
  done <<< "$REQUIRED"

  if [ "$(printf '%s' "$rows" | jq 'length')" -eq 0 ]; then
    continue
  fi

  # Forward direction: every trigger path of the workflow is covered by every
  # row that names it.
  while IFS= read -r p; do
    [ -n "$p" ] || continue
    omitting="$(printf '%s' "$rows" | jq --arg p "$p" '[.[] | select(.paths | index($p) | not)] | length')"
    if [ "$omitting" -eq 0 ]; then
      ok "PATH_GATED rows for $base cover '$p'"
    else
      bad "PATH_GATED rows for $base cover '$p'" \
        "$omitting of $(printf '%s' "$rows" | jq 'length') rows omit it"
    fi
  done <<< "$paths"
done

# Reverse direction, per row: every path in the row is a trigger path of the
# workflow the row names, and the row names EXACTLY ONE workflow. An extra
# path makes the check required for a diff that never starts the workflow, so
# the check never reports and the gate blocks forever. A row that names no
# workflow is never matched to one, and a row that names two is checked
# against the wrong trigger set.
while IFS= read -r row; do
  [ -n "$row" ] || continue
  name="$(printf '%s' "$row" | jq -r '.name')"
  markers="$(printf '%s' "$row" | jq -r '.paths[] | select(test("^\\.github/workflows/[^/]+\\.yml$"))')"
  nmarkers="$(printf '%s\n' "$markers" | grep -c . || true)"
  if [ "$nmarkers" -ne 1 ]; then
    bad "PATH_GATED row '$name' names exactly one workflow" \
      "it names $nmarkers workflow markers"
    continue
  fi
  wf="$WORKFLOWS_DIR/$(basename "$markers")"
  if [ ! -f "$wf" ]; then
    bad "PATH_GATED row '$name' names an existing workflow" \
      "$markers does not exist"
    continue
  fi
  wfpaths="$(workflow_paths "$wf")"
  while IFS= read -r rp; do
    [ -n "$rp" ] || continue
    if printf '%s\n' "$wfpaths" | grep -qxF -- "$rp"; then
      ok "PATH_GATED row '$name' lists only trigger paths ('$rp')"
    else
      bad "PATH_GATED row '$name' lists only trigger paths ('$rp')" \
        "'$rp' is not a trigger path of $(basename "$wf")"
    fi
  done <<< "$(printf '%s' "$row" | jq -r '.paths[]' | sort -u)"
done <<< "$(printf '%s' "$GATED" | jq -c '.[]')"

echo "pr-checks fixtures: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
