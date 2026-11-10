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
# A root file is the sharpest case for the `**/` glob: GitHub Actions matches
# `**/Cargo.toml` against the root `Cargo.toml`, so the workflow RUNS for that
# diff and the code.yml checks are not exempt. If the glob translation turned
# `**/` into a pattern that REQUIRES a directory separator, a root `Cargo.toml`
# diff would exempt the six code.yml checks -- and the gate could pass before
# CI reported them. The translation is `(.*/)?`: zero or more directories.
run_case "root Cargo.toml does not exempt the code.yml checks" "$NO_CODE_FIXTURE" \
  "Cargo.toml" "$CODE_MISSING"
# The opposite error: a pattern with NO `**/` prefix is ROOT-only in GitHub
# Actions. `Cargo.lock` does not match `fuzz/Cargo.lock`, so code.yml does not
# run for that diff and its six checks ARE exempt. An unanchored translation
# would match the nested file, require the checks that never report, and block
# the gate forever with `missing_required`.
run_case "a nested fuzz/Cargo.lock exempts the code.yml checks" "$NO_CODE_FIXTURE" \
  "fuzz/Cargo.lock" "$FULL_JSON"

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
# The root `README.md` is the same glob question as the root `Cargo.toml`:
# `**/*.md` matches it in GitHub Actions, so markdown.yml RUNS and the three
# checks are not exempt.
run_case "root README.md keeps the markdown three required" "$NO_MD_FIXTURE" "README.md" \
  "$MD_MISSING"
# Root-only again: `lefthook.yml` does not match `tools/lefthook.yml`, so
# markdown.yml does not run and the three checks are exempt.
run_case "a nested tools/lefthook.yml exempts the markdown three" "$NO_MD_FIXTURE" \
  "tools/lefthook.yml" "$FULL_JSON"
run_case "rust-only diff exempts the markdown three" "$NO_MD_FIXTURE" \
  "crates/arbitraitor-core/src/lib.rs" "$FULL_JSON"

# 12. agents.yml path-gate mirror (arbsec/arbitraitor#862). `Agent Skills Shell
#     Suites` is `required` and has a PATH_GATED row, so it is required exactly
#     for the diffs that trigger agents.yml (`.agents/**`,
#     `.github/workflows/agents.yml`, `.shellcheckrc`) and exempt for every
#     other diff. `.shellcheckrc` is in the list because it can weaken the
#     gate itself (a `disable=` there silences rules for every script). The
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
run_case ".shellcheckrc diff requires the Agent Skills Shell Suites" "$NO_SUITE_FIXTURE" \
  ".shellcheckrc" "$SUITE_MISSING"
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
# file. The workflows spell the list out under both `push` and `pull_request`
# (actionlint cannot resolve an alias); the union of the two is the same set.
#
# Deliberately NOT shared with tests/paths-grammar.awk. It is a different
# grammar -- no trigger scoping, a list reopened per `paths:` key, the block
# closed by falling back out rather than exiting -- and it is the independent
# side of the `trigger_paths covers the workflow_paths union` assertion below.
# Routing it through the shared program would make that assertion compare one
# implementation against itself and stop catching a scoping regression.
workflow_paths() {
  awk '
    # A comment line carries no YAML structure: `#` is not part of the
    # `^[[:space:]]*paths:` prefix this parser matches, so a comment can never
    # open a list -- and must not terminate one. Hoisted to the first rule so a
    # comment at column 0 or at the list indent cannot end the scan.
    # Exactly one comment rule per program.
    /^[[:space:]]*#/ { next }
    /^[[:space:]]*paths:/ { f = 1; next }
    f && /^[[:space:]]*$/ { next }
    f && /^[[:space:]]*-[[:space:]]*/ {
      line = $0
      sub(/^[[:space:]]*-[[:space:]]*/, "", line)
      sub(/[[:space:]]+#.*$/, "", line)
      sub(/[[:space:]]+$/, "", line)
      print line
      next
    }
    f { f = 0 }
  ' "$1" | tr -d "\"'" | sort -u
}

# The trigger paths of ONE trigger (`push` or `pull_request`): every entry of
# that trigger's `paths:` list, one per line, normalised (quotes removed,
# trailing inline comments stripped, sorted). The grammar itself lives in
# tests/paths-grammar.awk and is loaded by this suite AND by
# tests/agent-skills-workflow.bash, so there is exactly one implementation of
# it and one suite can no longer pass where the other fails. The block and
# list boundaries that grammar pins are documented there.
#
# The union in workflow_paths is blind to a one-sided edit; the two triggers
# must carry the same set because PATH_GATED mirrors the union for BOTH event
# types.
TRIGGER_PATHS_AWK="$HERE/paths-grammar.awk"

trigger_paths() {
  awk -v want="$1" -v mode=paths -f "$TRIGGER_PATHS_AWK" "$2" | tr -d "\"'" | sort -u
}

# Count `paths` keys in key position, in ONE pass, printing "<any> <block>".
# Both counts skip block-scalar bodies, so a shell line such as `paths: x`
# inside a `run: |` step is never mistaken for a YAML key.
#
#   any   -- every key-position spelling: line-initial, or after `{`/`,` in a
#            flow mapping; quoted (`'paths'`, `"paths"`) or bare; with or
#            without a space before the colon. These are the forms the block
#            parser cannot represent.
#   block -- only the bare line-initial `paths:` that opens a block-style list.
#
# A block scalar starts on a line whose value is `|` or `>` (optionally with
# chomping/indent indicators, e.g. `|-`, `>+2`). Its body ends at the first
# non-blank line indented at or below the key column that introduced it: a
# sibling key at the scalar's own column terminates the body, a deeper line is
# still body text. The key column, not the line's leading indent, is used so a
# `- run: |` sequence item is measured at `run`, not at the `-`. A nested
# `|`/`>` inside a body is literal text (the body is skipped wholesale); a
# scalar that runs to end-of-file simply never resumes counting, which is
# correct -- any `paths` there is body text.
#
# Stays here rather than joining tests/paths-grammar.awk: it is already
# single-copy, so moving it would remove no duplication, and it answers a
# different question (every key-position spelling, plus block-scalar bodies)
# than the trigger-block grammar that file exists to keep single-source.
paths_key_counts() {
  awk -v quote="['\"]" '
    function indent(s,   n) {
      n = 0
      while (substr(s, n + 1, 1) == " ") n++
      return n
    }
    function key_col(s,   n, rest) {
      n = indent(s)
      rest = substr(s, n + 1)
      if (rest ~ /^- /) {
        n += 2
        while (substr(s, n + 1, 1) == " ") n++
      }
      return n
    }
    BEGIN {
      keyre = "(^[[:space:]]*|[{,][[:space:]]*)" quote "?paths" quote "?[[:space:]]*:"
      scalre = ":[[:space:]]*[|>][-+0-9]*[[:space:]]*(#.*)?$"
    }
    {
      if (in_scalar) {
        if ($0 ~ /^[[:space:]]*$/) next
        if (indent($0) <= scalar_indent) in_scalar = 0
        else next
      }
      # A comment line carries no YAML structure -- same rule as
      # tests/paths-grammar.awk -- so it must not count as a key nor start a
      # scalar skip. After `in_scalar`, which already owns comment lines inside
      # a block-scalar body (they are body text).
      if ($0 ~ /^[[:space:]]*#/) next
      if ($0 ~ keyre) any++
      if ($0 ~ /^[[:space:]]*paths:[[:space:]]*(#.*)?$/) block++
      if ($0 ~ scalre) { in_scalar = 1; scalar_indent = key_col($0) }
    }
    END { print any + 0, block + 0 }
  ' "$1"
}

# 13a. Direct test of paths_key_counts -- the guard that decides WHETHER the
# contract test may read a workflow at all. A wrong count does not fail that
# workflow's own assertions, it changes which ones run: an inflated `any` rejects
# a valid file and `continue`s past every per-workflow assertion, and a comment
# that starts a block-scalar skip hides a real key so a `paths`-filtered
# workflow looks unfiltered. Neither is visible in a green run over the eight
# committed workflows, so the helper is exercised here on purpose-built YAML.
pkc_case() {
  local name="$1" yaml="$2" want="$3" tmp got
  tmp="$(mktemp)"
  printf '%s' "$yaml" > "$tmp"
  got="$(paths_key_counts "$tmp")"
  rm -f "$tmp"
  if [ "$got" = "$want" ]; then
    ok "paths_key_counts $name"
  else
    bad "paths_key_counts $name" "expected [$want], got [$got]"
  fi
}

# A valid block-style list: the one key is both a key-position spelling and a
# block-style opener.
pkc_case "counts one block-style paths key" "$(cat <<'YAML'
on:
  push:
    paths:
      - "crates/**"
YAML
)" "1 1"

# Regression: a comment inside the list that contains `paths:` text used to
# increment `any` only, rejecting a valid file and skipping every assertion for
# that workflow.
pkc_case "ignores a comment containing paths: text" "$(cat <<'YAML'
on:
  push:
    paths:
      # keep in sync, paths: must match pull_request below
      - "crates/**"
YAML
)" "1 1"

# Regression: a column-0 comment ending `: |` used to start a block-scalar skip
# that swallowed the following `paths:` key, so a filtered workflow counted as
# `0 0` -- indistinguishable from one with no filter.
pkc_case "ignores a comment ending in a block-scalar indicator" "$(cat <<'YAML'
# example: |
  on:
    push:
      paths:
        - "crates/**"
YAML
)" "1 1"

# A real block-scalar body may contain anything, including a line that looks
# like a `paths:` key; it is body text, not a key.
pkc_case "ignores paths: text inside a run: | body" "$(cat <<'YAML'
on:
  push:
    paths:
      - "crates/**"
jobs:
  test:
    steps:
      - run: |
          paths: not-a-key
YAML
)" "1 1"

# No `paths` key at all is the only case that legitimately reads `0 0`.
pkc_case "counts no paths key" "$(cat <<'YAML'
name: Release
on:
  push:
    branches:
      - main
YAML
)" "0 0"

# A flow-style key is unreadable by the block parser, so the counts must differ
# and the loud rejection must fire. The flow key sits after a block list -- the
# "later flow key hiding behind an earlier block list" case.
pkc_case "counts a flow-style key apart from the block count" "$(cat <<'YAML'
on:
  push:
    paths:
      - "a"
  pull_request:
    paths: ["b"]
YAML
)" "2 1"

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

# Workflows that are deliberately push-only: they deploy or publish on main and
# have no PR-time job. Verified across all eight workflows in .github/workflows/
# when this assertion was added -- only docs.yml qualifies. Every OTHER
# path-filtered workflow must start on both events; codeql.yml and release.yml
# declare no `paths:` at all, so they never reach the per-trigger assertions.
#
# This is a whitespace-separated LIST. Every use must test membership against
# the whole list (`case " $PUSH_ONLY " in`) -- a scalar `[ "$base" = "$PUSH_ONLY" ]`
# silently works for one entry and makes a second allowlisted workflow fail the
# both-triggers assertion instead.
PUSH_ONLY="docs"

seen_push_only=""

for wf in "$WORKFLOWS_DIR"/*.yml; do
  base="$(basename "$wf" .yml)"
  marker=".github/workflows/$base.yml"

  # The contract test can only read a block-style `paths:` sequence:
  #
  #     paths:
  #       - "entry"
  #
  # GitHub also accepts flow style (`paths: ["a", "b"]`), a separation space
  # before the colon (`paths :`), a quoted key (`'paths':`), and a scalar.
  # Those parse to an empty union here, which would skip the entire
  # per-workflow block below -- a live gate silently blind to a disjoint path
  # set. Reject them loudly instead of mis-parsing; counting every key-position
  # spelling against the keys the block parser can open a list from also
  # catches a later flow key hiding behind an earlier block list. The counts
  # skip block-scalar bodies, so a shell line such as `paths: x` inside a
  # `run: |` step is not misread as a YAML key.
  counts="$(paths_key_counts "$wf")"
  keys="${counts%% *}"
  block_keys="${counts##* }"
  if [ "$keys" != "$block_keys" ]; then
    bad "workflow $base declares only block-style paths: lists" \
      ".github/workflows/$base.yml has a paths key the contract test cannot read (flow sequence, quoted key, or 'paths :'); only block-style paths: lists are supported"
    continue
  fi

  paths="$(workflow_paths "$wf")"
  if [ -z "$paths" ]; then
    continue   # unfiltered workflow: every check of it always reports
  fi

  # Deleting a trigger does not change the `paths:` union, so without this
  # presence check the equality assertion below simply never runs and the suite
  # stays green while the workflow stops reporting for that event -- for
  # code.yml the required Code checks would never appear and every PR would
  # block forever. Only an allowlisted push-only workflow may omit a trigger,
  # and the allowlist is closed-world: the push-only workflow must still
  # declare `push:` and must NOT declare `pull_request:`, so a file that gained
  # a PR trigger cannot keep the exemption (and the coverage it implies).
  #
  # Membership test against the list, never scalar equality: with two entries a
  # `[ "$base" = "$PUSH_ONLY" ]` matches neither, and both allowlisted
  # workflows fall into the both-triggers branch below and fail.
  push_only=false
  case " $PUSH_ONLY " in
    *" $base "*) push_only=true ;;
  esac
  if [ "$push_only" = true ]; then
    seen_push_only="$seen_push_only $base"
    if grep -q -E '^  push:[[:space:]]*(#.*)?$' "$wf"; then
      ok "workflow $base has a push trigger"
    else
      bad "workflow $base has a push trigger" \
        "the push-only allowlist entry must still trigger on push"
    fi
    if grep -q -E '^  pull_request:[[:space:]]*(#.*)?$' "$wf"; then
      bad "workflow $base is push-only (no pull_request trigger)" \
        "it is allowlisted as push-only but declares a pull_request trigger; only a push-only allowlist entry ($PUSH_ONLY) may omit one"
    else
      ok "workflow $base is push-only (no pull_request trigger)"
    fi
  else
    for trigger in push pull_request; do
      if grep -q -E "^  $trigger:[[:space:]]*(#.*)?\$" "$wf"; then
        ok "workflow $base has a $trigger trigger"
      else
        bad "workflow $base has a $trigger trigger" \
          "a path-filtered workflow must start on both push and pull_request; only a push-only allowlist entry ($PUSH_ONLY) may omit one"
      fi
    done
  fi

  # Both triggers must carry the same path set. The union above is blind to a
  # one-sided edit: a `paths:` entry removed from only one trigger leaves the
  # union intact, so GitHub would start the workflow for one event but not the
  # other while every union-based assertion stayed green. Guard on the two
  # triggers -- docs.yml is push-only, and comparing its list against an empty
  # pull_request set would false-positive.
  if grep -q -E '^  push:[[:space:]]*(#.*)?$' "$wf" &&
     grep -q -E '^  pull_request:[[:space:]]*(#.*)?$' "$wf"; then
    push_paths="$(trigger_paths push "$wf")"
    pr_paths="$(trigger_paths pull_request "$wf")"
    if [ "$push_paths" = "$pr_paths" ]; then
      ok "workflow $base push and pull_request paths are identical"
    else
      bad "workflow $base push and pull_request paths are identical" \
        "push=[$push_paths] pull_request=[$pr_paths]"
    fi
  fi

  # The scoped parser must account for every entry the union parser sees. If
  # `trigger_paths` regressed to print nothing, both trigger sets would be
  # empty and the equality assertion above would pass vacuously ("" == "").
  # Comparing their union against workflow_paths makes that regression fail
  # loudly instead. Runs for push-only workflows too (docs.yml): their union is
  # just the one trigger's list.
  scoped_paths="$({ trigger_paths push "$wf"; trigger_paths pull_request "$wf"; } | sort -u)"
  if [ "$scoped_paths" = "$paths" ]; then
    ok "workflow $base trigger_paths covers the workflow_paths union"
  else
    bad "workflow $base trigger_paths covers the workflow_paths union" \
      "scoped=[$scoped_paths] union=[$paths]"
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

# The push-only allowlist is closed-world. An allowlisted workflow that was
# never checked -- its file deleted or renamed -- or that lost its `paths:`
# list (the `continue` above fires before the branch) would silently remove the
# push-only exemption AND the union-coverage and paths-ignore assertions that
# hang off it. Assert every allowlist entry was actually reached.
for allow in $PUSH_ONLY; do
  case " $seen_push_only " in
    *" $allow "*)
      ok "workflow $allow on the push-only allowlist was checked" ;;
    *)
      bad "workflow $allow on the push-only allowlist was checked" \
        "$allow is allowlisted as push-only, but no checked workflow matched it (deleted, renamed, or missing its paths: list)" ;;
  esac
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
