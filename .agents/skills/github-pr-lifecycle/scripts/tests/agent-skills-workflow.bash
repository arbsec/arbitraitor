#!/usr/bin/env bash
# Contract test for the agent-skill CI gate (.github/workflows/agents.yml).
#
# The gate is the single home for the agent-skill shell suites: a diff that
# only touches `.agents/**` never reaches a Rust-scoped workflow, so the skill
# shell suites would never execute (arbsec/arbitraitor#859). This suite pins
# the invariants that make the gate work and keeps them from drifting:
#
#   1. the workflow exists, triggers on `.agents/**` for pull requests and for
#      pushes to `main`;
#   2. the required check name `Agent Skills Tests` is reported by exactly ONE
#      workflow (agents.yml) and the superseded name `Agent Skills Shell
#      Suites` is reported by NO workflow — a mixed Rust + `.agents` diff must
#      never produce two checks under one name;
#   3. the syntax check runs `bash -n` once per file (`bash -n a b` parses
#      only `a`, so the `find -exec bash -n {} +` form checks one file);
#   4. the check name is registered in the project config and the superseded
#      name is not;
#   5. the workflow uses no YAML anchor/alias (actionlint cannot parse an
#      alias node and reports it as a syntax error);
#   6. shellcheck is pinned by version and a 64-hex digest, runs at
#      `-S warning`, runs the same file-selection command as the syntax step,
#      and asserts the selection is non-empty;
#   7. `.shellcheckrc` is pinned byte-for-byte to its two lines and carries no
#      `disable=` — the rc is a gate-weakening surface;
#   8. `.shellcheckrc` is path-gated by BOTH triggers, so a diff touching only
#      the rc runs the lint and this contract test.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../../../../.." && pwd)"
WORKFLOWS="$ROOT/.github/workflows"
AGENTS_WORKFLOW="$WORKFLOWS/agents.yml"
EXAMPLE_TOML="$ROOT/.agents/project/github-project.example.toml"
SHELLCHECKRC="$ROOT/.shellcheckrc"

# Print the body of a workflow step, given its `name:` value.
step_body() {
  awk -v want="$1" '
    /^      - name: / { if (inside) exit; inside = ($0 == "      - name: " want); next }
    inside { print }
  ' "$AGENTS_WORKFLOW"
}

# The trigger paths of ONE trigger (`push` or `pull_request`): every entry of
# that trigger's `paths:` list, one per line, normalised (quotes removed,
# trailing inline comments stripped, sorted). The grammar lives in
# tests/paths-grammar.awk and is shared with tests/pr-checks.bash, so there is
# exactly one implementation of it and one suite can no longer pass where the
# other fails. Three boundaries matter, and the grammar file documents each:
#   - the TRIGGER block ends at ANY key at or above the trigger's indent,
#     including column 0, so a missing `paths:` under `push:` cannot make
#     `trigger_paths push` walk into `pull_request:` -- or into a top-level
#     section such as `jobs:` -- and print that block's entries (a false PASS);
#   - the trigger and `paths:` keys tolerate a trailing comment, so a
#     commented key does not silently return an empty list;
#   - the `paths:` list ends at the first line that is neither a list entry,
#     a blank line, nor a comment.
# Each was verified by manual mutation testing out of tree; the assertions
# below exist to keep them true.
TRIGGER_PATHS_AWK="$HERE/paths-grammar.awk"

trigger_paths() {
  awk -v want="$1" -v mode=paths -f "$TRIGGER_PATHS_AWK" "$AGENTS_WORKFLOW" | tr -d "\"'" | sort -u
}

# Does the trigger block carry a `paths:` key at all? Used to prove that a
# present list never parses to empty after a parser regression. Same grammar,
# `has` mode: it shares the block boundaries with trigger_paths by
# construction instead of restating them.
trigger_has_paths() {
  awk -v want="$1" -v mode=has -f "$TRIGGER_PATHS_AWK" "$AGENTS_WORKFLOW"
}

pass=0
fail=0
ok() { pass=$((pass + 1)); echo "PASS $1"; }
bad() { fail=$((fail + 1)); echo "FAIL $1${2:+: $2}" >&2; }

# Count workflow job names across every workflow file. Job names are the
# GitHub status-check names; the workflow-level `name:` is not a check name,
# so the pattern is anchored on the job indentation.
count_job_names() {
  local wanted="$1" total=0 file hits
  for file in "$WORKFLOWS"/*.yml; do
    hits="$(grep -c -E "^[[:space:]]{2,}name:[[:space:]]*${wanted}[[:space:]]*$" "$file" || true)"
    total=$((total + hits))
  done
  printf '%s' "$total"
}

# 1. The workflow exists and covers `.agents/**` on pull requests and main pushes.
if [ -f "$AGENTS_WORKFLOW" ]; then
  ok "agents workflow exists"
else
  bad "agents workflow exists" "missing $AGENTS_WORKFLOW"
  echo "agent-skills-workflow fixtures: $pass passed, $fail failed"
  exit 1
fi

# The filter must live inside each trigger's `paths:` list, not merely appear
# somewhere in the file -- a comment or an unrelated key must not satisfy it.
for trigger in push pull_request; do
  if trigger_paths "$trigger" | grep -qxF '.agents/**'; then
    ok "agents workflow covers .agents/** ($trigger)"
  else
    bad "agents workflow covers .agents/** ($trigger)" \
      "no .agents/** in the $trigger paths list"
  fi
done

# A `paths:` key that parses to an empty list is a parser regression, not a
# workflow with no filter. Fail loudly so an empty list can never satisfy the
# `push == pull_request` equality check as "" == "".
for trigger in push pull_request; do
  if [ -n "$(trigger_has_paths "$trigger")" ]; then
    if [ -n "$(trigger_paths "$trigger")" ]; then
      ok "agents workflow $trigger paths list is non-empty"
    else
      bad "agents workflow $trigger paths list is non-empty" \
        "a paths: key is present but trigger_paths returned nothing"
    fi
  fi
done

if grep -q -E '^[[:space:]]*pull_request:' "$AGENTS_WORKFLOW"; then
  ok "agents workflow triggers on pull requests"
else
  bad "agents workflow triggers on pull requests" "no pull_request trigger"
fi

if grep -q -E '^[[:space:]]*branches:[[:space:]]*\[main\]' "$AGENTS_WORKFLOW"; then
  ok "agents workflow triggers on pushes to main"
else
  bad "agents workflow triggers on pushes to main" "no main branch filter"
fi

# 2. Check-name uniqueness across workflows.
if [ "$(count_job_names 'Agent Skills Tests')" -eq 1 ]; then
  ok "check name 'Agent Skills Tests' is reported by exactly one workflow"
else
  bad "check name 'Agent Skills Tests' is reported by exactly one workflow" \
    "count=$(count_job_names 'Agent Skills Tests')"
fi

if [ "$(count_job_names 'Agent Skills Shell Suites')" -eq 0 ]; then
  ok "superseded check name 'Agent Skills Shell Suites' is reported by no workflow"
else
  bad "superseded check name 'Agent Skills Shell Suites' is reported by no workflow" \
    "count=$(count_job_names 'Agent Skills Shell Suites')"
fi

# 3. One `bash -n` per file — `find -exec bash -n {} +` parses only the first file.
if grep -q -- '-exec bash -n {} +' "$AGENTS_WORKFLOW"; then
  bad "syntax check runs bash -n once per file" "batched form parses only the first file"
else
  ok "syntax check runs bash -n once per file"
fi

# 4. The check name is registered in the project config, and the superseded
#    name is not. A stale name in [checks].required can never report, and
#    `missing_required` is derived from `required` alone -- so it would block
#    the gate forever with no way to tell why.
if grep -q '"Agent Skills Tests"' "$EXAMPLE_TOML"; then
  ok "check name is registered in the project config"
else
  bad "check name is registered in the project config" "not listed in github-project.example.toml"
fi

if grep -q '"Agent Skills Shell Suites"' "$EXAMPLE_TOML"; then
  bad "superseded check name is not in the project config" \
    "a stale name in [checks].required can never report and blocks the gate forever"
else
  ok "superseded check name is not in the project config"
fi

# 5. No YAML anchor/alias. actionlint cannot resolve an alias node and
#    reports it as a syntax error ("paths section must be sequence node but
#    got alias node"); qlty runs actionlint over the changed lines of a diff
#    and reported that as a blocking issue on this workflow.
# Comments are stripped first — the workflow explains the pattern in prose.
workflow_yaml="$(grep -v -E '^[[:space:]]*#' "$AGENTS_WORKFLOW")"
if printf '%s\n' "$workflow_yaml" | grep -q -E ':[[:space:]]*&[A-Za-z_]' ||
   printf '%s\n' "$workflow_yaml" | grep -q -E ':[[:space:]]*\*[A-Za-z_]'; then
  bad "workflow avoids YAML anchors and aliases" "actionlint cannot parse an alias node"
else
  ok "workflow avoids YAML anchors and aliases"
fi

# 6. Shellcheck pin: version, 64-hex digest, severity, selection, non-empty guard.
# The pin greps are scoped to the install step body: a bare grep over the whole
# file would also match a comment or another step quoting the same text.
if step_body 'Install shellcheck' | grep -q 'SHELLCHECK_VERSION: v0\.11\.0$'; then
  ok "shellcheck version is pinned"
else
  bad "shellcheck version is pinned" "no 'SHELLCHECK_VERSION: v0.11.0'"
fi

if step_body 'Install shellcheck' | grep -q -E 'SHELLCHECK_SHA256: [0-9a-f]{64}$'; then
  ok "shellcheck digest is a pinned 64-hex sha256"
else
  bad "shellcheck digest is a pinned 64-hex sha256" "no 64-hex SHELLCHECK_SHA256"
fi

# The severity assertion is scoped to the shellcheck STEP: a bare grep over
# the workflow text would also match any other line that mentions both
# `shellcheck` and `-S warning`, and would keep the test green if the real
# invocation regressed to `-S error`.
if step_body 'Shellcheck agent skill scripts' |
   grep -q -E '^[[:space:]]*shellcheck .*-S warning'; then
  ok "shellcheck runs at -S warning"
else
  bad "shellcheck runs at -S warning" "SC2155 is a warning; -S error would miss it"
fi

syntax_finds="$(step_body 'Syntax-check agent skill scripts' |
  sed -n -E 's/^[[:space:]]*(find \.agents.*)$/\1/p' || true)"
lint_finds="$(step_body 'Shellcheck agent skill scripts' |
  sed -n -E 's/^[[:space:]]*(find \.agents.*)$/\1/p' || true)"
if [ -n "$syntax_finds" ] && [ "$lint_finds" = "$syntax_finds" ]; then
  ok "shellcheck selects the same files as the syntax check"
else
  bad "shellcheck selects the same files as the syntax check" \
    "lint=[$lint_finds] syntax=[$syntax_finds]"
fi

if step_body 'Shellcheck agent skill scripts' |
     grep -q -F "if [ \"\${#files[@]}\" -eq 0 ]; then" &&
   step_body 'Shellcheck agent skill scripts' |
     grep -q -F '::error::no shell files selected'; then
  ok "shellcheck step fails on an empty file selection"
else
  bad "shellcheck step fails on an empty file selection" "no non-empty assertion"
fi

# 7. `.shellcheckrc` is a proven gate-weakening surface: pin it byte-for-byte.
if [ -f "$SHELLCHECKRC" ] &&
   printf '%s\n' 'source-path=SCRIPTDIR' 'external-sources=true' | cmp -s - "$SHELLCHECKRC"; then
  ok ".shellcheckrc is pinned byte-for-byte"
else
  bad ".shellcheckrc is pinned byte-for-byte" "expected exactly source-path=SCRIPTDIR + external-sources=true"
fi

if [ -f "$SHELLCHECKRC" ] && grep -q 'disable=' "$SHELLCHECKRC"; then
  bad ".shellcheckrc has no disable=" "the rc must not weaken the gate"
else
  ok ".shellcheckrc has no disable="
fi

# 8. `.shellcheckrc` is itself path-gated, so a change to it runs the lint and
#    this contract test. Both triggers must carry it.
for trigger in push pull_request; do
  if trigger_paths "$trigger" | grep -qxF '.shellcheckrc'; then
    ok "agents workflow triggers on .shellcheckrc ($trigger)"
  else
    bad "agents workflow triggers on .shellcheckrc ($trigger)" \
      "the rc can weaken the gate; a diff touching only it must run the gate"
  fi
done

if [ "$(trigger_paths push)" = "$(trigger_paths pull_request)" ]; then
  ok "push and pull_request path filters are identical"
else
  bad "push and pull_request path filters are identical" \
    "push=[$(trigger_paths push)] pull_request=[$(trigger_paths pull_request)]"
fi

# 9. No workflow may batch the syntax check. `find … -exec bash -n {} +` parses
#    only the FIRST file and hands the rest to bash as positional parameters,
#    so the whole `.agents` tree would be covered by one parse of one file
#    (arbsec/arbitraitor#863). The `\;` form is no better: find reports every
#    error but exits 0, so the failure never propagates. Grepped across EVERY
#    workflow, not just this one: the defect survived because only agents.yml
#    was ever checked.
if grep -rn -- '-exec bash -n' "$WORKFLOWS" >/dev/null 2>&1; then
  bad "no workflow batches the syntax check" \
    "a batched bash -n parses only the first file"
else
  ok "no workflow batches the syntax check"
fi

# 10. The syntax-check selection must cover the scripts git tracks as 100644
#     (`commit-identity`, `pr-review-local`). Run the SAME selection the
#     workflow runs and assert the two paths are in its output -- an executable
#     -bit filter would drop both.
syntax_selected="$(cd "$ROOT" && eval "$syntax_finds" 2>/dev/null | sort -u)"
for want in \
  .agents/skills/github-pr-lifecycle/scripts/commit-identity \
  .agents/skills/github-pr-lifecycle/scripts/pr-review-local
do
  if printf '%s\n' "$syntax_selected" | grep -qxF -- "$want"; then
    ok "syntax check selects $want"
  else
    bad "syntax check selects $want" "not in the workflow's file selection"
  fi
done

# 11. Exactly ONE workflow runs the skill suites. Two runners duplicate the CI
#     cost on a mixed diff and can drift apart.
suite_runners=0
for file in "$WORKFLOWS"/*.yml; do
  if grep -q 'scripts/tests/\*\.bash' "$file"; then
    suite_runners=$((suite_runners + 1))
  fi
done
if [ "$suite_runners" -eq 1 ]; then
  ok "exactly one workflow runs the skill suites"
else
  bad "exactly one workflow runs the skill suites" "found $suite_runners workflows"
fi

# 12. The gate must run for a workflow-file diff: the suites assert the
#     PATH_GATED table against the workflow files, so a workflow-file diff can
#     invalidate that table.
for trigger in push pull_request; do
  if trigger_paths "$trigger" | grep -qxF '.github/workflows/**'; then
    ok "agents workflow triggers on workflow files ($trigger)"
  else
    bad "agents workflow triggers on workflow files ($trigger)" \
      "no .github/workflows/** in the $trigger paths list"
  fi
done

echo "agent-skills-workflow fixtures: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
