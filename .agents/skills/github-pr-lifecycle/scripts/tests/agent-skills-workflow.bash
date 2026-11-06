#!/usr/bin/env bash
# Contract test for the agent-skill CI gate (.github/workflows/agents.yml).
#
# The gate exists because `code.yml` is Rust/Cargo-scoped: a diff that only
# touches `.agents/**` never reaches the `Agent Skills Tests` job it owns, so
# the skill shell suites never executed (arbsec/arbitraitor#859). This suite
# pins the invariants that make the gate work and keeps them from drifting:
#
#   1. the workflow exists, triggers on `.agents/**` for pull requests and for
#      pushes to `main`;
#   2. the required check name `Agent Skills Tests` stays with `code.yml` and
#      the new workflow reports a DIFFERENT name — a mixed Rust + `.agents`
#      diff must never produce two checks under one name;
#   3. the syntax check runs `bash -n` once per file (`bash -n a b` parses
#      only `a`, so the `find -exec bash -n {} +` form checks one file);
#   4. the new check is registered in the project config;
#   5. the workflow uses no YAML anchor/alias (actionlint cannot parse an
#      alias node and reports it as a syntax error).
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../../../../.." && pwd)"
WORKFLOWS="$ROOT/.github/workflows"
AGENTS_WORKFLOW="$WORKFLOWS/agents.yml"
EXAMPLE_TOML="$ROOT/.agents/project/github-project.example.toml"

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

if grep -q -E '^[[:space:]]*-[[:space:]]*"\.agents/\*\*"' "$AGENTS_WORKFLOW"; then
  ok "agents workflow covers .agents/**"
else
  bad "agents workflow covers .agents/**" "no .agents/** path filter"
fi

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

if [ "$(count_job_names 'Agent Skills Shell Suites')" -eq 1 ]; then
  ok "check name 'Agent Skills Shell Suites' is reported by exactly one workflow"
else
  bad "check name 'Agent Skills Shell Suites' is reported by exactly one workflow" \
    "count=$(count_job_names 'Agent Skills Shell Suites')"
fi

# 3. One `bash -n` per file — `find -exec bash -n {} +` parses only the first file.
if grep -q -- '-exec bash -n {} +' "$AGENTS_WORKFLOW"; then
  bad "syntax check runs bash -n once per file" "batched form parses only the first file"
else
  ok "syntax check runs bash -n once per file"
fi

# 4. The new check is registered in the project config.
if grep -q '"Agent Skills Shell Suites"' "$EXAMPLE_TOML"; then
  ok "new check is registered in the project config"
else
  bad "new check is registered in the project config" "not listed in github-project.example.toml"
fi

if grep -q '"Agent Skills Tests"' "$EXAMPLE_TOML"; then
  ok "required check name stays in the project config"
else
  bad "required check name stays in the project config" "not listed in github-project.example.toml"
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

echo "agent-skills-workflow fixtures: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
