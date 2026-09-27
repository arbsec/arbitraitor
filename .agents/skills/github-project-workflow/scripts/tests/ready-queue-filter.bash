#!/usr/bin/env bash
# Regression test for scripts/ready-queue.jq (upstream regression: arbsec/orchestraitor#251,
# assignee rule from #307): the filter must parse, treat task/bug labels as
# leaf when issueType is null, ignore resolved (CLOSED) blockedBy edges, and
# exclude items assigned to humans while keeping service-identity assigns
# schedulable (see .agents/project/arbitraitor-workflow.md "Service identity").
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
JQ_PROGRAM="$HERE/../ready-queue.jq"

run_case() {
  local name="$1" fixture="$2" expected="$3" service_slugs="${4:-arbsec-agent}" mvp_label="${5-MVP}"
  local service_json got
  service_json="$(printf '%s' "$service_slugs" | tr ',' '\n' | sed 's/^[[:space:]]*//; s/[[:space:]]*$//; /^$/d' | jq -R . | jq -s .)"
  got="$(printf '%s' "$fixture" | jq --arg mvp "$mvp_label" --argjson service "$service_json" -f "$JQ_PROGRAM" | jq -c 'map(.number)')"
  if [ "$got" != "$expected" ]; then
    echo "FAIL $name: expected $expected, got $got" >&2
    exit 1
  fi
  echo "PASS $name"
}

run_case "empty input parses" '[]' '[]'

run_case "leaf/label/blocker semantics" '[
  {"number":1,"title":"leaf task","issueType":null,"labels":[{"name":"task"},{"name":"MVP"}],"blockedBy":{"nodes":[],"totalCount":0}},
  {"number":2,"title":"open blocker","issueType":null,"labels":[{"name":"bug"},{"name":"MVP"}],"blockedBy":{"nodes":[{"state":"OPEN"}],"totalCount":1}},
  {"number":3,"title":"closed blocker only","issueType":null,"labels":[{"name":"task"},{"name":"MVP"}],"blockedBy":{"nodes":[{"state":"CLOSED"}],"totalCount":1}},
  {"number":4,"title":"epic not leaf","issueType":null,"labels":[{"name":"epic"},{"name":"MVP"}],"blockedBy":{"nodes":[],"totalCount":0}},
  {"number":5,"title":"not MVP","issueType":null,"labels":[{"name":"task"}],"blockedBy":{"nodes":[],"totalCount":0}},
  {"number":6,"title":"native type Task without labels","issueType":{"name":"Task"},"labels":[{"name":"MVP"}],"blockedBy":{"nodes":[],"totalCount":0}},
  {"number":7,"title":"native Feature but task label","issueType":{"name":"Feature"},"labels":[{"name":"task"},{"name":"MVP"}],"blockedBy":{"nodes":[],"totalCount":0}},
  {"number":8,"title":"truncated blocker page hides open blocker","issueType":null,"labels":[{"name":"task"},{"name":"MVP"}],"blockedBy":{"nodes":[{"state":"CLOSED"}],"totalCount":2}}
]' '[1,3,6]'

# Assignee exclusion (spec 10-orchestrator.md §9.41): a human assignee excludes
# the item; a service identity (App bot `<slug>[bot]` or bare slug form, case
# insensitive) keeps it schedulable; unassigned stays schedulable. An issue
# shared with any human co-assignee is excluded.
run_case "assignee exclusion: humans out, service identity in" '[
  {"number":1,"title":"unassigned","issueType":null,"labels":[{"name":"task"},{"name":"MVP"}],"assignees":[],"blockedBy":{"nodes":[],"totalCount":0}},
  {"number":2,"title":"assignees field absent","issueType":null,"labels":[{"name":"task"},{"name":"MVP"}],"blockedBy":{"nodes":[],"totalCount":0}},
  {"number":3,"title":"bot assigned","issueType":null,"labels":[{"name":"task"},{"name":"MVP"}],"assignees":[{"login":"arbsec-agent[bot]"}],"blockedBy":{"nodes":[],"totalCount":0}},
  {"number":4,"title":"bare slug assigned","issueType":null,"labels":[{"name":"task"},{"name":"MVP"}],"assignees":[{"login":"ArbSec-Agent"}],"blockedBy":{"nodes":[],"totalCount":0}},
  {"number":5,"title":"human assigned","issueType":null,"labels":[{"name":"task"},{"name":"MVP"}],"assignees":[{"login":"mekwall"}],"blockedBy":{"nodes":[],"totalCount":0}},
  {"number":6,"title":"bot plus human co-assignee","issueType":null,"labels":[{"name":"task"},{"name":"MVP"}],"assignees":[{"login":"arbsec-agent[bot]"},{"login":"mekwall"}],"blockedBy":{"nodes":[],"totalCount":0}},
  {"number":7,"title":"human casing variant","issueType":null,"labels":[{"name":"task"},{"name":"MVP"}],"assignees":[{"login":"Arbsec-Agent[Bot]Whoops"}],"blockedBy":{"nodes":[],"totalCount":0}}
]' '[1,2,3,4]'

# A configured additional service identity is honored; identities not in the
# configured set are treated as human.
run_case "service set is declarative, not inferred" '[
  {"number":1,"title":"renovate bot item","issueType":null,"labels":[{"name":"task"},{"name":"MVP"}],"assignees":[{"login":"renovate[bot]"}],"blockedBy":{"nodes":[],"totalCount":0}},
  {"number":2,"title":"arbsec-agent item outside the set","issueType":null,"labels":[{"name":"task"},{"name":"MVP"}],"assignees":[{"login":"arbsec-agent[bot]"}],"blockedBy":{"nodes":[],"totalCount":0}}
]' '[1]' 'renovate'
# Whitespace around comma-separated slugs (the $ARB_SERVICE_IDENTITIES form)
# is trimmed before matching, mirroring the config-file path (#307).
run_case "whitespace-padded env slugs are trimmed" '[
  {"number":1,"title":"arbsec-agent item","issueType":null,"labels":[{"name":"task"},{"name":"MVP"}],"assignees":[{"login":"arbsec-agent[bot]"}],"blockedBy":{"nodes":[],"totalCount":0}},
  {"number":2,"title":"renovate item","issueType":null,"labels":[{"name":"task"},{"name":"MVP"}],"assignees":[{"login":"renovate[bot]"}],"blockedBy":{"nodes":[],"totalCount":0}},
  {"number":3,"title":"human item","issueType":null,"labels":[{"name":"task"},{"name":"MVP"}],"assignees":[{"login":"mekwall"}],"blockedBy":{"nodes":[],"totalCount":0}}
]' '[1,2]' '  arbsec-agent ,  renovate  '

# Optional label gate: an empty $mvp disables the label requirement entirely
# (arbitraitor default — post-MVP; scheduling runs on the P0/P1 queue).
run_case "empty mvp label disables the label gate" '[
  {"number":1,"title":"task, no labels","issueType":null,"labels":[{"name":"task"}],"blockedBy":{"nodes":[],"totalCount":0}},
  {"number":2,"title":"bug, no labels","issueType":null,"labels":[{"name":"bug"}],"blockedBy":{"nodes":[],"totalCount":0}},
  {"number":3,"title":"epic, no labels","issueType":null,"labels":[{"name":"epic"}],"blockedBy":{"nodes":[],"totalCount":0}},
  {"number":4,"title":"human-assigned task, no labels","issueType":null,"labels":[{"name":"task"}],"assignees":[{"login":"mekwall"}],"blockedBy":{"nodes":[],"totalCount":0}}
]' '[1,2]' 'arbsec-agent' ''

echo "ready-queue-filter: all cases passed"
