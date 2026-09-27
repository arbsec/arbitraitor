# Eligibility filter for ready-queue (single source; regression-tested by
# scripts/tests/ready-queue-filter.bash, regression: arbsec/orchestraitor#251).
# Input: gh issue list JSON array with fields
#   number, title, url, issueType{name}|null, labels[{name}],
#   assignees[{login}]|null, blockedBy{nodes[{state}],totalCount}
# Args: $mvp (label name), $service (array of service-identity slugs; a login
#   matches a slug case-insensitively in both `<slug>` and `<slug>[bot]` forms).
# Output: the eligible subset, sorted by issue number.
map(
  select(
    # Leaf type: the native issue type wins when configured (org types may be
    # restored at any time); labels are the fallback while org-level native
    # types are unset (see [issue_types] in github-project.example.toml).
    # A conflicting label MUST NOT override an authoritative non-leaf native
    # type (review finding on arbsec/orchestraitor#254).
    if .issueType != null
    then ((.issueType.name // "") | test("^(Task|Bug)$"))
    else (any(.labels[]?.name; . == "task" or . == "bug"))
    end
    and (([.blockedBy.nodes[]? | select(.state != "CLOSED")] | length) == 0)
    # Fail closed on truncated blocker pages sticks to the security rules of
    # fail-closed by construction: gh returns a `nodes` window; when
    # `totalCount` does not equal the returned node count, an unseen blocker
    # may still be open, so the issue is NOT eligible.
    and (.blockedBy as $b | ((($b.nodes // []) | length) == ($b.totalCount // 0)))
    # Optional label gate: when $mvp is non-empty the issue must carry that
    # label; when empty (the arbitraitor default — post-MVP project) the gate
    # is disabled entirely.
    and (($mvp | length) == 0 or any(.labels[]?.name; . == $mvp))
    # Assignee exclusion (arbitraitor-workflow.md "Service identity"): every
    # assignee must
    # be a declared service identity; any human assignee excludes the item.
    # Unassigned items and service-identity assigns stay schedulable.
    and ((.assignees // []) | all(
      .login as $login
      | any($service[]?;
          ((. | ascii_downcase) == ($login | ascii_downcase))
          or (((. + "[bot]") | ascii_downcase) == ($login | ascii_downcase)))
    ))
  )
)
| sort_by(.number)
