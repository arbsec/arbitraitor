  def path_gated_exempt($name):
    (any($pathgated[]; .name == $name))
    and (([$pathgated[] | select(.name == $name) | .paths[] as $p
           | $files[] | select(test(pathmatch($p)))] | length) == 0);
  def exempt:
    (.bucket == "skipping")
    and (((($skip_exempt | index(.name)) != null)
          or (($optional | index(.name)) != null)));
  . as $rollup
  | ($rollup | map(.name)) as $present
  | [$required[]
     | select(($present | index(.)) == null)
     | select(path_gated_exempt(.) | not)] as $missing_required
  | {
      checks: ($rollup | map({
        name: .name,
        state: .state,
        bucket: .bucket,
        workflow: .workflow,
        link: .link,
        classification: (
          if exempt then "not-applicable"
          elif .bucket == "pass" then "pass"
          elif .bucket == "fail" then "fail"
          elif .bucket == "pending" then "pending"
          elif .bucket == "skipping" then "skip"
          elif .bucket == "cancel" then "fail"
          else "unknown"
          end
        )
      })),
      missing_required: $missing_required,
      all_passed: ((($rollup | length) > 0)
        and ($rollup | all(.[]; .bucket == "pass" or exempt))
        and (($missing_required | length) == 0)),
      any_failing: ($rollup | any(.[]; .bucket == "fail" or .bucket == "cancel")),
      any_pending: ($rollup | any(.[]; .bucket == "pending"))
