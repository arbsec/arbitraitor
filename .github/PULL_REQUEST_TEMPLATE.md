<!--
  Arbitraitor pull-request template.
  Checkboxes are verified facts, not intentions. Every managed-list marker
  (<!-- arb:... -->) is machine-readable and consumed by the pr-lifecycle skill
  (.agents/skills/github-pr-lifecycle). See AGENTS.md "Pre-merge gate" for the
  gate these items enforce.
-->

## Summary

<!-- What does this PR do and why? One paragraph. -->

## Approach

<!-- How does this PR solve the problem? What alternatives were considered? -->

## Linked issue

<!-- Closes #N or Refs #N. The linked issue must be Status = Ready with no
     unresolved blockers before this PR may merge (workflow policy). -->

## Specification references

<!-- docs/spec/spec.md §N and/or docs/adr/NNNN-*.md that this change implements.
     Every implementation PR traces to a spec requirement or an accepted ADR. -->

## Security impact

<!-- Required. Arbitraitor is a security boundary — every contribution is attack
     surface. Security-sensitive paths are listed in docs/conventions.md
     "Security-sensitive paths" and routed to @arbsec/security via CODEOWNERS. -->

- [ ] No security impact
- [ ] Security-sensitive path changed (requires security-owner review)
- [ ] Security invariant affected (describe below)

## Test evidence

<!-- What tests were added/updated? For security-sensitive behavior, include
     negative and adversarial tests asserting the forbidden effect did not occur. -->

- [ ] Unit tests added/updated
- [ ] Property tests added where applicable
- [ ] Security invariant assertions included
- [ ] Regression test added for any defect found during this work

## Compatibility impact

- [ ] No public API change
- [ ] Public API changed (describe below)
- [ ] Plugin protocol changed (describe below)
- [ ] Receipt schema changed (describe below)

## Dependencies

- [ ] No new dependencies
- [ ] Dependencies added (justification required — see AGENTS.md critical rules)

## Documentation impact

<!-- Any change to public behavior updates human-facing docs in the same PR
     (AGENTS.md "Documentation is current"). Generated API docs alone do not count. -->

- [ ] No public-behavior change
- [ ] Public behavior changed — docs updated (README, book/CLI reference, CHANGELOG)
- [ ] Not required — justification:

## Rollback implications

<!-- How is this change reverted or recovered if it goes wrong? -->

- [ ] Independently revertible
- [ ] Rollback/recovery behavior verified where applicable

## PR dependencies (in-flight work)

<!-- List any issues, PRs, or ADRs this work depends on or conflicts with, so the
     reviewer knows what must land first. Or state "none". -->

## Newly discovered follow-up work

<!-- Do NOT hide newly discovered work inside this PR. List any follow-up issues
     opened here (or state "none"). -->

## Merge checklist

<!-- The pr-lifecycle skill reads the arb:* markers below. Checkboxes are verified facts. -->

- [ ] <!-- arb:issue --> Linked issue and specification requirements are satisfied
- [ ] <!-- arb:tests --> Tests are added or updated
- [ ] <!-- arb:security --> Security impact is reviewed
- [ ] <!-- arb:docs --> Human-facing documentation is updated, or not required with justification
- [ ] <!-- arb:rollback --> Rollback or recovery behavior is verified where applicable
- [ ] <!-- arb:checks --> All required and non-optional checks pass
- [ ] <!-- arb:review --> All noteworthy findings are resolved
- [ ] <!-- arb:threads --> All actionable review threads are resolved
