## Summary

<!-- Brief description of what this PR does and why. -->

## Approach

<!-- How does this PR solve the problem? What alternatives were considered? -->

## Linked Issue

<!-- Closes #N or Refs #N -->

## Security Impact

<!-- Describe any security implications. Is this change to a security-sensitive path? -->

- [ ] No security impact
- [ ] Security-sensitive path changed (requires security-owner review)
- [ ] Security invariant affected (describe below)

## Tests

<!-- What tests were added or modified? -->

- [ ] Unit tests added/updated
- [ ] Property tests added where applicable
- [ ] Security invariant assertions included

## Compatibility Impact

- [ ] No public API change
- [ ] Public API changed (describe below)
- [ ] Plugin protocol changed (describe below)
- [ ] Receipt schema changed (describe below)

## Dependencies

- [ ] No new dependencies
- [ ] Dependencies added (justification required — see AGENTS.md Section 6)

## Checklist

- [ ] `cargo fmt --check` passes
- [ ] `cargo clippy --workspace --all-targets --all-features -- -D warnings` passes
- [ ] `cargo check --workspace --all-targets --all-features` passes
- [ ] `cargo nextest run` passes
- [ ] No `unwrap()`/`expect()` in production code
- [ ] No unrelated refactoring mixed in
- [ ] PR title follows Conventional Commits format
