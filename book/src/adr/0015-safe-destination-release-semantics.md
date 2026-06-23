# ADR 0015: Safe destination release semantics

**Status:** Accepted
**Date:** 2026-06-16
**Issue:** #10

## Context

The CAS is carefully designed with atomic commit, restrictive permissions, and digest verification. However, release to a user-specified path is underspecified. The adversarial review (H-01) identified TOCTOU and overwrite attack vectors at the release destination.

## Decision

Define mandatory release-to-path controls. Every release operation follows this sequence:

### Release procedure

1. Reopen the CAS object read-only.
2. Recompute SHA-256.
3. Compare with scanned identity. FAIL if mismatch.
4. Verify no policy or intelligence update invalidated the verdict (if freshness policy requires it).
5. Open the destination parent directory through a capability-rooted handle (cap-std Dir).
6. Reject symlinks, junctions, reparse points, hard-link surprises, and unexpected replacement at the destination path.
7. Create a new sibling temporary file with:
   - Restrictive permissions (0600 on POSIX, user-restricted ACL on Windows).
   - O_NOFOLLOW / no-follow semantics.
   - No executable bit (never make scripts executable just because the URL ended in .sh).
8. Write the artifact bytes.
9. Verify the final digest of the written file.
10. Atomically rename to the destination when the filesystem supports it.
11. If atomic rename is not possible (cross-filesystem), report and require policy approval for the non-atomic copy.
12. Preserve or add platform download provenance (see ADR 0010).
13. Record the final destination identity and release method in the receipt.

### Overwrite policy

- **No overwrite by default.** If the destination exists, release fails.
- `--replace` requires explicit flag **and** policy approval.
- Replacement follows the same sibling-temp + atomic-rename procedure.

### Symlink and reparse-point defense

Before writing:
- `fstatat` with `AT_SYMLINK_NOFOLLOW` on POSIX to verify the destination is not a symlink.
- Check for reparse points / junctions on Windows.
- Reject hard links (check link count).

The parent directory handle (from step 5) ensures the path cannot be replaced with a symlink between the check and the write, because all operations are relative to the capability handle.

### Cross-filesystem awareness

If the staging directory and destination are on different filesystems, atomic rename is impossible. Arbitraitor:
1. Detects the cross-filesystem condition.
2. Reports it as a finding.
3. Requires explicit policy approval or `--allow-non-atomic`.
4. Records the non-atomic copy in the receipt.

## Consequences

- An attacker who can write to the destination directory cannot intercept, replace, or corrupt the released artifact.
- Users must explicitly opt in to overwrite or non-atomic copies.
- Scripts are never silently made executable.
- The release path is as carefully defended as the CAS commit path.

## Alternatives considered

- **Simple `std::fs::write`:** Rejected. No TOCTOU defense, no capability handles, no symlink rejection.
- **Always atomic (refuse cross-filesystem):** Rejected. Too restrictive for real-world use. Report and require approval instead.
- **Inherit umask permissions:** Rejected. Unpredictable; use explicit restrictive permissions.

## References

- `.spec/arbitraitor-adversarial-review-and-gap-analysis.md` H-01
- `.spec/arbitraitor-comprehensive-spec-v0.4.md` §26.2 (Exact-byte and destination-safe release)
- `.spec/arbitraitor-tech-stack.md` §5 (Filesystem and content-addressed store)
- [ADR 0010](./0010-platform-provenance-preservation.md) — Provenance markers
