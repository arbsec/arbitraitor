# ADR 0032: Tar parser consensus check

**Status:** Accepted
**Date:** 2026-07-20
**Issue:** #459

## Context

Tar archives have multiple metadata layers that can alter how later entries are
interpreted. PAX extended headers (`x` and `g`) carry key-value records such as
`size=`, while GNU long-name/long-link headers (`L` and `K`) and further PAX
headers may appear between that metadata and the eventual file entry.

POSIX says PAX records apply to the file entry, not to intermediary extension
headers. Vulnerable parsers have instead applied `size=` to an intermediary
header, consuming a different number of bytes and desynchronizing the rest of
the stream. That is a CWE-436 parser differential: one scanner can report a
clean member set while a different extractor observes and releases another.

Relevant public cases include:

- GHSA-vmf3-w455-68vh / CVE-2026-53655 (`node-tar` PAX `size=` parser split).
- GHSA-3pv8-6f4r-ffg2 (`tar-rs` PAX header desynchronization, fixed in 0.4.46).
- GHSA-9ppj-qmqm-q256 / CVE-2026-31802 (`node-tar` symlink drive-relative
  traversal).
- CVE-2025-45582 (GNU tar two-step `../` symlink traversal).

Hardening only the primary parser is not enough for Arbitraitor. Invariant 1
requires no release before inspection, and inspection must match what downstream
extractors will see. Invariant 4 also requires bounded parsing, so any added
check must avoid unbounded archive expansion.

## Decision

Arbitraitor keeps `tar-rs` as the primary tar parser and requires the locked
crate version to be at least 0.4.46. The archive detector also runs a bounded
consensus scanner over raw tar blocks after primary parsing.

The consensus scanner is intentionally narrow rather than a full second tar
implementation. It walks 512-byte tar headers under the same file-count,
byte-count, depth, and wall-clock limits as normal archive inspection. It emits
`FindingCategory::ParserDifferential` when either:

- a PAX `size=` record is pending and an intermediary `L`, `K`, `x`, or `g`
  extension header appears before the next file entry; or
- the primary parser's member list differs from the bounded consensus member
  list.

These findings carry the `parser-smelting` hazard tag, severity `Medium` (the
policy layer may elevate it), and a CWE-436 taxonomy reference. The finding is
recorded in receipts, and normal verdict calculation refuses automatic release
because the artifact is no longer clean.

`arbitraitor doctor` reports the locked `tar` crate version and marks the system
unhealthy if it is below 0.4.46 or absent from `Cargo.lock`.

## Consequences

- Parser smelting is distinct from path traversal: traversal describes where an
  agreed entry writes; smelting describes disagreement over which entries exist.
- The check is fail-closed. A consensus-parser failure becomes a parser
  differential finding rather than a clean result.
- The scanner does not add a production dependency or call out to a host
  `tar`/`libarchive` binary, preserving reproducible local analysis.
- The scanner is not a general-purpose extractor. It exists only to catch
  consensus hazards and member-list disagreement under bounded processing.

## Alternatives considered

### Rely only on patched `tar-rs`

Rejected. Pinning 0.4.46 fixes the known tar-rs PAX desync, but does not prove
that the scanner and every downstream extractor share identical membership
semantics for future extension-header combinations.

### Add libarchive as a second parser

Rejected for this change. It would add a native dependency and build/runtime
surface requiring the dependency admission checklist. The current vulnerability
class is detectable with a bounded raw-header cross-check and member-list
comparison.

### Shell out to Python `tarfile` or system `tar`

Rejected. Host tools vary by platform and version, and subprocess execution is
unnecessary for a deterministic parser-consensus guard.

## References

- Arbitraitor spec §19.1, parser consensus check.
- Arbitraitor spec §19.3, archive hazards.
- CWE-436: Interpretation Conflict.
- GHSA-3pv8-6f4r-ffg2, `tar-rs` PAX header desynchronization.
- GHSA-vmf3-w455-68vh / CVE-2026-53655.
- GHSA-9ppj-qmqm-q256 / CVE-2026-31802.
- CVE-2025-45582.
