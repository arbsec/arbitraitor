# ADR 0022: SLSA Build Level target for Arbitraitor releases

**Status:** Accepted
**Date:** 2026-06-29
**Issue:** #272

## Context

Spec v0.5 §14.6 commits Arbitraitor's own releases to targeting SLSA Build
Level 3. SLSA (Supply-chain Levels for Software Artifacts) v1.2 defines four
build levels (L1–L3 plus Source and Dependencies tracks). L3 requires a
hardened build platform with provenance that is non-forgeable.

Currently Arbitraitor uses GitHub Actions hosted runners, pinned actions by
SHA, and GitHub artifact attestations for build provenance. This meets SLSA
Build L1 (provenance available). The path to L2 (hosted build service) and L3
(non-forgeable hermetic boundary) requires additional work documented below.

## Decision

Arbitraitor v0.5 releases self-describe as **SLSA Build L2**. The v0.6 target
is L3, contingent on:

1. **Hermetic builds:** all dependencies fetched before build; no network
   access during compilation step. Achieved via `cargo build --offline` after
   `cargo fetch`.
2. **Provenance generation:** SLSA Provenance v1 statement
   (`predicateType: https://slsa.dev/provenance/v1`) with
   `buildDefinition.buildType`, `runDetails.builder.id`, and
   `resolvedDependencies` populated.
3. **Non-forgeable provenance:** the provenance statement is signed and
   published as a GitHub artifact attestation verifiable via
   `gh attestation verify`.
4. **Reproducibility evidence:** a second build from the same source produces
   bit-identical artifacts, or a documented explanation of unavoidable variance.
5. **Isolated release workflow:** release jobs run only from protected tags,
   use OIDC trusted publishing, and share no writable caches with PR workflows.

## Consequences

- Release pipeline complexity increases (offline build, provenance generation).
- Reproducibility may require `CARGO_PROFILE_RELEASE_DEBUG=0` and
  `SOURCE_DATE_EPOCH` normalization.
- Until all five criteria are met, releases must not claim L3.

## Alternatives considered

- **L1 only (status field):** insufficient for a security boundary tool.
- **L3 immediately:** unverifiable without offline build and reproducibility
  evidence.

## References

- SLSA v1.2 spec: <https://slsa.dev/spec/v1.2/build-provenance>
- SLSA Build Levels: <https://slsa.dev/spec/v1.2/levels>
- GitHub artifact attestations: <https://docs.github.com/actions/how-tos/secure-your-work/use-artifact-attestations>
- Spec §14.6, §44
