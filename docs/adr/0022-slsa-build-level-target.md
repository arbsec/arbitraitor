# ADR 0022: SLSA Build Level target for Arbitraitor releases

**Status:** Accepted
**Date:** 2026-06-29
**Issue:** #272

## Context

Spec v0.5 §14.6 commits Arbitraitor's own releases to targeting SLSA Build
Level 3. SLSA (Supply-chain Levels for Software Artifacts) v1.2 defines
separate Build and Source tracks. Build L3 requires a hardened build platform
with provenance that is non-forgeable.

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

### Source Track consumption

SLSA v1.2 adds a Source Track for evidence about how source revisions are
authored, reviewed, and accepted:

- **Source L1 (version controlled):** the source revision is managed by a
  version control system and is uniquely identifiable.
- **Source L2 (history and provenance):** continuous change history and
  tamper-resistant source provenance record when and how a revision was
  created, including source-contributor identity and enforced controls.
- **Source L3 (continuous technical controls):** the source control system
  continuously enforces declared controls on protected references, such as
  branch-protection rules, required status checks, and review requirements.

The final v1.2 specification defines mandatory two-party review at Source L4.
Arbitraitor consumes explicit two-party-review evidence when available, but
must not infer it from Source L3 alone.

A verified Source L2+ VSA and its supporting provenance, bound to the exact
source revision, is a stronger provenance signal than Build L1 alone: Build L1
shows that build provenance exists, while Source L2+ also supplies
source-authoring history, contributor identity, and control evidence. This
signal is additive. It does not raise the artifact's Build level or replace
verification of the build provenance, attestation issuer, or subject digest.

## Alternatives considered

- **L1 only (status field):** insufficient for a security boundary tool.
- **L3 immediately:** unverifiable without offline build and reproducibility
  evidence.

## References

- SLSA v1.2 announcement: <https://slsa.dev/blog/2025/11/announce-slsa-v1.2>
- SLSA v1.2 specification: <https://slsa.dev/spec/v1.2/>
- SLSA v1.2 changes: <https://slsa.dev/spec/v1.2/whats-new>
- SLSA Build Provenance: <https://slsa.dev/spec/v1.2/build-provenance>
- SLSA Build Levels: <https://slsa.dev/spec/v1.2/levels>
- GitHub artifact attestations: <https://docs.github.com/actions/how-tos/secure-your-work/use-artifact-attestations>
- Spec §14.6, §44
