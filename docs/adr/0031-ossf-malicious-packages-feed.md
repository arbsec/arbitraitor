# ADR 0031: OpenSSF malicious-packages feed via OSV.dev

**Status:** Accepted
**Date:** 2026-07-20
**Issue:** #474

## Context

Spec §21 extends Arbitraitor's intelligence model with package-reputation
feeds. OpenSSF's malicious-packages repository publishes package malware
records as OSV advisories with identifiers in the `MAL-YYYY-NNNN` family.
OSV.dev exposes those records through the same API surface used for other
package advisories, including the `/v1/querybatch` endpoint for package and
version batches.

This matters for npm because npm v11.10 added `--min-release-age`, making
freshly published packages a first-class risk-control axis. Arbitraitor needs
to ingest OpenSSF `MAL-` identifiers as explicit intelligence indicators so
package-manager policy can combine age gating with malicious-package evidence.

## Decision

Arbitraitor treats OpenSSF malicious-packages as a bundled Tier-1 intelligence
feed named `ossf-malicious-packages`.

- The adapter consumes OSV.dev `querybatch` JSON responses and emits one
  signed-feed entry for each `MAL-` advisory.
- `MAL-` identifiers are parsed into the `OsvMalId` newtype before entering
  the domain model. Invalid or non-`MAL-` OSV advisories are not promoted to
  OpenSSF malicious-package entries.
- Entries use `IndicatorType::OsvMal` and
  `FeedSourceClass::OssfMaliciousPackages`, with `Block` disposition,
  `High` severity, and `Confirmed` confidence.
- Network access remains off by default. Fetching happens only when an
  operator runs `arbitraitor intel update --ossf-malicious-packages` or points
  the adapter at a signed mirror URL.
- Feed retrieval continues through `arbitraitor-fetch` and the existing local
  intel store ingestion path so SSRF policy, byte limits, TLS policy, and
  signed-store handling remain centralized.

### Signing scheme

The OpenSSF/OSV response is source data, not Arbitraitor trust metadata. During
ingestion, Arbitraitor converts parsed `MAL-` records into its local
`SignedFeedEntry` scheme: each normalized `FeedEntry` is canonicalized with
the same JSON/RFC 8785 discipline used for receipts and signed by the
configured intel feed key before distribution in bundled feed snapshots.

Online updates may fetch OSV.dev directly, but redistributable bundled feeds
must be signed Arbitraitor feed snapshots. Consumers verify the bundled
snapshot signature before using entries for blocking policy.

### Freshness requirements

Freshness mirrors OSV.dev's malicious-package update cadence. The OpenSSF
malicious-packages feed is considered Tier-1 current when the local signed
snapshot was built from OSV data updated within the last 24 hours. Operators
may shorten this interval for npm enforcement profiles that combine `MAL-`
matches with `npm --min-release-age` checks.

Stale or unavailable OpenSSF malicious-package data never creates a clean
result. Enforcement that requires current Tier-1 package intelligence must
fail closed; advisory-only configurations may continue with an explicit
incomplete-intel diagnostic.

### Batch endpoint limits

The adapter targets OSV.dev `/v1/querybatch`, which accepts a batch of package
queries and returns a parallel `results` array. Arbitraitor callers must bound
batch size and payload size before fetch:

- split package inventories into deterministic batches;
- preserve result-to-query order for diagnostics;
- apply the same byte, timeout, redirect, TLS, and SSRF limits as other feed
  retrieval;
- skip non-`MAL-` advisories from mixed OSV responses instead of treating them
  as malicious-package IDs.

## Consequences

- OpenSSF malicious packages become explicit, type-safe intel indicators
  rather than free-form advisory strings.
- npm policy can combine release-age controls with OSV-backed malicious
  package evidence.
- No new production dependency is required; parsing uses existing `serde` and
  retrieval uses the existing `Fetcher` boundary.
- OSV.dev API changes that alter response shape fail as feed decode errors,
  preserving fail-closed behavior for enforcement policies.

## Alternatives considered

- **Read the OpenSSF GitHub repository directly:** rejected because OSV.dev is
  the stable advisory API surface and already normalizes package ecosystem
  metadata.
- **Treat `MAL-` as generic advisory IDs:** rejected because malicious-package
  IDs have different enforcement semantics from CVE/GHSA vulnerability
  advisories and need a distinct indicator type.
- **Enable live network lookups during artifact inspection:** rejected because
  feed retrieval must remain explicit and policy-bounded, with cached signed
  feed snapshots available for offline operation.

## References

- Spec §21.1, §21.4, §21.5
- ADR-0025 OpenSSF Scorecard, deps.dev, and GUAC as optional integrations
- OpenSSF blog: <https://openssf.org/blog/2026/05/20/detecting-malicious-packages-using-the-osv-api/>
- OpenSSF malicious-packages: <https://github.com/ossf/malicious-packages>
- OSV API: <https://api.osv.dev/v1/querybatch>
