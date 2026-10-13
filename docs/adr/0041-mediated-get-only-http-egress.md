# ADR 0041: Mediated GET-only HTTP egress for agent web tools

**Status:** Accepted
**Date:** 2026-10-13
**Issue:** #797 (parent #798: spec amendment; implementation: #799)

## Context

Agent harnesses — `arbsec/orchestraitor` first — need Arbitraitor-mediated
HTTP access for built-in `web_search`/`web_fetch`-class tools. Without such a
capability, those tools must either fail closed (losing general web access)
or open direct-socket paths that bypass Arbitraitor's network model
(§11.2, ADR-0018). #797 requested the capability and verified it is unclaimed
spec territory: the §11.2 retriever persists bytes into the CAS and returns
only receipts/verdicts — no operation returns response content to a caller.

Two constraints shaped the decision:

1. **The upload line.** §39.7 places uploads and arbitrary HTTP methods with
   request bodies outside the wrapper model; §9 invariant 9 ("No hidden cloud
   upload"), §9 invariant 24 ("untrusted project configuration cannot permit
   uploads"), and §5 non-goals draw a deliberate line at content upload.
2. **The grant gap.** §39.15 describes plugins "request[ing] network
   operation[s] through the core" and "request[ing] secret references without
   reading secret values", but no grant-shaped capability object binding a
   host/method/path scope (or a secret reference) to an egress right exists.

## Decision

Add a **mediated HTTP egress** operation class, specified normatively at
spec §11.6:

- **GET only.** Requests carrying a body fail closed with a typed
  unsupported result — a distinct, egress-owned outcome in the operation's
  result enum, not a generic error — and no HTTP attempt is made. This
  decision does not reopen the upload line; see "Explicitly deferred" below.
- **Grant-scoped.** Each request executes under an explicit policy egress
  grant scoping allowlisted hosts, the `GET` method, a path prefix, response
  size, and content types. Grants are minted by policy only — never by
  untrusted project configuration (ADR-0017).
- **Caller-origin bound.** The daemon derives the §23.1.1 caller-origin
  class per request (peer-credential-derived) and records it on the grant
  evaluation and receipt; policy MAY deny `agent_session`/low-trust origins;
  transport authentication is required before a self-reported class is
  honored.
- **Same transport floor as retrieval.** HTTPS-only default, certificate
  rejection, redirect limits, cross-origin credential stripping (§11.2,
  §11.4, ADR-0033), connected-peer verification with rebinding and
  private-address blocking (ADR-0018), and §31.2/§11.5 receipts in the
  ADR-0023/ADR-0039 envelope — §31.2 fields apply where meaningful;
  artifact-centric fields are replaced by the egress fields (grant identity,
  caller-origin class, query policy, body outcome) §11.6 specifies.
- **Return path with no artifact semantics.** The bounded body returns to
  the calling tool; it is not CAS-stored and, by default
  (`body_treatment = unscanned`), never scanned or verdict-gated by
  Arbitraitor. `inspect_first` grants are the sole exception: the body
  passes through the inspection pipeline (without CAS population) and only
  a passing verdict delivers it. Callers wanting artifact treatment submit
  the body through `inspect_url`/`scan_artifact` like any untrusted content.
- Implemented as a thin-consumer MCP tool (`HttpEgressTool`, §40.3) and a
  daemon operation over the engine; the HTTP client stays behind the
  `Fetcher` trait (ADR-0003, tech-stack §4.7).

## Explicitly deferred (not decided here)

**Body-bearing methods (POST et al.).** Two candidate designs are recorded
for a future ruling; neither is enabled by this ADR:

- **(a) Caller-origin policy class.** Build on §23.1.1: a dedicated origin
  class (e.g. a config/owner-established `tool_host` origin) may be granted
  body-bearing egress while `agent_session` can never enable it. Requires
  policy-schema design and a threat-model pass on the new class.
- **(b) Plan-bound approval.** Every body-bearing request routes through §28.5
  plan-bound approval (§9 invariant 23): the human approves the full plan
  (destination, method, bounded body digest) per request. Highest assurance,
  worst ergonomics for interactive search APIs.

A future ADR must also decide whether body-bearing egress, if granted,
conflicts with §9 invariant 9's receipt obligations for outbound content
(content sent *to* a remote service is still an upload even when the
response returns).

**Secret-brokered headers (SecretGrant-shaped).** Paid search APIs need
credential headers whose values must never enter the calling agent's memory
(§39.15 "request secret references without reading secret values"; ADR-0033
"receipts record only the credential class, never the raw credential value").
v1 ships without it: self-hosted engines need no credentials. A follow-up
design must define the capability object that binds a secret reference to an
egress grant and injects the header broker-side, plus receipt handling for
injected-header identity.

**Grant shape follows #799.** §11.6 names the grant properties normatively
(query policy, `body_treatment`, size/content-type bounds) but does not fix
the TOML schema; the grant schema is designed and tested in #799 against
`arbitraitor-policy`'s existing `NetworkConfig` layering (ADR-0017
monotonicity applies to every property).

## Consequences

- `arbsec/orchestraitor` can implement `web_search`/`web_fetch` on top of the
  `http_egress` MCP capability (§33.1) instead of failing closed or opening
  bypass paths.
- The engine gains a second return-to-caller network path; its separation
  from artifact retrieval (no CAS, no scan, no release) must be preserved in
  implementation and tests.
- **Caller-side laundering threat (accepted for v1, mitigated by grant
  shape).** A confused-deputy or compromised agent (§8.2) can use egress to
  retrieve executable content, bypassing the detector pipeline, and execute
  it caller-side — Arbitraitor's own gates never see the bytes. v1 accepts
  this residual risk with two mitigations rather than refusing the
  capability: the `body_treatment` grant property (`inspect_first` routes
  executable content through inspection before delivery; deployments serving
  `agent_session`-class callers SHOULD set it), and the receipt's
  machine-readable `returned_unscanned` marker so audit pipelines can flag
  every unscanned delivery. Refusing egress outright was rejected because it
  drives harnesses back to direct-socket bypass paths, which are strictly
  worse (no grants, no receipts, no network model at all).
- **URL-borne exfiltration threat (bounded by grant shape).** GET has no
  body, but the caller-chosen path suffix and query string under a granted
  prefix can carry outbound data. §11.6 therefore requires every grant to
  declare an explicit query policy (`forbidden`/`pinned`/`bounded`/
  `allowed`), and requires egress receipts to preserve the full URL with
  credential-only redaction — overriding §11.5's "secrets removed" for this
  operation class — so an auditor sees the channel rather than a sanitized
  URL. Name denylists cannot enumerate every credential parameter, so an
  unlisted query value that matches the credential value-shape rules in
  §11.6 (high-entropy opaque tokens, JWT-shaped or UUID-shaped values in
  credential-position parameters) must never reach a receipt either:
  implementations (#799) apply these value-shape safeguards in addition to
  the denylist, and policy authors MUST NOT grant `allowed` query policy on
  hosts known to accept credentials in query parameters — use
  `pinned`/`bounded` so the grant shape itself bounds what can leak.
  Residual risk: a `bounded` or `allowed` grant still permits
  limited-bandwidth encoding; auditors of high-sensitivity deployments
  should prefer `forbidden`/`pinned`.
- Adversarial-test surface grows: rebinding, private-address, oversize,
  non-HTTPS, non-allowlisted-host, invalid-query-policy, and body-carrier
  smuggling attempts must be asserted to fail closed with the forbidden
  effect not occurring (workflow policy "Testing expectations").
- Receipt schema gains egress fields; per doc-ownership, receipt-schema pages
  update in the implementation PR (#799), not this one.

## Alternatives considered

- **Reuse the §11.2 retriever.** Rejected: store-only by design; adding a
  return path to it would entangle artifact identity, verdicts, and CAS
  retention with ephemeral web content, and put every web request through
  detector/verdict machinery sized for downloads.
- **Direct sockets in the harness.** Rejected: bypasses Arbitraitor's network
  model entirely; exactly the failure mode the shared security model forbids.
- **GET-only via plan-bound approval for every request.** Rejected for v1:
  approval-channel capacity is for execution-grade decisions (ADR-0013);
  spending it on every web search makes both the tool and the approval UI
  unusable. Retained as deferred design (b) for body-bearing methods.
- **General proxy mode.** Rejected: §11.6 is explicitly not a proxy; a proxy
  has a different (much larger) threat surface and would need its own ADR.

## References

- Spec §11.6 (mediated HTTP egress), §11.2/§11.4 (HTTP behavior, redirects),
  §23.1.1 (caller-origin axis), §31.2/§11.5 (receipts), §33.1 (MCP
  capabilities), §39.7/§39.15 (unsupported operations, capability model),
  §40.3 (MCP gateway), §5 (non-goals), §9 invariants 9/23/24.
- ADR-0003 (Fetcher trait), ADR-0013 (plan-bound approval), ADR-0017
  (monotonic project configuration), ADR-0018 (connected-peer verification),
  ADR-0023/ADR-0039 (receipt envelope), ADR-0033 (credential secrecy).
- Issues: #797 (request + maintainer decision), #798 (spec amendment,
  this ADR), #799 (implementation).
