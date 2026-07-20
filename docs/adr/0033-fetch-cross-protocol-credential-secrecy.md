# ADR 0033: Fetch cross-protocol credential secrecy

**Status:** Accepted
**Date:** 2026-07-20
**Issue:** #472

## Context

CVE-2025-14524 showed that a fetch transport can mishandle redirects from
HTTP(S) URLs carrying OAuth2 bearer credentials into non-HTTP protocols such as
IMAP, LDAP, POP3, or SMTP. Even when the first request is safe, a permissive
redirect stack can reinterpret bearer, cookie, or default `.netrc` credentials
as protocol credentials for the destination scheme.

Arbitraitor already blocks unsupported schemes and records redacted redirect
chains. It also keeps `reqwest` behind `arbitraitor-fetch` so transport policy
does not leak into callers. The missing piece was an explicit credential
secrecy outcome that records why a credential-bearing cross-protocol redirect
failed closed.

## Decision

Arbitraitor fetch policy blocks every credential-bearing redirect from `http` or
`https` into `imap`, `ldap`, `pop3`, `smtp`, `ftp`, `file`, `gopher`, or `smb`
before the destination request is constructed. This rule is stricter than
client defaults and applies before general scheme validation so diagnostics can
identify the credential-secrecy class instead of only reporting an unsupported
scheme.

Fetch metadata records `RedirectCredentialSecrecy`:

- `ok` when no credential-bearing cross-protocol redirect was observed.
- `bearer_leaked` when an `Authorization` bearer value would have crossed the
  protocol boundary.
- `cookie_leaked` when a `Cookie` value would have crossed the protocol
  boundary.
- `netrc_default_leaked` when a caller-declared default `.netrc` token would
  have crossed the protocol boundary.

Canonical receipts expose this outcome through optional retrieval metadata. The
field is `skip_serializing_if = "Option::is_none"` per ADR-0014 so receipts that
do not set it retain stable canonical bytes. Pipelines that have fetch metadata
set the field, including the `ok` outcome, so new receipts explain redirect
credential handling. This also aligns with ADR-0023: the in-toto Statement
envelope carries the same canonical receipt predicate and therefore records the
transport secrecy decision without a second schema.

## Consequences

- Credential-bearing cross-protocol redirects fail closed before any outbound
  request reaches the non-HTTP target.
- Error messages and receipts record only the credential class, never the raw
  credential value.
- Existing callers that do not configure credentials continue to see ordinary
  scheme-policy failures for unsupported redirect targets.
- Future compatibility tests for `reqwest`, `hyper`, `ureq`, and `neqo` can use
  the recorded outcome as the matrix assertion for spec §43.7.

## Alternatives considered

- Rely on the HTTP client redirect policy. Rejected because CVE-2025-14524 is a
  client-default failure mode; Arbitraitor must enforce this boundary itself.
- Strip credentials and continue into the destination protocol. Rejected because
  Arbitraitor's fetcher is an HTTP retrieval component; cross-protocol redirects
  into mail, directory, file, or SMB protocols are outside its trust envelope.
- Record only an error string. Rejected because receipts need a stable,
  machine-readable field for compatibility matrices and audit queries.

## References

- Spec §11.4 redirect handling
- Spec §43.7 cross-protocol redirect compatibility matrix
- ADR-0014: Receipt canonicalization (RFC 8785 JCS)
- ADR-0018: SSRF, proxy, and connected-peer verification
- ADR-0023: in-toto Statement receipt envelope
- CVE-2025-14524: curl OAuth2 bearer token cross-protocol redirect leak
- CVE-2025-0167: curl `.netrc` default-token leak
