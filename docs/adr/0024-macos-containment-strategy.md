# ADR 0024: macOS containment strategy

**Status:** Proposed
**Date:** 2026-06-29
**Issue:** #279

## Context

Spec §27.4 states macOS supports only `inspect` and `mediated` assurance
until a containment ADR is accepted. Apple deprecated `sandbox-exec` with
no documented replacement for non-App-Store server-side process sandboxing
([Apple containerization issue 737](https://github.com/apple/containerization/issues/737)).

The Endpoint Security framework (introduced macOS Catalina, `es_subscribe`,
~60 MAC hooks) provides **observation** and **authorization** events
(`es_respond_auth_result` can allow/deny some operations), but it is not a
complete containment primitive — it lacks network sandbox coverage and is
not a declarative filesystem/network/process boundary like Linux namespaces
or seccomp. It is distributed as a Developer ID-signed System Extension (not
Mac App Store), requires notarization, and its audit subsystem is deprecated
in favor of unified logging.

App Sandbox requires `com.apple.security.app-sandbox` entitlement and is
designed for GUI/Mac-App-Store apps, not headless CLI tools.

## Decision

macOS containment ADR is **deferred** until one of the following primitives
becomes available:

1. **Apple Containerization `DarwinProcess` lite isolation** — currently an
   open research question (issue 737, May 2026).
2. **Disposable VM via Virtualization.framework** — heavyweight but proven;
   requires a separate VM image management story.
3. **External helper using a non-App-Store System Extension** — requires
   Developer ID signing and an end-user install consent flow, with
   Endpoint Security for observation paired with an external sandbox
   mechanism.

Until the ADR is Accepted:

- macOS supports `inspect` and `mediated` assurance only.
- Contained assurance requests on macOS must downgrade to `mediated`
  (or `block` per policy) — the receipt's effective-controls matrix
  (§27.7) records `filesystem_isolation`, `network_isolation`,
  `process_tree_containment`, and `privilege_suppression` as `unavailable`.
- The `arbitraitor doctor` command reports macOS containment as
  `unavailable — ADR pending`.

For observation mode (`sandbox: observe`), the Endpoint Security framework
via System Extension is the supported path. This provides process-tree,
file-access, and network-connection observation events (§27.6). The ES AUTH
events may allow/deny some operations, but coverage is incomplete and not
equivalent to a full containment profile.

## Consequences

- macOS users cannot claim `contained` assurance — only `inspect` or
  `mediated`.
- Enterprise deployments requiring `contained` assurance on macOS must use
  disposable VMs or wait for platform support.
- The receipt must be honest about the platform's limitations (ADR-0007).
- No native macOS sandbox code is shipped until this ADR is Accepted.

## Alternatives considered

- **Ship `sandbox-exec` profiles anyway:** deprecated, unreliable, Apple
  explicitly discourages third-party use.
- **Require HyperKit/disposable VM for all macOS `contained` requests:**
  heavyweight, poor UX, but defensible for enterprise.
- **Port to App Sandbox:** requires GUI app packaging, not suitable for a
  headless CLI security gate.

## References

- Endpoint Security framework: <https://developer.apple.com/videos/play/wwdc2020/10159/>
- Apple containerization issue 737: <https://github.com/apple/containerization/issues/737>
- Spec §27.4, §27.7, ADR-0007 (assurance levels), ADR-0010 (provenance)
