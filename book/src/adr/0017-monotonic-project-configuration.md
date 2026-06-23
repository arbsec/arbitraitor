# ADR 0017: Monotonic project configuration

**Status:** Accepted
**Date:** 2026-06-16
**Issue:** #13

## Context

A cloned repository may contain `.arbitraitor.toml`. Automatically treating it as trusted policy would let the repository request plugins, trust roots, network access, remote analysis, or weaker execution. The adversarial review (H-10) identified this as a high-severity gap.

## Decision

Project configuration (`.arbitraitor.toml`) is **untrusted repository content**. It may only **tighten** inherited policy, never **weaken** it.

### What project config MAY do (monotonic tightening)

- Require stricter detectors.
- Lower resource limits (max bytes, max time, max depth).
- Declare expected hashes (`expected_sha256 = "..."`).
- Declare expected signer identities.
- Deny network, plugins, or execution modes.
- Require additional provenance verification.

### What project config MAY NOT do

| Prohibited action | Reason |
|---|---|
| Add trust roots or allowed publishers | Untrusted content cannot grant trust |
| Enable a plugin | Plugin code is extended TCB |
| Permit remote sample upload | Privacy violation |
| Relax HTTPS, network, sandbox, or privilege restrictions | Weakens security boundary |
| Weaken required detectors | Could hide malicious behavior |
| Create allow exceptions | Could suppress real findings |
| Alter update channels | Could redirect to malicious updates |
| Select a privileged helper | Privilege escalation vector |

### Discovery and loading rules

1. **Explicit opt-in:** Project config is loaded only when enabled by user or organization policy (`[discovery] load_project_config = true`).
2. **Rooted to verified workspace:** The `.arbitraitor.toml` file must be in the current working directory or an explicitly declared workspace root.
3. **Safe handles:** Configuration paths are opened through capability handles (cap-std), not string-prefix checks.
4. **Origin in policy trace:** The policy evaluation trace identifies which settings came from untrusted project configuration.
5. **Digest recorded:** The project config file's SHA-256 is recorded in the receipt.

### Validation

When loading project config, the policy engine validates that every setting is a **monotonic tightening** of the inherited policy.

### Configuration precedence

```
built-in defaults
  > /etc/arbitraitor/config.toml       (trusted: system)
  > organization-managed config        (trusted: org)
  > project .arbitraitor.toml          (UNTRUSTED: repository content, monotonic only)
  > user config                        (trusted: user-owned)
  > command-line options               (trusted: user-invoked)
```

Each level may tighten but not weaken the level above it (except project config, which may only tighten, period). CLI override with audit is the sole exception.

## Consequences

- Cloning a malicious repository cannot weaken Arbitraitor's security posture.
- A project can declare "this artifact should be signed by identity X" — a legitimate tightening — but cannot declare "trust all artifacts from this repository."
- The policy trace makes it visible when project config is active.
- The monotonic-tightening validation is property-tested.

## Alternatives considered

- **Trust project config fully:** Rejected. Repository content is attacker-controlled.
- **Ignore project config entirely:** Rejected. Loses legitimate use case of declaring expected hashes and signers.
- **Sign project config and trust signed ones:** Rejected for MVP. Creates a key management burden and a new trust root bootstrap problem. May be reconsidered later for trusted organizations.

## References

- `.spec/arbitraitor-adversarial-review-and-gap-analysis.md` H-10
- `.spec/arbitraitor-comprehensive-spec-v0.4.md` §9.24 (Monotonic project configuration), §30.3 (Configuration trust boundaries)
- [ADR 0004](./0004-toml-for-configuration-and-policy.md) — TOML format
