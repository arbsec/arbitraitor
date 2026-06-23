# ADR 0011: Plugin trust classification model

**Status:** Accepted
**Date:** 2026-06-16
**Issue:** #6

## Context

The adversarial review (C-03) identified that wrapper plugins are part of the
extended trusted computing base. The core can validate a plan's shape, but it
cannot prove that a plugin faithfully represented the original command.

A malicious or buggy wrapper can:

- Omit a URL or redirect-affecting option.
- Mishandle authentication scope.
- Falsely label a partial translation as exact.
- Hide an upload or side effect.
- Delegate to the original tool after scanning a different artifact.
- Omit package-manager lifecycle stages.

## Decision

Classify plugins by **security role**. Each class has different trust, capability,
and enforcement properties.

### Plugin classes

| Class | TCB | What it does | Enforcement default |
|-------|-----|-------------|-------------------|
| Evidence-only detector | **Not** in verdict TCB | Produces findings (policy inputs) | Allowed |
| Semantic translator (wrapper) | Extended TCB | Controls what operation the core performs | Advisory or disabled in enforce mode |
| Execution/package adapter | Extended TCB | Controls process and lifecycle boundaries | First-party only in enforce mode |
| UI extension | — | — | **Prohibited initially** |

### Evidence-only detectors

Examples: YARA-X, antivirus adapters, binary metadata analyzers, language
analyzers.

- Findings are **policy inputs**, never direct verdicts.
- A detector cannot authorize release or suppress another detector's findings.
- Community detectors are allowed but their findings carry the source's
  confidence and provenance.

### Semantic translators (wrappers)

Examples: `curl` wrapper, `wget` wrapper, shell execution adapters.

- **Extended TCB:** the core depends on the wrapper faithfully representing the
  original tool invocation.
- Community semantic translators default to **advisory or disabled** in
  enforcement mode.
- First-party wrappers require:
  - Conformance tests (must pass official conformance suite for the command
    shape).
  - Exact version ranges for the wrapped tool.
  - Signed provenance.
  - Independent review.

### Execution and package adapters

Examples: shell executors, Homebrew adapter, Arch adapter.

- **Extended TCB:** controls process creation, lifecycle, and child-process
  boundaries.
- In enforcement mode, only first-party or explicitly trusted adapters are
  permitted.
- Package-manager adapters report coverage per stage (resolution, metadata,
  source downloads, build, package artifact, install hooks, final installation).
  A plugin must not hide an unmediated build or install stage.

### UI extensions

**Prohibited initially.** Plugins return structured fields only; the core owns
all user-facing rendering. This prevents:

- Terminal control sequence injection by plugins.
- Phishing through fake approval prompts.
- Confusion of reviewer by plugin-generated UI elements.

### Capability and permission model

```text
Capabilities (what a plugin can request the core to do):
  - parse_argv
  - resolve_original_executable
  - read_tool_version
  - request_secret_reference (without reading the secret value)
  - read_immutable_artifact (opaque read handle)
  - emit_findings
  - request_network_operation (through core)
  - request_sandbox_execution
  - request_package_manager_delegation

Permissions (what a plugin can directly access):
  - network: false by default
  - filesystem read/write: scoped paths only
  - environment variable names: explicit list
  - process execution: false by default
  - terminal rendering: false always
```

Community plugins receive **no network, no process execution, no arbitrary
filesystem access, and no terminal-rendering authority** by default.

### Semantic confidence

Every wrapper translation states one of:

| Level | Meaning |
|-------|---------|
| `exact` | Supported semantics fully represented |
| `equivalent` | Behavior differs in non-security-relevant ways |
| `partial` | Some options or side effects not modeled |
| `opaque` | Plugin cannot determine the operation safely |

Policy defaults:

```toml
[wrappers]
minimum_semantic_confidence = "exact"
allow_equivalent = "prompt"
partial = "block"
opaque = "block"
```

A plugin may not label a translation `exact` unless it passes the official
conformance suite for that command shape.

## Consequences

- Evidence-only detectors from the community are safe to run — their output is
  just policy input.
- Wrappers and execution adapters from untrusted sources cannot silently alter
  operations in enforcement mode.
- The plugin ecosystem has clear trust tiers that users can reason about.
- Adding a new wrapper plugin requires conformance testing, not just code
  review.

## Alternatives considered

- **All plugins are equal, core validates everything:** Rejected. The core
  cannot validate semantic fidelity of a translation it didn't perform.
- **No plugins at all:** Rejected. Limits extensibility for detectors and
  intelligence providers that don't affect the TCB.
- **Full plugin UI rendering:** Rejected. Creates terminal injection and
  phishing channels.

## References

- `.spec/arbitraitor-adversarial-review-and-gap-analysis.md` C-03
- `.spec/arbitraitor-comprehensive-spec-v0.4.md` §39 (Plugin, wrapper, and
  adapter system)
- [ADR 0006](0006-wasmtime-component-model-plugins.md) — Plugin runtime
