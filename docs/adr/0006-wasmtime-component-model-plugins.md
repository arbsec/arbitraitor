# ADR 0006: Wasmtime Component Model for plugins

**Status:** Accepted
**Date:** 2026-06-16

## Context

Arbitraitor needs a plugin system for downloaders, shell adapters, detectors,
intelligence providers, sandbox adapters, and provenance verifiers. Plugins run
untrusted or semi-trusted code. In-process dynamic libraries (`.so`, `.dylib`,
`.dll`) would make plugin compromise equivalent to core compromise.

## Decision

Use **Wasmtime Component Model with WIT interfaces** as the primary plugin
runtime. WASI Preview 2 is the baseline. Do not build around experimental WASI
Preview 3 behavior.

**Separate WIT worlds** (not one universal interface):

```text
arbitraitor:plugin/wrapper       — downloader argument translation
arbitraitor:plugin/detector      — artifact analysis, returns findings
arbitraitor:plugin/intelligence   — indicator lookup
arbitraitor:plugin/provenance    — signature/attestation verification
```

A downloader argument parser does not automatically gain detector or network
capabilities.

**Default plugin instance sandbox:**

| Control | Value |
|---------|-------|
| Network | None |
| Ambient filesystem | None |
| Inherited environment | None |
| Clock | Deterministic or host-provided only when requested |
| Memory | Bounded |
| Table count | Bounded |
| Fuel/epoch interruption | Enabled |
| Total execution deadline | Enforced |
| Output size | Limited |
| Dynamic loading | Prohibited |
| Artifact paths | Opaque read capability only (no raw paths) |
| Host-call deadline | Per-call, with cancellation |
| Host-call count | Bounded |
| Host-call output size | Bounded |

**Critical limitation:** fuel and epoch interruption do **not** stop a guest
blocked inside a host call. Therefore every host function must have its own
deadline and cancellation — no host function may perform unbounded blocking work.

**Subprocess fallback:** some integrations (platform AV, package managers)
require native subprocesses. Use a framed protocol (length-prefixed JSON).
Controls: absolute executable path, expected binary digest, clean environment,
closed inherited descriptors, process group/Job Object, timeout, kill-tree,
output/memory limits, no shell interpolation.

**No native dynamic plugin ABI** is supported initially.

## Consequences

- Plugins are memory-isolated from the host process.
- Capability-based access: each plugin world grants only what its role needs.
- Community plugins default to disabled in enforcement mode (see
  [ADR 0011](0011-plugin-trust-classification.md)).
- WIT packages are versioned semantically; compatibility fixtures and generated
  bindings checked in CI.
- Subprocess plugins are capability-restricted and auditable.

## Alternatives considered

- **Native dynamic libraries (.so/.dylib/.dll):** Rejected. Same memory
  authority as core; plugin compromise = core compromise.
- **Embedded scripting language (Lua, Rhai):** Rejected. Adds language runtime
  attack surface; not memory-isolated.
- **Process-per-plugin only (no WASM):** Rejected for MVP. Startup overhead and
  IPC complexity for small plugins. WASM provides isolation with lower overhead.

## References

- `docs/spec/tech-stack.md` §10 (Plugin runtime)
- `docs/spec/spec.md` H-04 (Wasmtime
  limits and blocked host calls)
- [ADR 0011](0011-plugin-trust-classification.md) — Plugin trust classification
- [Wasmtime interruption docs](https://docs.wasmtime.dev/examples-interrupting-wasm.html)
- [Wasmtime ResourceLimiter](https://docs.wasmtime.dev/api/wasmtime/trait.ResourceLimiter.html)
