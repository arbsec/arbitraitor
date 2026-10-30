# ADR 0043: No Wasmtime compilation cache

**Status:** Accepted
**Date:** 2026-10-30
**Issue:** #773

## Context

`arbitraitor-plugin-host` builds its Wasmtime `Engine` with
`default-features = false` and, until this decision, the `cache` feature. The
`.cache(Some(Cache::new(CacheConfig::new())))` call made Wasmtime write compiled
component code to an on-disk cache so that repeated loads of the same component
skipped compilation.

The feature also pulls `wasmtime-internal-cache`, which declares `zstd ^0.13`
in every published Wasmtime release checked (48.0.0 through 50.0.1). That
requirement resolves a second `zstd` copy into the lockfile that no Wasmtime
version bump can remove, and those versions carry
RUSTSEC-2026-0391 (`zstd 0.13.3`) plus RUSTSEC-2026-0398/0403 and the
RUSTSEC-2026-0395–0406 `unsound` set (`zstd-safe 7.3.0`). The alternative to
dropping the feature is a permanent advisory waiver on the plugin sandbox
boundary, which the security gate exists to prevent.

Two properties of the cache are independently uncomfortable for a security
boundary:

- Its files live outside the CAS. The digest that the pipeline verified applies
  to the `.wasm` bytes, not to the compiled artifact, so a writable cache
  directory is a cache-poisoning surface: tampering with an entry changes the
  code that runs for an already-verified component.
- It is host-global state that survives process exit, so it is neither covered
  by the receipt nor cleared by any lifecycle step the host controls.

## Decision

Do not enable Wasmtime's compilation cache. `arbitraitor-plugin-host` depends on
`wasmtime` with `cranelift`, `runtime`, `component-model`, and
`parallel-compilation` only, and `WasmEngine::new` does not construct a
`Cache`. Components are compiled on every load.

`parallel-compilation` stays enabled: it is orthogonal to caching and bounds
the cost of the compilation that now happens on each load.

## Consequences

- Repeated loads of the same plugin pay compilation cost each time. This is a
  real latency regression for a host that loads many plugins in one process;
  it is accepted because the alternative is shipping advisory-laden transitive
  crates or a standing waiver.
- No compiled-code artifact is written outside the CAS, so there is no cache
  directory to poison, tamper with, or account for, and the verified digest
  remains sufficient to determine the code that executes.
- `wasmtime-internal-cache`, `zstd 0.13.3`, and `zstd-safe 7.3.0` leave the
  dependency graph, which is what makes the advisory gate pass with no new
  `--ignore` in `deny.toml` or `security.yml`.
- The plugin sandbox's feature set changes, so
  [ADR 0037](0037-wasmtime-cve-risk-register.md) (Wasmtime CVE risk register)
  is amended in place to list the new feature set and the withdrawn advisories.
- If per-load compilation later proves prohibitive, the mitigation must keep
  the compiled artifact inside the verified trust path — for example a
  digest-keyed cache under the CAS with its own integrity check — rather than
  restoring an unverified host-global cache. That would require a new ADR.

## Alternatives considered

### Bump Wasmtime until the zstd advisories are fixed

Rejected. `wasmtime-internal-cache` requires `zstd ^0.13` in every published
release; the vulnerability is in the requirement, not in the Wasmtime version,
so no bump removes it.

### Keep the cache and add an advisory waiver

Rejected. It would be a permanent `--ignore` for two crates on the plugin
sandbox boundary, and the gate's value is that such waivers stay exceptional.
It also leaves the untracked on-disk artifact in place.

### Keep the cache and patch `wasmtime-internal-cache` via `[patch]`

Rejected. It pins a fork of a Bytecode Alliance internal crate and takes on the
maintenance of the cache format and its correctness, for a feature this ADR
removes for security reasons anyway.

## References

- Issue #773 — dependency advisory gate drift on `main`.
- [ADR 0006](0006-wasmtime-component-model-plugins.md) — Wasmtime Component
  Model for plugins.
- [ADR 0037](0037-wasmtime-cve-risk-register.md) — Wasmtime CVE risk register.
- [ADR 0040](0040-wasmtime-security-floor.md) — Wasmtime security floor.
- RustSec RUSTSEC-2026-0391 (`zstd`), RUSTSEC-2026-0398/0403 and
  RUSTSEC-2026-0395–0406 (`zstd-safe`).
- `crates/arbitraitor-plugin-host/Cargo.toml` — Wasmtime dependency
  declaration and feature set.
