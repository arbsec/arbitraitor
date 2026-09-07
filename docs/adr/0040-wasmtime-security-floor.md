# ADR 0040: Wasmtime security floor in Cargo.toml

**Status:** Accepted
**Date:** 2026-09-07
**Issue:** —

## Context

`arbitraitor-plugin-host` declared its direct `wasmtime` dependency as
`version = ">=29"` since the crate was introduced. The version actually used
was determined entirely by `Cargo.lock`, which held two copies of the `wasmtime`
facade crate:

- **47.0.3** — our direct dependency (plugin runtime).
- **43.0.2** — a transitive copy required by yara-x's `wasmtime ^43.0.2`
  dependency requirement (yara-x 1.19.0).

In August 2026 the RustSec database published two advisories affecting the
wasmtime line:

- **RUSTSEC-2026-0268** (medium, 6.9) — guest controlled-size host heap
  allocation through WASIp3 streams; affects `>=46.0.0, <46.0.3` and
  `>=47.0.0, <47.0.4`.
- **RUSTSEC-2026-0269** (high, 8.8) — filesystem sandbox escape when paths or
  symlinks contain trailing slashes; fixed in `>=47.0.4` on the 47.x line.

Both were triggered by our 47.0.3 copy, failing the Security CI jobs
(`cargo audit`, `cargo deny check`) on every open PR, including dependency
automation PRs that do not touch Rust dependencies at all.

While investigating the fix, a second defect surfaced: because `>=29` overlaps
yara-x's `wasmtime ^43.0.2` requirement, any *fresh* resolution of the
dependency graph
(`cargo update`, or a resolver-driven edit to the lockfile) is free to unify
both copies onto the single 43.0.2 version — silently replacing our patched
47.x plugin runtime with a four-major-versions-older, advisory-affected
wasmtime. ADR-0037's rejected-alternative "pin a minimum version floor" was
explicitly deferred as "a separate decision that requires its own ADR".

## Decision

1. Raise the `wasmtime` version requirement in
   `crates/arbitraitor-plugin-host/Cargo.toml` from `>=29` to
   **`>=47.0.4`** and bump the lockfile to `47.0.4`.
2. Keep the requirement a floor, not a pin: the constraint expresses the
   *minimum security-acceptable* version. Semver-compatible upgrades remain
   the dependency tooling's to make (Renovate).
3. RUSTSEC-2026-0269 remains applicable to the yara-x-pinned `wasmtime
   43.0.2` transitive copy; it is ignored in `deny.toml` (and the audit
   workflow) with a recorded reason and an explicit removal condition —
   drop the ignore when a yara-x release requires a patched wasmtime
   (>= 46.0.3 or >= 47.0.4), since no such yara-x release exists today
   (1.20.0 still pins `wasmtime ^45.0.3`).

## Consequences

- The direct wasmtime copy can never unify with yara-x's `^43.0.2` range:
  the two requirements are now disjoint, so the dual-copy lockfile state is
  stable under `cargo update` and fresh resolves. A future accidental
  four-major-version downgrade of the plugin runtime is a resolver error,
  not a silent change.
- Stale ignore entries are pruned (RUSTSEC-2026-0185/0186/0190 — quinn-proto,
  memmap2, and anyhow versions long since fixed in the lockfile). These could
  never fail `cargo deny check` on their own (`advisory-not-detected` is a
  warning in cargo-deny 0.20.x, and the CI failures were driven by the
  unignored 0268/0269 vulnerability errors), but pruning keeps the
  unused-ignore warning signal clean so genuinely stale entries stand out
  during future ignore hygiene.
- Both Security CI jobs pass again; dependency automation PRs are no longer
  blocked by unrelated advisory-database drift.
- When yara-x publishes a version with a non-vulnerable wasmtime range, the
  ignore must be re-evaluated and (if unneeded) removed, keeping the
  `unused-ignored-advisory` signal meaningful.
- Future floor raises are expected whenever a wasmtime advisory lands with a
  fix above the current floor; the floor documents the minimum
  security-acceptable version rather than the resolved version.

## Alternatives considered

### Keep `>=29` and bump only the lockfile

Rejected. The lockfile would still carry a 47.0.4 copy that any re-resolve may
collapse onto yara-x's 43.0.2 — the exact failure mode observed while
preparing this ADR. The manifest must state the security floor for the
lockfile state to be stable.

### Pin `=47.0.4` exactly

Rejected. An exact pin blocks semver-compatible upgrades and turns every
routine dependency update into a manifest edit. The floor expresses the
security requirement; the lockfile expresses the exact build.

### Bump to wasmtime 48.0.1 (latest)

Rejected for this change. 47.0.4 is the minimal patch consistent with the
advisory fix ranges and identical to the previously resolved line, keeping
the diff reviewable. Moving major lines is a dependency-update decision for
Renovate to propose separately, with its own review.

### Drop or vendor yara-x to remove the 43.0.2 copy

Rejected. YARA rule evaluation is core functionality (ADR-0037 context); the
43.0.2 copy's exposure is bounded: it is compiled into the analysis crate, not
the plugin host, and RUSTSEC-2026-0269 is a bug in the `wasmtime-wasi`
filesystem sandbox (cap-std trailing-slash symlink handling, exercised via
WASI preopened directories), while yara-x's wasmtime dependency enables no
WASI feature and configures no preopened directories. Tracked via the
ignore's removal condition instead.

## References

- [ADR 0037](0037-wasmtime-cve-risk-register.md) — Wasmtime CVE risk register
  (pinned-version table updated by this change).
- [ADR 0006](0006-wasmtime-component-model-plugins.md) — Wasmtime Component
  Model for plugins.
- RUSTSEC-2026-0268 —
  <https://rustsec.org/advisories/RUSTSEC-2026-0268>
- RUSTSEC-2026-0269 —
  <https://rustsec.org/advisories/RUSTSEC-2026-0269>
- `deny.toml` — advisories ignore list and scoping rationale.
- `.github/workflows/security.yml` — `cargo audit` invocation.
- `crates/arbitraitor-plugin-host/Cargo.toml` — wasmtime dependency
  declaration and feature set.
