# ADR 0044: Sandbox API stability for cross-project consumption

**Status:** Accepted
**Date:** 2026-10-30
**Issue:** —

## Context

Arbitraitor owns the sandbox and execution-control layer. The ownership
boundary is normative in two places: `.agents/project/arbitraitor-workflow.md`
records "Sandboxing, process hardening, mediated execution" as Arbitraitor's
to implement here, and the consumer's own specification says the same — "Sandbox
backends and their common capability interface are owned and implemented by
Arbitraitor. Orchestraitor selects a requested profile, sends the action plan
to Arbitraitor, and consumes the effective-control report"
(`arbsec/orchestraitor` §9.6), and "Orchestraitor may contain adapters that
translate orchestration requests into Arbitraitor calls, but those adapters must
not make independent allow, deny, containment, trust, approval, or promotion
decisions" (`arbsec/orchestraitor` §16.1).

That ownership is not a documentation nicety: the consumer's §16.1 states
"Arbitraitor is not merely a collection of reusable crates or an optional
backend. It is Orchestraitor's complete security subsystem", and §16.2 steps
3, 5, and 6 require the capability to be implemented in Arbitraitor, exposed
behind a versioned API with a capability identifier, and released or pinned
before the consumer's integration is added.

**The gap.** The consumer consumes Arbitraitor in-process, not over a
protocol. Its `Cargo.toml` pins eight Arbitraitor crates by commit-pinned git
dependency — `arbitraitor-core`, `arbitraitor-model`, `arbitraitor-policy`,
`arbitraitor-sandbox`, `arbitraitor-exec`, `arbitraitor-receipt`,
`arbitraitor-mcp`, and `arbitraitor-plugin-api`. Of these,
`arbitraitor-sandbox` and `arbitraitor-exec` are `publish = false`, so the
crates.io stability promise in spec §40.6 — which covers the published
`arbitraitor-engine` crate only — never reaches them. They are consumed
anyway, by git pin, with no stability contract attached.

Two failure classes follow.

1. **Loud breakage.** Renaming `arbitraitor_sandbox::EffectiveControls`,
   adding a variant to `ControlState`, or changing the signature of
   `compute_effective_controls` breaks the consumer's build. That is
   survivable but untracked: there is no release-note trail and no
   requirement that the consumer's pin moves with the change.
2. **Silent breakage.** A *semantic* change that keeps the types compiling —
   a control that reports `Unavailable` where it used to report `Degraded`,
   a probe matrix that stops reporting a control at all — breaks the
   consumer's security posture without breaking its build. This is the
   dangerous class, and it is exactly what §27.7's fail-closed rule and
   ADR-0007's assurance levels exist to prevent.

**A live specimen of the class.** The consumer's `docs/spec/tech-stack.md:48`
pins "landlock 0.4.5 + rustix 1.1.4 + nix 0.31.3" for this sandbox layer.
This repository's `Cargo.lock` has moved `rustix` to 1.1.6. The consumer's
documented expectation about the exact dependency set of Arbitraitor's sandbox
layer drifted, with no signal crossing the boundary. The two specifications
disagree today, in the same repository pair, over a dependency version.

**Why now.** Spec §40.9 (added with this decision) states the consumption
contract, and spec §43.10 makes tier-4a host-syscall sandbox verification the
blocking evidence behind ADR-0007's `contained` assurance level on Linux. A
contract that carries that weight cannot be left to the implicit SemVer
behaviour of a crate that crates.io has never seen.

## Decision

1. **The consumed surface is enumerated.** Spec §40.9 names it: both
   `arbitraitor_sandbox::EffectiveControls` (the platform capability probe
   matrix, with its `ControlState` enum) and `arbitraitor_exec::EffectiveControls`
   (the per-control receipt proof matrix), plus `SandboxMode`,
   `compute_effective_controls(mode, platform)`, `configure_command`, and
   `apply_sandbox`. Nothing else in the sandbox crates is a supported
   consumption surface without a spec amendment.
2. **The consumer selects, it does not decide.** A consuming harness MAY
   select a requested sandbox profile and consume the effective-control
   reports. It MUST NOT make independent allow, deny, containment, trust,
   approval, or promotion decisions.
3. **`publish = false` does not mean "unstable".** Because the sandbox crates
   are consumed by commit-pinned git dependency, their public API is
   SemVer-relevant in practice. Breaking changes to the consumed surface
   require a coordinated consumer update — the consumer's revision pin is
   bumped in the same effort as the change — and every breaking change is
   flagged in the release PR. Additive changes are preferred.
4. **The carve-out is first-party and narrow.** Spec §40.5.1 gains a
   first-party carve-out: same-organisation sibling products may consume
   `publish = false` workspace crates via commit-pinned git dependencies. This
   is a supported consumption mode, distinct from the crates.io stability
   promise in §40.6, and it does not extend to third parties outside the
   organisation — who continue to propose changes through issues rather than
   crate dependencies.
5. **Semantics are not restated here.** The semantics of the control reports
   stay in spec §27.7. The consumer's runtime capability-negotiation
   obligation — "A version match alone is not evidence that a control is
   effective" (`arbsec/orchestraitor` §16.7) — stays with the consumer. This
   ADR governs the API contract between the two projects, not the meaning of
   the reports and not the consumer's negotiation protocol.

## Consequences

- Breaking-change discipline now applies to two crates that never reach
  crates.io. A change to `EffectiveControls`, `ControlState`, `SandboxMode`,
  `compute_effective_controls`, `configure_command`, or `apply_sandbox` is a
  coordinated release event for the organisation, not an internal refactor.
- The consumer's revision pin becomes a release-blocking coordination point:
  a breaking change to the consumed surface cannot ship without the consumer
  moving to a revision that contains it.
- The loud/silent split above becomes actionable: the loud class is caught by
  the consumer's build and is now tracked by the release-PR flag; the silent
  class — a control that changes `ControlState` without changing the type —
  is caught by the §43.10 tier-4a paired-test assertions, which must
  exercise every control the consumed matrix reports.
- The dependency-drift specimen is now a tracked obligation rather than an
  accident: when this repository moves a dependency that the consumer's
  documented dependency set names, the consumer's pin is revisited in the
  same effort.
- The rule covers defaults, not only types. A default inside the consumed
  crates changes the consumer's observable behaviour without changing a single
  type: the open implementation issue (#794) shows the default `RLIMIT_NPROC`
  of the mediated-execution path making the consumer's mediated-script test
  fail on a busy host, with a caller-side override of the limit explicitly
  ruled out as a fix. A default change in the consumed surface is a
  coordinated release event in the same way a type change is.
- Spec §40.5 no longer claims the agent harness reaches Arbitraitor through
  the MCP gateway; it pins the crates in-process and says so.

## Alternatives considered

- **Publish `arbitraitor-sandbox` and `arbitraitor-exec` to crates.io before
  1.0.** Rejected. §40.6 gives the crates.io stability promise to
  `arbitraitor-engine` alone; widening it would make the sandbox crates a
  permanent public API surface before the sandbox model has settled (§27.7's
  capability-report semantics, ADR-0028's Landlock ABI matrix). Pre-1.0
  `0.x` SemVer still advertises instability, so publishing would give the
  illusion of a contract without its substance.
- **Vendoring or submodule-ing the consumed crates into the consumer.**
  Rejected. It forks the security implementation into two copies of the
  boundary the consumer is forbidden to own, and the ownership rule in
  `.agents/project/arbitraitor-workflow.md` exists precisely to prevent that.
  A vendored copy also silently stops receiving Arbitraitor's fixes.
- **Status quo — treat git-pinned `publish = false` crates as internal.**
  Rejected. Silent breakage is the defect. The status quo allows this
  repository to rename or re-shape the sandbox API, or to change a control's
  reported state, with no obligation to move the consumer and no place in the
  release notes where the change is visible.
- **Version the consumed surface through the daemon or MCP protocol
  instead.** Rejected as the primary mechanism: it would put a transport
  boundary between the consumer and the enforcement code it is required to
  rely on, and the consumer's own §16.2 step 5 requires a versioned *API*,
  not only a versioned protocol. The daemon and MCP surfaces remain
  available (§40.2, §40.3) but are not the mechanism for the in-process
  consumer.

## References

- Spec §40.5 (integration surfaces), §40.5.1 (library contract constraints),
  §40.6 (public API stability contract), §40.9 (sandbox and execution-control
  consumption contract), §27.7 (sandbox limitations and capability
  reporting), §43.10 (sandbox verification testing).
- ADR-0007 (assurance levels model — inspect/mediated/contained),
  ADR-0021 (Landlock filesystem isolation), ADR-0028 (Landlock ABI probe and
  receipt recording), ADR-0038 (pipeline engine crate extraction).
- `.agents/project/arbitraitor-workflow.md` — ownership boundaries and
  testing expectations.
- `arbsec/orchestraitor` — `Cargo.toml` (commit-pinned git dependencies on
  eight Arbitraitor crates), `docs/spec/40-arbitraitor-integration.md` §9.6,
  §16.1, §16.2, §16.7, and `docs/spec/tech-stack.md:48`.
