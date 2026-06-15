# Governance

## Status

Arbitraitor is currently maintained by its founding contributors. Governance will evolve as the community grows.

## Decision Making

### Technical Decisions

Architecturally significant decisions are recorded as ADRs (Architecture Decision Records) in `docs/adr/`. Each ADR has a state: `Proposed`, `Accepted`, `Superseded`, or `Rejected`.

### Security Decisions

Changes to security-sensitive paths (see `AGENTS.md` Section 9) require security-owner review. Changes to security invariants require maintainer consensus.

## Roles

| Role | Responsibilities |
|------|-----------------|
| Contributor | Submits PRs, participates in discussions |
| Maintainer | Reviews PRs, merges changes, manages releases |
| Security Owner | Reviews security-sensitive changes, manages vulnerability response |

## Teams

GitHub teams map to review boundaries:

- `@arbitraitor/maintainers` — general maintenance and CI
- `@arbitraitor/security` — security-critical path review
- `@arbitraitor/plugin-maintainers` — WIT and plugin interface
- `@arbitraitor/rule-reviewers` — YARA-X rule packs
