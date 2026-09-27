# Documentation gate

Any change to **public behavior** updates human-facing docs in the same PR (AGENTS.md "Documentation is current", [doc-ownership](../../../../docs/doc-ownership.md) map). This reference defines what counts as public behavior and how `classify-docs-impact` classifies it.

## Public behavior surfaces

A change touches public behavior if the diff affects any of:

| Surface | Detection pattern (file paths / content) |
|---|---|
| CLI behavior | `crates/arbitraitor-cli/`, clap subcommands/flags, exit codes |
| Wrappers | `crates/arbitraitor-wrapper/`, shim/init surface, `wrappers install/init/status`, `wrap` |
| Configuration | `~/.arbitraitor/config.toml` schema, `crates/arbitraitor-core/` config types, `[policy]`/`[fetch]`/`[detectors]` blocks, `crates/arbitraitor-policy/` TOML policy schema |
| Environment variables | `ARBITRAITOR_*`, any `secret://env/<VAR>` reference in code or docs |
| Public APIs | `pub fn`, `pub struct`, `pub trait`, `pub enum` in `crates/arbitraitor-{core,model,policy,plugin-api,engine}/` |
| Receipt schema | `crates/arbitraitor-receipt/`, RFC 8785 canonicalization, receipt fields |
| MCP behavior | `crates/arbitraitor-mcp/`, tool schema, namespacing, lifecycle |
| Daemon protocols | Unix-socket protocol in `crates/arbitraitor-daemon/` |
| Plugin protocol | `crates/arbitraitor-plugin-api/`, `crates/arbitraitor-plugin-host/`, `wit/` interface definitions |
| Security guarantees | `SECURITY.md`, `AGENTS.md` security rules, `docs/conventions.md` invariants, sandbox/verdict surfaces in `crates/arbitraitor-{sandbox,exec,fetch,store}/` |
| Package-manager policies | `crates/arbitraitor-package-manager/`, lifecycle policy tables |
| Error behavior | exit-code tables, error enums in `crates/arbitraitor-model/` |
| Installation/migration/removal | README install steps, wrappers migration, config migration |

## What does NOT require doc updates

- Internal refactors with no public API change (private function moves, test restructuring).
- Dependency version bumps with no behavior change (lockfile updates).
- CI workflow changes (`.github/workflows/`) — these are not public behavior.
- Code comment improvements (docstrings on private items).

Even in these cases, no `CHANGELOG.md [Unreleased]` entry is warranted unless the change has
a consumer-visible effect — internal development notes stay out of the changelog per
`AGENTS.md` (release notes for consumers, never a development log); "chore: bump deps" and
"refactor: move X to Y" entries belong in the PR description instead.

## `classify-docs-impact` output

The script reads `gh pr diff --name-only` + the diff body, matches against the patterns above, and outputs:

```json
{
  "public_behavior_changed": true,
  "touched_surfaces": ["CLI behavior", "Configuration"],
  "docs_required": true,
  "changelog_updated_in_pr": null,
  "checklist_marker": "arb:docs"
}
```

The script does NOT verify the docs were actually updated — that is the reviewer's and `reconcile-checklist`'s job. It classifies the impact; the checklist marker `<!-- arb:docs -->` must be checked based on the classification + evidence of doc changes in the PR diff.

## `CHANGELOG.md [Unreleased]`

Every public-behavior change gains an entry in `CHANGELOG.md` under `[Unreleased]` in the same PR. The entry follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) format: `Added`, `Changed`, `Deprecated`, `Removed`, `Fixed`, `Security`.

## Generated docs do not count

Generated `cargo doc` output and `///` doc comments on public items are necessary but NOT sufficient. The requirement is **human-facing** documentation — README, CLI reference, configuration guide, security docs, CHANGELOG. A PR that only adds `///` comments to public functions but does not update README/CHANGELOG/config docs has NOT met the documentation gate for a public-behavior change.
