# ADR 0004: TOML for configuration and policy

**Status:** Accepted
**Date:** 2026-06-16

## Context

Arbitraitor needs a human-authored format for user configuration, organization policy, plugin manifests, and release configuration. The format must be deterministic, parseable without ambiguity, and suitable as a security policy language.

## Decision

Use **TOML** with `serde` and the `toml` crate for all human-authored configuration and policy. Use **JSON** for machine protocols, receipts, findings, intelligence records, and SARIF output.

**TOML is used for:**

- User configuration (`~/.config/arbitraitor/config.toml`)
- Organization policy
- Project policy (`.arbitraitor.toml` — untrusted, see ADR 0017)
- Plugin manifests
- Release configuration

**YAML is explicitly rejected** for Arbitraitor policy because:

- Implicit typing (`yes`/`no`/`null` coercion).
- Aliases and anchors expand the parsing surface.
- Multiple interpretations of the same document.
- The widely used `serde_yaml` crate is deprecated.
- GitHub Actions requires YAML, but that does not require Arbitraitor itself to use it.

**Policy engine uses a constrained declarative TOML schema** compiled into an internal expression tree. No general scripting language (CEL, Rego, Cedar) is embedded for the MVP. This keeps the attack surface small, ensures deterministic evaluation, and simplifies explainability.

## Consequences

- Policy is statically typed and schema-validated before evaluation.
- `deny_unknown_fields` enforced on security-critical input structures.
- No YAML anywhere in Arbitraitor's own configuration.
- Future policy backends (CEL, Rego/OPA, Cedar, WASM) can be added behind the evaluator trait without changing the authoring format.

## Alternatives considered

- **YAML:** Rejected. Parsing surface, deprecated ecosystem, implicit typing.
- **JSON for human config:** Rejected. No comments, verbose, error-prone for humans.
- **Dhall/Starlark:** Rejected. Adds a language runtime to the security core.

## References

- `.spec/arbitraitor-tech-stack.md` §6.1 (TOML for human-authored configuration)
- `.spec/arbitraitor-comprehensive-spec-v0.4.md` §23 (Policy engine)
