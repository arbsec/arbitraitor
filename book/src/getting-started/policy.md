# Validating policies

Arbitraitor uses TOML policy files to define rules for verdict computation. Before running artifacts, verify your policy is well-formed.

## Validate a policy file

```sh
arbitraitor policy my-policy.toml
```

Output shows the policy version, rule count, and digest:

```text
Policy valid
  Version: 1
  Rules: 5
  Digest: sha256:abc123...
```

## What happens on invalid policy

If the policy TOML is malformed or contains unknown fields, the command exits with a non-zero code and prints the validation error.

See the [CLI reference](../cli-reference.md#policy-command) for full flag details.
