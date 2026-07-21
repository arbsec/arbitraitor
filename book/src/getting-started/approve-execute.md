# Decoupled approval and execution

For workflows where inspection and execution happen at different times, Arbitraitor provides a decoupled `approve` + `execute` flow.

## Step 1: Inspect with receipt

```sh
arbitraitor inspect https://example.com/install.sh --receipt receipt.json
```

## Step 2: Approve

```sh
arbitraitor approve receipt.json
```

This displays the artifact SHA-256, verdict, and findings, then prompts for approval. If approved, writes a time-limited approval file (5-minute expiry) to `receipt.approval.json`.

## Step 3: Execute

```sh
arbitraitor execute receipt.approval.json
```

Reads the artifact from CAS by SHA-256 and executes it via sandboxed bash. Use `--network` to allow network access during execution.

Only `ArtifactType::ShellScript(Posix | Bash)` artifacts are executable via this path; all other classified types (HTML, JSON, XML, archives, Zsh, `Unknown`, etc.) fail closed even when the approval file is otherwise valid. See [ADR-0036](../../../docs/adr/0036-run-pipeline-content-type-execution-gate.md) for the rationale.

```sh
# With network access:
arbitraitor execute receipt.approval.json --network
```

## Approval expiry

Approval files expire 5 minutes after creation. If the approval has expired, `execute` will refuse to run and exit with an error.

See the [CLI reference](../cli-reference.md#approve-command) for full details.
