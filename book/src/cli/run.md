# run

The `run` command executes the full Arbitraitor pipeline including human approval for elevated findings.

## Synopsis

```sh
arbitraitor run <URL or file path> [flags]
```

## Description

`run` performs Level 2 (Mediated) or Level 3 (Contained) execution. It:

1. Retrieves and buffers the artifact
2. Runs the detection pipeline
3. Constructs a canonical execution plan
4. Evaluates policy against the plan
5. Requests human approval if findings require it
6. Executes the exact buffered artifact in a controlled context
7. Emits a signed receipt

## The approval flow

When findings exceed policy thresholds, `run` pauses for human approval:

```
Artifact: sha256:a1b2c3d4e5f6...
Plan:     sha256:91ab...
Type the first 12 characters of the plan digest to approve:
```

Approval binds the entire execution context — not just the artifact digest. Changing any parameter (interpreter, arguments, environment, destination) requires fresh approval.

## Flags

### `--receipt <PATH>`

Write the execution receipt to this path. The receipt proves what was executed and what controls were in effect.

### `--output <PATH>`

Write the artifact's stdout and stderr to this path instead of the terminal.

```sh
arbitraitor run install.sh --output /tmp/install.log
```

### `--native`

Allow native binary execution. Requires `--native` gate enabled in policy. Without this flag, native binaries are blocked.

```sh
arbitraitor run ./bin/tool --native
```

### `--interactive`

Force the interactive approval prompt even if `--non-interactive` is set globally.

### `--non-interactive`

Block immediately if human approval would be required. Returns exit code 5.

```sh
arbitraitor run https://example.com/install.sh --non-interactive
```

### `--policy <PATH>`

Path to a pre-issued approval capability JSON file. Used in CI and automation instead of interactive approval.

```sh
arbitraitor run https://example.com/install.sh \
  --policy ./ci-capability.json
```

### `--working-dir <PATH>`

Set the working directory for execution. Defaults to a temporary directory.

### `--env <KEY=VALUE>`

Set environment variables for execution. Repeatable.

```sh
arbitraitor run install.sh --env HOME=/tmp/home --env USER=test
```

### `--network`

Allow network access during execution. By default, mediated execution denies all network access.

### `--fs-grant <PATH>`

Grant read access to the specified path during execution. Repeatable for multiple paths.

```sh
arbitraitor run install.sh --fs-grant /tmp --fs-grant /var/cache
```

## The full pipeline flow

```
inspect (retrieve once)
  -> record transport metadata
  -> buffer in CAS (immutable)
  -> identify content
  -> hash and verify provenance
  -> scan (detectors)
  -> evaluate policy
  -> construct execution plan

if plan requires approval:
  -> request human approval
  -> on approval: execute
  -> on denial: block

execute (exact buffered bytes only)
  -> construct clean environment
  -> apply sandbox controls
  -> run with mediator
  -> capture output

emit receipt
  -> policy snapshot
  -> assurance level
  -> findings
  -> capability matrix
  -> signatures
```

## Exit codes

| Code | Meaning |
|------|---------|
| 0 | Executed successfully, pass verdict |
| 1 | Executed with warnings |
| 2 | Incomplete (analysis could not finish) |
| 3 | Blocked by policy |
| 4 | Error (network, I/O, configuration) |
| 5 | Approval required in non-interactive mode |

## Examples

### Interactive approval

```sh
arbitraitor run https://example.com/install.sh
```

### Non-interactive (CI)

```sh
arbitraitor run https://example.com/install.sh \
  --non-interactive \
  --receipt ./receipt.json
```

### With pre-issued capability

```sh
# Issue capability first
arbitraitor approve receipt.json --output capability.json

# Later, in CI
arbitraitor run https://example.com/install.sh \
  --policy ./capability.json \
  --receipt ./receipt.json
```

### Script with limited access

```sh
arbitraitor run install.sh \
  --network \
  --fs-grant /tmp \
  --output /tmp/install.log
```

### Native binary (requires gate)

```sh
arbitraitor run ./bin/mytool --native
```
