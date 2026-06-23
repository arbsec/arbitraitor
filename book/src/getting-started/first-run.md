# First Run with Approval

The `run` command executes the full pipeline: fetch → inspect → approve → execute.

```sh
arbitraitor run https://example.com/install.sh
```

When the verdict requires approval, you'll see:

```text
Fetching https://example.com/install.sh...
  → sha256:a1b2c3d4e5f6...
  → 4.2 KB, application/x-shellscript

Detecting threats...
  Shell analysis: 2 suspicious patterns

Verdict: PROMPT (2 suspicious findings)

Plan: execute via /bin/bash with network isolated
Type this code to approve: a1b2c3d4e5f6
> █
```

Type the plan digest prefix to approve. The script then runs in a sandboxed bash interpreter with network isolation, resource limits, and output capping.

## Exit codes

| Code | Meaning                                |
|------|----------------------------------------|
| 0    | Success (script executed and exited 0) |
| 1    | Script execution failed (non-zero exit)|
| 2    | Approval denied or required but skipped|
| 3    | Fetch error                            |
| 4    | Detection error (scanner failure)      |
| 5    | Internal error                         |

## Non-interactive mode

In CI or automated contexts where no human can approve:

```sh
arbitraitor run https://example.com/install.sh --non-interactive
```

If the verdict is Prompt or Block, the command exits with code 2 immediately — it **never** silently approves.

## Native binary execution

To execute a native binary (ELF/Mach-O) instead of a script, use the `--native` gate:

```sh
arbitraitor run https://example.com/binary --native
```

This constructs a `NativeExecutionGate` that opts into native execution. Without `--native`, native artifacts are always rejected.
