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

Arbitraitor uses its own exit codes to report the verdict — these are
**not** the exit code of the executed script.

| Code | Meaning                                                       |
|------|---------------------------------------------------------------|
| 0    | Pass — artifact passed all policy checks                      |
| 1    | Warn — artifact has findings, human review recommended        |
| 2    | Incomplete — analysis could not complete, blocking by default |
| 3    | Block — artifact blocked by policy                            |
| 4    | Error — fatal error (network, I/O, configuration)             |
| 5    | Approval required in non-interactive mode                     |

## Non-interactive mode

In CI or automated contexts where no human can approve:

```sh
arbitraitor run https://example.com/install.sh --non-interactive
```

If the verdict is Prompt or Block, the command exits with code 5 immediately — it **never** silently approves.

## Native binary execution

Arbitraitor auto-detects whether an artifact is a native binary (ELF, Mach-O, PE) or a script from the downloaded bytes. When a native binary is detected:

- **Interactive mode**: you'll be prompted to confirm native execution before proceeding.
- **Non-interactive mode**: native execution is blocked unless you pass `--native` to pre-approve it.

```sh
# Auto-detected: native binary → prompts for confirmation
arbitraitor run https://example.com/binary

# Pre-approve native execution (skips the prompt)
arbitraitor run https://example.com/binary --native
```
