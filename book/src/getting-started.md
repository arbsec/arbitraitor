# Getting Started

This guide walks you through installing Arbitraitor and running your first inspection and execution.

## Prerequisites

- **Rust 1.96+** (Rust 2024 edition)
- **mise** for toolchain management — [install instructions](https://mise.jdx.dev/getting-started.html)
- **pkg-config** and **OpenSSL development headers** (for the HTTP stack)

Install mise tools after cloning:

```sh
mise install
```

This installs the pinned Rust toolchain, lefthook (git hooks), cocogitto (conventional commits), and rumdl (markdown linter) from `.mise.toml`.

Verify your Rust version:

```sh
rustc --version   # should print 1.96.0
```

## Installation

Clone the repository and install the CLI:

```sh
git clone https://github.com/arbsec/arbitraitor.git
cd arbitraitor
cargo install --path crates/arbitraitor-cli
```

Verify the installation:

```sh
arbitraitor --version
arbitraitor --help
```

You should see the list of subcommands: `inspect`, `run`, `daemon`, `unpack`, `intel`, `status`, `wrappers`.

## First inspection

The `inspect` command retrieves an artifact, runs it through the detection pipeline, and reports findings **without executing anything**:

```sh
arbitraitor inspect https://example.com/install.sh
```

The output shows the artifact identity, content type, detection findings, and a verdict.

### Understanding the verdict

The policy engine produces one of five verdicts:

| Verdict  | Meaning                                                        |
|----------|----------------------------------------------------------------|
| Pass     | No findings or only informational findings. Safe to proceed.   |
| Warn     | Suspicious patterns detected. Proceed with caution.            |
| Prompt   | Findings require human approval before execution.              |
| Block    | Confirmed malicious content. Execution refused.                |
| Incomplete | A detector failed. Treat as untrusted until re-scanned.      |

### Provenance verification

If the publisher provides a signature, you can verify it during inspection:

```sh
arbitraitor inspect https://example.com/install.sh \
  --minisign-key RWQf6LRCGA9i53mlYecO4IzT51TGPpvWucNSCh1CBM0QUVlq39r+nX7p
```

Arbitraitor fetches the artifact once, verifies the signature against the public key, and only proceeds to detection if the signature is valid.

### Explainability

Add `--explain` to get a human-readable explanation of each finding:

```sh
arbitraitor inspect https://example.com/install.sh --explain
```

Use `--explain --format shellcheck` for output compatible with tools that consume ShellCheck JSON.

## First run with approval

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

### Exit codes

| Code | Meaning                                  |
|------|------------------------------------------|
| 0    | Success (script executed and exited 0)   |
| 1    | Script execution failed (non-zero exit)  |
| 2    | Approval denied or required but skipped  |
| 3    | Fetch error                              |
| 4    | Detection error (scanner failure)        |
| 5    | Internal error                           |

### Non-interactive mode

In CI or automated contexts where no human can approve:

```sh
arbitraitor run https://example.com/install.sh --non-interactive
```

If the verdict is Prompt or Block, the command exits with code 2 immediately — it **never** silently approves.

### Native binary execution

To execute a native binary (ELF/Mach-O) instead of a script, use the `--native` gate:

```sh
arbitraitor run https://example.com/binary --native
```

This constructs a `NativeExecutionGate` that opts into native execution. Without `--native`, native artifacts are always rejected.

## Wrappers

Arbitraitor can install shell shims that intercept `curl` and `wget` commands, routing them through the inspection pipeline:

```sh
# Install shims for all supported wrappers
arbitraitor wrappers install

# Check which shims are installed
arbitraitor wrappers status

# Print a shell init snippet for your dotfiles
arbitraitor wrappers init-script >> ~/.bashrc
```

After installation, any `curl https://example.com/file | sh` is transparently intercepted and inspected before the bytes reach the shell.

## Health checks

Check the status of Arbitraitor's subsystems:

```sh
# Human-readable status
arbitraitor status

# JSON output for monitoring
arbitraitor status --json
```

This reports CAS store health, detector availability, and version information.

## Configuration

Arbitraitor reads configuration from `~/.arbitraitor/config.toml`:

```toml
[fetch]
timeout = 30
max_redirects = 10

[policy]
default_action = "prompt"
non_interactive_prompt_action = "block"

[detectors]
shell_analysis = true
powershell_analysis = true
max_archive_depth = 10
```

Secrets can be referenced from environment variables or files without hardcoding:

```toml
[intel]
urlhaus_key = "secret://env/URLHAUS_API_KEY"
```

See the [Configuration](./configuration.md) reference for all options.

## Next steps

- [CLI Reference](./cli-reference.md) — all commands and flags
- [Architecture](./architecture/overview.md) — what happens under the hood
- [Security Model](./architecture/security.md) — invariants, threat model, sandbox
- [Plugins](./plugins/overview.md) — extend Arbitraitor with custom detectors
