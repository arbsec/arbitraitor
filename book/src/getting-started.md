# Getting Started

This guide walks you through installing Arbitraitor and running your first inspection and execution.

## Prerequisites

- **Rust 1.96+** with the Rust 2024 edition
- **mise** for toolchain management (see `.mise.toml` in the repository)

Check your Rust version:

```sh
rustc --version
cargo --version
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

## First inspection

The `inspect` command retrieves an artifact, runs it through the detection pipeline, and reports findings without executing anything:

```sh
arbitraitor inspect https://example.com/install.sh
```

Sample output:

```
Artifact:    sha256:a1b2c3d4e5f6...
Source:      https://example.com/install.sh
Type:        application/x-shellscript
Size:        4.2 KB

Findings:
  - network:curl (high)
  - fs:write:/tmp (medium)
  - exec:subprocess (high)

Verdict: WARN (inspect)
  Elevated findings require human review before execution.
```

The exit code reflects the verdict:

| Verdict | Exit code |
|---------|-----------|
| Pass | 0 |
| Warn | 1 |
| Incomplete | 2 |
| Block | 3 |

## First run with approval

The `run` command executes the full pipeline including human approval for elevated findings:

```sh
arbitraitor run https://example.com/install.sh
```

What happens:

1. Arbitraitor retrieves and buffers the artifact
2. The detection pipeline runs
3. If findings require approval, you are prompted:

```
Artifact: sha256:a1b2c3d4e5f6...
Plan:     sha256:91ab...
Type the first 12 characters of the plan digest to approve:
```

4. On approval, the exact buffered artifact is executed in a mediated context
5. A signed receipt is emitted

## Non-interactive environments

In CI or automated contexts, use `--non-interactive`:

```sh
# Block if approval would be required
arbitraitor run https://example.com/install.sh --non-interactive

# Use a pre-approved policy capability
arbitraitor run https://example.com/install.sh \
  --policy-capability ./approved-capability.json
```

## Using wrappers

Arbitraitor can install shell shims that route `curl` and `wget` through the inspection pipeline automatically:

```sh
# Install wrappers
arbitraitor wrappers install

# Check status
arbitraitor wrappers status

# See what's happening
WRAPPERS_VERBOSE=1 curl -fsSL https://example.com/install.sh
```

Wrappers intercept downloads and run them through Arbitraitor before passing bytes downstream.

## Configuration

Arbitraitor reads configuration from `~/.arbitraitor/config.toml`. A minimal config:

```toml
[fetch]
timeout = 30
max_redirects = 10

[policy]
default_action = "prompt"
non_interactive_prompt_action = "block"
```

See the [Configuration](./configuration.md) reference for all options.

## Next steps

- [CLI Reference](./cli-reference.md) — all commands and flags
- [Architecture](./architecture/overview.md) — understand what happens under the hood
- [Plugins](./plugins/overview.md) — extend Arbitraitor with custom detectors
