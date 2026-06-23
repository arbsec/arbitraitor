# CLI Reference

The `arbitraitor` CLI provides commands for inspection, execution, wrapper management, and status checking.

## Commands

| Command | Description |
|---------|-------------|
| `arbitraitor inspect` | Retrieve and analyze an artifact without executing it |
| `arbitraitor run` | Execute the full pipeline with approval flow |
| `arbitraitor wrappers` | Manage curl/wget wrapper shims |
| `arbitraitor status` | Show system health and configured detectors |
| `arbitraitor approve` | Issue an approval capability for a previously inspected artifact |
| `arbitraitor execute` | Execute using a pre-issued approval capability |
| `arbitraitor receipt` | Verify and inspect a receipt file |

## Global flags

These flags apply to all commands:

| Flag | Description |
|------|-------------|
| `--config <PATH>` | Path to TOML configuration file |
| `--policy <PATH>` | Path to policy TOML file |
| `--output <FORMAT>` | Output format: `text`, `json`, `yaml` (default: `text`) |
| `--log-level <LEVEL>` | Log level: `error`, `warn`, `info`, `debug`, `trace` |
| `--no-color` | Disable colored output |
| `--quiet` | Suppress non-essential output |

## Exit codes

| Code | Meaning |
|------|---------|
| 0 | Pass — artifact passed all policy checks |
| 1 | Warn — artifact has findings, human review recommended |
| 2 | Incomplete — analysis could not complete, blocking by default |
| 3 | Block — artifact blocked by policy |
| 4 | Error — a fatal error occurred (network, I/O, configuration) |
| 5 | Approval required — human approval needed, non-interactive mode |

## Inspect command

```sh
arbitraitor inspect <URL or file path> [flags]
```

### Flags

| Flag | Description |
|------|-------------|
| `--receipt <PATH>` | Write a JSON receipt to this path |
| `--detectors <NAMES>` | Comma-separated list of detectors to run |
| `--no-detectors` | Skip all detectors, only retrieve and identify |
| `--content-type <TYPE>` | Override content type detection |
| `--timeout <SECONDS>` | Maximum time for retrieval and analysis |
| `--native` | Treat as a native binary, not a script |

### Examples

```sh
# Basic inspection
arbitraitor inspect https://example.com/install.sh

# With receipt
arbitraitor inspect https://example.com/install.sh --receipt receipt.json

# Specific detectors only
arbitraitor inspect script.sh --detectors shell,archive

# Inspect a local file
arbitraitor inspect ./downloads/script.sh
```

## Run command

```sh
arbitraitor run <URL or file path> [flags]
```

### Flags

| Flag | Description |
|------|-------------|
| `--receipt <PATH>` | Write receipt to path |
| `--output <PATH>` | Write script stdout/stderr to path |
| `--native` | Allow native binary execution (requires `--native` gate in policy) |
| `--interactive` | Force interactive approval prompt |
| `--non-interactive` | Block if approval required |
| `--policy-capability <PATH>` | Path to pre-issued approval capability |
| `--working-dir <PATH>` | Set the working directory for execution |
| `--env <KEY=VALUE>` | Set environment variables (repeatable) |
| `--network` | Allow network access during execution |
| `--fs-grant <PATH>` | Grant read access to a path (repeatable) |

### Examples

```sh
# Interactive approval
arbitraitor run https://example.com/install.sh

# Non-interactive (block if approval needed)
arbitraitor run https://example.com/install.sh --non-interactive

# With pre-approved capability
arbitraitor run https://example.com/install.sh \
  --policy-capability ./approved-capability.json

# Script with network and filesystem access
arbitraitor run install.sh --network --fs-grant /tmp
```

## Wrappers command

```sh
arbitraitor wrappers <subcommand>
```

### Subcommands

#### `install`

Install curl and wget shims to `~/.local/bin`:

```sh
arbitraitor wrappers install
```

The wrappers route downloads through Arbitraitor automatically. Original binaries are preserved and called with `exec`.

#### `status`

Show installed wrappers and what they are routing:

```sh
arbitraitor wrappers status
```

#### `init-script`

Print the shell initialization snippet to source:

```sh
arbitraitor wrappers init-script
# Add to .bashrc or .zshrc:
# eval "$(arbitraitor wrappers init-script)"
```

#### `uninstall`

Remove installed wrappers:

```sh
arbitraitor wrappers uninstall
```

## Status command

```sh
arbitraitor status [flags]
```

### Flags

| Flag | Description |
|------|-------------|
| `--json` | Output as JSON |
| `--detectors` | Show detector status |
| `--feeds` | Show intelligence feed status |
| `--store` | Show store health and disk usage |

### What it checks

- **Store**: CAS health, corruption check, garbage collection status
- **Detectors**: Loaded plugins and their current status
- **Feeds**: Last sync time and freshness for each configured feed
- **Config**: Validity of configuration files
