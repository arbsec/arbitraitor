# CLI Reference

The `arbitraitor` CLI provides commands for inspection, execution, wrapper management, storage, policy validation, and system health.

## Commands

| Command | Description |
|---------|-------------|
| `arbitraitor inspect` | Retrieve and analyze an artifact without executing it |
| `arbitraitor run` | Execute the full pipeline with approval flow |
| `arbitraitor scan` | Scan a local file or stdin without retrieval |
| `arbitraitor explain` | Explain a verdict from a receipt file |
| `arbitraitor daemon` | Unix socket daemon with background queue (start/stop/status) |
| `arbitraitor unpack` | Unpack an archive to a directory for inspection |
| `arbitraitor intel` | Manage local threat-intelligence feeds (update) |
| `arbitraitor status` | Show system health and configured detectors |
| `arbitraitor wrappers` | Manage curl/wget wrapper shims |
| `arbitraitor store` | Manage CAS artifacts (list, inspect, gc) |
| `arbitraitor policy` | Validate a policy TOML file |
| `arbitraitor doctor` | Run system health diagnostics |
| `arbitraitor rules` | Manage YARA-X rule packs (list, validate) |
| `arbitraitor update` | Verify signed update manifests |
| `arbitraitor plugin` | Manage plugin registry (list, info, discover, remove) |
| `arbitraitor hook` | Print shell integration hooks |
| `arbitraitor shim` | Manage package manager compatibility shims |
| `arbitraitor graph` | Render payload containment tree for archives |
| `arbitraitor approve` | Approve execution from a receipt file |
| `arbitraitor execute` | Execute an artifact from CAS using an approval file |
| `arbitraitor mcp` | Start MCP JSON-RPC 2.0 server over stdio |
| `arbitraitor version` | Print version, license, and repository |

> **Note:** `arbitraitor fetch` is a hidden command used internally by wrappers. It retrieves an artifact to CAS without analysis.

## Global flags

These flags apply to all commands:

| Flag | Description |
|------|-------------|
| `--config <PATH>` | Path to TOML configuration file |
| `--verbose` | Enable verbose output (repeat for more detail: `-v`, `-vv`) |

> **Note:** Per-command output format flags (e.g., `--format`, `--json`) are available on specific subcommands, not as global flags.

## Exit codes

| Code | Meaning |
|------|---------|
| 0 | Pass — artifact passed all policy checks |
| 10 | Warn — artifact has findings, human review recommended |
| 21 | Prompt — human approval needed (non-interactive mode blocks by default) |
| 30 | Block — artifact blocked by policy |
| 33 | Error — a fatal error occurred (network, I/O, configuration) |
| 34 | Incomplete — analysis could not complete, blocking by default |

## Inspect command

```sh
arbitraitor inspect <URL or file path> [flags]
```

### Flags

| Flag | Description |
|------|-------------|
| `--receipt <PATH>` | Write a JSON receipt to this path |
| `--cas-dir <DIR>` | Override the CAS directory |
| `--sha256 <HEX>` | Expected SHA-256 digest for provenance verification |
| `--rules <DIR>` | Path to a directory of YARA-X rule packs |
| `--minisign-sig <PATH>` | minisign signature file (repeatable) |
| `--minisign-key <KEY>` | minisign public key (repeatable) |
| `--cosign-bundle <PATH>` | cosign bundle file (repeatable) |
| `--cosign-identity <IDENTITY>` | cosign identity (repeatable) |
| `--cosign-issuer <ISSUER>` | cosign certificate issuer (repeatable) |
| `--explain` | Show an explainability report for detected findings |
| `--format <FORMAT>` | Output format for explainability: `text`, `shellcheck` (implies `--explain`) |

```sh
# Basic inspection
arbitraitor inspect https://example.com/install.sh

# With receipt
arbitraitor inspect https://example.com/install.sh --receipt receipt.json

# With provenance verification
arbitraitor inspect https://example.com/install.sh --sha256 abc123... --minisign-key pubkey

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
| `--native` | Pre-approve native binary execution without interactive prompt |
| `--non-interactive` | Skip interactive approval prompts (block if approval needed) |
| `--network` | Allow network access during execution (default: isolated) |
| `--policy <PATH>` | Policy file path |

### Examples

```sh
# Interactive approval
arbitraitor run https://example.com/install.sh

# Non-interactive (block if approval needed)
arbitraitor run https://example.com/install.sh --non-interactive

# With native binary and network access
arbitraitor run https://example.com/binary --native --network

# With policy file
arbitraitor run https://example.com/install.sh --policy ./my-policy.toml
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

## Scan command

```sh
arbitraitor scan [FILE] [flags]
arbitraitor scan --stdin [flags]
```

Scans a local file or stdin without network retrieval. Runs detectors and reports findings.

### Flags

| Flag | Description |
|------|-------------|
| `--stdin` | Read input from stdin instead of a file path |
| `--rules <DIR>` | Path to a directory of YARA-X rule packs |
| `--explain` | Print an explainability summary after findings |
| `--format <FORMAT>` | Output format for explainability: `text`, `shellcheck` (implies `--explain`) |

### Examples

```sh
# Scan a local script
arbitraitor scan ./suspicious.sh

# Scan piped input
curl -s https://example.com/script.sh | arbitraitor scan --stdin

# Scan with explainability output
arbitraitor scan ./script.sh --explain
```

## Explain command

```sh
arbitraitor explain <RECEIPT_PATH>
```

Reads a receipt file from a prior `inspect` or `run` and prints a human-readable summary of the verdict, findings, and retrieval metadata.

### Examples

```sh
arbitraitor inspect https://example.com/install.sh --receipt receipt.json
arbitraitor explain receipt.json
```

## Store command

```sh
arbitraitor store <subcommand> [flags]
```

Manages artifacts in the content-addressed store (CAS).

### Subcommands

#### `list`

List all stored artifacts:

```sh
arbitraitor store list
```

#### `inspect <SHA256>`

Show metadata for a specific artifact:

```sh
arbitraitor store inspect <sha256>
```

#### `gc`

Run garbage collection on the store:

```sh
arbitraitor store gc
arbitraitor store gc --max-age-days 30
```

### Flags

| Flag | Description |
|------|-------------|
| `--cas-dir <DIR>` | Override the CAS directory |

## Policy command

```sh
arbitraitor policy <POLICY_PATH>
```

Validates a TOML policy file and prints version, rule count, and digest.

### Examples

```sh
arbitraitor policy my-policy.toml
```

## Doctor command

```sh
arbitraitor doctor [flags]
```

Runs system health diagnostics and outputs a JSON report covering store health, detector status, and rule pack versions.

### Flags

| Flag | Description |
|------|-------------|
| `--cas-dir <DIR>` | Override the CAS directory to check |
| `--rules <DIR>` | Path to rule packs directory |

## Rules command

```sh
arbitraitor rules <subcommand> [flags]
```

Manages YARA-X rule packs.

### Subcommands

#### `list`

List all loaded rule packs with source, namespace, version, auth status, and digest:

```sh
arbitraitor rules list
```

#### `validate <FILE>`

Validate that a YARA-X rule file compiles:

```sh
arbitraitor rules validate /path/to/rules.yar
```

### Flags

| Flag | Description |
|------|-------------|
| `--rules-dir <DIR>` | Directory containing rule packs |

## Update command

```sh
arbitraitor update <subcommand>
```

Verifies signed update manifests for rule packs, intel feeds, trust roots, and plugin registries.

### Subcommands

#### `verify <MANIFEST> --key <KEY> [--signature <SIG>]`

Verify a signed minisign update manifest:

```sh
arbitraitor update verify manifest.json --key pubkey.pub
# Signature defaults to manifest.minisig (extension replaced)
arbitraitor update verify manifest.json --key pubkey.pub --signature custom.minisig
```

## Plugin command

```sh
arbitraitor plugin <subcommand>
```

Manages the plugin registry — discovery, listing, inspection, and removal.

### Subcommands

#### `list`

List all registered plugins:

```sh
arbitraitor plugin list
```

#### `info <ID>`

Show manifest details for a specific plugin:

```sh
arbitraitor plugin info <id>
```

#### `discover`

Run plugin discovery from default directories:

```sh
arbitraitor plugin discover
```

#### `remove <ID>`

Unregister a plugin:

```sh
arbitraitor plugin remove <id>
```

## Hook command

```sh
arbitraitor hook <subcommand>
```

Shell integration hooks.

### Subcommands

#### `init [--binary <PATH>]`

Print a bash hook that intercepts `curl|sh` patterns and suggests `arbitraitor run`:

```sh
arbitraitor hook init
# Custom binary path:
arbitraitor hook init --binary /usr/local/bin/arbitraitor
```

## Shim command

```sh
arbitraitor shim <subcommand>
```

Manages package manager compatibility shims that route tool invocations through Arbitraitor.

### Subcommands

#### `list`

List installed shims. Package-manager shims are not yet implemented — use `arbitraitor wrappers install` for curl/wget support:

```sh
arbitraitor shim list
```

#### `install <TOOL>`

Package-manager shims are not yet implemented. Use `arbitraitor wrappers install` for curl/wget support:

```sh
arbitraitor shim install npm
# Error: package-manager shims are not yet implemented
```

#### `uninstall <TOOL>`

Remove a compatibility shim (not yet implemented for package managers):

```sh
arbitraitor shim uninstall npm
```

## Graph command

```sh
arbitraitor graph <FILE>
```

Renders a payload containment tree for archives, showing nested artifact types and SHA-256 digests.

### Examples

```sh
arbitraitor graph ./archive.tar.gz
```

## Approve command

```sh
arbitraitor approve <RECEIPT>
```

Decoupled approval flow: reads a receipt from a prior inspection, displays findings, prompts for approval, and writes a time-limited approval file (5-minute expiry).

### Examples

```sh
arbitraitor inspect https://example.com/install.sh --receipt receipt.json
arbitraitor approve receipt.json
# Writes receipt.approval.json
```

## Execute command

```sh
arbitraitor execute <APPROVAL> [flags]
```

Executes an artifact from CAS using a previously generated approval file.

### Flags

| Flag | Description |
|------|-------------|
| `--network` | Allow network access during execution |

### Examples

```sh
arbitraitor execute receipt.approval.json
# With network access:
arbitraitor execute receipt.approval.json --network
```

## MCP command

```sh
arbitraitor mcp
```

Starts a Model Context Protocol JSON-RPC 2.0 server over stdio for AI agent integration. Provides tools for inspecting, scanning, explaining, and approving artifact execution.

## Version command

```sh
arbitraitor version
```

Prints version, license, and repository information.
