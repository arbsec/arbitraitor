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
| `arbitraitor wrappers` | Install curl/wget shims + render shell-integration snippet |
| `arbitraitor env` | Hidden alias of `wrappers init` (shell env setup) |
| `arbitraitor store` | Manage CAS artifacts (list, inspect, gc) |
| `arbitraitor policy` | Validate a policy TOML file |
| `arbitraitor doctor` | Run system health diagnostics |
| `arbitraitor rules` | Manage YARA-X rule packs (list, validate) |
| `arbitraitor update` | Verify signed update manifests |
| `arbitraitor plugin` | Manage plugin registry (list, info, discover, remove) |
| `arbitraitor hook` | Deprecated bash DEBUG trap (prefer `wrappers init --install`) |
| `arbitraitor shim` | Manage package manager compatibility shims |
| `arbitraitor graph` | Render payload containment tree for archives |
| `arbitraitor approve` | Approve execution from a receipt file |
| `arbitraitor execute` | Execute an artifact from CAS using an approval file |
| `arbitraitor report` | Report user feedback on findings (e.g. false positive, spec §21.7) |
| `arbitraitor allow` | Record a scoped allow exception for an artifact digest (spec §21.7) |
| `arbitraitor pm` | Run a package manager through advisory scan (npm) |
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

Arbitraitor uses the stable exit codes defined in spec §29. Each code
encodes a distinct policy decision or operational condition so CI
pipelines, shell scripts, and process supervisors can react precisely.
Machine consumers should prefer `--json` or `--sarif` output for full
evidence; exit codes are a coarse-grained summary.

| Code | Meaning |
|------|---------|
| 0 | Pass — artifact passed all required checks and the requested release completed |
| 1 | General operational error (no more specific code applies) |
| 2 | Invalid arguments or configuration (semantic invalidity after parsing) |
| 10 | Warning verdict, no release requested |
| 20 | Interactive approval declined by the user |
| 21 | Prompt required in non-interactive mode |
| 30 | Blocked by policy (generic) |
| 31 | Confirmed malicious indicator (signed feed or `Confidence::Confirmed` finding) |
| 32 | Integrity or signature failure (digest mismatch, bad signature, missing trust root) |
| 33 | Required detector unavailable or stale |
| 34 | Analysis incomplete due to resource limit (time, memory, depth, byte budget) |
| 40 | Network retrieval failure |
| 41 | Redirect or transport policy violation (cross-origin, HTTPS→HTTP, SSRF) |
| 42 | Content type or size policy violation |
| 50 | Execution failed after approval (non-zero child exit, signal, sandbox violation) |
| 60 | Internal integrity invariant failure (e.g. running as root per ADR-0009) |

These numeric values are stable for the lifetime of the project. New codes
may be added (with a corresponding spec change); existing codes are not
renumbered.

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
arbitraitor wrappers <subcommand> [flags]
```

Installs `curl` and `wget` shims that route downloads through Arbitraitor,
and renders the shell-integration snippet that puts the shim directory on
`PATH`. See [wrappers](./cli/wrappers.md) for the full reference.

### Subcommands

#### `install`

Install curl and/or wget shims (default: both) to the shim directory
(default: `~/.arbitraitor/shims`):

```sh
arbitraitor wrappers install
arbitraitor wrappers install curl        # install only the curl shim
```

Flags inherited by all wrappers subcommands:

| Flag | Default | Description |
|------|---------|-------------|
| `--shim-dir <PATH>` | `~/.arbitraitor/shims` | Override the shim installation directory |
| `--use-scripts` | `false` | Install shell scripts instead of symlinks |

#### `uninstall`

Remove installed shims (default: all):

```sh
arbitraitor wrappers uninstall
```

#### `status`

Show installed shims and their state:

```sh
arbitraitor wrappers status
```

States: `installed (script)`, `installed (symlink)`, `not installed`,
`foreign file`.

#### `init`

Render or install the shell-integration snippet that puts the shim
directory on `PATH`. This is the primary surface for wiring Arbitraitor
into an interactive shell.

```sh
# Print mode (default) — emit snippet to stdout
arbitraitor wrappers init
eval "$(arbitraitor wrappers init)"

# Auto-install mode — write a marked block to the detected shell's rcfile
arbitraitor wrappers init --install

# Detect which shell you're running and which rcfile is targeted
arbitraitor wrappers init --detect-shell

# Remove the PATH block from your rcfile
arbitraitor wrappers init --uninstall

# Specify a shell explicitly (default: auto-detected from $SHELL)
arbitraitor wrappers init zsh
arbitraitor wrappers init fish --install
```

Flags:

| Flag | Description |
|------|-------------|
| `[shell]` (positional) | Target shell. Auto-detected from `$SHELL` if omitted. |
| `--install` | Write the snippet to the rcfile (instead of stdout). |
| `--uninstall` | Remove a previously installed block from the rcfile. |
| `--detect-shell` | Print detected shell and target rcfile, then exit. |
| `--dry-run` | Show what would change without writing. Requires `--install`. |
| `--no-backup` | Skip `<rcfile>.arbitraitor.bak` creation. Requires `--install`. |

Supported shells: `bash`, `zsh`, `sh`, `fish`, `nu`, `xonsh`,
`powershell`, `elvish`, `posix`, `tcsh`, `oil` (also `osh` / `ysh`).

The rcfile block is wrapped in marker lines
(`# >>> arbitraitor wrappers >>>` / `# <<< arbitraitor wrappers <<<`)
so re-runs replace in place rather than appending. The corresponding
in-shell snippet is idempotent: re-`eval`ing does not duplicate `PATH`
entries.

#### `init-script`

Print the shell-init script for the default shell. Equivalent to
`wrappers init` with no flags:

```sh
arbitraitor wrappers init-script
# Add to .bashrc or .zshrc:
# eval "$(arbitraitor wrappers init-script)"
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

> **Deprecated.** The bash DEBUG trap runs on every command, has
> measurable overhead in interactive sessions, and only supports bash.
> Replace with `arbitraitor wrappers install && arbitraitor wrappers init --install`,
> which works across every supported shell and wires the shim directory
> onto `PATH` via a marked rcfile block. See [wrappers](./cli/wrappers.md).

### Subcommands

#### `init [--binary <PATH>]`

Print a bash hook that intercepts `curl|sh` patterns and suggests
`arbitraitor run`. Emits a deprecation warning to stderr on use.

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

List installed shims and supported tools:

```sh
arbitraitor shim list
# Supported shims: npm
```

#### `install <TOOL>`

Install a compatibility shim for a supported package manager. The shim invokes `arbitraitor pm run --tool <TOOL>` so every invocation passes through advisory scan:

```sh
arbitraitor shim install npm
# Writes ~/.arbitraitor/shims/npm
```

Supported tools: `npm`.

#### `uninstall <TOOL>`

Remove a compatibility shim:

```sh
arbitraitor shim uninstall npm
```

## PM command

```sh
arbitraitor pm run --tool <TOOL> [-- <ARGS>...]
```

Runs a package manager tool through Arbitraitor's advisory scan (spec §39.14 Phase 1), then executes it if the verdict allows. Currently supports `npm`.

### Advisory scan flow (npm)

1. Resolves the dependency tree via `package-lock.json` (generates it with `npm install --package-lock-only --ignore-scripts` if absent).
2. Parses lifecycle scripts (`preinstall`, `install`, `postinstall`, `prepare`, `prepublish`) from the root `package.json`.
3. Flags dependencies with install lifecycle scripts (`hasInstallScript` in the lockfile).
4. Flags dependencies resolved from non-registry sources (git URLs, file: links).
5. Derives a verdict (Pass / Warn / Block) and emits a `PackageManagerReceipt`.
6. If the verdict allows execution (Pass or Warn), runs `npm install --ignore-scripts` (scripts denied per the npm adapter's `DeniedByDefault` lifecycle policy).

### Flags

| Flag | Description |
|------|-------------|
| `--tool <TOOL>` | Package manager tool to wrap (currently: `npm`) |

### Exit codes

The `pm` command uses the standard verdict-to-exit-code mapping (0=Pass, 10=Warn, 30=Block). An error during scan or execution exits with code 33.

### Examples

```sh
# Advisory scan + gated install (default)
arbitraitor pm run --tool npm

# Pass extra arguments to npm
arbitraitor pm run --tool npm -- install --save-dev lodash
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

## Report command

```sh
arbitraitor report <SUBCOMMAND>
```

Records user feedback on findings (spec §21.7). All reported feedback is
scoped and auditable.

### Subcommands

| Subcommand | Description |
|------------|-------------|
| `false-positive <FINDING_ID>` | Mark a finding as a false positive so future inspections do not re-surface it |

### Examples

```sh
arbitraitor report false-positive SHELL-EVAL-001
```

## Allow command

```sh
arbitraitor allow sha256:<HEX> --scope <SCOPE> --expires <DURATION> --reason <TEXT>
```

Records a scoped, time-bounded allow exception for an artifact digest
(spec §21.7). Every exception requires a scope, an expiry, and a written
justification for audit.

### Flags

| Flag | Description |
|------|-------------|
| `sha256:<HEX>` (positional) | SHA-256 of the artifact in `sha256:<64-hex>` form |
| `--scope <SCOPE>` | Exception scope: `user`, `project`, or `org` (required) |
| `--expires <DURATION>` | Duration until expiry: `<N>s`, `<N>m`, `<N>h`, or `<N>d` (required) |
| `--reason <TEXT>` | Free-form justification recorded for auditing (required) |

### Examples

```sh
# Project-wide allow for one week
arbitraitor allow sha256:abababababababababababababababababababababababababababababababab \
  --scope project --expires 7d --reason "approved by sec review #482"
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
