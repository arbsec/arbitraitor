# CLI Reference

The `arbitraitor` CLI provides commands for inspection, execution, wrapper management, storage, policy validation, and system health.

## Commands

| Command | Description |
|---------|-------------|
| `arbitraitor inspect` | Retrieve and analyze an artifact without executing it |
| `arbitraitor fetch` | Fetch an artifact with provenance verification (spec §28.2) |
| `arbitraitor wrap` | Wrap an existing tool invocation through Arbitraitor (spec §28.1) |
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
| `arbitraitor plugin` | Manage plugin registry and local plugin lifecycle |
| `arbitraitor hook` | Deprecated bash DEBUG trap (prefer `wrappers init --install`) |
| `arbitraitor shim` | Manage npm/curl/wget/brew compatibility shims |
| `arbitraitor graph` | Render payload containment tree for archives |
| `arbitraitor approve` | Approve execution from a receipt file |
| `arbitraitor execute` | Execute an artifact from CAS using an approval file |
| `arbitraitor report` | Report user feedback on findings (e.g. false positive, spec §21.7) |
| `arbitraitor allow` | Record a scoped allow exception for an artifact digest (spec §21.7) |
| `arbitraitor pm` | Run a package manager through advisory scan (npm) |
| `arbitraitor mcp` | Start MCP JSON-RPC 2.0 server over stdio |
| `arbitraitor version` | Print version, license, and repository |

### `arbitraitor intel update`

Updates local threat-intelligence feed snapshots on demand.

| Flag | Description |
|------|-------------|
| `--urlhaus` | Ingest the URLhaus malicious-URL feed |
| `--urlhaus-url <URL>` | Override the URLhaus CSV or JSON endpoint |
| `--ossf-malicious-packages` | Ingest OpenSSF malicious-packages `MAL-` IDs from an OSV querybatch response |
| `--ossf-malicious-packages-url <URL>` | Override the OSV querybatch endpoint or use a signed mirror response |
| `--intel-store <PATH>` | Override the local intel store path |

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
| `--sign-receipt <METHOD>` | Sign the receipt with the specified method (spec §31.3): `minisign`, `cosign`, `enterprisekey`, `tpm` |

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

## Fetch command

```sh
arbitraitor fetch <URL> [flags]
```

Fetches an artifact from a URL with provenance verification, content-addressed
storage, and optional receipt emission. When invoked via a wrapper symlink
(`curl`/`wget`), the `--tool` flag is set automatically and passthrough
arguments are captured after `--`.

### Flags

| Flag | Description |
|------|-------------|
| `-o, --output <PATH>` | Write the fetched artifact to this path instead of stdout |
| `--sha256 <HEX>` | Expected SHA-256 digest for provenance verification |
| `--signature <PATH>` | minisign signature file (repeatable; requires key via config) |
| `--cosign-bundle <PATH>` | cosign bundle file (repeatable) |
| `--identity <IDENTITY>` | cosign identity (repeatable) |
| `--issuer <ISSUER>` | cosign certificate issuer (repeatable) |
| `--expected-type <TYPE>` | Expected artifact type (e.g., `shell`, `elf`, `archive`) |
| `--expected-content-type <TYPE>` | Expected content type (e.g., `application/x-sh`) |
| `--max-bytes <BYTES>` | Maximum bytes to fetch |
| `--header <HEADER>` | HTTP header to send (repeatable, format: `Key: Value`) |
| `--policy <PATH>` | Policy file path (CLI override; requires `--audit-override`) |
| `--audit-override` | Record and allow the `--policy` CLI override in the receipt audit trail |
| `--recursive` | Recursively fetch and inspect referenced payloads |
| `--sandbox` | Sandbox execution after fetch |
| `--non-interactive` | Skip interactive approval prompts |
| `--json` | Output results as JSON |
| `--sarif` | Output results as SARIF |
| `--receipt <PATH>` | Write a JSON receipt to this path |
| `--no-cache` | Skip cache and force a fresh fetch |

### Examples

```sh
# Basic fetch
arbitraitor fetch https://example.com/install.sh

# Fetch with output file and SHA-256 pinning
arbitraitor fetch --output install.sh --sha256 abc123... https://example.com/install.sh

# Fetch with cosign provenance verification
arbitraitor fetch \
  --cosign-bundle artifact.bundle \
  --identity builder@example.test \
  --issuer https://issuer.example.test \
  https://example.com/artifact

# Fetch with receipt output
arbitraitor fetch --receipt receipt.json https://example.com/install.sh

# Non-interactive JSON output
arbitraitor fetch --non-interactive --json https://example.com/install.sh
```

## Wrap command

```sh
arbitraitor wrap <TOOL> -- [tool arguments...]
```

Wraps an existing tool invocation as a first-class top-level command. The
wrapper parses the original tool and arguments, creates a normalized operation
plan, and submits useful artifacts to Arbitraitor core. The wrapper does not
decide the final verdict and does not release content directly.

`curl` and `wget` invocations delegate to the same guarded download pipeline
used by PATH shims. `bash` inspects a local script path when one is present;
other tools currently emit a warning and release nothing.

### Examples

```sh
arbitraitor wrap curl -- -fsSL https://example.com/install.sh
arbitraitor wrap wget -- -qO- https://example.com/install.sh
arbitraitor wrap bash -- ./approved-script.sh
arbitraitor wrap brew -- install example
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
| `--sign-receipt <METHOD>` | Sign the receipt with the specified method (spec §31.3): `minisign`, `cosign`, `enterprisekey`, `tpm` |

### Examples

```sh
# Interactive approval
arbitraitor run https://example.com/install.sh

# Non-interactive (block if approval needed)
arbitraitor run https://example.com/install.sh --non-interactive

# With native binary and network access
arbitraitor run https://example.com/binary --native --network

# With an audited CLI policy override
arbitraitor run https://example.com/install.sh --policy ./my-policy.toml --audit-override
```

### Supported artifact types

Only shell scripts and native executables are runnable by `arbitraitor run`
(see [ADR-0036](../../docs/adr/0036-run-pipeline-content-type-execution-gate.md)
for the rationale):

| `ArtifactType`                                  | Executable via       |
|-------------------------------------------------|----------------------|
| `ShellScript(Posix \| Bash \| Zsh)`             | `/bin/bash`          |
| `PeExecutable`, `ElfExecutable`, `MachOExecutable` | native binary     |

All other classified types — `HtmlDocument`, `JsonDocument`, `XmlDocument`,
`GenericText`, `GenericBinary`, archives (`ZipArchive`, `TarArchive`,
`*Compressed`), `PowerShellScript`, `PythonScript`, `JavaScript`, and
`Unknown` — fail closed with `blocked by policy` (exit code
`BlockedByPolicy`) before reaching the execution layer. Piping such bytes to
`/bin/bash` is incorrect (bash doesn't understand them) and unsafe (HTML,
JSON, and XML can incidentally contain bash-parseable `$(...)`,
redirections, and pipes).

When a script or native execution does fail, the user-visible error now
includes the captured child stderr so the actual root cause is visible
(e.g. `script input I/O failure during write-script-stdin (child exited 1;
stderr: "bash: !DOCTYPE: event not found")`), distinguishing "I fed bash
junk" from "kernel denied the user namespace" from "Landlock blocked the
interpreter path". See #612 for the bug report and Fix B details.

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

Hidden legacy command. Prints a generic POSIX shell-init snippet that
prepends `~/.arbitraitor/shims` to `PATH` (no auto-detection of shell,
no per-shell idempotency). Prefer `wrappers init`, which auto-detects
the target shell and emits a shell-specific, runtime-idempotent snippet.

```sh
arbitraitor wrappers init-script
# Add to .bashrc or .zshrc:
# eval "$(arbitraitor wrappers init-script)"
```

## Status command

```sh
arbitraitor status [flags]
```

`status` reports Arbitraitor component health, daemon-process identity
(PID, uptime, last operation), and the bounded recent-operations ring
buffer when a local daemon is running. Falls back to a store-only
summary when the daemon socket is unreachable (spec §28.1).

### Flags

| Flag | Description |
|------|-------------|
| `--json` | Output the full report (health + daemon snapshot) as JSON |
| `--detectors` | Show detector status |
| `--feeds` | Show intelligence feed status |
| `--store` | Show store health and disk usage |
| `--cas-dir <DIR>` | Override the content-addressed store root to probe |
| `--rules <DIR>` | Load YARA-X rule packs from this directory and report their versions |
| `--socket <PATH>` | Daemon socket path to query (default: standard `~/.cache/arbitraitor/daemon.sock`) |

### What it reports

The `status` command surfaces:

- **Store**: CAS health, corruption check, garbage collection status
- **Detectors**: Loaded plugins and their current status
- **Feeds**: Last sync time and freshness for each configured feed
- **Config**: Validity of configuration files
- **Daemon (if running)**: PID, uptime in seconds, last operation, and a
  bounded list of recent operations (`inspect`, `scan`, `query_receipt`,
  `health`, `shutdown`). When no daemon is reachable, the report line
  `Daemon: not running (store-only status)` is emitted so callers can
  distinguish "daemon down" from "daemon healthy".

The JSON shape mirrors the human-readable layout — every component
report is keyed under `health.checks`, and the daemon snapshot (or
`null`) is a top-level `daemon` field.

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
| `--emit-on-pass` | Buffer stdin and emit the original bytes to stdout only when the scan verdict is `Pass` |
| `--recursive` | Recursively scan archive payloads |
| `--type <TYPE>` | Require an artifact class (`elf`, `pe`, `mach-o`, `sh`, `archive`) |
| `--name <NAME>` | Keep findings and detector status for the named detector only |
| `--source-url <URL>` | Record a source URL in scan provenance metadata |
| `--json` | Output the structured scan receipt as JSON instead of human-readable text |
| `--sarif` | Output scan findings as SARIF 2.1.0 |
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

# Emit structured JSON receipt
arbitraitor scan ./script.sh --json

# Gate piped bytes: stdout receives bytes only on Pass
curl -s https://example.com/script.sh | arbitraitor scan --stdin --emit-on-pass
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

Runs system health diagnostics. The default output is human-readable; `--json` emits the structured report for automation. The report covers store health, detectors, policies, YARA-X rules, antivirus adapters, scanner freshness, feed signatures, update trust roots, sandbox adapters, plugin manifests and protocol compatibility, wrapper coverage, shim PATH order, clock skew, proxy settings, and receipt signing keys.

### Flags

| Flag | Description |
|------|-------------|
| `--cas-dir <DIR>` | Override the CAS directory to check |
| `--rules <DIR>` | Path to rule packs directory |
| `--receipt-signing-key <PATH>` | Path to the receipt signing key file (spec §31.3) |
| `--json` | Emit structured JSON with each check status as `pass`, `fail`, `warn`, or `skipped` |

### Checks

| Check | Description |
|-------|-------------|
| `store` | CAS directory exists, is writable, and reports object counts |
| `detectors` | Detector and rule-pack versions are configured |
| `version` | Arbitraitor build and rule-pack version summary |
| `policy_validity` | Configured standalone policy TOML parses and validates |
| `yara_rules` | Configured YARA-X rule directories exist and parse |
| `av_adapters` | ClamAV or Microsoft Defender command availability |
| `scanner_freshness` | Scanner signature/database files are within the freshness window when configured |
| `feed_signatures` | Configured intel feed signature files exist and are readable |
| `update_trust_root` | Configured update trust-root key exists and is readable |
| `sandbox_adapters` | Platform sandbox adapter availability |
| `plugin_manifests` | Installed plugin manifests are readable |
| `plugin_protocol` | Installed plugin manifests advertise compatible protocol metadata when declared |
| `wrapper_coverage` | Installed `curl`/`wget` commands have wrapper semantic coverage |
| `shim_path_order` | Shim directory precedes original tools in `PATH` |
| `clock_skew` | Local system clock is plausible for signature freshness decisions |
| `proxy_settings` | Proxy environment variables use supported URL schemes |
| `receipt_signing_key` | Configured receipt signing key exists and is readable |

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

Manages the plugin registry and local plugin lifecycle. Registry-backed
operations currently expose the stable CLI surface and return stub output
until registry plumbing is complete.

### Subcommands

#### `list`

List all registered plugins:

```sh
arbitraitor plugin list
```

#### `info <ID>`

Show manifest details for a specific plugin. `inspect` is an alias:

```sh
arbitraitor plugin info <id>
arbitraitor plugin inspect <id>
```

#### `search <QUERY>`

Search the plugin registry:

```sh
arbitraitor plugin search yara
```

#### `discover`

Run plugin discovery from default directories:

```sh
arbitraitor plugin discover
```

#### `install <ID>`

Install a plugin by registry ID:

```sh
arbitraitor plugin install <id>
```

#### `update [--all]`

Update plugins. Use `--all` to update every installed plugin:

```sh
arbitraitor plugin update --all
```

#### `enable <ID>`

Enable an installed plugin:

```sh
arbitraitor plugin enable <id>
```

#### `disable <ID>`

Disable an installed plugin:

```sh
arbitraitor plugin disable <id>
```

#### `trust <DIGEST_OR_SIGNER>`

Trust a plugin digest or signer identity:

```sh
arbitraitor plugin trust sha256:<hex>
arbitraitor plugin trust signer@example.test
```

#### `doctor`

Run plugin health checks:

```sh
arbitraitor plugin doctor
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

Manages compatibility shims that route supported tool invocations through Arbitraitor.

### Subcommands

#### `list`

List installed shims and supported tools:

```sh
arbitraitor shim list
# Supported shims: npm, curl, wget, brew
```

#### `install <TOOL>`

Install a compatibility shim for a supported tool. Shims are written under
`~/.arbitraitor/shims` and dispatch by tool:

- `npm` invokes `arbitraitor pm run --tool npm`.
- `curl` and `wget` invoke `arbitraitor fetch --tool <TOOL>`.
- `brew` invokes `arbitraitor wrap brew`.

```sh
arbitraitor shim install npm
arbitraitor shim install curl
arbitraitor shim install wget
arbitraitor shim install brew
# Writes ~/.arbitraitor/shims/npm
```

Supported tools: `npm`, `curl`, `wget`, `brew`.

#### `remove <TOOL>` / `uninstall <TOOL>`

Remove a compatibility shim:

```sh
arbitraitor shim remove curl
# Legacy alias:
arbitraitor shim uninstall npm
```

#### `real <TOOL>`

Resolve the real binary path for a supported tool by searching `PATH` while
excluding `~/.arbitraitor/shims`:

```sh
arbitraitor shim real curl
# /usr/bin/curl
```

#### `status`

Show every supported shim and its current slot state:

```sh
arbitraitor shim status
# npm: not installed
# curl: installed
# wget: not installed
# brew: not installed
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
arbitraitor approve <RECEIPT> [flags]
```

Decoupled approval flow: reads a receipt from a prior inspection, displays findings, prompts for approval, and writes a time-limited approval file (5-minute expiry). If `--output` is omitted, the approval path defaults to `<receipt>.approval.json`.

### Flags

| Flag | Description |
|------|-------------|
| `--output <PATH>` | Write the approval file to this path |

### Examples

```sh
arbitraitor inspect https://example.com/install.sh --receipt receipt.json
arbitraitor approve receipt.json --output approval.json
# Without --output, writes receipt.approval.json
arbitraitor approve receipt.json
```

## Execute command

```sh
arbitraitor execute --approval <APPROVAL> [flags]
```

Executes an artifact from CAS using a previously generated approval file.
The legacy positional approval path is still accepted for compatibility but emits a deprecation warning; use `--approval <PATH>` for new scripts.

### Flags

| Flag | Description |
|------|-------------|
| `--approval <PATH>` | Approval file from `arbitraitor approve` |
| `--network` | Allow network access during execution |

### Examples

```sh
arbitraitor execute --approval approval.json
# With network access:
arbitraitor execute --approval approval.json --network
```

### Supported artifact types

Only `ArtifactType::ShellScript(_)` artifacts are executable via the
`execute` command. All other classified types — `HtmlDocument`,
`JsonDocument`, `XmlDocument`, `GenericText`, `GenericBinary`, archives,
`PowerShellScript`, `PythonScript`, `JavaScript`, and `Unknown` — fail
closed with an error before reaching `ScriptExecution::bash`, even when
the approval file is otherwise valid. This mirrors the content-type gate
on `arbitraitor run` and `run_approved_artifact` (MCP) per
[ADR-0036](../../docs/adr/0036-run-pipeline-content-type-execution-gate.md)
and [issue #612](https://github.com/arbsec/arbitraitor/issues/612).
Native executables are also not accepted via `execute` because the
approval flow always binds to the bash interpreter (native execution
uses a separate release path).

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
