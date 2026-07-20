# Wrappers

Arbitraitor installs shell shims that intercept `curl` and `wget`,
routing every invocation through the inspection pipeline before bytes
reach the downstream consumer:

```sh
# 1. Install curl/wget shims
arbitraitor wrappers install

# 2. Wire the shim directory onto PATH (one-time)
arbitraitor wrappers init --install

# 3. (Optional) Verify the setup
arbitraitor wrappers status
```

After that, `curl https://example.com/file | sh` is transparently
intercepted and inspected before the bytes reach the shell. A `Block`
verdict emits nothing to stdout and exits non-zero — `bash` receives input
only when the artifact passed all configured checks.

## Shell integration

`wrappers init` is the primary command for wiring the shim directory onto
`PATH`. Two modes:

```sh
# Print mode — emit snippet to stdout, eval inline or hand-paste
eval "$(arbitraitor wrappers init)"

# Auto-install mode — write a marked, idempotent block to your rcfile
# (creates ~/.bashrc.arbitraitor.bak before editing)
arbitraitor wrappers init --install

# Detect which shell you're running and which rcfile is targeted
arbitraitor wrappers init --detect-shell

# Specify a shell explicitly (default: auto-detected from $SHELL)
arbitraitor wrappers init zsh
arbitraitor wrappers init fish --install
```

Supported shells: `bash`, `zsh`, `sh`, `fish`, `nu` (Nushell), `xonsh`,
`powershell`, `elvish`, `posix`, `tcsh`, `oil` (also `osh` / `ysh`).

To remove the PATH block from your rcfile:

```sh
arbitraitor wrappers init --uninstall
```

The block is wrapped in marker lines (`# >>> arbitraitor wrappers >>>` /
`# <<< arbitraitor wrappers <<<`), so re-running `--install` after an
upgrade replaces in place rather than duplicating. The in-shell snippet is
also idempotent: re-`eval`ing it does not duplicate `PATH` entries.

See the [wrappers CLI reference](../cli/wrappers.md) for the full flag
surface, the default shim directory rationale, and the deprecated
`hook init` migration path.

## Default shim directory

Default: `~/.arbitraitor/shims`

This directory is intentionally **not** on any operating system's default
`PATH`. A namespaced directory avoids silent replacement of system
binaries (spec §28.7 invariant) and avoids collisions with user-owned
scripts of the same name in `~/.local/bin`.

Override with `--shim-dir`:

```sh
arbitraitor wrappers install --shim-dir ~/.local/bin
arbitraitor wrappers init --install --shim-dir ~/.local/bin
```

`~/.local/bin` is on default `PATH` on Debian (bash ≥ 4.3-15, 2016),
Ubuntu (≥ 16.04), and Fedora (bash ≥ 4.2.10-3, 2012). It is **not** on
default `PATH` on Arch, RHEL, NixOS, Alpine, or inside minimal containers.
The rcfile snippet written by `wrappers init --install` puts any chosen
shim directory on `PATH` regardless of distro defaults.

## Health checks

Check the status of Arbitraitor's subsystems:

```sh
# Human-readable status
arbitraitor status

# JSON output for monitoring
arbitraitor status --json
```

This reports CAS store health, detector availability, and version
information.

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

Secrets can be referenced from environment variables or files without
hardcoding:

```toml
[intel]
urlhaus_key = "secret://env/URLHAUS_API_KEY"
```

See the [Configuration](../configuration.md) reference for all options.

## Next steps

- [CLI Reference](../cli-reference.md) — all commands and flags
- [Architecture](../architecture/overview.md) — what happens under the hood
- [Security Model](../architecture/security.md) — invariants, threat model, sandbox
- [Plugins](../plugins/overview.md) — extend Arbitraitor with custom detectors
