# wrappers

The `wrappers` command installs shell shims (PATH intercepts) that route
`curl` and `wget` invocations through Arbitraitor, and produces the
shell-integration snippet that puts the shim directory on `PATH`.

```sh
arbitraitor wrappers <subcommand> [flags]
```

> **Stability: Unstable.** Verified against commit `7cb6906`.
> Flags, default directories, and the supported-shell list may change before 1.0.

## How shims work

A shim is a small file (shell script or symlink) placed in a dedicated
directory. When that directory precedes the real tool's directory on
`PATH`, the shell finds the shim instead of the original binary. The shim
calls `arbitraitor fetch` with the original arguments; Arbitraitor
retrieves, inspects, and renders a verdict before any bytes reach the
downstream consumer.

The original `curl` or `wget` is not modified. Arbitraitor resolves it
through `PATH` lookup that excludes the shim directory, so the real tool
performs the HTTP request under Arbitraitor's SSRF, redirect, and TLS
controls.

```text
$ curl https://example.com/install.sh | sh
       │
       ▼
~/.arbitraitor/shims/curl      ←── shim runs first
       │
       ▼
arbitraitor fetch https://example.com/install.sh
       │
       ▼
   [inspect + verdict]
       │
  Pass ─────────┐
  Block ───────┴── non-zero exit, no bytes emitted
```

## Default shim directory

Default: `~/.arbitraitor/shims`

This directory is **not** on any operating system's default `PATH`. This is
intentional:

1. **No silent binary replacement.** A namespaced directory makes the
   shadowing explicit and reversible. Arbitraitor must never silently
   replace system binaries (spec §28.7 invariant).
2. **No collision with user scripts.** Putting `curl`/`wget` shims into
   `~/.local/bin` or `/usr/local/bin` would shadow user-installed scripts
   of the same name without warning.
3. **Idempotent uninstall.** `arbitraitor wrappers uninstall` wipes one
   directory rather than scanning shared user paths for Arbitraitor-managed
   files.

Users who prefer `~/.local/bin` may override with `--shim-dir`:

```sh
arbitraitor wrappers install --shim-dir ~/.local/bin
arbitraitor wrappers init --install --shim-dir ~/.local/bin
```

`~/.local/bin` is on default `PATH` on Debian (bash ≥ 4.3-15, 2016),
Ubuntu (≥ 16.04), and Fedora (bash ≥ 4.2.10-3, 2012). It is **not** on
default `PATH` on Arch, RHEL, NixOS, Alpine, or any minimal/container base
image. The rcfile snippet written by `wrappers init --install` puts any
chosen shim directory on `PATH` regardless of distro defaults.

## Subcommands

### install

Install `curl` and `wget` shims (default: both):

```sh
arbitraitor wrappers install
arbitraitor wrappers install curl        # install only the curl shim
arbitraitor wrappers install wget        # install only the wget shim
```

Flags inherited from the parent `wrappers` command:

| Flag | Default | Description |
|------|---------|-------------|
| `--shim-dir <PATH>` | `~/.arbitraitor/shims` | Override the shim installation directory |
| `--use-scripts` | `false` | Install shell scripts instead of symlinks (use when the shim directory is on a filesystem that does not support symlinks) |

After install, the shim directory is not yet on `PATH`. The command output
prints the next step:

```text
$ arbitraitor wrappers install
installed: /home/user/.arbitraitor/shims/curl
installed: /home/user/.arbitraitor/shims/wget
2 shims installed in /home/user/.arbitraitor/shims

To activate, add the shim directory to your PATH:
  eval "$(arbitraitor wrappers init)"    # print mode
  arbitraitor wrappers init --install      # auto-install to rcfile
```

### uninstall

Remove installed shims (default: all):

```sh
arbitraitor wrappers uninstall
arbitraitor wrappers uninstall curl      # remove only the curl shim
```

Does not remove the rcfile PATH snippet — use
[`wrappers init --uninstall`](#init) for that.

### status

Show installed shims and their state:

```sh
arbitraitor wrappers status
```

States:

| State | Meaning |
|-------|---------|
| `installed (script)` | Shim file is an Arbitraitor-managed shell script |
| `installed (symlink)` | Shim file is an Arbitraitor-managed symlink |
| `not installed` | No shim file present in the shim directory |
| `foreign file` | A file with the same name exists but is not Arbitraitor-managed (manual review required) |

### init

Render or install the shell-integration snippet that puts the shim
directory on `PATH`. This is the **primary surface** for wiring Arbitraitor
into an interactive shell.

```sh
# Print mode (default) — emit snippet to stdout
arbitraitor wrappers init
eval "$(arbitraitor wrappers init)"

# Auto-install mode — write a marked block to the detected shell's rcfile
arbitraitor wrappers init --install

# Detect which shell you are running and which rcfile is targeted
arbitraitor wrappers init --detect-shell

# Remove the PATH block from your rcfile
arbitraitor wrappers init --uninstall

# Specify a shell explicitly (defaults to auto-detect via $SHELL)
arbitraitor wrappers init bash
arbitraitor wrappers init zsh
arbitraitor wrappers init fish --install

# Preview what would be written (use with --install)
arbitraitor wrappers init --install --dry-run

# Skip backup file creation (default: backup is created)
arbitraitor wrappers init --install --no-backup
```

Flags:

| Flag | Description |
|------|-------------|
| `[shell]` (positional) | Target shell. Auto-detected from `$SHELL` if omitted. |
| `--install` | Write the snippet to the shell's rcfile (instead of stdout). |
| `--uninstall` | Remove a previously installed block from the rcfile. |
| `--detect-shell` | Print detected shell and target rcfile, then exit. |
| `--dry-run` | Show what would change without writing. Requires `--install`. |
| `--no-backup` | Skip `<rcfile>.arbitraitor.bak` creation. Requires `--install`. |

### Shells supported

`bash`, `zsh`, `sh`, `fish`, `nu`, `xonsh`, `powershell`, `elvish`,
`posix`, `tcsh`, `oil` (also accepts `osh` / `ysh`).

This list matches the industry-consensus shell coverage from starship (12
shells) and is ahead of zoxide (9), atuin (6), and direnv (8). Detection
falls back from `$SHELL` to parent-process inspection
(`/proc/$PPID/cmdline` on Linux, `ps -o comm=` on macOS).

### Idempotency

The rcfile block is wrapped in marker lines so re-runs replace in place
rather than appending:

```sh
# >>> arbitraitor wrappers >>>
export PATH="$HOME/.arbitraitor/shims:$PATH"
# <<< arbitraitor wrappers <<<
```

Re-running `wrappers init --install` after a directory change (via
`--shim-dir`) updates the block atomically. The corresponding in-shell
snippet is also idempotent: re-`eval`ing `arbitraitor wrappers init` does
not duplicate `PATH` entries (POSIX `case` guard for bash/zsh/sh,
`typeset -aU path` for zsh, `fish_add_path --move --path` for fish, etc.).

### Backups

`--install` writes `<rcfile>.arbitraitor.bak` before editing. Pass
`--no-backup` to skip. The backup is overwritten on each subsequent
`--install`.

### init-script

Print the shell-init script for all `WrapperTarget`s (currently `curl`
and `wget`). Primarily intended for environment-specific automation that
needs the ambient shell wiring rather than per-tool invocation:

```sh
arbitraitor wrappers init-script
```

Equivalent to `arbitraitor wrappers init` with no flags for the default
shell. Prefer `wrappers init` in interactive contexts.

## Hidden alias: `arbitraitor env`

`arbitraitor env` is a hidden alias of `arbitraitor wrappers init`. Same
flags and behaviour. Hidden because the dominant industry convention
(starship, zoxide, atuin) is the verb `init`; surfacing `env` as a
top-level command would conflict with `printenv(1)` semantics. The alias
exists as a discoverability shortcut.

## Deprecated command: `arbitraitor hook init`

`arbitraitor hook init` prints a bash DEBUG trap that intercepts
`curl|sh`-style invocations at runtime. It is **deprecated** and prints a
warning on use. The DEBUG trap runs on every command, has measurable
overhead in interactive sessions, and only supports bash.

Replace with `arbitraitor wrappers install && arbitraitor wrappers init
--install`, which:

1. Installs the curl/wget shims (one-time).
2. Wires the shim directory onto `PATH` via a marked rcfile block — works
   across every supported shell, no per-command trap overhead.

## Output behaviour per verdict

When the wrapper's inspection verdict is **Pass**, the wrapper emits the
fetched artifact bytes transparently — matching real `curl`/`wget`
semantics:

| Flags | Destination |
|-------|-------------|
| (none) | Raw bytes to **stdout** (pipe semantics: `curl URL \| bash` works) |
| `-o <file>` / `--output <file>` | Bytes written to the specified file |
| `-O` / `--remote-name` | Bytes written to a file named after the URL's last path segment |
| wget `-O <file>` | Same as curl `-o <file>` |

When the verdict is anything other than Pass (Warn, Prompt, Block, Error,
Incomplete):

- **Nothing is written to stdout** — downstream consumers receive no bytes.
- The wrapper exits non-zero.

This means `arbitraitor wrap curl -- URL | bash` is safe by construction:
`bash` receives input only when the artifact passed all configured checks.

## Security notes

- Wrappers do not grant automatic approval. Any script requiring approval
  still pauses for human input.
- Network access during wrapper execution is controlled by the active
  policy and the fetch transport policy (spec §11, ADR-0018).
- Every intercepted download is recorded in the Arbitraitor audit trail
  and contributes to the operation receipt.
- The shim directory is created with `0o700` permissions. Foreign files
  (not Arbitraitor-managed) are reported by `wrappers status` as
  `foreign file` and are never overwritten.
