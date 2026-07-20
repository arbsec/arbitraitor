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
is a thin dispatcher: it re-invokes `arbitraitor fetch --tool <curl|wget>`
with the original arguments. Arbitraitor performs retrieval through its
own fetch pipeline (SSRF controls, redirect policy, TLS verifier
selection — see spec §11, ADR-0018), inspects the artifact, and emits
bytes only on a `Pass` verdict.

The original `curl` or `wget` is not modified. `wrappers status` reports
the shim state (`installed (script)`, `installed (symlink)`,
`not installed`, or `foreign file` — see [Status semantics](#status)
below).

```text
$ curl https://example.com/install.sh | sh
       │
       ▼
~/.arbitraitor/shims/curl      ←── shim runs first
       │
       ▼
arbitraitor fetch --tool curl -- https://example.com/install.sh
       │
       ▼
   [fetch pipeline + inspect + verdict]
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
| `installed (script)` | A script file occupies the shim slot; content starts with the Arbitraitor shim marker |
| `installed (symlink)` | A symlink occupies the shim slot (target not validated) |
| `not installed` | No shim file present in the shim directory |
| `foreign file` | A file with the same name exists but does not start with the Arbitraitor shim marker (manual review recommended; the file **will** be overwritten on next `wrappers install`) |

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

For POSIX-family shells (`bash`, `zsh`, `sh`, `posix`, `tcsh`, `oil`),
the rcfile block is wrapped in marker lines so re-runs replace in place
rather than appending:

```sh
# >>> arbitraitor wrappers >>>
export PATH="$HOME/.arbitraitor/shims:$PATH"
# <<< arbitraitor wrappers <<<
```

Re-running `wrappers init --install` after a directory change (via
`--shim-dir`) updates the block atomically. The corresponding in-shell
snippet is also idempotent: re-`eval`ing `arbitraitor wrappers init`
does not duplicate `PATH` entries (POSIX `case` guard for bash/zsh/sh,
`typeset -aU path` for zsh, `fish_add_path --move --path` for fish,
etc.).

**Exceptions:** `fish`, `nu` (Nushell), and `powershell` use a
dedicated file rather than a marked block in an existing rcfile — fish
writes `~/.config/fish/conf.d/arbitraitor.fish`; nushell writes
`~/.config/nushell/vendor/autoload/arbitraitor.nu`; powershell writes
its `$PROFILE`. `--install` overwrites these files atomically on each
run (with `.arbitraitor.bak` backup by default); `--uninstall` removes
them. The runtime snippets remain idempotent for these shells.

### Backups

`--install` writes a backup before mutating the rcfile (or dedicated
shell file for fish/nu/powershell) using `Path::with_extension`
— for files without a conventional extension (e.g. `.bashrc`) this
appends `.arbitraitor.bak`; for files with an extension (e.g. PowerShell
`profile.ps1`) it replaces the extension to give
`profile.arbitraitor.bak`. The backup is overwritten on each subsequent
`--install`. Pass `--no-backup` to skip.

### init-script

Hidden legacy command that prints a generic POSIX shell-init snippet
that prepends `~/.arbitraitor/shims` to `PATH`. Retained from an earlier
version that did not have per-shell snippet generation. Prefer
`arbitraitor wrappers init` which auto-detects the target shell and
emits a shell-specific, runtime-idempotent snippet (POSIX `case` guard
for `bash`/`zsh`/`sh`, `typeset -aU path` for `zsh`,
`fish_add_path --move --path` for `fish`, etc.). Retained for backwards
compatibility with automation that pipes the legacy snippet into rcfiles.

```sh
arbitraitor wrappers init-script    # hidden, legacy
# Prefer:
arbitraitor wrappers init           # auto-detect shell, print snippet
eval "$(arbitraitor wrappers init)"
```

## Hidden alias: `arbitraitor env`

`arbitraitor env` is a hidden alias of `arbitraitor wrappers init`. It
accepts the same `init` flags (`--install`, `--uninstall`,
`--detect-shell`, `--dry-run`, `--no-backup`, positional `[shell]`)
but **does not** inherit the `wrappers` parent flags (`--shim-dir`,
`--use-scripts`) — it always uses the default shim directory
(`~/.arbitraitor/shims`). Pass `--shim-dir` via the `wrappers` parent
form (`arbitraitor wrappers init --install --shim-dir <PATH>`) when
overriding the directory.

Hidden because the dominant industry convention (starship, zoxide,
atuin) is the verb `init`; surfacing `env` as a top-level command would
conflict with `printenv(1)` semantics. The alias exists as a
discoverability shortcut.

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

This means `curl URL | bash` (with shims active) is safe by construction:
`bash` receives input only when the artifact received a `Pass` verdict.
Wrappers are a strict download gate; they do not perform interactive
approval. To require human approval before execution, use
`arbitraitor run <URL>` (which goes through the approval flow defined in
ADR-0013).

## Security notes

- The shim directory (`~/.arbitraitor/shims` by default) is created with
  the process umask; no explicit mode is set. If you require a specific
  mode, create the directory before running `wrappers install`.
- **`wrappers install` overwrites existing files in the shim directory.**
  If a file named `curl` or `wget` already exists at the shim path
  (including non-Arbitraitor-managed files), it is removed and replaced
  with the new shim. `wrappers status` reports `foreign file` for unknown
  files as an informational hint, but install will still clobber them.
  Use a dedicated shim directory (the default `~/.arbitraitor/shims`) to
  avoid collisions; if you override with `--shim-dir ~/.local/bin` or
  another shared path, audit it first.
- Network access during wrapper execution is controlled by the active
  policy and the fetch transport policy (spec §11, ADR-0018).
- Every intercepted download is recorded in the Arbitraitor audit trail
  and contributes to the operation receipt.
