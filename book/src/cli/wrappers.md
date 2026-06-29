# wrappers

The `wrappers` command manages shell shims that route `curl` and `wget` through Arbitraitor automatically.

## Synopsis

```sh
arbitraitor wrappers <subcommand> [flags]
```

## How wrappers work

Wrappers install shell scripts (or symlinks) named `curl` and `wget` into a shim directory (default: `~/.arbitraitor/shims`). When invoked, they call `arbitraitor fetch` with the original arguments, routing the download through the inspection pipeline before any bytes reach the shell.

The original binary is found via PATH lookup excluding the shim directory, so the real `curl` or `wget` is used for the actual HTTP request under Arbitraitor's control.

## Subcommands

### install

Install curl and wget shims to `~/.local/bin`:

```sh
arbitraitor wrappers install
```

Does not modify system binaries. Requires `~/.local/bin` to be in PATH.

### status

Show installed wrappers and their current state:

```sh
arbitraitor wrappers status
```

Output:

```
Wrappers:     installed
Location:      /home/user/.local/bin
curl:          /home/user/.local/bin/curl -> arbitraitor-proxy
wget:          /home/user/.local/bin/wget -> arbitraitor-proxy
Intercepting:  curl wget
```

### init-script

Print the shell initialization snippet:

```sh
arbitraitor wrappers init-script
```

Add the output to `.bashrc` or `.zshrc`:

```sh
eval "$(arbitraitor wrappers init-script)"
```

### uninstall

Remove installed wrappers:

```sh
arbitraitor wrappers uninstall
```

## How PATH shims work

A PATH shim is a shell script placed early in PATH that intercepts a command:

```sh
#!/bin/sh
# ~/.arbitraitor/shims/curl
exec /path/to/arbitraitor fetch "$@"
```

Arbitraitor resolves the real binary via PATH (excluding the shim directory), performs the HTTP request under its own SSRF and TLS controls, stores the result in CAS, and runs the detection pipeline.

For `wget`, the same pattern applies — the shim invokes `arbitraitor fetch` with the original arguments.

```sh
#!/bin/sh
# ~/.arbitraitor/shims/wget
exec /path/to/arbitraitor fetch "$@"
```

```

## Flags

### `--path <PATH>`

Override the installation directory (default: `~/.local/bin`).

```sh
arbitraitor wrappers install --path /opt/arbitraitor/bin
```

### `-- wrappers <NAMES>`

Install only the specified wrappers (default: `curl,wget`).

```sh
arbitraitor wrappers install --wrappers curl
```

### `--mode <MODE>`

Set the execution mode for intercepted downloads:

| Mode | Description |
|------|-------------|
| `inspect` | Run through detection pipeline only (default) |
| `run` | Full mediated execution with approval |
| `prompt` | Prompt for each download (interactive only) |

```sh
arbitraitor wrappers install --mode run
```

## Security notes

- Wrappers do not grant automatic approval. Any script requiring approval still pauses for human input.
- Network access during wrapper execution is controlled by the active policy.
- Wrappers log every intercepted download to the Arbitraitor audit trail.

## Output behavior on Pass verdict

When the inspection verdict is **Pass**, the wrapper emits the fetched artifact bytes transparently — matching real `curl`/`wget` semantics:

| Flags | Destination |
|-------|-------------|
| (none) | Raw bytes to **stdout** (pipe semantics: `arbitraitor wrap curl -- URL \| bash` works) |
| `-o <file>` / `--output <file>` | Bytes written to the specified file |
| `-O` / `--remote-name` | Bytes written to a file named after the URL's last path segment |
| wget `-O <file>` | Same as curl `-o <file>` |

When the verdict is anything other than Pass (Warn, Prompt, Block, Error, Incomplete):

- **Nothing is written to stdout** — downstream consumers receive no bytes.
- The wrapper exits non-zero.

This means `arbitraitor wrap curl -- URL | bash` is safe by construction: `bash` receives input only when the artifact passed all configured checks.
