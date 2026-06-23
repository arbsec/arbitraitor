# wrappers

The `wrappers` command manages shell shims that route `curl` and `wget` through Arbitraitor automatically.

## Synopsis

```sh
arbitraitor wrappers <subcommand> [flags]
```

## How wrappers work

Wrappers install shell scripts named `curl` and `wget` into `~/.local/bin`. When invoked, they:

1. Capture the original command arguments
2. Spawn the real `curl` or `wget` via an `exec` syscall
3. Pass the downloaded content to `arbitraitor run --output -` for inspection
4. Pipe the approved bytes to the original destination

The original binary is preserved and called through `exec`, so PATH ordering does not matter.

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
# ~/.local/bin/curl
exec /usr/bin/curl -fsSL "$@" | arbitraitor run --output - --non-interactive
```

The real binary is called with `exec`, replacing the shell process. Downloaded bytes flow through a pipe to Arbitraitor.

For `wget`, the shim downloads to a temporary file and passes that path:

```sh
#!/bin/sh
# ~/.local/bin/wget
TMPFILE=$(mktemp)
trap "rm -f $TMPFILE" EXIT
/usr/bin/wget -O "$TMPFILE" "$@"
arbitraitor run "$TMPFILE" --output - --non-interactive
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
