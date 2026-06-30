# Wrappers

Arbitraitor can install shell shims that intercept `curl` and `wget` commands, routing them through the inspection pipeline:

```sh
# Install shims for all supported wrappers
arbitraitor wrappers install

# Check which shims are installed
arbitraitor wrappers status
```

After installation, any `curl https://example.com/file | sh` is transparently intercepted and inspected before the bytes reach the shell.

## Shell integration

After installing shims, add the shim directory to your `PATH`:

```sh
# Print mode — add to rcfile manually or eval inline
eval "$(arbitraitor wrappers init)"

# Auto-install mode — write to the correct rcfile with idempotency markers
arbitraitor wrappers init --install

# Detect which shell you're running and which rcfile is targeted
arbitraitor wrappers init --detect-shell

# Specify a shell explicitly
arbitraitor wrappers init zsh
arbitraitor wrappers init fish --install
```

Supported shells: bash, zsh, sh, fish, nu, xonsh, powershell, elvish, posix, tcsh.

To remove the init block from your rcfile:

```sh
arbitraitor wrappers init --uninstall
```

## Health checks

Check the status of Arbitraitor's subsystems:

```sh
# Human-readable status
arbitraitor status

# JSON output for monitoring
arbitraitor status --json
```

This reports CAS store health, detector availability, and version information.

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

Secrets can be referenced from environment variables or files without hardcoding:

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
