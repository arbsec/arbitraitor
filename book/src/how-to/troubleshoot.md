# Troubleshooting

Common issues and how to resolve them.

## Build problems

### OpenSSL errors during `cargo install`

**Symptom:** Build fails with `Could not find directory of OpenSSL installation`.

**Fix:** Install the OpenSSL development headers.

```sh
# Ubuntu/Debian
sudo apt install pkg-config libssl-dev

# macOS
brew install pkg-config openssl@3
# May also need:
export OPENSSL_DIR=$(brew --prefix openssl@3)
```

### Out of memory during compilation

**Symptom:** Build killed by OOM killer or linker error.

**Fix:** Reduce parallelism.

```sh
cargo install --path crates/arbitraitor-cli -j 2
```

### `arbitraitor` command not found after install

**Symptom:** `command not found: arbitraitor`

**Fix:** Ensure `~/.cargo/bin` is on your PATH.

```sh
echo 'export PATH="$HOME/.cargo/bin:$PATH"' >> ~/.bashrc
source ~/.bashrc
```

## Inspection problems

### `inspect` returns `INCOMPLETE` verdict

**Cause:** A detector failed to complete. This is fail-closed behavior — Arbitraitor treats a failed detector as untrusted, not clean.

**Fix:**

1. Run `arbitraitor status` to check detector health.
2. Re-run the inspection — transient network errors may resolve.
3. If a specific detector consistently fails, check its configuration.
4. Use `--no-detectors` to identify-only (for debugging, not production).

### `inspect` reports findings on a script I trust

This is expected. Arbitraitor reports **what the script does**, not whether
it is safe. A finding like `network:curl` means the script downloads
content — that is information for your decision, not a verdict.

Use `--explain` to understand each finding:

```sh
arbitraitor inspect https://example.com/install.sh --explain
```

### Provenance verification fails

**Fix:**

1. Verify the public key is correct.
2. Ensure you are passing the `.pub` key, not the secret key.
3. The artifact may have changed since the signature was created.

## Execution problems

### `run` exits with code 5

The verdict requires approval, but you are in non-interactive mode.

**Fix:** Run interactively (without `--non-interactive`) to get the
approval prompt.

### `run` exits with code 3

The artifact was blocked by policy — findings exceeded your block
thresholds.

**Fix:** Review findings with `inspect --explain`. If you have a
legitimate need to run a blocked artifact, adjust your policy thresholds.
Do not disable policy enforcement globally.

### Script fails with network errors during execution

**Cause:** Mediated execution denies network access by default (Level 2).

**Fix:** If the script legitimately needs network access, grant it
explicitly:

```sh
arbitraitor run https://example.com/install.sh --network
```

This is an intentional security boundary. Only grant network access to
scripts you have inspected and trust.

## Configuration problems

### Config changes not taking effect

1. Config locations: `~/.arbitraitor/config.toml` (user) or
   `./.arbitraitor/config.toml` (project).
2. Override order: defaults → user config → project config → `--config`.
3. Run `arbitraitor status` to see the loaded configuration.

### Secret references not resolving

Ensure the environment variable or file exists:

```sh
export URLHAUS_API_KEY=your-key-here
```

File paths must be absolute in the config:

```toml
api_key = "secret://file//etc/arbitraitor/keys/api.key"
```

## Getting help

- [Open a discussion](https://github.com/arbsec/arbitraitor/discussions) for questions.
- [File an issue](https://github.com/arbsec/arbitraitor/issues) for bugs.
- See [SECURITY.md](https://github.com/arbsec/arbitraitor/blob/main/SECURITY.md) for vulnerability reporting — **do not report security issues through public issues.**
