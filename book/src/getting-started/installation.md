# Installation

Arbitraitor is built from source. There are no pre-built binaries yet —
it is pre-alpha software and the CLI, config format, and schemas change
between commits.

## Prerequisites

### Rust toolchain

**Rust 1.96+** (Rust 2024 edition). Install via [rustup](https://rustup.rs):

```sh
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

### System dependencies

You need **pkg-config** and **OpenSSL development headers** for the HTTP
stack.

**Ubuntu/Debian:**

```sh
sudo apt install pkg-config libssl-dev
```

**macOS:**

```sh
brew install pkg-config openssl@3
```

### mise (optional, recommended)

The project uses [mise](https://mise.jdx.dev/) to pin the exact Rust
toolchain and supporting tools. If you have mise installed:

```sh
mise install
```

This installs the Rust version pinned in `.mise.toml`, plus lefthook
(git hooks), cocogitto (conventional commits), and rumdl (markdown
linter).

## Build and install

```sh
git clone https://github.com/arbsec/arbitraitor.git
cd arbitraitor
cargo install --path crates/arbitraitor-cli
```

This compiles the CLI and all its dependencies. Expect **5–15 minutes**
depending on your machine and whether dependencies are cached.

The binary installs to `~/.cargo/bin/arbitraitor`.

## Verify the installation

```sh
arbitraitor --version
arbitraitor --help
```

You should see the version string and the list of subcommands:

```text
Commands:
  inspect   Retrieve and analyze an artifact without executing it
  run       Execute the full pipeline with approval flow
  daemon    Unix socket daemon with background queue
  unpack    Unpack an archive to a directory for inspection
  intel     Manage local threat-intelligence feeds
  status    Show system health and configured detectors
  wrappers  Manage curl/wget wrapper shims
```

## Troubleshooting

**Build fails with OpenSSL errors:**
Ensure `pkg-config` and `libssl-dev` (or `openssl@3` on macOS) are
installed. On macOS, you may need to set `OPENSSL_DIR`:

```sh
export OPENSSL_DIR=$(brew --prefix openssl@3)
```

**`arbitraitor` command not found:**
Ensure `~/.cargo/bin` is on your `PATH`:

```sh
echo 'export PATH="$HOME/.cargo/bin:$PATH"' >> ~/.bashrc
source ~/.bashrc
```

**Out of memory during build:**
The workspace is large. Try building with reduced parallelism:

```sh
cargo install --path crates/arbitraitor-cli -j 2
```
