# Installation

Arbitraitor offers two installation methods. Nightly binaries are the
fastest option; building from source is available for development.

## Nightly binaries (recommended)

Pre-built binaries are published every night from the latest `main`
commit. They are available for Linux and macOS on both x86_64 and
aarch64.

### Download

Fetch the latest binary for your platform from the
[nightly release page](https://github.com/arbsec/arbitraitor/releases/tag/nightly):

| Platform | File |
|----------|------|
| Linux x86_64 | `arbitraitor-x86_64-unknown-linux-gnu.tar.gz` |
| Linux aarch64 | `arbitraitor-aarch64-unknown-linux-gnu.tar.gz` |
| macOS x86_64 (Intel) | `arbitraitor-x86_64-apple-darwin.tar.gz` |
| macOS aarch64 (Apple Silicon) | `arbitraitor-aarch64-apple-darwin.tar.gz` |

### Install

```sh
# Download and extract
curl -fsSL https://github.com/arbsec/arbitraitor/releases/download/nightly/arbitraitor-x86_64-unknown-linux-gnu.tar.gz | tar xz

# Move to a directory on your PATH
sudo mv arbitraitor /usr/local/bin/

# Verify
arbitraitor --version
```

On macOS, substitute the file name with `arbitraitor-x86_64-apple-darwin.tar.gz`
or `arbitraitor-aarch64-apple-darwin.tar.gz` depending on your architecture.

> **Warning: Pre-alpha.** Nightly binaries are built from unreleased
> code. The CLI, config format, and schemas change between commits. Do
> not use in production.

## Build from source

Building from source is required for development or if you need a
platform without pre-built binaries (e.g. Windows).

### Prerequisites

**Rust 1.96+** (Rust 2024 edition). Install via [rustup](https://rustup.rs):

```sh
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

You also need **pkg-config** and **OpenSSL development headers**.

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

### Build and install

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
Ensure the binary is on your `PATH`:

```sh
echo 'export PATH="$HOME/.cargo/bin:$PATH"' >> ~/.bashrc
source ~/.bashrc
```

**Out of memory during build:**
The workspace is large. Try building with reduced parallelism:

```sh
cargo install --path crates/arbitraitor-cli -j 2
```
