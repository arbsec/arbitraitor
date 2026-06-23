# Getting Started

This guide walks you through installing Arbitraitor and running your first inspection and execution.

## Prerequisites

- **Rust 1.96+** (Rust 2024 edition)
- **mise** for toolchain management — [install instructions](https://mise.jdx.dev/getting-started.html)
- **pkg-config** and **OpenSSL development headers** (for the HTTP stack)

Install mise tools after cloning:

```sh
mise install
```

This installs the pinned Rust toolchain, lefthook (git hooks), cocogitto (conventional commits), and rumdl (markdown linter) from `.mise.toml`.

Verify your Rust version:

```sh
rustc --version   # should print 1.96.0
```
