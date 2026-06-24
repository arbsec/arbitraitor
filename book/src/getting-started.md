# Getting Started

> **Pre-alpha software.** Commands, flags, and output formats may change
> between versions. Examples in this guide reflect the current development
> state, not a stable release.

This guide walks you through installing Arbitraitor and running your first
inspection and execution. You will:

1. [**Install**](./getting-started/installation.md) Arbitraitor from source
2. [**Inspect**](./getting-started/first-inspection.md) a script without executing it
3. [**Run**](./getting-started/first-run.md) a script with human approval
4. [**Set up wrappers**](./getting-started/wrappers.md) to intercept `curl | sh`

Each step takes a few minutes. By the end, you will understand how
Arbitraitor replaces the `curl | sh` pattern with a controlled,
inspectable pipeline.

## What is Arbitraitor?

Arbitraitor is a security boundary for untrusted content. It separates
retrieval, trust, inspection, and execution into a controlled pipeline:

```text
download → store → identify → scan → evaluate policy → verdict → execute
```

Instead of piping a script directly into a shell, Arbitraitor fetches the
content, inspects it, produces explainable findings, and only executes
the exact inspected bytes — after you approve.

See the [Introduction](./introduction.md) for the full design rationale.

## Next steps

Start with [Installation](./getting-started/installation.md), then try
[inspecting a script](./getting-started/first-inspection.md).
