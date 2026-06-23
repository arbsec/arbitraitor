# Comparison with Other Tools

## How Arbitraitor differs

Arbitraitor is the only tool that provides a **complete download → inspect → approve → execute** pipeline with cryptographic provenance, plan-bound approval, and mediated execution in a single binary.

## Comparison

| Feature | Arbitraitor | ShellCheck | cosign | Firejail |
|---------|-------------|------------|--------|----------|
| Download interception | Yes | No | No | No |
| Static analysis | Yes | Yes (shell only) | No | No |
| Provenance verification | Yes | No | Yes | No |
| Human approval gate | Yes | No | No | No |
| Sandboxed execution | Yes | No | No | Yes |
| Receipt / audit trail | Yes | No | No | No |
| MCP integration | Yes | No | No | No |
| Plugin system | Yes | No | No | No |

This table will be updated with more tools based on ongoing research.
