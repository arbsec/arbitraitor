# Explaining Verdicts

If you saved a receipt during inspection, you can explain the verdict retrospectively:

```sh
arbitraitor inspect https://example.com/install.sh --receipt receipt.json
arbitraitor explain receipt.json
```

Output shows the artifact SHA-256, verdict, all findings with severity, and retrieval metadata (URL, final URL). All untrusted content from the receipt is sanitized per ADR-0016.

> **Stability: Unstable.** Verified against commit `<sha>`.
