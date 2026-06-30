# Scanning Local Files

Scan a local file or piped stdin content through the full detection pipeline:

```sh
arbitraitor scan ./suspicious.sh
```

Exit codes follow the spec §29 convention:

| Code | Meaning |
|------|---------|
| 0 | Passed |
| 10 | Warning verdict |
| 21 | Prompt required in non-interactive mode |
| 30 | Blocked by policy |
| 33 | Required detector unavailable |
| 34 | Analysis incomplete |

## Scanning stdin

```sh
curl -s https://example.com/script.sh | arbitraitor scan --stdin
```

### Using YARA-X rules

```sh
arbitraitor scan ./suspicious.sh --rules /path/to/yara/rules
```

### Explainability reports

```sh
arbitraitor scan ./suspicious.sh --explain --format text
arbitraitor scan ./suspicious.sh --explain --format shellcheck
```

> **Stability: Unstable.** Verified against commit `<sha>`.
> Flags and output may change before 1.0.
