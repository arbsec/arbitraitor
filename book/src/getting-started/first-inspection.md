# First Inspection

The `inspect` command retrieves an artifact, runs it through the detection pipeline, and reports findings **without executing anything**:

```sh
arbitraitor inspect https://example.com/install.sh
```

The output shows the artifact identity, content type, detection findings, and a verdict.

## Understanding the verdict

The policy engine produces one of five verdicts:

| Verdict     | Meaning                                                       |
|-------------|---------------------------------------------------------------|
| Pass        | No findings or only informational findings. Safe to proceed.  |
| Warn        | Suspicious patterns detected. Proceed with caution.           |
| Prompt      | Findings require human approval before execution.             |
| Block       | Confirmed malicious content. Execution refused.               |
| Incomplete  | A detector failed. Treat as untrusted until re-scanned.       |

## Provenance verification

If the publisher provides a signature, you can verify it during inspection:

```sh
arbitraitor inspect https://example.com/install.sh \
  --minisign-key RWQf6LRCGA9i53mlYecO4IzT51TGPpvWucNSCh1CBM0QUVlq39r+nX7p
```

Arbitraitor fetches the artifact once, verifies the signature against the public key, and only proceeds to detection if the signature is valid.

## Explainability

Add `--explain` to get a human-readable explanation of each finding:

```sh
arbitraitor inspect https://example.com/install.sh --explain
```

Use `--explain --format shellcheck` for output compatible with tools that consume ShellCheck JSON.
