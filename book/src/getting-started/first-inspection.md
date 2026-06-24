# First Inspection

The `inspect` command retrieves an artifact, runs it through the detection pipeline, and reports findings **without executing anything**:

```sh
arbitraitor inspect https://example.com/install.sh
```

## Reading the output

```text
Artifact:    sha256:a1b2c3d4e5f6...
Source:      https://example.com/install.sh
Type:        application/x-shellscript
Size:        4.2 KB
Detectors:   shell ✅  archive ✅

Findings:
  network:curl              high      Downloads content via curl
  network:wget               high      Downloads content via wget
  fs:write:/tmp              medium    Writes to /tmp directory
  exec:subprocess            high      Spawns subprocesses

Verdict: WARN (inspect)
  Elevated findings require human review before execution.
  Run 'arbitraitor run <URL>' to request approval.
```

| Line | What it tells you |
|------|-------------------|
| **Artifact** | The SHA-256 of the exact bytes that were inspected. This hash is immutable — execution uses these exact bytes. |
| **Source** | The final URL after redirects. May differ from what you typed if the server redirected. |
| **Type** | Detected content type. Determines which detectors run (shell scripts get shell analysis, archives get archive inspection). |
| **Detectors** | Which detectors ran and their status. A green check means the detector completed; a red cross means it failed (produces an Incomplete verdict). |
| **Findings** | Individual detections. Each has an ID, severity, and description. The ID format is `category:detail` (e.g., `network:curl` = network access via curl). |
| **Verdict** | The policy engine's decision. Always includes the assurance level in parentheses. |

## Understanding the verdict

The policy engine produces one of five verdicts:

| Verdict     | Meaning                                                       |
|-------------|---------------------------------------------------------------|
| Pass        | No findings or only informational findings. Safe to proceed.  |
| Warn        | Suspicious patterns detected. Proceed with caution.           |
| Prompt      | Findings require human approval before execution.             |
| Block       | Confirmed malicious content. Execution refused.               |
| Incomplete  | A detector failed. Treat as untrusted until re-scanned.       |

The verdict always states which assurance level was in effect: `PASS (inspect)`, `WARN (inspect)`, etc. A clean scan at the Inspect level means the content was analyzed but not executed — it is not a guarantee of safety.

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

## What you just did

You ran a complete security inspection on a remote artifact — without executing it. Arbitraitor:

1. Fetched the content once and buffered it immutably
2. Identified the content type
3. Ran detectors (shell analysis, archive inspection, etc.)
4. Evaluated findings against policy
5. Produced an explainable verdict

No bytes reached a shell. To actually execute the script (with sandboxing and approval), continue to [First Run with Approval](./first-run.md).
