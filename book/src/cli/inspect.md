# inspect

The `inspect` command retrieves an artifact and runs it through the detection pipeline without executing it. This is Arbitraitor's primary analysis command.

## Synopsis

```sh
arbitraitor inspect <URL or file path> [flags]
```

## Description

`inspect` performs Level 1 (Inspect) assurance. It:

1. Retrieves the artifact (or reads from disk)
2. Records transport metadata (final URL after redirects, TLS certificate info)
3. Buffers the artifact in content-addressed storage
4. Identifies the content type
5. Runs configured detectors
6. Evaluates policy
7. Emits a verdict and findings

**No execution occurs.** The artifact bytes never reach a runtime.

## Flags

### `--receipt <PATH>`

Write an RFC 8785 JCS canonicalized JSON receipt to the specified path. The receipt includes:

- Artifact identity (SHA-256)
- Content type
- All findings
- Verdict and assurance level
- Transport metadata
- Policy snapshot digest
- Timestamp

```sh
arbitraitor inspect https://example.com/install.sh --receipt receipt.json
```

### `--detectors <NAMES>`

Run only the specified detectors. Names are comma-separated.

```sh
arbitraitor inspect script.sh --detectors shell,archive
```

Available detectors: `shell`, `archive`, `yarax`, `powershell`, `av`, `intel`.

### `--no-detectors`

Skip all detectors. Only retrieve, identify, and hash.

```sh
arbitraitor inspect https://example.com/file.txt --no-detectors
```

### `--content-type <TYPE>`

Override automatic content type detection. Useful when a server misreports type.

```sh
arbitraitor inspect script.sh --content-type application/x-shellscript
```

### `--native`

Treat the artifact as a native executable, not a script. Changes which detectors run (skips shell analysis, enables binary signatures).

```sh
arbitraitor inspect ./bin/mytool --native
```

### `--timeout <SECONDS>`

Maximum time for retrieval and analysis combined. Default is 120 seconds.

```sh
arbitraitor inspect large-archive.zip --timeout 300
```

## Output format

### Text output

```
Artifact:    sha256:a1b2c3d4e5f6...
Source:      https://example.com/install.sh (final URL after redirects)
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

### JSON output

Use `--output json` for machine-readable output:

```sh
arbitraitor inspect https://example.com/install.sh --output json
```

```json
{
  "artifact_digest": "sha256:a1b2c3d4e5f6...",
  "source": "https://example.com/install.sh",
  "content_type": "application/x-shellscript",
  "size_bytes": 4305,
  "findings": [
    {
      "id": "network:curl",
      "severity": "high",
      "title": "Downloads content via curl",
      "description": "The script uses curl to fetch remote content"
    }
  ],
  "verdict": "warn",
  "assurance_level": "inspect",
  "policy_snapshot_digest": "sha256:91ab..."
}
```

## Reading the output

**Severity levels** map to policy actions:

| Severity | Default policy action |
|----------|----------------------|
| Critical | Block (unless explicitly allowed) |
| High | Prompt |
| Medium | Warn |
| Low | Pass |

**Verdicts:**

| Verdict | Meaning |
|---------|---------|
| Pass | All findings below policy thresholds |
| Warn | Findings at or above thresholds, human review recommended |
| Incomplete | A detector could not complete, blocking by default |
| Block | Findings exceeded block thresholds |

The `Verdict` line always includes the assurance level in parentheses, e.g., `WARN (inspect)`, `PASS (mediated)`.

## Examples

```sh
# Basic inspection of a remote script
arbitraitor inspect https://example.com/install.sh

# With receipt for later approval
arbitraitor inspect https://example.com/install.sh --receipt receipt.json

# Inspect a local file
arbitraitor inspect ./downloads/untrusted-script.sh

# Specific detectors, no archive scanning
arbitraitor inspect script.sh --detectors shell

# Quick identify only
arbitraitor inspect file.bin --no-detectors
```
