# Managing Storage

Arbitraitor stores all inspected artifacts in a content-addressed store (CAS) keyed by SHA-256.

## List stored artifacts

```sh
arbitraitor store list
```

Prints each artifact's digest prefix, byte size, and lock status.

### Inspect a specific artifact

```sh
arbitraitor store inspect <sha256>
```

Prints the full metadata entry as JSON, including source URL, content type, retention mode, and lock state.

### Garbage collection

Remove old or expired artifacts from the store:

```sh
# Collect all unlocked, non-forensic artifacts
arbitraitor store gc

# Only collect artifacts older than 30 days
arbitraitor store gc --max-age-days 30
```

GC preserves:

- **Locked** artifacts currently in use by an active operation.
- **Forensic** artifacts explicitly marked for indefinite retention.

> **Stability: Unstable.** Verified against commit `<sha>`.
