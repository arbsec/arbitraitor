# ADR 0010: Platform provenance preservation

**Status:** Accepted
**Date:** 2026-06-16
**Issue:** #5

## Context

The original v0.3 specification permitted optional removal of operating-system
quarantine metadata. macOS uses quarantine information (`com.apple.quarantine`)
as part of Gatekeeper behavior. Windows uses the `Zone.Identifier` alternate
data stream (Mark of the Web / MOTW) which feeds SmartScreen and other
protections.

The adversarial review (C-05) identified that silently removing these markers
disables platform defenses.

## Decision

**Preserve or add** platform provenance markers. **Never silently remove them.**

### macOS

- Attach or preserve `com.apple.quarantine` extended attribute for artifacts
  released to the filesystem that were retrieved from the Internet.
- The quarantine attribute includes the agent name, bundle ID, timestamp, and
  serialization of the download URL where policy permits.
- Preserve code signatures and notarization metadata.
- An explicit, audited `unquarantine` operation is available only if the user
  deliberately requests it and policy permits. It is logged in the receipt.

Implementation: use `xattr_set` / `fsetxattr` to attach
`com.apple.quarantine` with a format like:

```text
com.apple.quarantine: 0083;<timestamp>;arbitraitor;<download-url-hash>
```

### Windows

- Attach or preserve Mark of the Web (`Zone.Identifier` alternate data stream)
  for artifacts released to the filesystem.
- Include the `ZoneId` (3 = Internet), `ReferrerUrl`, and `HostUrl` where
  policy permits.
- Preserve Authenticode signatures.
- Never silently clear `Zone.Identifier`.

Implementation: write to `file:Zone.Identifier:$DATA` using NTFS alternate
data streams via the Windows API.

### Cross-platform abstraction

A trait in `arbitraitor-exec` (or a dedicated platform module) provides:

```rust
pub trait ProvenanceMarker {
    /// Attach or preserve platform download provenance for the given path.
    fn apply(&self, path: &Path, source: &ProvenanceSource) -> Result<()>;

    /// Check whether provenance markers are present.
    fn verify(&self, path: &Path) -> Result<ProvenanceStatus>;
}

pub struct ProvenanceSource {
    pub download_url: Option<RedactedUrl>,
    pub retriever_version: &'static str,
    pub timestamp: SystemTime,
}
```

### Archive extraction

Files created by archive extraction inherit provenance markers according to
platform behavior. Propagation limitations are documented:

- ZIP entries do not carry macOS quarantine attributes.
- NTFS Zone.Identifier is not per-entry in standard archives.
- Arbitraitor applies provenance markers to extracted files that are
  subsequently released, not to files only inspected in the staging directory.

## Consequences

- Platform defenses (Gatekeeper, SmartScreen) remain active for artifacts
  released by Arbitraitor.
- A user who downloads a malicious script through Arbitraitor and then
  double-clicks it still gets the OS-level warning.
- The receipt records whether provenance markers were applied.
- An explicit `unquarantine` is available but audited and never default.

## Alternatives considered

- **Optional removal (v0.3 spec):** Rejected. Disables platform defenses
  silently.
- **Always strip and rely on Arbitraitor's own analysis:** Rejected. Defense in
  depth — OS-level controls should complement, not be replaced by, Arbitraitor.
- **Never touch provenance at all:** Partially accepted. Arbitraitor preserves
  existing markers but may need to add them when the original download did not
  carry them (e.g., when acting as a proxy for another downloader).

## References

- `docs/spec/spec.md` C-05
- `docs/spec/spec.md` §9.20 (Platform provenance
  preservation)
- [macOS quarantine properties](https://developer.apple.com/documentation/foundation/urlresourcevalues/quarantineproperties)
- [Windows Zone.Identifier](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/6e3f7352-d11c-4d76-8c39-2516a9df36e8)
- [Windows SmartScreen reputation](https://learn.microsoft.com/en-us/windows/apps/package-and-deploy/smartscreen-reputation)
