# Verifying Update Manifests

Verify a signed update manifest (spec §34) using a minisign public key:

```sh
arbitraitor update verify manifest.json --key pubkey.pub
```

By default, the signature is loaded from `manifest.minisig` (minisign sidecar convention). To use a custom signature path:

```sh
arbitraitor update verify manifest.json --key pubkey.pub --signature custom.sig
```

Output shows the verified channel, manifest version, publisher, timestamps, and each target file with its declared SHA-256 and size.

> **Stability: Unstable.** Verified against commit `<sha>`.
