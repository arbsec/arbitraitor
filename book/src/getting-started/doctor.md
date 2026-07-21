# Checking system health

The `doctor` command runs system health diagnostics. It prints a human-readable report by default and can emit JSON for automation.

## Run doctor

```sh
arbitraitor doctor
```

## With custom paths

```sh
arbitraitor doctor --cas-dir /custom/store --rules /custom/rules
```

## JSON output

```sh
arbitraitor doctor --json
```

Each check reports `pass`, `fail`, `warn`, or `skipped`.

## What it checks

- **Store**: CAS health, writability, object counts, and disk usage
- **Detectors and YARA-X rules**: Loaded versions and rule parse status
- **Policy**: Validity of configured standalone policy files
- **AV and scanners**: ClamAV/Defender availability and signature freshness when configured
- **Feeds and updates**: Feed signature files and update trust-root key readability
- **Sandbox**: Platform sandbox adapter availability
- **Plugins**: Manifest readability and protocol compatibility
- **Wrappers**: Curl/wget semantic coverage, shim PATH order, and original-tool resolution posture
- **Environment**: Clock plausibility and proxy URL-scheme checks
- **Receipts**: Receipt signing key readability when configured

See the [CLI reference](../cli-reference.md#doctor-command) for full flag details.
