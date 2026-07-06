# Checking system health

The `doctor` command runs system health diagnostics and prints a human-readable health panel by default. It exits non-zero when any health or shell-integration check fails.

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

## What it checks

- **Store**: CAS health, corruption check, disk usage
- **Detectors**: Loaded plugins and their status
- **Rule packs**: Version and integrity of loaded YARA-X rules
- **Shell integration**: detected shell, installed shims, shim directory on `PATH`, and rcfile init block

When shell integration is incomplete, `doctor` prints a `Fix shell integration:` section with only the commands needed for failing checks.

See the [CLI reference](../cli-reference.md#doctor-command) for full flag details.
