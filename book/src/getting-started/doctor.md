# Checking system health

The `doctor` command runs system health diagnostics and outputs a JSON report covering store health, detector status, and rule pack versions.

## Run doctor

```sh
arbitraitor doctor
```

## With custom paths

```sh
arbitraitor doctor --cas-dir /custom/store --rules /custom/rules
```

## What it checks

- **Store**: CAS health, corruption check, disk usage
- **Detectors**: Loaded plugins and their status
- **Rule packs**: Version and integrity of loaded YARA-X rules
- **Config**: Validity of configuration files

See the [CLI reference](../cli-reference.md#doctor-command) for full flag details.
