# status

The `status` command shows Arbitraitor's current health state, including store integrity, loaded detectors, and intelligence feed freshness.

## Synopsis

```sh
arbitraitor status [flags]
```

## Description

`status` runs a series of health checks and reports their results. It does not modify state or perform any retrieval.

## Flags

### `--json`

Output results as JSON for programmatic consumption:

```sh
arbitraitor status --json
```

### `--detectors`

Show detailed detector status including version and capability information.

### `--feeds`

Show intelligence feed status including last sync time and freshness.

### `--store`

Show store health including disk usage, corruption checks, and garbage collection status.

## Health checks

### Store

- **CAS integrity**: Verifies all stored digests match their content
- **Disk usage**: Reports bytes used and available
- **Retention policy**: Shows when objects are eligible for garbage collection
- **Quarantine**: Lists any objects awaiting manual review

### Detectors

- **Shell analyzer**: Verifies bash/dash parser is operational
- **Archive extractor**: Confirms supported formats are registered
- **YARA-X engine**: Checks rule pack version and match count
- **PowerShell analyzer**: Verifies AST parser is functional
- **Plugin host**: Confirms Wasmtime runtime is available

### Intelligence feeds

- **Last sync**: When each feed was last updated
- **Freshness**: Whether the feed is within its configured TTL
- **Indicator count**: How many active indicators each feed provides

### Configuration

- **Config file validity**: TOML parsing and schema validation
- **Policy file validity**: Rule syntax and import resolution
- **Secret resolution**: Whether referenced secrets can be loaded

## Exit codes

`arbitraitor status` follows the stable exit codes defined in spec §29
(see [CLI reference → Exit codes](../cli-reference.md#exit-codes)).

The codes most relevant to `status` are:

| Code | Meaning |
|------|---------|
| 0 | Status reported, no health issues |
| 1 | General operational error (cannot read store, daemon unreachable but not expected) |
| 33 | Required detector unavailable or stale — surfaced as a health finding |
| 60 | Internal integrity invariant failure |

## Examples

```sh
# Full status
arbitraitor status

# JSON output for monitoring
arbitraitor status --json

# Store health only
arbitraitor status --store

# Detector details
arbitraitor status --detectors

# Feed freshness
arbitraitor status --feeds
```

## Sample output

```
Arbitraitor status
==================

Store:
  CAS integrity:   OK (1,247 objects, 42.3 MB)
  Disk usage:      42.3 MB / 100 GB
  Quarantine:      0 objects
  Last GC:         2026-06-20 04:00:00 UTC

Detectors:
  shell:           OK (28 categories)
  archive:         OK (6 formats, 15 hazard types)
  yarax:           OK (1,847 rules)
  powershell:      OK
  plugin-host:     OK (Wasmtime 28.0)

Intelligence:
  urlhaus:         OK (last sync: 2 minutes ago)
  community:       STALE (last sync: 6 hours ago)

Config:
  config.toml:     OK
  policy.toml:     OK (12 rules, 3 gates)

Overall: OK
```
