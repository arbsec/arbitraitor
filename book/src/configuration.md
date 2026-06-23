# Configuration

Arbitraitor uses TOML configuration files with layered defaults and project-specific overrides.

## Configuration file locations

Arbitraitor reads configuration from (in order of precedence, later wins):

1. Built-in defaults
2. `~/.arbitraitor/config.toml` (user-level)
3. `./.arbitraitor/config.toml` (project-level, if present)
4. Path specified by `--config <PATH>` (overrides all of the above)

Project-level configuration (`./.arbitraitor/config.toml`) may only **tighten** inherited policy. It cannot add trust roots, enable plugins, or weaken execution controls. See [ADR 0017](adr/0017-monotonic-project-configuration.md) for details.

## All configuration sections

### `[fetch]`

Controls HTTP retrieval behavior.

```toml
[fetch]
# Maximum time for a single retrieval (seconds)
timeout = 30

# Maximum number of redirects to follow
max_redirects = 10

# TLS certificate verification
verify_tls = true

# Custom CA certificate bundle (path or "system")
# ca_bundle = "system"

# Proxy URL (http, https, socks5)
# proxy = "socks5://localhost:1080"

# User agent string
user_agent = "arbitraitor/0.1.0"

# Maximum response body size (bytes)
max_body_size = 100_000_000  # 100 MB

# SSRF protection: block private IP ranges
block_private_ip = true

# SSRF protection: block link-local addresses
block_link_local = true
```

### `[policy]`

Controls verdict handling and approval flow.

```toml
[policy]
# Default action when findings exceed thresholds
default_action = "prompt"  # pass | warn | prompt | block

# Action in non-interactive mode when prompt is required
non_interactive_prompt_action = "block"  # pass | warn | block

# Verdict thresholds by severity
[policy.thresholds]
critical = "block"
high = "prompt"
medium = "warn"
low = "pass"

# Native binary execution gate
[policy.gates]
native = false  # require --native flag to run native binaries
network_in_mediated = false  # allow network in mediated execution
privilege_elevation = false  # allow sudo/su/doas in scripts
```

### `[detectors]`

Enables and configures individual detectors.

```toml
[detectors]
# Shell script analysis
shell_analysis = true
max_shell_script_size = 5_000_000  # bytes

# Archive extraction and inspection
archive_analysis = true
max_archive_depth = 10
max_archive_size = 500_000_000  # bytes
max_archive_members = 10_000

# YARA-X rule scanning
yarax_analysis = true
yarax_rules_path = "./rules"  # path to .yarax files

# PowerShell analysis
powershell_analysis = true

# Antivirus adapters
av_analysis = true
# av_vendor = "clamav" | "defender"

# Intelligence feed matching
intel_matching = true
```

### `[store]`

Content-addressed storage configuration.

```toml
[store]
# Store directory
path = "~/.arbitraitor/store"

# Maximum store size (bytes)
max_size = "10GB"

# Default retention period (days)
retention_days = 90

# Garbage collection schedule (cron expression)
# gc_schedule = "0 4 * * *"  # daily at 4 AM UTC

# Quarantine directory for manual review
quarantine_path = "~/.arbitraitor/quarantine"

# Enable cryptographic integrity checking
integrity_check = true
```

### `[intel]`

Threat intelligence feed configuration.

```toml
[intel]
# Enable intelligence matching
enabled = true

# URLhaus feed for malware URLs
[intel.feeds.urlhaus]
enabled = true
url = "https://urlhaus.abuse.ch/downloads/json/"
api_key = "secret://env/URLHAUS_API_KEY"  # optional
refresh_interval = "1h"
cache_ttl = "24h"

# Community submissions feed
[intel.feeds.community]
enabled = true
url = "https://api.arbitraitor.org/community/indicators"
api_key = "secret://env/COMMUNITY_API_KEY"
refresh_interval = "6h"
cache_ttl = "24h"
```

### `[exec]`

Mediated execution configuration.

```toml
[exec]
# Default assurance level for run command
default_assurance = "mediated"  # mediated | contained

# Working directory for mediated execution
# temp = use system temp directory (default)
# current = use current working directory
working_dir = "temp"

# Output size limit (bytes)
output_limit = 10_000_000  # 10 MB

# Execution timeout (seconds)
timeout = 300

# Sandbox profile
[exec.sandbox]
# Seccomp profile (auto, none, strict)
seccomp = "auto"

# Landlock filesystem restrictions (auto, none, strict)
landlock = "auto"

# Network policy in mediated mode (deny, read-only, full)
network = "deny"
```

### `[plugins]`

Plugin runtime configuration.

```toml
[plugins]
# Enable plugin host
enabled = true

# Plugin search directories
paths = [
  "~/.arbitraitor/plugins",
  "./plugins",
]

# Wasmtime configuration
[plugins.wasmtime]
# Maximum memory per plugin instance (bytes)
max_memory = 134_217_728  # 128 MB

# Maximum execution time per call (ms)
call_timeout = 5000

# Maximum fuel (instructions)
max_fuel = 1_000_000_000

# Allow clock access
allow_clock = false

# Allow random
allow_random = true

# Subprocess plugin configuration
[plugins.subprocess]
# Allowed executable paths
allowed_paths = [
  "/usr/bin/clamscan",
  "/usr/bin/yara",
]

# Require digest pinning for executables
pin_executables = true
```

### `[receipt]`

Receipt generation configuration.

```toml
[receipt]
# Signing key for receipts
signing_key = "secret://env/RECEIPT_SIGNING_KEY"

# Include transport metadata in receipts
include_transport_metadata = true

# Include detector findings in receipts
include_findings = true

# Receipt format version
format_version = "1.0"
```

### `[logging]`

Logging configuration.

```toml
[logging]
# Log level (error, warn, info, debug, trace)
level = "info"

# Log format (text, json, compact)
format = "text"

# Output (stdout, stderr, file)
output = "stderr"

# Log file path (if output includes file)
path = "~/.arbitraitor/logs/arbitraitor.log"

# Include timestamp in logs
timestamps = true

# Enable structured fields
structured = true
```

## Secret references

Secrets are never stored in configuration files. Instead, use secret references:

```toml
# From an environment variable
api_key = "secret://env/URLHAUS_API_KEY"

# From a file (path is expanded)
cert = "secret://file//path/to/cert.pem"

# From keyring (system keyring)
token = "secret://keyring/service/account"
```

The `secret://` prefix tells Arbitraitor to resolve the value at runtime from the specified source.

## Environment variables

These environment variables override configuration values:

| Variable | Overrides | Example |
|----------|-----------|---------|
| `ARBITRAITOR_CONFIG` | Config file path | `/path/to/config.toml` |
| `ARBITRAITOR_POLICY` | Policy file path | `/path/to/policy.toml` |
| `ARBITRAITOR_LOG_LEVEL` | Log level | `debug` |
| `ARBITRAITOR_STORE_PATH` | Store directory | `/path/to/store` |
| `ARBITRAITOR_NO_COLOR` | Disable color output | `1` |
