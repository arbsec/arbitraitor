# Plugin Registry

The plugin registry manages discovery, loading, and lifecycle of all Arbitraitor plugins.

## Directory structure

Arbitraitor searches for plugins in these directories (in order):

1. Built-in plugins (compiled into the binary)
2. `~/.arbitraitor/plugins/` (user-local)
3. `./plugins/` (project-local)

Each plugin lives in its own subdirectory:

```
~/.arbitraitor/plugins/
├── my-detector/
│   ├── manifest.toml
│   └── my-detector.wasm
├── urlhaus/
│   ├── manifest.toml
│   └── urlhaus.wasm
└── my-wrapper/
    ├── manifest.toml
    └── my-wrapper
```

## Manifest format

```toml
[plugin]
id = "my-detector"
name = "My Custom Detector"
version = "1.0.0"
description = "Detects custom threat patterns"
authors = ["Your Name <you@example.com>"]

# Plugin type
type = "detector"  # detector | intelligence | provenance | wrapper

# WIT world
world = "arbitraitor:plugin/detector"

# Trust classification
trust-class = "community"  # builtin | first_party | community

[plugin.runtime]
type = "wasmtime"  # wasmtime | subprocess
path = "my-detector.wasm"

# For subprocess plugins:
# type = "subprocess"
# path = "/usr/local/bin/my-detector"
# expected-digest = "sha256:abc123..."

[plugin.capabilities]
# Network access (none allowed by default)
allow-network = false

# Filesystem read paths
allow-filesystem-read = []

# Environment variables
allow-environment = []

# For WASM plugins, capabilities are declared in WIT
# For subprocess plugins, they are enforced via manifest

[plugin.limits]
max-memory = "128MB"
max-call-time-ms = 5000
max-fuel = 1_000_000_000

[plugin.policy]
# Auto-load in enforcement mode
enforcement-load = false  # community plugins default to false
```

## Discovery process

```
1. Scan plugin directories
2. Parse each manifest.toml
3. Validate against schema
4. Check trust class against active policy
5. Register if policy allows
6. Load runtime on first use
```

Discovery runs at Arbitraitor startup and when `--reload-plugins` is passed.

## Trust class enforcement

The policy controls which trust classes can load:

```toml
[policy.plugins]
# Allow all built-in and first-party plugins
allow-builtin = true
allow-first-party = true

# Community plugins require explicit enable
allow-community = false
```

To run a community plugin:

```toml
[policy.plugins.community]
my-detector = { enabled = true }
```

## Plugin states

A plugin can be in one of these states:

| State | Meaning |
|-------|---------|
| **Discovered** | Found in directory, manifest valid |
| **Registered** | Passed trust check, in plugin registry |
| **Loaded** | Runtime instance created |
| **Initialized** | Received init call, ready to process |
| **Running** | Processing a request |
| **Failed** | Error during load, init, or call |
| **Unloaded** | Dropped due to idle or shutdown |

## Loading and initialization

Plugins are loaded lazily on first use:

```
PluginRegistry::get("my-detector")
  -> check trust class
  -> check not already loaded
  -> load runtime (Wasmtime or subprocess)
  -> send init message
  -> return plugin handle
```

The plugin receives its configuration and declared capabilities. It returns its version and concurrency limits.

## Subprocess plugin restrictions

Subprocess plugins run as isolated processes with:

- **Executable path**: Must be in the allowlist and digest-pinned
- **Arguments**: No shell interpolation, structured JSON only
- **Environment**: Clean environment, no inherited variables
- **File descriptors**: Closed except for stdin/stdout
- **Process group**: Isolated (Job Object on Windows)
- **Resource limits**: Memory, CPU, time enforced via cgroup/ulimit

## Plugin API versioning

WIT packages are versioned semantically. The plugin host tracks compatibility:

| Host version | Plugin world version | Compatible |
|-------------|---------------------|-----------|
| 1.0.0 | 1.0.0 | Yes |
| 1.0.0 | 1.1.0 | Yes (minor backward compat) |
| 1.0.0 | 2.0.0 | No (major bump) |
| 1.0.0 | 0.9.0 | No (preview) |

The `manifest.toml` declares which world version the plugin implements.
