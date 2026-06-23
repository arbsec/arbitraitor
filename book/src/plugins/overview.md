# Plugins Overview

Arbitraitor supports a plugin system for extending detection, intelligence, and execution capabilities. Plugins are isolated from the core using either the Wasmtime Component Model or a subprocess protocol.

## Plugin types

| Type | Role | Examples |
|------|------|----------|
| **Detector** | Analyzes artifacts, returns findings | YARA-X rules, custom AV, language analyzers |
| **Intelligence** | Provides threat indicators | URLhaus adapter, community feed, custom TI |
| **Provenance** | Verifies signatures and attestations | minisign, cosign, custom PKI |
| **Wrapper** | Translates download tool arguments | curl, wget, fetch |

Each plugin type has a specific WIT world (interface contract) that limits what capabilities it can access.

## Trust tiers

Plugins are classified by trust level:

| Tier | Description | Enforcement |
|------|-------------|-------------|
| **Built-in** | Ships with Arbitraitor | Always loaded in enforcement mode |
| **First-party** | Developed by ArbSec team | Always loaded, code reviewed |
| **Community** | Submitted by users | Disabled by default in enforcement mode |

See [ADR 0011](../adr/0011-plugin-trust-classification.md) for the full trust classification model.

## Plugin manifest

Every plugin has a `manifest.toml`:

```toml
[plugin]
id = "my-detector"
name = "My Custom Detector"
version = "1.0.0"
type = "detector"  # detector | intelligence | provenance | wrapper

# WIT world this plugin implements
world = "arbitraitor:plugin/detector"

# Trust tier
trust_class = "community"  # builtin | first_party | community

# Plugin binary
[plugin.runtime]
type = "wasmtime"  # wasmtime | subprocess
path = "./my-detector.wasm"

# Or for subprocess:
[plugin.runtime]
type = "subprocess"
path = "/usr/local/bin/my-detector"
expected_digest = "sha256:abc123..."

# Capabilities requested by this plugin
[plugin.capabilities]
# For WASM: declared in WIT, enforced by runtime
# For subprocess: explicit allowlist
allow_network = false
allow_filesystem_read = ["/tmp/arbitraitor"]
allow_environment = []
```

## Plugin lifecycle

```
discover -> load -> init -> call -> shutdown
```

### Discover

Plugins are discovered from configured search directories:

1. Read `~/.arbitraitor/plugins/*/manifest.toml`
2. Validate manifest schema
3. Check trust class against policy
4. Add to available plugin registry

### Load

The plugin host loads the runtime instance:

- **Wasmtime**: Initialize Wasmtime engine with resource limits
- **Subprocess**: Spawn process with clean environment, closed descriptors

### Init

The plugin receives initialization data:

```rust
// For WASM plugins
init {
    config: PluginConfig,
    workspace: WorkspaceCapabilities,
}

// For subprocess plugins
{"type": "init", "config": {...}}
```

The plugin validates the config and returns capabilities it will use.

### Call

The core calls the plugin with input data:

```rust
// For detector plugins
fn analyze(&self, artifact: ArtifactHandle) -> Vec<Finding>;

// For intelligence plugins
fn lookup(&self, indicator: Indicator) -> Vec<IndicatorMatch>;
```

### Shutdown

When the pipeline completes or a timeout is reached, the plugin is dropped:

- WASM: Guest memory is freed, resource limits are enforced
- Subprocess: Process is terminated with SIGTERM, then SIGKILL if needed

## Capability enforcement

Plugins declare capabilities in their WIT interface and cannot exceed them at runtime.

### Wasmtime sandbox defaults

| Control | Default |
|---------|---------|
| Network | None |
| Filesystem | None |
| Environment | None |
| Clock | Deterministic or host-provided only |
| Memory | Bounded (128 MB default) |
| Execution fuel | Bounded (1B instructions default) |
| Host calls | Bounded by count and deadline |

### Subprocess controls

| Control | Enforcement |
|---------|-------------|
| Executable path | Allowlisted, digest-pinned |
| Arguments | Structured (no raw shell strings) |
| Environment | Clean, explicit allowlist |
| Descriptors | Closed inherited |
| Process group | Isolated (Job Object on Windows) |
| Timeout | Enforced with kill-tree |
| Output size | Limited |
| Memory | Limited via cgroup/resource limits |

## Writing a detector plugin

See [WIT Interfaces](./wit.md) for the detector world definition and [Subprocess Protocol](./protocol.md) for the JSON protocol format.

## Plugin security

- Plugins cannot access the filesystem unless explicitly granted
- Plugins cannot make network calls unless explicitly granted
- WASM plugins are memory-isolated from the host process
- Subprocess plugins are killed if they exceed resource limits
- No plugin can bypass the approval flow
