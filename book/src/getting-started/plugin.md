# Managing plugins

Arbitraitor supports a plugin system with subprocess and Wasmtime Component Model runtimes. The `plugin` command manages the plugin registry.

## List registered plugins

```sh
arbitraitor plugin list
```

## Discover plugins

Discovery scans default plugin directories and registers new plugins:

```sh
arbitraitor plugin discover
```

## Inspect a specific plugin

```sh
arbitraitor plugin info <id>
```

Outputs the full plugin manifest as JSON, including identity, version, trust class, and plugin type.

## Remove a plugin

```sh
arbitraitor plugin remove <id>
```

See the [CLI reference](../cli-reference.md#plugin-command) for full details.
