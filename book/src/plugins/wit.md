# WIT Interfaces

Arbitraitor uses the WebAssembly Component Model (WASI Preview 2) for plugin isolation. Plugins are compiled to WASM components and communicate through WIT-defined interfaces.

## WIT overview

WIT (WebAssembly Interface Types) defines the types and functions a component can import and export. Each Arbitraitor plugin world has its own WIT package.

## Plugin worlds

### Detector world

```wit
package arbitraitor:plugin/detector@1.0.0;

interface analyzer {
  record artifact {
    digest: string,
    content-type: string,
  }

  record finding {
    id: string,
    severity: severity,
    title: string,
    description: string,
    locations: list<location>,
  }

  enum severity {
    low,
    medium,
    high,
    critical,
  }

  record location {
    path: string,
    offset: u64,
    line: u32,
  }

  analyze: func(artifact: artifact) -> list<finding>;
}

world detector {
  export analyzer;
}
```

### Intelligence world

```wit
package arbitraitor:plugin/intelligence@1.0.0;

interface lookup {
  record indicator {
    type: indicator-type,
    value: string,
  }

  enum indicator-type {
    url,
    domain,
    ip-address,
    sha256,
    email,
  }

  record match {
    indicator: indicator,
    source: string,
    confidence: confidence,
    last-seen: string,
    tags: list<string>,
  }

  enum confidence {
    low,
    medium,
    high,
  }

  lookup: func(indicator: indicator) -> list<match>;
}

world intelligence {
  export lookup;
}
```

### Provenance world

```wit
package arbitraitor:plugin/provenance@1.0.0;

interface verifier {
  record artifact {
    digest: string,
    size: u64,
  }

  record attestation {
    type: attestation-type,
    signer: string,
    timestamp: string,
    data: list<u8>,
  }

  enum attestation-type {
    minisign,
    cosign,
    tuf,
    gpg,
  }

  verify: func(artifact: artifact) -> option<attestation>;
}

world provenance {
  export verifier;
}
```

### Wrapper world

```wit
package arbitraitor:plugin/wrapper@1.0.0;

interface translator {
  record command {
    tool: string,
    args: list<string>,
    env: list<tuple<string, string>>,
  }

  translate: func(command: command) -> result<command, string>;
}

world wrapper {
  export translator;
}
```

## Host functions

Plugins can call host functions provided by Arbitraitor:

```wit
package arbitraitor:plugin/host@1.0.0;

interface host {
  // Read artifact bytes (opaque handle)
  read-artifact: func(digest: string) -> list<u8>;

  // Log a message
  log: func(level: log-level, message: string);

  // Get current time
  wall-clock: func() -> tuple<u64, u32>;  // seconds, nanoseconds

  // Get deterministic time for the current operation
  operation-time: func() -> tuple<u64, u32>;

  enum log-level {
    debug,
    info,
    warn,
    error,
  }
}

world host {
  import host;
}
```

## Compiling a Wasm component

### 1. Install tooling

```sh
cargo install cargo-component
wasmtime --version
```

### 2. Define WIT

Create `wit/my-detector.wit`:

```wit
package my-org:my-detector@1.0.0;

interface analyzer {
  record artifact {
    digest: string,
    content-type: string,
  }

  record finding {
    id: string,
    severity: severity,
    title: string,
    description: string,
  }

  enum severity {
    low,
    medium,
    high,
    critical,
  }

  analyze: func(artifact: artifact) -> list<finding>;
}

world my-detector {
  export analyzer;
}
```

### 3. Implement in Rust

```toml
# my-detector/Cargo.toml
[package]
name = "my-detector"
version = "1.0.0"
edition = "2021"

[lib]
crate-type = ["cdylib"]

[dependencies]
wit-bindgen = "0.28"
serde = { version = "1.0", features = ["derive"] }

[profile.release]
opt-level = "s"
lto = true
```

```rust
// src/lib.rs
use wit_bindgen::generate;

generate!({
    world: "my-detector",
    exports: {
        "my-org:my-detector/analyzer": Analyzer,
    }
});

struct Analyzer;

impl exports::analyzer::Analyzer for Analyzer {
    fn analyze(artifact: exports::analyzer::Artifact) -> Vec<exports::analyzer::Finding> {
        // Read artifact bytes via host
        let bytes = host::host::read_artifact(&artifact.digest);

        // Analyze content
        let mut findings = Vec::new();

        if contains_malicious_pattern(&bytes) {
            findings.push(exports::analyzer::Finding {
                id: "my-detector:bad-pattern".to_string(),
                severity: exports::analyzer::Severity::High,
                title: "Malicious pattern detected".to_string(),
                description: "Found known bad pattern".to_string(),
            });
        }

        findings
    }
}
```

### 4. Build

```sh
cargo component build --release
# Output: target/wasm32-wasip2/release/my_detector.wasm
```

## Host function reference

### `read-artifact`

Reads artifact bytes from CAS by digest. The plugin receives the content it was approved to analyze.

```rust
fn read-artifact(digest: &str) -> Vec<u8>
```

### `log`

Logs a message at the specified level.

```rust
fn log(level: LogLevel, message: &str)
```

### `wall-clock`

Returns the current wall clock time.

```rust
fn wall-clock() -> (u64, u32)  // (seconds since epoch, nanoseconds)
```

### `operation-time`

Returns a deterministic time for the current operation. This is monotonically increasing within a single pipeline run, allowing plugins to implement time-based logic without breaking determinism.

```rust
fn operation-time() -> (u64, u32)  // (seconds, nanoseconds)
```

## Resource limits

The host enforces resource limits on all plugins:

| Resource | Default limit |
|----------|---------------|
| Memory | 128 MB |
| Execution fuel | 1 billion instructions |
| Call deadline | 5 seconds |
| Host calls per invocation | 100 |
| Output size | 1 MB |
