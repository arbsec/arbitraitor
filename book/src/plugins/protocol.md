# Subprocess Protocol

Some plugins run as native subprocesses rather than Wasm components. This is used for integrations that require platform-specific binaries (e.g., antivirus scanners, package managers) that cannot be compiled to WASM.

## Protocol design

Communication uses length-prefixed JSON frames over stdin/stdout:

```
┌─ frame 1: request ────────────────────────────────────┐
│  {"jsonrpc": "2.0", "id": 1, "method": "analyze", ...}  │
└────────────────────────────────────────────────────────┘
┌─ frame 2: response ───────────────────────────────────┐
│  {"jsonrpc": "2.0", "id": 1, "result": {...}}           │
└────────────────────────────────────────────────────────┘
```

Each frame is preceded by an 8-byte big-endian length header:

```
[0x00 0x00 0x00 0x00 0x00 0x00 0x01 0x2B]  # 299 bytes follows
```

## Message types

### `init`

Sent once after process spawn to configure the plugin.

**Request:**
```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "init",
  "params": {
    "config": {
      "rule_paths": ["/etc/arbitraitor/rules"],
      "timeout_ms": 5000
    },
    "capabilities": {
      "allow_network": false,
      "allow_filesystem_read": ["/tmp"],
      "allow_environment": []
    }
  }
}
```

**Response:**
```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": {
    "version": "1.0.0",
    "ready": true,
    "max_concurrent_calls": 4
  }
}
```

### `analyze`

Analyze an artifact.

**Request:**
```json
{
  "jsonrpc": "2.0",
  "id": 2,
  "method": "analyze",
  "params": {
    "artifact": {
      "digest": "sha256:abc123...",
      "path": "/tmp/arbitraitor/artifact-xyz",
      "content_type": "application/x-shellscript"
    },
    "options": {
      "depth": 0,
      "parent_digest": null
    }
  }
}
```

**Response:**
```json
{
  "jsonrpc": "2.0",
  "id": 2,
  "result": {
    "findings": [
      {
        "id": "custom:malicious-pattern",
        "severity": "high",
        "title": "Matched malicious pattern",
        "description": "Found known bad pattern at offset 0x1a2b",
        "locations": [
          {"path": "/tmp/artifact", "offset": 6699, "line": 42}
        ]
      }
    ],
    "metadata": {
      "rules_loaded": 1847,
      "analysis_time_ms": 23
    }
  }
}
```

### `lookup`

Look up an indicator in intelligence feeds.

**Request:**
```json
{
  "jsonrpc": "2.0",
  "id": 3,
  "method": "lookup",
  "params": {
    "indicator": {
      "type": "url",
      "value": "https://evil.example.com/malware.exe"
    }
  }
}
```

**Response:**
```json
{
  "jsonrpc": "2.0",
  "id": 3,
  "result": {
    "matches": [
      {
        "indicator_type": "url",
        "indicator_value": "https://evil.example.com/malware.exe",
        "source": "urlhaus",
        "confidence": "high",
        "last_seen": "2026-06-20T12:00:00Z",
        "tags": ["malware", "payload"]
      }
    ]
  }
}
```

### `shutdown`

Clean plugin shutdown.

**Request:**
```json
{
  "jsonrpc": "2.0",
  "id": 4,
  "method": "shutdown",
  "params": {}
}
```

**Response:**
```json
{
  "jsonrpc": "2.0",
  "id": 4,
  "result": {
    "ok": true
  }
}
```

## Error responses

```json
{
  "jsonrpc": "2.0",
  "id": 2,
  "error": {
    "code": -32603,
    "message": "Analysis timed out",
    "data": {
      "stage": "pattern_matching",
      "elapsed_ms": 5000
    }
  }
}
```

Error codes:

| Code | Meaning |
|------|---------|
| -32700 | Parse error (malformed JSON) |
| -32600 | Invalid request (wrong method or params) |
| -32603 | Internal error (plugin crashed or timed out) |
| -32000 | Artifact not found |
| -32001 | Unsupported content type |

## Writing a subprocess plugin

### 1. Create the manifest

```toml
[plugin]
id = "my-av"
name = "My Antivirus"
version = "1.0.0"
type = "detector"

[plugin.runtime]
type = "subprocess"
path = "/usr/local/bin/my-av-scanner"
expected_digest = "sha256:abc123..."

[plugin.capabilities]
allow_network = false
allow_filesystem_read = ["/var/lib/my-av"]
allow_environment = []
```

### 2. Implement the protocol

```rust
use std::io::{self, Read, Write};

fn main() {
    let mut stdin = io::stdin().lock();
    let mut stdout = io::stdout().lock();

    loop {
        // Read frame header (8 bytes)
        let mut header = [0u8; 8];
        stdin.read_exact(&mut header).unwrap();
        let len = u64::from_be_bytes(header) as usize;

        // Read frame body
        let mut body = vec![0u8; len];
        stdin.read_exact(&mut body).unwrap();

        // Parse JSON-RPC request
        let request: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let id = request["id"].as_i64().unwrap();
        let method = request["method"].as_str().unwrap();

        // Handle request
        let response = match method {
            "init" => handle_init(&request["params"]),
            "analyze" => handle_analyze(&request["params"]),
            "lookup" => handle_lookup(&request["params"]),
            "shutdown" => break handle_shutdown(&request["params"]),
            _ => error_response(id, -32600, "Unknown method"),
        };

        // Write response frame
        let json = serde_json::to_vec(&response).unwrap();
        let header = (json.len() as u64).to_be_bytes();
        stdout.write_all(&header).unwrap();
        stdout.write_all(&json).unwrap();
        stdout.flush().unwrap();
    }
}
```

### 3. Security considerations

- Never echo untrusted input back to stdout
- Always honor resource limits
- Use structured output, never shell interpolation
- Validate all input before processing
