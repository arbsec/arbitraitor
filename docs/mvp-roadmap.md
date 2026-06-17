# MVP Roadmap

**Goal**: Deliver the minimum viable Arbitraitor pipeline — `arbitraitor fetch URL` and `arbitraitor scan FILE` that inspect shell scripts and produce a verdict with receipt.

## MVP Definition

The MVP delivers the core value proposition: **replace `curl | sh` with a safe, inspected alternative**.

### Critical Pipeline
```
resolve policy → retrieve once → buffer in CAS → identify content
→ scan (shell AST + detection rules) → evaluate policy → verdict
→ release exact bytes → emit receipt
```

### MVP Scope (must-have)
1. HTTPS retrieval with SSRF/redirect/TLS policy ✅ (arbitraitor-fetch)
2. Content-addressed immutable storage ✅ (arbitraitor-store)
3. Shell normalization (AST, constants, decode chains) ✅ (arbitraitor-shell)
4. Artifact identification (file type classifier) ❌ (arbitraitor-artifact)
5. Shell detection rules (29 categories) ❌ (arbitraitor-shell, #38)
6. Policy engine MVP (typed TOML → verdict) ❌ (arbitraitor-policy)
7. Analysis coordinator (orchestrate detectors) ❌ (arbitraitor-analysis)
8. Safe destination release ❌ (arbitraitor-exec, #41)
9. Receipt system (JSON output + canonical form) ❌ (arbitraitor-receipt)
10. CLI MVP (fetch, scan, explain commands) ❌ (arbitraitor-cli)

### Post-MVP (deferred)
- YARA-X integration
- Antivirus integrations (ClamAV, Defender)
- Archive inspection
- Recursive payload discovery
- Sandbox / mediated execution
- Plugin system (Wasmtime)
- Shell hooks / wrappers
- MCP gateway
- PowerShell analysis
- Community intelligence feeds
- Update security / TUF
- Daemon mode

## Phases

### Phase 1: Secure Fetch Core ✅ DONE
- Workspace scaffold, CI, tooling
- Domain model types
- HTTP retrieval with SSRF/redirect policy
- Content-addressed store
- Core state machine
- Update verifier trait

### Phase 2: Static Analysis ✅ DONE (normalization layer)
- Shell normalization (AST, constants, decode chains)
- Execution context builder

### Phase 3: Detection + Policy (CURRENT)
- Shell detection rules (29 categories)
- Policy engine MVP
- Analysis coordinator
- Receipt system

### Phase 4: Integration
- CLI MVP (fetch, scan, explain)
- Safe destination release
- End-to-end pipeline wiring

### Phase 5: Hardening
- Adversarial review
- Fuzz targets
- Property tests for invariants
- Performance benchmarks

## Wave Plan

| Wave | Issues | Status |
|------|--------|--------|
| Foundation | #31, #27, #28 | ✅ Merged |
| Wave 2 | #36, #30, #32, #40 | ✅ Merged |
| Wave 3 | #34, #37 | ✅ Merged |
| Wave 4A | #41, shell detection, artifact ID | 🔄 Planning |
| Wave 4B | Policy engine, receipt system | ⏳ Blocked on 4A |
| Wave 4C | Analysis coordinator, CLI MVP | ⏳ Blocked on 4B |

## Test Inventory
- Main: 181 tests passing
- Foundation: model (31), fetch (11), testkit (12)
- Wave 2: core (17), update (27)
- Wave 3: store (15), shell (40)
