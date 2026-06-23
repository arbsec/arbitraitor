# ADR 0013: Plan-bound approval capability

**Status:** Accepted
**Date:** 2026-06-16
**Issue:** #8

## Context

The adversarial review (C-08) identified that digest-only approval is **replayable**. The same bytes may be harmless when viewed, dangerous when executed natively, or behave differently with another interpreter, argument vector, working directory, environment, destination, privilege request, or network policy.

Additionally (H-11), an AI agent that proposes a command must not be able to manufacture or confirm the human approval for that command through the same tool capability.

## Decision

Replace digest-only approval with **plan-bound approval capabilities**.

### Canonical execution plan

Approval binds to a canonical execution plan containing:

```rust
pub struct ExecutionPlan {
    pub artifact_digest: Sha256Digest,
    pub operation: OperationType,          // fetch, run, scan, unpack
    pub release_mode: ReleaseMode,         // file, stdout, execute, mount
    pub interpreter: InterpreterIdentity,   // path + digest or signer
    pub argument_vector: Vec<String>,
    pub environment_profile_digest: Sha256Digest,
    pub working_directory_policy: WorkDirPolicy,
    pub filesystem_grants: Vec<FilesystemGrant>,
    pub network_grants: NetworkGrants,
    pub sandbox_capabilities: SandboxRequirements,
    pub release_destination: Option<DestinationSpec>,
    pub policy_digest: Sha256Digest,
    pub detector_snapshot_digest: Sha256Digest,
    pub intelligence_snapshot_digest: Sha256Digest,
    pub expiry: SystemTime,
    pub nonce: OperationId,                 // single-use
}
```

**Any material difference in the plan invalidates the approval.** Changing the interpreter, adding an argument, altering the environment, changing the destination, or updating the policy snapshot all require fresh approval.

### Approval flow

```sh
# Step 1: inspect and produce a receipt
arbitraitor fetch https://example.com/install.sh --receipt receipt.json

# Step 2: review and approve the execution plan
arbitraitor approve receipt.json --output approval.json

# Step 3: execute using the approved plan
arbitraitor execute --approval approval.json
```

The approval capability is a **signed token** containing the plan digest, approver identity, approval method, expiry, and nonce. It is non-replayable across changed plans.

### Human approval display

For elevated findings, interactive approval requires typing a prefix of the plan digest:

```
Artifact: sha256:7c...
Plan:     sha256:91...
Type the first 12 characters of the plan digest to override:
```

This binds human attention to both the artifact identity and the execution context, not just the bytes.

### Agent capability separation

For AI agent and MCP integration, three **separate capabilities** are exposed:

| Capability | What it does | Who uses it |
|------------|-------------|-------------|
| `inspect` | Retrieve, scan, report findings. No release. | Agent |
| `request_approval` | Submit plan for human review. Cannot self-approve. | Agent |
| `execute_approved` | Execute using a pre-issued approval token. | Agent or CI |

Rules:
- The agent that requests inspection or execution **cannot** also satisfy human approval through the same capability.
- Approval is rendered by the **core-owned UI** or another authenticated channel — never through agent-provided text.
- Agent-provided prose is **never** inserted into the approval prompt.
- Unattended automation requires a **pre-issued policy capability** (e.g., CI with a pinned policy and digest expectation), not simulated user consent.

### Non-interactive mode

`--non-interactive` must **never** infer approval. A prompt verdict becomes block unless policy defines an alternative (e.g., auto-pass for pinned-digest CI workflows).

## Consequences

- A leaked or replayed approval token cannot be used for a materially different operation.
- AI agents cannot manufacture human approval.
- CI pipelines use pre-issued policy capabilities with pinned digests, not generic `--yes` bypasses.
- The approval model is more complex than digest-only, but the security guarantee is materially stronger.

## Alternatives considered

- **Digest-only approval (`--approve sha256:...`):** Rejected. Replayable across interpreters, arguments, environments, and destinations.
- **Generic `--yes` / `--force`:** Rejected. No binding to specific plan.
- **Trusted UI in plugin:** Rejected. Creates phishing channel.

## References

- `.spec/arbitraitor-adversarial-review-and-gap-analysis.md` C-08, H-11
- `.spec/arbitraitor-comprehensive-spec-v0.4.md` §25.3 (Approval), §33 (AI agent and MCP integration)
- [ADR 0007](./0007-assurance-levels-model.md) — Assurance levels
