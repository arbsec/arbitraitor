//! Plan-bound approval capability file (spec §28.5, ADR-0013).
//!
//! The CLI `approve` command writes an [`ApprovalFile`] that binds every
//! material execution-plan dimension. The `execute` command recomputes the
//! canonical plan digest from the file's plan fields and rejects any mismatch,
//! so a file tampered after approval cannot be used.

use std::fmt::Write as _;

use arbitraitor_model::ids::Sha256Digest;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Current approval-file schema version.
pub const APPROVAL_SCHEMA_VERSION: u32 = 2;

/// Fixed MVP execution-profile constants shared with the MCP canonical plan.
/// Changing any of these invalidates outstanding approvals by construction.
const OPERATION: &str = "execute";
const RELEASE_MODE: &str = "execute";
const INTERPRETER_ARGUMENTS: &[&str] = &["--noprofile", "--norc"];
const ENVIRONMENT_PROFILE_DIGEST: &str = "mvp ExecutionContext allowlist v1";
const WORKING_DIRECTORY_POLICY: &str = "sandbox-root-stdin-fed";
const FILESYSTEM_GRANTS: &[&str] = &[];
const SANDBOX_CAPABILITIES: &str = "prctl NoNewPrivs + close_range fd closure";
const RELEASE_DESTINATION: &str = "inline-execute";

/// Errors produced while building or verifying a plan-bound approval file.
#[derive(Debug, thiserror::Error)]
pub enum ApprovalError {
    /// The approval-file schema version is unsupported.
    #[error("unsupported approval schema version: {0}")]
    UnsupportedSchema(u32),
    /// The recomputed plan digest does not match the stored digest.
    #[error("plan digest mismatch: approval file was tampered or bound to a different plan")]
    PlanDigestMismatch,
    /// The approval has expired.
    #[error("approval has expired")]
    Expired,
    /// The approval is missing a required field.
    #[error("approval missing required field: {field}")]
    MissingField {
        /// Name of the missing field.
        field: &'static str,
    },
}

/// Plan-bound approval capability file (spec §28.5, ADR-0013).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ApprovalFile {
    /// Approval-file schema version.
    pub schema_version: u32,
    /// SHA-256 of the approved artifact as lowercase hex.
    pub artifact_sha256: String,
    /// Operation type (always `"execute"` for the MVP).
    pub operation: String,
    /// Release mode (always `"execute"` for the MVP).
    pub release_mode: String,
    /// Interpreter binary path.
    pub interpreter: String,
    /// Interpreter argument vector (e.g. `["--noprofile", "--norc"]`).
    pub interpreter_arguments: Vec<String>,
    /// Digest of the mediated environment profile.
    pub environment_profile_digest: String,
    /// Working-directory policy label.
    pub working_directory_policy: String,
    /// Filesystem grants bound to this approval.
    pub filesystem_grants: Vec<String>,
    /// Whether network access is isolated (denied).
    pub network_isolated: bool,
    /// Sandbox capabilities label.
    pub sandbox_capabilities: String,
    /// Release destination label.
    pub release_destination: String,
    /// Policy snapshot digest at approval time.
    pub policy_snapshot_digest: String,
    /// Detector snapshot digest at approval time.
    pub detector_snapshot_digest: String,
    /// Canonical plan digest binding all plan fields above.
    pub plan_digest: String,
    /// Single-use nonce.
    pub nonce: String,
    /// Approver identity.
    pub approver: String,
    /// Approval timestamp (Unix seconds).
    pub approved_at: u64,
    /// Expiry timestamp (Unix seconds).
    pub expires_at: u64,
    /// Verdict at approval time.
    pub verdict: String,
}

/// Inputs that determine the execution plan for the CLI path.
pub struct ExecutionPlanInputs {
    /// Artifact SHA-256.
    pub artifact_sha256: Sha256Digest,
    /// Whether the execution will isolate (deny) network.
    pub network_isolated: bool,
    /// Policy snapshot digest.
    pub policy_snapshot_digest: String,
    /// Detector snapshot digest.
    pub detector_snapshot_digest: String,
}

impl ApprovalFile {
    /// Computes the canonical plan digest from the plan-bound fields.
    ///
    /// The digest covers every field that materially affects execution.
    /// Fields outside the plan (`nonce`, `approver`, `approved_at`,
    /// `expires_at`, `verdict`, `schema_version`, and `plan_digest` itself)
    /// are excluded.
    #[must_use]
    pub fn compute_plan_digest(&self) -> String {
        let mut buf = String::new();
        // Deterministic field-order encoding — no serde_json dependency needed
        // and immune to struct field reordering.
        writeln!(buf, "artifact_sha256={}", self.artifact_sha256).unwrap_or(());
        writeln!(buf, "operation={}", self.operation).unwrap_or(());
        writeln!(buf, "release_mode={}", self.release_mode).unwrap_or(());
        writeln!(buf, "interpreter={}", self.interpreter).unwrap_or(());
        writeln!(
            buf,
            "interpreter_arguments={}",
            self.interpreter_arguments.join(",")
        )
        .unwrap_or(());
        writeln!(
            buf,
            "environment_profile_digest={}",
            self.environment_profile_digest
        )
        .unwrap_or(());
        writeln!(
            buf,
            "working_directory_policy={}",
            self.working_directory_policy
        )
        .unwrap_or(());
        writeln!(
            buf,
            "filesystem_grants={}",
            self.filesystem_grants.join(",")
        )
        .unwrap_or(());
        writeln!(buf, "network_isolated={}", self.network_isolated).unwrap_or(());
        writeln!(buf, "sandbox_capabilities={}", self.sandbox_capabilities).unwrap_or(());
        writeln!(buf, "release_destination={}", self.release_destination).unwrap_or(());
        writeln!(
            buf,
            "policy_snapshot_digest={}",
            self.policy_snapshot_digest
        )
        .unwrap_or(());
        writeln!(
            buf,
            "detector_snapshot_digest={}",
            self.detector_snapshot_digest
        )
        .unwrap_or(());
        let mut hasher = Sha256::new();
        hasher.update(buf.as_bytes());
        hex::encode(hasher.finalize())
    }

    /// Verifies that the stored `plan_digest` matches a recomputation.
    ///
    /// # Errors
    ///
    /// Returns [`ApprovalError::PlanDigestMismatch`] when any plan field was
    /// altered after approval, or [`ApprovalError::UnsupportedSchema`] when
    /// the schema version is not current.
    pub fn verify(&self, now: u64) -> Result<(), ApprovalError> {
        if self.schema_version != APPROVAL_SCHEMA_VERSION {
            return Err(ApprovalError::UnsupportedSchema(self.schema_version));
        }
        let recomputed = self.compute_plan_digest();
        if recomputed != self.plan_digest {
            return Err(ApprovalError::PlanDigestMismatch);
        }
        if now >= self.expires_at {
            return Err(ApprovalError::Expired);
        }
        Ok(())
    }

    /// Builds a new approval file for the MVP bash execution path.
    ///
    /// # Errors
    ///
    /// Returns [`ApprovalError::MissingField`] when a required input is empty.
    pub fn for_bash_execution(
        inputs: &ExecutionPlanInputs,
        approver: &str,
        approved_at: u64,
        expires_at: u64,
        verdict: &str,
    ) -> Result<Self, ApprovalError> {
        let artifact_hex = inputs.artifact_sha256.to_string();
        if approver.is_empty() {
            return Err(ApprovalError::MissingField { field: "approver" });
        }
        let mut file = Self {
            schema_version: APPROVAL_SCHEMA_VERSION,
            artifact_sha256: artifact_hex,
            operation: OPERATION.to_owned(),
            release_mode: RELEASE_MODE.to_owned(),
            interpreter: "/bin/bash".to_owned(),
            interpreter_arguments: INTERPRETER_ARGUMENTS
                .iter()
                .map(|s| (*s).to_owned())
                .collect(),
            environment_profile_digest: ENVIRONMENT_PROFILE_DIGEST.to_owned(),
            working_directory_policy: WORKING_DIRECTORY_POLICY.to_owned(),
            filesystem_grants: FILESYSTEM_GRANTS.iter().map(|s| (*s).to_owned()).collect(),
            network_isolated: inputs.network_isolated,
            sandbox_capabilities: SANDBOX_CAPABILITIES.to_owned(),
            release_destination: RELEASE_DESTINATION.to_owned(),
            policy_snapshot_digest: inputs.policy_snapshot_digest.clone(),
            detector_snapshot_digest: inputs.detector_snapshot_digest.clone(),
            plan_digest: String::new(),
            nonce: uuid::Uuid::new_v4().to_string(),
            approver: approver.to_owned(),
            approved_at,
            expires_at,
            verdict: verdict.to_owned(),
        };
        file.plan_digest = file.compute_plan_digest();
        Ok(file)
    }
}

#[cfg(test)]
mod tests;
