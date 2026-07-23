//! Legacy v1 receipt format for migration to the v2 envelope schema
//! (spec §31.1).
//!
//! [`ReceiptV1`] mirrors the pre-envelope flat receipt structure
//! (`schema_version` = 1). It is used by [`crate::Receipt::parse`] to//! transparently migrate v1 JSON receipts to the current v2 envelope
//! structure via [`crate::Receipt::from_v1`].

use arbitraitor_analysis::PayloadGraph;
use arbitraitor_exec::EffectiveControls;
use arbitraitor_model::finding::DetectorProvenance;
use serde::Deserialize;

use crate::{
    AllowRuleMetadata, ApprovalInfo, AuditEvent, DetectorVersion, FindingSummary, ReceiptSignature,
    ReceiptTimestamps, ReleaseMethod, RetrievalInfo, Signature, VerdictInfo,
};

/// Legacy v1 release info (without `approval` and `effective_controls`).
#[derive(Clone, Debug, Deserialize)]
pub struct ReleaseInfoV1 {
    pub(super) method: ReleaseMethod,
    pub(super) destination: Option<String>,
    pub(super) sha256_verified: bool,
    pub(super) timestamp: String,
}

/// Legacy v1 receipt format (flat structure, `schema_version` = 1).
///
/// Used by [`crate::Receipt::parse`] to migrate v1 receipts to the current
/// envelope structure (spec §31.1).
#[derive(Clone, Debug, Deserialize)]
pub struct ReceiptV1 {
    #[allow(dead_code)]
    pub(super) schema_version: u32,
    pub(super) arbitraitor_version: String,
    #[serde(default)]
    pub(super) config_digest: Option<String>,
    #[serde(default)]
    pub(super) policy_digest: Option<String>,
    pub(super) artifact_sha256: String,
    pub(super) artifact_size: u64,
    #[serde(default)]
    pub(super) artifact_type: Option<String>,
    #[serde(default)]
    pub(super) retrieval: Option<RetrievalInfo>,
    pub(super) findings: Vec<FindingSummary>,
    pub(super) verdict: VerdictInfo,
    pub(super) release: Option<ReleaseInfoV1>,
    pub(super) detector_versions: Vec<DetectorVersion>,
    #[serde(default)]
    pub(super) audit_trail: Vec<AuditEvent>,
    #[serde(default)]
    pub(super) detector_provenance: Vec<DetectorProvenance>,
    pub(super) timestamps: ReceiptTimestamps,
    #[serde(default)]
    pub(super) effective_controls: Option<EffectiveControls>,
    #[serde(default)]
    pub(super) allow_rule_metadata: Vec<AllowRuleMetadata>,
    #[serde(default)]
    pub(super) approval: Option<ApprovalInfo>,
    #[serde(default)]
    pub(super) verifier_identity: Option<String>,
    #[serde(default)]
    pub(super) payload_graph: Option<PayloadGraph>,
    #[serde(default)]
    pub(super) signature: Option<ReceiptSignature>,
    #[serde(default)]
    pub(super) signatures: Vec<Signature>,
}
