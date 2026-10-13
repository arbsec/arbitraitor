//! Legacy receipt formats for migration to the current envelope schema.
//!
//! [`ReceiptV1`] mirrors the pre-envelope flat receipt structure
//! (`schema_version` = 1). It is used by [`crate::Receipt::parse`] to
//! transparently migrate v1 JSON receipts to the current envelope structure
//! via [`crate::Receipt::from_v1`].
//!
//! The v2→v3 migration adds only the optional `ingress` bucket and is
//! handled in place by [`Receipt::migrated_from_v2`]: v2 JSON deserializes
//! directly into [`crate::Receipt`] (`ingress` defaults to `None`), then the
//! schema version is stamped to [`crate::CURRENT_SCHEMA_VERSION`].

use arbitraitor_analysis::PayloadGraph;
use arbitraitor_exec::EffectiveControls;
use arbitraitor_model::finding::DetectorProvenance;
use serde::Deserialize;

use crate::{
    AllowRuleMetadata, ApprovalInfo, AuditEvent, DetectorVersion, FindingSummary, Receipt,
    ReceiptSignature, ReceiptTimestamps, ReleaseMethod, RetrievalInfo, Signature,
    V2_SCHEMA_VERSION, VerdictInfo,
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
/// envelope structure.
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

impl Receipt {
    /// Migrate a v2 envelope receipt to the current v3 schema.
    ///
    /// The v2→v3 change adds only the optional `ingress` bucket. v2 JSON
    /// deserializes into [`Receipt`] with `ingress: None` via the field
    /// default; this conversion stamps the current schema version and forces
    /// `ingress` to `None`, so a crafted document claiming `schema_version`
    /// 2 while carrying an `ingress` bucket is normalized, not trusted.
    ///
    /// Receipts whose `schema_version` is not [`V2_SCHEMA_VERSION`] are
    /// returned unchanged.
    pub(crate) fn migrated_from_v2(mut self) -> Self {
        if self.schema_version == V2_SCHEMA_VERSION {
            self.schema_version = crate::CURRENT_SCHEMA_VERSION;
            self.ingress = None;
        }
        self
    }
}
