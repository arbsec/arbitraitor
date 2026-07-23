//! Plugin ABI traits, capability declarations, and WIT-adjacent model types.
//!
//! See `docs/spec/` for the full specification.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use arbitraitor_intel::{FeedEntry, Indicator};
use arbitraitor_model::finding::Finding;
use arbitraitor_model::ids::Sha256Digest;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Current normalized operation-plan protocol version.
pub const OPERATION_PLAN_PROTOCOL_VERSION: u32 = 1;

/// Unique identity for a plugin instance.
#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PluginIdentity {
    /// Stable plugin identifier.
    pub id: String,
    /// Plugin version string.
    pub version: String,
    /// Trust classification assigned to this plugin.
    pub trust_class: PluginTrustClass,
}

/// Trust classification per ADR 0011.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum PluginTrustClass {
    /// Plugin shipped as part of Arbitraitor itself.
    BuiltIn,
    /// Plugin maintained by the Arbitraitor project or an approved first party.
    FirstParty,
    /// Community plugin that has completed project review.
    CommunityReviewed,
    /// Community plugin that has not completed project review.
    CommunityUnreviewed,
}

/// Capabilities a plugin may request.
#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CapabilitySet {
    /// Requested network access.
    pub network: NetworkCapability,
    /// Requested filesystem access.
    pub filesystem: FilesystemCapability,
    /// Requested child-process access.
    pub process: ProcessCapability,
    /// Optional maximum memory budget in bytes.
    pub max_memory_bytes: Option<u64>,
    /// Optional maximum CPU budget in milliseconds.
    pub max_cpu_ms: Option<u64>,
}

impl CapabilitySet {
    /// Returns whether this capability set contains every capability in `requested`.
    #[must_use]
    pub const fn contains(&self, requested: &Self) -> bool {
        network_contains(self.network, requested.network)
            && filesystem_contains(self.filesystem, requested.filesystem)
            && process_contains(self.process, requested.process)
            && optional_limit_contains(self.max_memory_bytes, requested.max_memory_bytes)
            && optional_limit_contains(self.max_cpu_ms, requested.max_cpu_ms)
    }
}

const fn optional_limit_contains(declared: Option<u64>, requested: Option<u64>) -> bool {
    match (declared, requested) {
        (_, None) => true,
        (Some(declared), Some(requested)) => requested <= declared,
        (None, Some(_)) => false,
    }
}

const fn network_contains(declared: NetworkCapability, requested: NetworkCapability) -> bool {
    network_rank(declared) >= network_rank(requested)
}

const fn network_rank(capability: NetworkCapability) -> u8 {
    match capability {
        NetworkCapability::None => 0,
        NetworkCapability::LoopbackOnly => 1,
        NetworkCapability::OutboundHttps => 2,
        NetworkCapability::Full => 3,
    }
}

const fn filesystem_contains(
    declared: FilesystemCapability,
    requested: FilesystemCapability,
) -> bool {
    filesystem_rank(declared) >= filesystem_rank(requested)
}

const fn filesystem_rank(capability: FilesystemCapability) -> u8 {
    match capability {
        FilesystemCapability::None => 0,
        FilesystemCapability::ReadOnly => 1,
        FilesystemCapability::ReadWrite => 2,
    }
}

const fn process_contains(declared: ProcessCapability, requested: ProcessCapability) -> bool {
    process_rank(declared) >= process_rank(requested)
}

const fn process_rank(capability: ProcessCapability) -> u8 {
    match capability {
        ProcessCapability::None => 0,
        ProcessCapability::Spawn => 1,
    }
}

/// Network access requested by a plugin.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum NetworkCapability {
    /// No network access.
    #[default]
    None,
    /// Loopback network access only.
    LoopbackOnly,
    /// Outbound HTTPS access only.
    OutboundHttps,
    /// Unrestricted network access.
    Full,
}

impl NetworkCapability {
    /// Returns `true` when the capability grants no network access at all and
    /// the executor must apply its kernel-level network isolation.
    ///
    /// `LoopbackOnly` is intentionally treated as non-isolated: loopback
    /// sockets require lifting the broad seccomp-BPF network syscall block.
    /// Finer-grained loopback filtering, if needed, is the executor's
    /// responsibility above the isolation switch reported here.
    #[must_use]
    pub const fn is_isolated(self) -> bool {
        matches!(self, Self::None)
    }
}

/// Filesystem access requested by a plugin.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum FilesystemCapability {
    /// No filesystem access.
    #[default]
    None,
    /// Read-only filesystem access.
    ReadOnly,
    /// Read-write filesystem access.
    ReadWrite,
}

/// Process access requested by a plugin.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ProcessCapability {
    /// No child-process access.
    #[default]
    None,
    /// Permission to spawn child processes.
    Spawn,
}

/// Context provided to plugin adapter methods for an artifact.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PluginContext {
    /// SHA-256 digest of the immutable artifact bytes supplied to the plugin.
    pub artifact_sha256: Sha256Digest,
    /// Artifact type label selected by the caller.
    pub artifact_type: String,
    /// Redacted retrieval URL, when available.
    pub retrieval_url: Option<String>,
}

/// Declarative metadata advertised by a plugin package.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PluginManifest {
    /// Plugin identity.
    pub identity: PluginIdentity,
    /// Capabilities requested by the plugin.
    pub capabilities: CapabilitySet,
    /// Adapter type exposed by the plugin.
    pub plugin_type: PluginType,
    /// Human-readable plugin description.
    pub description: String,
}

/// Normalized plan produced by a wrapper plugin for validation by core.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OperationPlan {
    /// Operation-plan protocol version.
    pub protocol_version: u32,
    /// Plugin that normalized the original tool invocation.
    pub plugin: PluginIdentity,
    /// Downloader or installer tool whose invocation was normalized.
    pub original_tool: String,
    /// Ordered linear operation chain requested by the wrapper.
    pub operations: Vec<PlannedOperation>,
    /// Capabilities requested to carry out the planned operations.
    pub requested_capabilities: CapabilitySet,
    /// Wrapper confidence that the plan preserves the original command semantics.
    pub semantic_confidence: SemanticConfidence,
}

impl OperationPlan {
    /// Validates this operation plan using only self-contained plan invariants.
    ///
    /// # Errors
    ///
    /// Returns [`PlanError`] when the plan is unsupported, opaque, empty, or has
    /// conflicting operations.
    pub fn validate(&self) -> Result<(), PlanError> {
        if self.protocol_version != OPERATION_PLAN_PROTOCOL_VERSION {
            return Err(PlanError::UnsupportedProtocolVersion {
                found: self.protocol_version,
                supported: OPERATION_PLAN_PROTOCOL_VERSION,
            });
        }

        if self.operations.is_empty() {
            return Err(PlanError::NoOperations);
        }

        if self.semantic_confidence == SemanticConfidence::Opaque {
            return Err(PlanError::OpaqueSemantics);
        }

        self.validate_operation_order()?;
        Ok(())
    }

    /// Validates this plan against capabilities declared by the producing plugin.
    ///
    /// # Errors
    ///
    /// Returns [`PlanError`] if validation fails or the plan requests capability
    /// not declared by the plugin manifest.
    pub fn validate_for_plugin_capabilities(
        &self,
        declared_capabilities: &CapabilitySet,
    ) -> Result<(), PlanError> {
        self.validate()?;
        if !declared_capabilities.contains(&self.requested_capabilities) {
            return Err(PlanError::CapabilityExceedsDeclaration);
        }
        Ok(())
    }

    fn validate_operation_order(&self) -> Result<(), PlanError> {
        let mut terminal_operation_index = None;
        let mut saw_artifact_source = false;

        for (index, operation) in self.operations.iter().enumerate() {
            if terminal_operation_index.is_some() {
                return Err(PlanError::OperationAfterTerminal { index });
            }

            match operation {
                PlannedOperation::Retrieve { .. } => {
                    if saw_artifact_source {
                        return Err(PlanError::ConflictingOperations {
                            index,
                            reason: "multiple artifact sources",
                        });
                    }
                    saw_artifact_source = true;
                }
                PlannedOperation::PassThrough => {
                    if self.operations.len() != 1 {
                        return Err(PlanError::ConflictingOperations {
                            index,
                            reason: "pass-through cannot be combined with other operations",
                        });
                    }
                    terminal_operation_index = Some(index);
                }
                PlannedOperation::ReleaseToFile { .. }
                | PlannedOperation::ExecuteInterpreter { .. }
                | PlannedOperation::ExecuteNative { .. } => {
                    terminal_operation_index = Some(index);
                }
                PlannedOperation::VerifyDigest { .. }
                | PlannedOperation::VerifySignature { .. }
                | PlannedOperation::Decode { .. }
                | PlannedOperation::Extract { .. } => {}
            }
        }

        Ok(())
    }
}

/// Single normalized operation in an [`OperationPlan`].
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case", tag = "type")]
pub enum PlannedOperation {
    /// Retrieve bytes from a URL with non-secret, redacted headers.
    Retrieve {
        /// Retrieval URL.
        url: String,
        /// Non-secret request headers.
        headers: Vec<(String, String)>,
    },
    /// Verify that the current bytes match an expected SHA-256 digest.
    VerifyDigest {
        /// Expected SHA-256 digest.
        expected_sha256: Sha256Digest,
    },
    /// Verify a signature or provenance envelope for the current bytes.
    VerifySignature {
        /// Signature or provenance system.
        system: String,
        /// Key identifier used by the signature system.
        key_id: String,
    },
    /// Decode the current bytes into another representation.
    Decode {
        /// Decode format.
        format: DecodeFormat,
    },
    /// Extract contained payloads from the current bytes.
    Extract {
        /// Extraction format label.
        format: String,
    },
    /// Execute the inspected bytes through an interpreter.
    ExecuteInterpreter {
        /// Interpreter executable.
        interpreter: String,
        /// Interpreter arguments.
        args: Vec<String>,
    },
    /// Execute the inspected bytes as a native program.
    ExecuteNative {
        /// Native execution arguments.
        args: Vec<String>,
    },
    /// Release inspected bytes to a file path.
    ReleaseToFile {
        /// Destination path.
        path: String,
    },
    /// Preserve the command unchanged when no normalized semantics are available.
    PassThrough,
}

/// Decode format requested by a normalized operation plan.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum DecodeFormat {
    /// Base64 decoding.
    Base64,
    /// Hexadecimal decoding.
    Hex,
    /// Gzip decompression.
    Gzip,
    /// Zstandard decompression.
    Zstd,
}

/// Confidence that the normalized plan preserves original command semantics.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum SemanticConfidence {
    /// The wrapper recognized exact semantics.
    Exact,
    /// The normalized plan is semantically equivalent for security-relevant effects.
    Equivalent,
    /// The wrapper recognized only part of the original command semantics.
    Partial,
    /// The wrapper could not inspect semantics; policy must block by default.
    Opaque,
}

/// Validation error for normalized wrapper operation plans.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum PlanError {
    /// Protocol version is not supported by this crate.
    #[error(
        "unsupported operation-plan protocol version {found}; supported version is {supported}"
    )]
    UnsupportedProtocolVersion {
        /// Version found in the plan.
        found: u32,
        /// Version supported by this crate.
        supported: u32,
    },
    /// Plan does not contain any operations.
    #[error("operation plan contains no operations")]
    NoOperations,
    /// Opaque wrapper semantics are blocked by default.
    #[error("operation plan has opaque semantics")]
    OpaqueSemantics,
    /// Operation conflicts with another operation in the same plan.
    #[error("operation at index {index} conflicts with plan: {reason}")]
    ConflictingOperations {
        /// Index of the conflicting operation.
        index: usize,
        /// Safe static diagnostic reason.
        reason: &'static str,
    },
    /// Operation appears after a terminal release or execution operation.
    #[error("operation at index {index} appears after a terminal operation")]
    OperationAfterTerminal {
        /// Index of the operation after a terminal operation.
        index: usize,
    },
    /// Requested capabilities exceed the plugin's declaration.
    #[error("operation plan requests capabilities not declared by the plugin")]
    CapabilityExceedsDeclaration,
}

/// Adapter category exposed by a plugin.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum PluginType {
    /// Detector adapter.
    Detector,
    /// Downloader-wrapper adapter.
    Wrapper,
    /// Threat-intelligence adapter.
    Intelligence,
    /// Provenance-verification adapter.
    Provenance,
    /// Sandbox adapter.
    Sandbox,
}

/// Result returned by provenance verifier plugins.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct VerificationResult {
    /// Whether the supplied signature verifies the artifact bytes.
    pub verified: bool,
    /// Signature or provenance scheme used by the verifier.
    pub scheme: String,
    /// Identity bound by the verified signature, when available.
    pub signer_identity: Option<String>,
}

/// Error returned by plugin adapter methods.
#[derive(Debug, Error)]
pub enum PluginError {
    /// Plugin input could not be parsed or validated.
    #[error("invalid plugin input: {reason}")]
    InvalidInput {
        /// Safe diagnostic reason.
        reason: String,
    },
    /// Plugin execution failed.
    #[error("plugin execution failed during {stage}: {reason}")]
    Execution {
        /// Execution stage that failed.
        stage: &'static str,
        /// Safe diagnostic reason.
        reason: String,
    },
}

/// Base trait all plugins implement.
pub trait Plugin: Send + Sync {
    /// Returns the stable identity for this plugin instance.
    fn identity(&self) -> &PluginIdentity;

    /// Returns the capabilities requested by this plugin instance.
    fn capabilities(&self) -> &CapabilitySet;
}

/// Detector plugin: analyzes artifacts and returns findings.
pub trait DetectorPlugin: Plugin {
    /// Analyzes immutable artifact bytes within the supplied context.
    fn analyze(&self, artifact: &[u8], context: &PluginContext) -> Vec<Finding>;
}

/// Downloader wrapper plugin: translates tool commands to operation plans.
pub trait WrapperPlugin: Plugin {
    /// Parses a downloader command line into a planned operation.
    ///
    /// # Errors
    ///
    /// Returns [`PluginError`] when the command line is not supported or cannot
    /// be mapped to a valid operation plan.
    fn parse_command(&self, argv: &[String]) -> Result<OperationPlan, PluginError>;
}

/// Intelligence provider plugin.
pub trait IntelligencePlugin: Plugin {
    /// Queries plugin-provided intelligence for an indicator.
    fn query(&self, indicator: &Indicator) -> Vec<FeedEntry>;
}

/// Provenance verifier plugin.
pub trait ProvenancePlugin: Plugin {
    /// Verifies a detached signature over immutable artifact bytes.
    ///
    /// # Errors
    ///
    /// Returns [`PluginError`] when verification cannot complete. A completed
    /// verification with an invalid signature returns `Ok` with
    /// [`VerificationResult::verified`] set to `false`.
    fn verify(&self, artifact: &[u8], signature: &[u8]) -> Result<VerificationResult, PluginError>;
}

#[cfg(test)]
mod tests {
    use super::{
        CapabilitySet, DecodeFormat, DetectorPlugin, FilesystemCapability, IntelligencePlugin,
        NetworkCapability, OPERATION_PLAN_PROTOCOL_VERSION, OperationPlan, PlanError,
        PlannedOperation, Plugin, PluginContext, PluginError, PluginIdentity, PluginTrustClass,
        ProcessCapability, ProvenancePlugin, SemanticConfidence, VerificationResult, WrapperPlugin,
    };
    use arbitraitor_intel::Indicator;
    use arbitraitor_model::finding::Finding;
    use arbitraitor_model::ids::Sha256Digest;

    #[test]
    fn plugin_identity_round_trips_and_rejects_unknown_fields()
    -> Result<(), Box<dyn std::error::Error>> {
        let identity = PluginIdentity {
            id: "plugin.example.detector".to_owned(),
            version: "1.2.3".to_owned(),
            trust_class: PluginTrustClass::CommunityReviewed,
        };

        let json = serde_json::to_string(&identity)?;
        assert_eq!(serde_json::from_str::<PluginIdentity>(&json)?, identity);
        assert!(
            serde_json::from_str::<PluginIdentity>(
                r#"{"id":"x","version":"1","trust_class":"built-in","extra":true}"#
            )
            .is_err()
        );
        Ok(())
    }

    #[test]
    fn capability_set_defaults_to_most_restrictive() {
        let capabilities = CapabilitySet::default();

        assert_eq!(capabilities.network, NetworkCapability::None);
        assert_eq!(capabilities.filesystem, FilesystemCapability::None);
        assert_eq!(capabilities.process, ProcessCapability::None);
        assert_eq!(capabilities.max_memory_bytes, None);
        assert_eq!(capabilities.max_cpu_ms, None);
    }

    #[test]
    fn plugin_trait_objects_can_be_created() -> Result<(), Box<dyn std::error::Error>> {
        let plugin = MockPlugin {
            identity: PluginIdentity {
                id: "plugin.example.all".to_owned(),
                version: env!("CARGO_PKG_VERSION").to_owned(),
                trust_class: PluginTrustClass::FirstParty,
            },
            capabilities: CapabilitySet::default(),
        };
        let context = PluginContext {
            artifact_sha256: Sha256Digest::new([0x42; 32]),
            artifact_type: "text/plain".to_owned(),
            retrieval_url: None,
        };
        let indicator = Indicator {
            indicator_type: arbitraitor_intel::IndicatorType::Sha256,
            value: context.artifact_sha256.to_string(),
        };

        let base: &dyn Plugin = &plugin;
        assert_eq!(base.identity().id, "plugin.example.all");
        assert_eq!(base.capabilities(), &CapabilitySet::default());

        let detector: &dyn DetectorPlugin = &plugin;
        assert!(detector.analyze(b"artifact", &context).is_empty());

        let wrapper: &dyn WrapperPlugin = &plugin;
        assert!(wrapper.parse_command(&["curl".to_owned()]).is_err());

        let intelligence: &dyn IntelligencePlugin = &plugin;
        assert!(intelligence.query(&indicator).is_empty());

        let provenance: &dyn ProvenancePlugin = &plugin;
        assert_eq!(
            provenance.verify(b"artifact", b"signature")?,
            VerificationResult {
                verified: true,
                scheme: "mock".to_owned(),
                signer_identity: Some("test-signer".to_owned()),
            }
        );
        Ok(())
    }

    #[test]
    fn valid_retrieve_release_plan_passes_validation() -> Result<(), Box<dyn std::error::Error>> {
        let plan = operation_plan(vec![
            PlannedOperation::Retrieve {
                url: "https://example.invalid/artifact.bin".to_owned(),
                headers: Vec::new(),
            },
            PlannedOperation::ReleaseToFile {
                path: "/tmp/artifact.bin".to_owned(),
            },
        ]);
        let declared = CapabilitySet {
            network: NetworkCapability::OutboundHttps,
            filesystem: FilesystemCapability::ReadWrite,
            process: ProcessCapability::None,
            max_memory_bytes: None,
            max_cpu_ms: None,
        };

        plan.validate_for_plugin_capabilities(&declared)?;
        Ok(())
    }

    #[test]
    fn opaque_confidence_is_rejected() {
        let mut plan = operation_plan(vec![PlannedOperation::PassThrough]);
        plan.semantic_confidence = SemanticConfidence::Opaque;

        assert_eq!(plan.validate(), Err(PlanError::OpaqueSemantics));
    }

    #[test]
    fn conflicting_release_and_execute_operations_are_rejected() {
        let plan = operation_plan(vec![
            PlannedOperation::Retrieve {
                url: "https://example.invalid/tool".to_owned(),
                headers: Vec::new(),
            },
            PlannedOperation::ReleaseToFile {
                path: "/tmp/tool".to_owned(),
            },
            PlannedOperation::ExecuteNative {
                args: vec!["--version".to_owned()],
            },
        ]);

        assert_eq!(
            plan.validate(),
            Err(PlanError::OperationAfterTerminal { index: 2 })
        );
    }

    #[test]
    fn operation_plan_serialization_round_trips() -> Result<(), Box<dyn std::error::Error>> {
        let plan = operation_plan(vec![
            PlannedOperation::Retrieve {
                url: "https://example.invalid/archive.gz".to_owned(),
                headers: vec![("accept".to_owned(), "application/gzip".to_owned())],
            },
            PlannedOperation::VerifyDigest {
                expected_sha256: Sha256Digest::new([0x24; 32]),
            },
            PlannedOperation::Decode {
                format: DecodeFormat::Gzip,
            },
            PlannedOperation::ReleaseToFile {
                path: "/tmp/archive".to_owned(),
            },
        ]);

        assert_eq!(
            serde_json::from_str::<OperationPlan>(&serde_json::to_string(&plan)?)?,
            plan
        );
        Ok(())
    }

    struct MockPlugin {
        identity: PluginIdentity,
        capabilities: CapabilitySet,
    }

    fn operation_plan(operations: Vec<PlannedOperation>) -> OperationPlan {
        OperationPlan {
            protocol_version: OPERATION_PLAN_PROTOCOL_VERSION,
            plugin: PluginIdentity {
                id: "plugin.example.wrapper".to_owned(),
                version: "1.0.0".to_owned(),
                trust_class: PluginTrustClass::FirstParty,
            },
            original_tool: "curl".to_owned(),
            operations,
            requested_capabilities: CapabilitySet {
                network: NetworkCapability::OutboundHttps,
                filesystem: FilesystemCapability::ReadWrite,
                process: ProcessCapability::None,
                max_memory_bytes: None,
                max_cpu_ms: None,
            },
            semantic_confidence: SemanticConfidence::Exact,
        }
    }

    impl Plugin for MockPlugin {
        fn identity(&self) -> &PluginIdentity {
            &self.identity
        }

        fn capabilities(&self) -> &CapabilitySet {
            &self.capabilities
        }
    }

    impl DetectorPlugin for MockPlugin {
        fn analyze(&self, _artifact: &[u8], _context: &PluginContext) -> Vec<Finding> {
            Vec::new()
        }
    }

    impl WrapperPlugin for MockPlugin {
        fn parse_command(&self, _argv: &[String]) -> Result<OperationPlan, PluginError> {
            Err(PluginError::InvalidInput {
                reason: "mock wrapper does not produce operation plans".to_owned(),
            })
        }
    }

    impl IntelligencePlugin for MockPlugin {
        fn query(&self, _indicator: &Indicator) -> Vec<arbitraitor_intel::FeedEntry> {
            Vec::new()
        }
    }

    impl ProvenancePlugin for MockPlugin {
        fn verify(
            &self,
            _artifact: &[u8],
            _signature: &[u8],
        ) -> Result<VerificationResult, PluginError> {
            Ok(VerificationResult {
                verified: true,
                scheme: "mock".to_owned(),
                signer_identity: Some("test-signer".to_owned()),
            })
        }
    }
}
