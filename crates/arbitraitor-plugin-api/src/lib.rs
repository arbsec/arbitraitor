//! Plugin ABI traits, capability declarations, and WIT-adjacent model types.
//!
//! See `.spec/` for the full specification.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use arbitraitor_intel::{FeedEntry, Indicator};
use arbitraitor_model::finding::Finding;
use arbitraitor_model::ids::Sha256Digest;
use arbitraitor_model::operation::OperationPlan;
use serde::{Deserialize, Serialize};
use thiserror::Error;

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
        CapabilitySet, DetectorPlugin, FilesystemCapability, IntelligencePlugin, NetworkCapability,
        Plugin, PluginContext, PluginError, PluginIdentity, PluginTrustClass, ProcessCapability,
        ProvenancePlugin, VerificationResult, WrapperPlugin,
    };
    use arbitraitor_intel::Indicator;
    use arbitraitor_model::finding::Finding;
    use arbitraitor_model::ids::Sha256Digest;
    use arbitraitor_model::operation::OperationPlan;

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

    struct MockPlugin {
        identity: PluginIdentity,
        capabilities: CapabilitySet,
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
