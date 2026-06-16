//! Operation planning types for requested and policy-resolved operations.

use serde::{Deserialize, Serialize};

use crate::ids::{ArtifactId, OperationId};

/// Operation plan describing an artifact and requested execution context.
// TODO: spec-required binding fields (plugin identity, argv digest, policy snapshot) — see #30.
// TODO: state machine transitions — see #30.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OperationPlan {
    /// Unique operation identifier or nonce.
    pub operation_id: OperationId,
    /// Artifact identity the operation applies to.
    pub artifact_id: ArtifactId,
    /// Requested operation type.
    pub operation_type: OperationType,
    /// Optional policy-approved interpreter.
    pub interpreter: Option<String>,
    /// Operation arguments.
    pub arguments: Vec<String>,
    /// Environment variable names allowed to pass into the operation.
    pub environment_allowlist: Vec<String>,
    /// Whether network access is permitted.
    pub network_allowed: bool,
    /// Whether sandboxing is enabled.
    pub sandbox_enabled: bool,
    /// Optional timestamp string at which this plan expires.
    pub expiry: Option<String>,
}

/// Type of operation requested for an artifact.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum OperationType {
    /// Execute an artifact.
    Execute,
    /// Fetch an artifact.
    Fetch,
    /// Scan an artifact.
    Scan,
    /// Inspect an artifact without release.
    Inspect,
    /// Release an inspected artifact.
    Release,
}

/// Planned operation plus the capabilities requested by untrusted input.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlannedOperation {
    /// Operation plan.
    pub plan: OperationPlan,
    /// Capabilities requested by the operation submitter.
    pub requested_capabilities: RequestedCapabilities,
}

/// Boolean capability grant serialized as a JSON boolean.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct CapabilityGrant(pub bool);

/// Boolean capability request serialized as a JSON boolean.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct CapabilityRequest(pub bool);

/// Capabilities requested by a plugin, wrapper, or other untrusted submitter.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RequestedCapabilities {
    /// Whether network access is requested.
    pub network: CapabilityRequest,
    /// Whether file write access is requested.
    pub file_write: CapabilityRequest,
    /// Whether process execution is requested.
    pub execute: CapabilityRequest,
    /// Whether environment modification is requested.
    pub environment_modify: CapabilityRequest,
}

/// Capabilities granted by core policy evaluation.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize)]
pub struct GrantedCapabilities {
    network: CapabilityGrant,
    file_write: CapabilityGrant,
    execute: CapabilityGrant,
    environment_modify: CapabilityGrant,
}

impl GrantedCapabilities {
    /// Creates policy-granted capabilities after validation by trusted core code.
    #[must_use]
    pub const fn new(
        network: CapabilityGrant,
        file_write: CapabilityGrant,
        execute: CapabilityGrant,
        environment_modify: CapabilityGrant,
    ) -> Self {
        Self {
            network,
            file_write,
            execute,
            environment_modify,
        }
    }

    /// Returns whether network access is granted.
    #[must_use]
    pub const fn network(&self) -> bool {
        self.network.0
    }

    /// Returns whether file write access is granted.
    #[must_use]
    pub const fn file_write(&self) -> bool {
        self.file_write.0
    }

    /// Returns whether process execution is granted.
    #[must_use]
    pub const fn execute(&self) -> bool {
        self.execute.0
    }

    /// Returns whether environment modification is granted.
    #[must_use]
    pub const fn environment_modify(&self) -> bool {
        self.environment_modify.0
    }
}

/// Operation after trusted policy resolution has granted capabilities.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct ResolvedOperation {
    /// Operation plan.
    pub plan: OperationPlan,
    /// Capabilities granted by trusted policy evaluation.
    pub granted_capabilities: GrantedCapabilities,
}

impl ResolvedOperation {
    /// Creates a resolved operation from a plan and trusted policy grants.
    #[must_use]
    pub const fn new(plan: OperationPlan, granted_capabilities: GrantedCapabilities) -> Self {
        Self {
            plan,
            granted_capabilities,
        }
    }
}
#[cfg(test)]
mod tests {
    use super::{
        CapabilityGrant, CapabilityRequest, GrantedCapabilities, OperationPlan, OperationType,
        PlannedOperation, RequestedCapabilities, ResolvedOperation,
    };
    use crate::ids::{ArtifactId, OperationId, Sha256Digest};

    fn plan() -> OperationPlan {
        OperationPlan {
            operation_id: OperationId::new(),
            artifact_id: ArtifactId(Sha256Digest::new([0; 32])),
            operation_type: OperationType::Execute,
            interpreter: Some("/bin/sh".to_owned()),
            arguments: vec!["-c".to_owned(), "true".to_owned()],
            environment_allowlist: vec!["PATH".to_owned()],
            network_allowed: false,
            sandbox_enabled: true,
            expiry: Some("9999-12-31T23:59:59Z".to_owned()),
        }
    }

    #[test]
    fn operation_type_round_trips_edge_variant() -> Result<(), Box<dyn std::error::Error>> {
        let value = OperationType::Release;
        assert_eq!(
            serde_json::from_str::<OperationType>(&serde_json::to_string(&value)?)?,
            value
        );
        Ok(())
    }
    #[test]
    fn operation_plan_round_trips_with_generated_id() -> Result<(), Box<dyn std::error::Error>> {
        let value = plan();
        assert_eq!(
            serde_json::from_str::<OperationPlan>(&serde_json::to_string(&value)?)?,
            value
        );
        Ok(())
    }

    #[test]
    fn capability_grant_round_trips_as_bool() -> Result<(), Box<dyn std::error::Error>> {
        let value = CapabilityGrant(true);
        assert_eq!(serde_json::to_string(&value)?, "true");
        assert_eq!(serde_json::from_str::<CapabilityGrant>("true")?, value);
        Ok(())
    }

    #[test]
    fn requested_capabilities_round_trip_all_false_edge() -> Result<(), Box<dyn std::error::Error>>
    {
        let value = RequestedCapabilities {
            network: CapabilityRequest(false),
            file_write: CapabilityRequest(false),
            execute: CapabilityRequest(false),
            environment_modify: CapabilityRequest(false),
        };
        assert_eq!(
            serde_json::from_str::<RequestedCapabilities>(&serde_json::to_string(&value)?)?,
            value
        );
        Ok(())
    }

    #[test]
    fn planned_operation_round_trips() -> Result<(), Box<dyn std::error::Error>> {
        let value = PlannedOperation {
            plan: plan(),
            requested_capabilities: RequestedCapabilities {
                network: CapabilityRequest(false),
                file_write: CapabilityRequest(true),
                execute: CapabilityRequest(true),
                environment_modify: CapabilityRequest(false),
            },
        };
        assert_eq!(
            serde_json::from_str::<PlannedOperation>(&serde_json::to_string(&value)?)?,
            value
        );
        Ok(())
    }

    #[test]
    fn resolved_operation_serializes_but_grants_do_not_deserialize()
    -> Result<(), Box<dyn std::error::Error>> {
        let value = ResolvedOperation::new(
            plan(),
            GrantedCapabilities::new(
                CapabilityGrant(false),
                CapabilityGrant(true),
                CapabilityGrant(true),
                CapabilityGrant(false),
            ),
        );
        let json = serde_json::to_string(&value)?;
        assert!(json.contains("granted_capabilities"));
        Ok(())
    }

    #[test]
    fn operation_plan_rejects_unknown_fields() {
        let json = format!(
            "{{\"operation_id\":\"{}\",\"artifact_id\":\"{}\",\"operation_type\":\"execute\",\"interpreter\":null,\"arguments\":[],\"environment_allowlist\":[],\"network_allowed\":false,\"sandbox_enabled\":true,\"expiry\":null,\"extra\":true}}",
            OperationId::new(),
            Sha256Digest::new([0; 32])
        );
        assert!(serde_json::from_str::<OperationPlan>(&json).is_err());
    }
}
