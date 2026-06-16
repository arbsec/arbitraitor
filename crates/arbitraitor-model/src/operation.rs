//! Operation planning types that bind approvals to concrete capabilities.

use serde::{Deserialize, Serialize};

use crate::ids::{ArtifactId, OperationId};

/// Operation plan bound to an artifact and requested execution context.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
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

/// Planned operation plus the derived capability set.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct PlannedOperation {
    /// Operation plan.
    pub plan: OperationPlan,
    /// Capabilities granted to the plan.
    pub capabilities: CapabilitySet,
}

/// Boolean capability grant serialized as a JSON boolean.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct CapabilityGrant(pub bool);

/// Capability grants derived from policy for a planned operation.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct CapabilitySet {
    /// Whether network access is granted.
    pub network: CapabilityGrant,
    /// Whether file write access is granted.
    pub file_write: CapabilityGrant,
    /// Whether process execution is granted.
    pub execute: CapabilityGrant,
    /// Whether environment modification is granted.
    pub environment_modify: CapabilityGrant,
}
#[cfg(test)]
mod tests {
    use super::{CapabilityGrant, CapabilitySet, OperationPlan, OperationType, PlannedOperation};
    use crate::ids::{ArtifactId, OperationId, Sha256Digest};

    fn plan() -> OperationPlan {
        OperationPlan {
            operation_id: OperationId(String::new()),
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
    fn operation_plan_round_trips_with_empty_id_edge() -> Result<(), Box<dyn std::error::Error>> {
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
    fn capability_set_round_trips_all_false_edge() -> Result<(), Box<dyn std::error::Error>> {
        let value = CapabilitySet {
            network: CapabilityGrant(false),
            file_write: CapabilityGrant(false),
            execute: CapabilityGrant(false),
            environment_modify: CapabilityGrant(false),
        };
        assert_eq!(
            serde_json::from_str::<CapabilitySet>(&serde_json::to_string(&value)?)?,
            value
        );
        Ok(())
    }

    #[test]
    fn planned_operation_round_trips() -> Result<(), Box<dyn std::error::Error>> {
        let value = PlannedOperation {
            plan: plan(),
            capabilities: CapabilitySet {
                network: CapabilityGrant(false),
                file_write: CapabilityGrant(true),
                execute: CapabilityGrant(true),
                environment_modify: CapabilityGrant(false),
            },
        };
        assert_eq!(
            serde_json::from_str::<PlannedOperation>(&serde_json::to_string(&value)?)?,
            value
        );
        Ok(())
    }
}
