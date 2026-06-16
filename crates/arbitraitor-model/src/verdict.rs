//! Policy verdict, severity, confidence, and assurance enums.

use serde::{Deserialize, Serialize};

/// Final policy decision for an operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Verdict {
    /// All required checks passed and no approval is needed.
    Pass,
    /// Release is permitted with a warning.
    Warn,
    /// Interactive approval is required.
    Prompt,
    /// Release is prohibited.
    Block,
    /// A required operation failed.
    Error,
    /// Analysis completed but mandatory coverage was not achieved.
    Incomplete,
}

/// Severity assigned to a finding.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    /// Informational finding with no direct risk by itself.
    Informational,
    /// Low severity finding.
    Low,
    /// Medium severity finding.
    Medium,
    /// High severity finding.
    High,
    /// Critical severity finding.
    Critical,
}

/// Confidence assigned by a detector.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Confidence {
    /// Weak signal that needs corroboration.
    Speculative,
    /// Low confidence signal.
    Low,
    /// Medium confidence signal.
    Medium,
    /// High confidence signal.
    High,
    /// Confirmed signal.
    Confirmed,
}

/// Assurance posture for inspecting, mediating, or containing an operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AssuranceLevel {
    /// Inspect without granting release or execution by itself.
    Inspect,
    /// Execute through a controlled, policy-mediated context.
    Mediated,
    /// Execute or process under stronger containment.
    Contained,
}
#[cfg(test)]
mod tests {
    use super::{AssuranceLevel, Confidence, Severity, Verdict};

    #[test]
    fn verdict_round_trips_and_uses_lowercase() -> Result<(), Box<dyn std::error::Error>> {
        let json = serde_json::to_string(&Verdict::Incomplete)?;
        assert_eq!(json, "\"incomplete\"");
        assert_eq!(serde_json::from_str::<Verdict>(&json)?, Verdict::Incomplete);
        Ok(())
    }

    #[test]
    fn severity_round_trips_edge_variant() -> Result<(), Box<dyn std::error::Error>> {
        let value = Severity::Critical;
        assert_eq!(
            serde_json::from_str::<Severity>(&serde_json::to_string(&value)?)?,
            value
        );
        Ok(())
    }

    #[test]
    fn confidence_round_trips_edge_variant() -> Result<(), Box<dyn std::error::Error>> {
        let value = Confidence::Speculative;
        assert_eq!(
            serde_json::from_str::<Confidence>(&serde_json::to_string(&value)?)?,
            value
        );
        Ok(())
    }

    #[test]
    fn assurance_level_round_trips_edge_variant() -> Result<(), Box<dyn std::error::Error>> {
        let value = AssuranceLevel::Contained;
        assert_eq!(
            serde_json::from_str::<AssuranceLevel>(&serde_json::to_string(&value)?)?,
            value
        );
        Ok(())
    }
}
