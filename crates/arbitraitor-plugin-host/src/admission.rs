//! ADR-0011 trust-tier capability admission.
//!
//! Enforces the policy that community plugins receive no network, no process
//! spawning, and no arbitrary filesystem write authority by default
//! (`docs/adr/0011-plugin-trust-classification.md`). First-party and built-in
//! plugins may declare any capability; their admission is gated by review and
//! provenance, not by this check.

#![forbid(unsafe_code)]

use arbitraitor_plugin_api::{
    CapabilitySet, FilesystemCapability, NetworkCapability, PluginTrustClass, ProcessCapability,
};

/// Policy outcome describing why a capability declaration was rejected.
#[derive(Debug, thiserror::Error)]
pub enum AdmissionError {
    /// A community-tier plugin requested a capability reserved for first-party
    /// or built-in plugins.
    #[error(
        "community-tier plugin cannot declare `{capability}` \
         (`{trust_tier}` is restricted to `{allowed_tiers}` per ADR-0011)"
    )]
    CapabilityDeniedForTrustTier {
        /// Short label of the denied capability kind (`network`, `process`,
        /// `filesystem`).
        capability: &'static str,
        /// Trust tier of the rejected plugin.
        trust_tier: &'static str,
        /// Trust tiers permitted to request this capability.
        allowed_tiers: &'static str,
    },
}

/// Enforces ADR-0011 capability restrictions against the plugin's trust tier.
///
/// Returns `Ok(())` when the declaration is admissible. Built-in and
/// first-party plugins always pass; community-tier plugins must declare only
/// capabilities allowed for community use (no network, no process spawn, no
/// read-write filesystem).
///
/// # Errors
///
/// Returns [`AdmissionError::CapabilityDeniedForTrustTier`] when a
/// community-tier plugin declares a reserved capability.
pub fn enforce_trust_tier_capabilities(
    trust: PluginTrustClass,
    capabilities: &CapabilitySet,
) -> Result<(), AdmissionError> {
    if matches!(
        trust,
        PluginTrustClass::BuiltIn | PluginTrustClass::FirstParty
    ) {
        return Ok(());
    }

    let tier = trust_tier_label(trust);
    if capabilities.network != NetworkCapability::None {
        return Err(AdmissionError::CapabilityDeniedForTrustTier {
            capability: "network",
            trust_tier: tier,
            allowed_tiers: "built-in, first-party",
        });
    }
    if capabilities.process == ProcessCapability::Spawn {
        return Err(AdmissionError::CapabilityDeniedForTrustTier {
            capability: "process",
            trust_tier: tier,
            allowed_tiers: "built-in, first-party",
        });
    }
    if capabilities.filesystem == FilesystemCapability::ReadWrite {
        return Err(AdmissionError::CapabilityDeniedForTrustTier {
            capability: "filesystem",
            trust_tier: tier,
            allowed_tiers: "built-in, first-party",
        });
    }
    Ok(())
}

const fn trust_tier_label(trust: PluginTrustClass) -> &'static str {
    match trust {
        PluginTrustClass::BuiltIn => "built-in",
        PluginTrustClass::FirstParty => "first-party",
        PluginTrustClass::CommunityReviewed => "community-reviewed",
        PluginTrustClass::CommunityUnreviewed => "community-unreviewed",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    #[test]
    fn first_party_passes_with_any_capability() -> TestResult {
        let caps = CapabilitySet {
            network: NetworkCapability::Full,
            filesystem: FilesystemCapability::ReadWrite,
            process: ProcessCapability::Spawn,
            max_memory_bytes: None,
            max_cpu_ms: None,
        };

        enforce_trust_tier_capabilities(PluginTrustClass::FirstParty, &caps)?;
        Ok(())
    }

    #[test]
    fn built_in_passes_with_any_capability() -> TestResult {
        let caps = CapabilitySet {
            network: NetworkCapability::Full,
            filesystem: FilesystemCapability::ReadWrite,
            process: ProcessCapability::Spawn,
            max_memory_bytes: None,
            max_cpu_ms: None,
        };

        enforce_trust_tier_capabilities(PluginTrustClass::BuiltIn, &caps)?;
        Ok(())
    }

    #[test]
    fn community_reviewed_rejects_network() {
        let caps = CapabilitySet {
            network: NetworkCapability::LoopbackOnly,
            ..CapabilitySet::default()
        };

        let result = enforce_trust_tier_capabilities(PluginTrustClass::CommunityReviewed, &caps);

        assert!(
            matches!(
                result,
                Err(AdmissionError::CapabilityDeniedForTrustTier {
                    capability: "network",
                    ..
                })
            ),
            "expected network denial for community-reviewed; got {result:?}"
        );
    }

    #[test]
    fn community_unreviewed_rejects_process_spawn() {
        let caps = CapabilitySet {
            process: ProcessCapability::Spawn,
            ..CapabilitySet::default()
        };

        let result = enforce_trust_tier_capabilities(PluginTrustClass::CommunityUnreviewed, &caps);

        assert!(
            matches!(
                result,
                Err(AdmissionError::CapabilityDeniedForTrustTier {
                    capability: "process",
                    ..
                })
            ),
            "expected process denial for community-unreviewed; got {result:?}"
        );
    }

    #[test]
    fn community_tier_rejects_read_write_filesystem() {
        let caps = CapabilitySet {
            filesystem: FilesystemCapability::ReadWrite,
            ..CapabilitySet::default()
        };

        let result = enforce_trust_tier_capabilities(PluginTrustClass::CommunityReviewed, &caps);

        assert!(
            matches!(
                result,
                Err(AdmissionError::CapabilityDeniedForTrustTier {
                    capability: "filesystem",
                    ..
                })
            ),
            "expected filesystem denial for community-reviewed; got {result:?}"
        );
    }

    #[test]
    fn community_tier_admits_read_only_filesystem() -> TestResult {
        let caps = CapabilitySet {
            filesystem: FilesystemCapability::ReadOnly,
            ..CapabilitySet::default()
        };

        enforce_trust_tier_capabilities(PluginTrustClass::CommunityReviewed, &caps)?;
        Ok(())
    }

    #[test]
    fn community_tier_admits_most_restrictive_default() -> TestResult {
        enforce_trust_tier_capabilities(
            PluginTrustClass::CommunityUnreviewed,
            &CapabilitySet::default(),
        )?;
        Ok(())
    }
}
