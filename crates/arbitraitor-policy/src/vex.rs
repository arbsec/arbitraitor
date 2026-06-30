//! VEX anti-suppression rules (spec §19.5, invariant 21).
//!
//! A VEX statement may downgrade the severity of a vulnerability finding,
//! but only when all five binding conditions are met. Only `PackageRisk`
//! findings are eligible for downgrade — all other categories are
//! non-suppressible by default.

use std::collections::HashSet;

use arbitraitor_model::finding::FindingCategory;
use arbitraitor_model::verdict::Severity;
use arbitraitor_model::vex::{VexStatement, VexStatus};

const FRESHNESS_WINDOW_SECS: i64 = 90 * 24 * 3_600;

const SUPPRESSIBLE_CATEGORIES: &[FindingCategory] = &[FindingCategory::PackageRisk];

/// Configuration for VEX-based severity downgrade.
#[derive(Clone, Debug)]
pub struct VexPolicy {
    enabled: bool,
    trusted_issuers: HashSet<String>,
    freshness_window_secs: i64,
}

impl VexPolicy {
    /// Creates a VEX policy with severity downgrade disabled.
    #[must_use]
    pub fn disabled() -> Self {
        Self {
            enabled: false,
            trusted_issuers: HashSet::new(),
            freshness_window_secs: FRESHNESS_WINDOW_SECS,
        }
    }

    /// Enables VEX downgrade and sets the list of trusted issuers.
    #[must_use]
    pub fn with_trusted_issuers(mut self, issuers: &[&str]) -> Self {
        self.enabled = true;
        self.trusted_issuers = issuers.iter().map(|s| (*s).to_owned()).collect();
        self
    }

    /// Sets the freshness window in seconds.
    #[must_use]
    pub const fn with_freshness_window(mut self, secs: i64) -> Self {
        self.freshness_window_secs = secs;
        self
    }
}

impl Default for VexPolicy {
    fn default() -> Self {
        Self::disabled()
    }
}

/// Result of validating a VEX statement for severity downgrade.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum VexDowngradeResult {
    /// All 5 conditions met; severity may be downgraded to the given level.
    Allow(Severity),
    /// Downgrade denied; the finding retains its original severity.
    Deny(VexDenyReason),
}

/// Reason a VEX downgrade was denied.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum VexDenyReason {
    /// VEX policy is not enabled.
    PolicyDisabled,
    /// VEX issuer is not in the trust root.
    UntrustedIssuer,
    /// VEX subject does not match the finding's artifact.
    SubjectMismatch,
    /// VEX status is not `not_affected` or `fixed`.
    InvalidStatus,
    /// VEX timestamp is missing.
    MissingTimestamp,
    /// VEX timestamp is outside the freshness window.
    Stale,
    /// Finding category is not eligible for VEX downgrade.
    NonSuppressibleCategory,
}

/// Validates whether a VEX statement may downgrade a finding's severity.
///
/// Per spec §19.5, all five conditions must be true:
/// 1. VEX issuer is in the trust root
/// 2. VEX subject matches the artifact's digest or coordinate
/// 3. VEX status is `not_affected` or `fixed`
/// 4. VEX timestamp is present and within the freshness window
/// 5. Policy explicitly enables VEX-based downgrade for this issuer
///
/// Only `PackageRisk` findings are eligible for downgrade. All other
/// categories are non-suppressible (invariant 21).
#[must_use]
pub fn validate_vex_downgrade(
    policy: &VexPolicy,
    vex: &VexStatement,
    finding_category: FindingCategory,
    finding_subject: &str,
    now_epoch: i64,
) -> VexDowngradeResult {
    if !policy.enabled {
        return VexDowngradeResult::Deny(VexDenyReason::PolicyDisabled);
    }

    if !SUPPRESSIBLE_CATEGORIES.contains(&finding_category) {
        return VexDowngradeResult::Deny(VexDenyReason::NonSuppressibleCategory);
    }

    if !policy.trusted_issuers.contains(&vex.issuer) {
        return VexDowngradeResult::Deny(VexDenyReason::UntrustedIssuer);
    }

    if vex.subject != finding_subject {
        return VexDowngradeResult::Deny(VexDenyReason::SubjectMismatch);
    }

    if !matches!(vex.status, VexStatus::NotAffected | VexStatus::Fixed) {
        return VexDowngradeResult::Deny(VexDenyReason::InvalidStatus);
    }

    let Some(timestamp) = vex.timestamp else {
        return VexDowngradeResult::Deny(VexDenyReason::MissingTimestamp);
    };

    let age = now_epoch - timestamp;
    if age < 0 || age > policy.freshness_window_secs {
        return VexDowngradeResult::Deny(VexDenyReason::Stale);
    }

    VexDowngradeResult::Allow(Severity::Informational)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn trusted_vex() -> VexStatement {
        VexStatement {
            issuer: "pkg:github/owner/repo".to_owned(),
            subject: "pkg:foo@1.0".to_owned(),
            status: VexStatus::NotAffected,
            justification: None,
            statement: None,
            timestamp: Some(1_000_000),
        }
    }

    fn policy() -> VexPolicy {
        VexPolicy::disabled().with_trusted_issuers(&["pkg:github/owner/repo"])
    }

    #[test]
    fn deny_when_policy_disabled() {
        let result = validate_vex_downgrade(
            &VexPolicy::disabled(),
            &trusted_vex(),
            FindingCategory::PackageRisk,
            "pkg:foo@1.0",
            1_000_000,
        );
        assert_eq!(
            result,
            VexDowngradeResult::Deny(VexDenyReason::PolicyDisabled)
        );
    }

    #[test]
    fn allow_valid_downgrade() {
        let result = validate_vex_downgrade(
            &policy(),
            &trusted_vex(),
            FindingCategory::PackageRisk,
            "pkg:foo@1.0",
            1_000_000,
        );
        assert!(matches!(result, VexDowngradeResult::Allow(_)));
    }

    #[test]
    fn deny_untrusted_issuer() {
        let vex = VexStatement {
            issuer: "untrusted".to_owned(),
            ..trusted_vex()
        };
        let result = validate_vex_downgrade(
            &policy(),
            &vex,
            FindingCategory::PackageRisk,
            "pkg:foo@1.0",
            1_000_000,
        );
        assert_eq!(
            result,
            VexDowngradeResult::Deny(VexDenyReason::UntrustedIssuer)
        );
    }

    #[test]
    fn deny_subject_mismatch() {
        let result = validate_vex_downgrade(
            &policy(),
            &trusted_vex(),
            FindingCategory::PackageRisk,
            "pkg:different@2.0",
            1_000_000,
        );
        assert_eq!(
            result,
            VexDowngradeResult::Deny(VexDenyReason::SubjectMismatch)
        );
    }

    #[test]
    fn deny_invalid_status() {
        let vex = VexStatement {
            status: VexStatus::Affected,
            ..trusted_vex()
        };
        let result = validate_vex_downgrade(
            &policy(),
            &vex,
            FindingCategory::PackageRisk,
            "pkg:foo@1.0",
            1_000_000,
        );
        assert_eq!(
            result,
            VexDowngradeResult::Deny(VexDenyReason::InvalidStatus)
        );
    }

    #[test]
    fn deny_stale_vex() {
        let result = validate_vex_downgrade(
            &policy(),
            &trusted_vex(),
            FindingCategory::PackageRisk,
            "pkg:foo@1.0",
            1_000_000 + FRESHNESS_WINDOW_SECS + 1,
        );
        assert_eq!(result, VexDowngradeResult::Deny(VexDenyReason::Stale));
    }

    #[test]
    fn deny_non_suppressible_category() {
        let result = validate_vex_downgrade(
            &policy(),
            &trusted_vex(),
            FindingCategory::MalwareSignature,
            "pkg:foo@1.0",
            1_000_000,
        );
        assert_eq!(
            result,
            VexDowngradeResult::Deny(VexDenyReason::NonSuppressibleCategory)
        );
    }

    #[test]
    fn allow_fixed_status() {
        let vex = VexStatement {
            status: VexStatus::Fixed,
            ..trusted_vex()
        };
        let result = validate_vex_downgrade(
            &policy(),
            &vex,
            FindingCategory::PackageRisk,
            "pkg:foo@1.0",
            1_000_000,
        );
        assert!(matches!(result, VexDowngradeResult::Allow(_)));
    }

    #[test]
    fn deny_unknown_status() {
        let vex = VexStatement {
            status: VexStatus::Unknown,
            ..trusted_vex()
        };
        let result = validate_vex_downgrade(
            &policy(),
            &vex,
            FindingCategory::PackageRisk,
            "pkg:foo@1.0",
            1_000_000,
        );
        assert_eq!(
            result,
            VexDowngradeResult::Deny(VexDenyReason::InvalidStatus)
        );
    }

    #[test]
    fn all_non_suppressible_categories_denied() {
        let non_eligible = [
            FindingCategory::MalwareSignature,
            FindingCategory::ContentMismatch,
            FindingCategory::PolicyViolation,
            FindingCategory::ResourceLimitEvent,
            FindingCategory::SuspiciousScriptBehavior,
            FindingCategory::Obfuscation,
            FindingCategory::CredentialAccess,
            FindingCategory::Persistence,
            FindingCategory::PrivilegeEscalation,
            FindingCategory::DestructiveBehavior,
            FindingCategory::NetworkBehavior,
            FindingCategory::DynamicCodeExecution,
            FindingCategory::ArchiveHazard,
            FindingCategory::Provenance,
            FindingCategory::Reputation,
            FindingCategory::Transport,
            FindingCategory::ParserError,
        ];
        for cat in &non_eligible {
            let result =
                validate_vex_downgrade(&policy(), &trusted_vex(), *cat, "pkg:foo@1.0", 1_000_000);
            assert_eq!(
                result,
                VexDowngradeResult::Deny(VexDenyReason::NonSuppressibleCategory),
                "category {cat:?} should be non-suppressible",
            );
        }
    }

    #[test]
    fn deny_future_timestamp_as_stale() {
        let vex = VexStatement {
            timestamp: Some(2_000_000),
            ..trusted_vex()
        };
        let result = validate_vex_downgrade(
            &policy(),
            &vex,
            FindingCategory::PackageRisk,
            "pkg:foo@1.0",
            1_000_000,
        );
        assert_eq!(result, VexDowngradeResult::Deny(VexDenyReason::Stale));
    }

    #[test]
    fn deny_missing_timestamp() {
        let vex = VexStatement {
            timestamp: None,
            ..trusted_vex()
        };
        let result = validate_vex_downgrade(
            &policy(),
            &vex,
            FindingCategory::PackageRisk,
            "pkg:foo@1.0",
            1_000_000,
        );
        assert_eq!(
            result,
            VexDowngradeResult::Deny(VexDenyReason::MissingTimestamp)
        );
    }
}
