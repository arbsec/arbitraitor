//! Community feed submission review workflow.
//!
//! [`SubmissionWorkflow`] evaluates a validated [`FeedSubmission`] and
//! determines its initial [`SubmissionStatus`] based on the submitter's trust
//! tier, confidence level, and attached evidence. The workflow does not
//! itself mutate state — it is a pure policy function whose output a caller
//! applies to whatever persistence layer owns the submission queue.

use crate::submission::{
    ConfidenceLevel, FeedSubmission, SubmissionEvidence, SubmissionStatus, TrustTier,
};

/// Manages the community submission lifecycle.
///
/// Construct with [`SubmissionWorkflow::new`] for the default policy, or
/// [`SubmissionWorkflow::with_policy`] to tune auto-accept and evidence
/// thresholds. The workflow assumes the submission has already passed
/// [`crate::validate_submission`]; it does not re-run structural validation.
#[derive(Clone, Debug)]
pub struct SubmissionWorkflow {
    /// Minimum trust tier required for auto-acceptance.
    min_trust_for_auto_accept: TrustTier,
    /// When `true`, high-confidence submissions without sample-hash evidence
    /// are routed to [`SubmissionStatus::UnderReview`] instead of being
    /// auto-accepted.
    require_evidence_for_high: bool,
}

impl SubmissionWorkflow {
    /// Creates a workflow with the default policy:
    ///
    /// - Auto-accept only from [`TrustTier::Verified`] and above.
    /// - Do not require evidence for high-confidence submissions (confirmed
    ///   always requires evidence per [`crate::validate_submission`]).
    #[must_use]
    pub fn new() -> Self {
        Self {
            min_trust_for_auto_accept: TrustTier::Verified,
            require_evidence_for_high: false,
        }
    }

    /// Creates a workflow with a custom auto-accept threshold and evidence
    /// policy.
    ///
    /// Set `min_trust_for_auto_accept` to [`TrustTier::Trusted`] to require
    /// the highest trust tier for auto-acceptance. Set
    /// `require_evidence_for_high` to `true` to route high-confidence
    /// submissions without sample hashes to manual review.
    #[must_use]
    pub fn with_policy(
        min_trust_for_auto_accept: TrustTier,
        require_evidence_for_high: bool,
    ) -> Self {
        Self {
            min_trust_for_auto_accept,
            require_evidence_for_high,
        }
    }

    /// Evaluates a submission and returns the initial status.
    ///
    /// - Submissions meeting the auto-accept threshold are [`Accepted`](SubmissionStatus::Accepted),
    ///   unless a `require_evidence_for_high` downgrade applies.
    /// - Submissions below the threshold are [`Pending`](SubmissionStatus::Pending).
    /// - High-confidence submissions without evidence under an enabled
    ///   evidence requirement are [`UnderReview`](SubmissionStatus::UnderReview).
    #[must_use]
    pub fn evaluate(&self, submission: &FeedSubmission) -> SubmissionStatus {
        if !self.can_auto_accept(submission) {
            return SubmissionStatus::Pending;
        }

        if self.require_evidence_for_high
            && submission.indicator.confidence == ConfidenceLevel::High
            && evidence_is_sparse(&submission.evidence)
        {
            return SubmissionStatus::UnderReview;
        }

        SubmissionStatus::Accepted
    }

    /// Returns `true` if the submission can be auto-accepted based on trust tier.
    ///
    /// Auto-acceptance is granted when `submitter.trust_tier` is greater than
    /// or equal to the configured `min_trust_for_auto_accept`.
    #[must_use]
    pub fn can_auto_accept(&self, submission: &FeedSubmission) -> bool {
        submission.submitter.trust_tier >= self.min_trust_for_auto_accept
    }

    /// Returns the review priority (higher = more urgent).
    ///
    /// Priority is derived from the submitter-assigned confidence level so
    /// that reviewers can triage the most impactful submissions first:
    ///
    /// | Confidence | Priority |
    /// |---|---|
    /// | [`Confirmed`] | 4 |
    /// | [`High`] | 3 |
    /// | [`Medium`] | 2 |
    /// | [`Low`] | 1 |
    ///
    /// [`Confirmed`]: ConfidenceLevel::Confirmed
    /// [`High`]: ConfidenceLevel::High
    /// [`Medium`]: ConfidenceLevel::Medium
    /// [`Low`]: ConfidenceLevel::Low
    #[must_use]
    pub fn review_priority(&self, submission: &FeedSubmission) -> u8 {
        match submission.indicator.confidence {
            ConfidenceLevel::Confirmed => 4,
            ConfidenceLevel::High => 3,
            ConfidenceLevel::Medium => 2,
            ConfidenceLevel::Low => 1,
        }
    }
}

impl Default for SubmissionWorkflow {
    fn default() -> Self {
        Self::new()
    }
}

/// Returns `true` when evidence lacks both sample hashes and a description.
fn evidence_is_sparse(evidence: &SubmissionEvidence) -> bool {
    evidence.sample_hashes.is_empty() && evidence.description.trim().is_empty()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::submission::{
        ConfidenceLevel, FeedSubmission, SubmissionEvidence, SubmissionMetadata,
        SubmittedIndicator, SubmitterIdentity, TrustTier,
    };

    fn submission(tier: TrustTier, confidence: ConfidenceLevel) -> FeedSubmission {
        FeedSubmission {
            submitter: SubmitterIdentity {
                handle: "analyst".to_owned(),
                trust_tier: tier,
                key_fingerprint: None,
            },
            indicator: SubmittedIndicator {
                indicator_type: crate::submission::IndicatorType::Domain,
                value: "evil.example".to_owned(),
                confidence,
            },
            evidence: SubmissionEvidence::default(),
            metadata: SubmissionMetadata::default(),
        }
    }

    #[test]
    fn auto_accept_trusted_tier() {
        let workflow = SubmissionWorkflow::with_policy(TrustTier::Trusted, false);
        let submission = submission(TrustTier::Trusted, ConfidenceLevel::High);
        assert_eq!(workflow.evaluate(&submission), SubmissionStatus::Accepted);
        assert!(workflow.can_auto_accept(&submission));
    }

    #[test]
    fn verified_tier_auto_accepted_by_default() {
        let workflow = SubmissionWorkflow::new();
        let submission = submission(TrustTier::Verified, ConfidenceLevel::Medium);
        assert_eq!(workflow.evaluate(&submission), SubmissionStatus::Accepted);
    }

    #[test]
    fn anonymous_needs_review() {
        let workflow = SubmissionWorkflow::new();
        let submission = submission(TrustTier::Anonymous, ConfidenceLevel::Medium);
        assert_eq!(workflow.evaluate(&submission), SubmissionStatus::Pending);
        assert!(!workflow.can_auto_accept(&submission));
    }

    #[test]
    fn registered_below_default_threshold_is_pending() {
        let workflow = SubmissionWorkflow::new();
        let submission = submission(TrustTier::Registered, ConfidenceLevel::Medium);
        assert_eq!(workflow.evaluate(&submission), SubmissionStatus::Pending);
    }

    #[test]
    fn review_priority_higher_for_confirmed() {
        let workflow = SubmissionWorkflow::new();
        let low = submission(TrustTier::Anonymous, ConfidenceLevel::Low);
        let confirmed = submission(TrustTier::Registered, ConfidenceLevel::Confirmed);
        assert!(workflow.review_priority(&confirmed) > workflow.review_priority(&low));
    }

    #[test]
    fn review_priority_increases_monotonically_with_confidence() {
        let workflow = SubmissionWorkflow::new();
        let low =
            workflow.review_priority(&submission(TrustTier::Registered, ConfidenceLevel::Low));
        let medium =
            workflow.review_priority(&submission(TrustTier::Registered, ConfidenceLevel::Medium));
        let high =
            workflow.review_priority(&submission(TrustTier::Registered, ConfidenceLevel::High));
        let confirmed = workflow.review_priority(&submission(
            TrustTier::Registered,
            ConfidenceLevel::Confirmed,
        ));
        assert!(low < medium);
        assert!(medium < high);
        assert!(high < confirmed);
    }

    #[test]
    fn require_evidence_for_high_routes_to_review() {
        let workflow = SubmissionWorkflow::with_policy(TrustTier::Trusted, true);
        let mut submission = submission(TrustTier::Trusted, ConfidenceLevel::High);
        submission.evidence = SubmissionEvidence::default();
        assert_eq!(
            workflow.evaluate(&submission),
            SubmissionStatus::UnderReview
        );
    }

    #[test]
    fn require_evidence_for_high_accepts_with_description() {
        let workflow = SubmissionWorkflow::with_policy(TrustTier::Trusted, true);
        let mut submission = submission(TrustTier::Trusted, ConfidenceLevel::High);
        submission.evidence.description = "observed dropper".to_owned();
        assert_eq!(workflow.evaluate(&submission), SubmissionStatus::Accepted);
    }
}
