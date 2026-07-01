//! Review workflow and dispute resolution for community intelligence feeds.
//!
//! Builds on [`crate::submission`] and [`crate::workflow`] to provide the
//! review lifecycle. [`ReviewWorkflow`] processes [`Review`] decisions against
//! a submission and tracks reviewer consensus, while [`AntiAbuseChecker`]
//! enforces per-submitter rate limits on submissions and disputes
//! (spec §22.3 anti-abuse controls).
//!
//! All review and dispute types use [`serde`] with `deny_unknown_fields` so
//! unexpected keys are rejected at the deserialization boundary, matching the
//! crate convention for security-critical untrusted input
//! (see `docs/conventions.md`).

use crate::submission::{SubmissionStatus, TrustTier};
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Minimum trimmed character length for a review rationale.
const MIN_RATIONALE_LEN: usize = 10;

/// A review decision on a community submission.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Review {
    /// Identity and trust tier of the reviewer.
    pub reviewer: ReviewerIdentity,
    /// The decision rendered by the reviewer.
    pub decision: ReviewDecision,
    /// Free-form justification for the decision.
    pub rationale: String,
    /// Unix timestamp (seconds since epoch) when the review was rendered.
    pub reviewed_at: u64,
}

/// Identity and trust tier of a reviewer.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReviewerIdentity {
    /// Human-readable handle for the reviewer.
    pub handle: String,
    /// Trust tier assigned to the reviewer; gates which decisions the
    /// reviewer is permitted to render (see [`ReviewWorkflow::validate_review`]).
    pub trust_tier: TrustTier,
}

/// The decision rendered by a reviewer on a submission.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReviewDecision {
    /// Approve the submission for inclusion in the feed.
    Accept,
    /// Reject the submission.
    Reject,
    /// Request changes before a final decision can be reached.
    RequestChanges,
    /// Escalate to higher-tier review; suspends a final decision.
    Escalate,
}

/// A dispute filed against an accepted indicator.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Dispute {
    /// Identity of the community member filing the dispute.
    pub submitter: crate::submission::SubmitterIdentity,
    /// The canonical indicator value being disputed.
    pub indicator_value: String,
    /// The reason the indicator is being disputed.
    pub reason: DisputeReason,
    /// Supporting evidence justifying the dispute (required).
    pub evidence: String,
    /// Unix timestamp (seconds since epoch) when the dispute was filed.
    pub filed_at: u64,
}

/// The reason a submitted indicator is being disputed.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DisputeReason {
    /// The indicator is a false positive.
    FalsePositive,
    /// The indicator is no longer an active threat.
    Outdated,
    /// The indicator's threat classification is incorrect.
    IncorrectClassification,
    /// The original submission lacked sufficient evidence.
    InsufficientEvidence,
    /// The original submission was filed in bad faith to poison the feed.
    MaliciousSubmission,
}

/// Triage priority assigned to a dispute.
///
/// [`DisputeReason::MaliciousSubmission`] is escalated to [`DisputePriority::High`]
/// because it alleges deliberate feed poisoning and demands expedited review.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DisputePriority {
    /// Standard triage priority.
    Normal,
    /// High priority — expedited review queue.
    High,
}

/// Manages the review lifecycle for community submissions (spec §22.5).
///
/// Construct with [`ReviewWorkflow::new`] for the default policy (2 accepting
/// reviews required, [`TrustTier::Registered`] minimum to accept), or
/// [`ReviewWorkflow::with_policy`] to tune the thresholds. The workflow is a
/// pure policy function: it does not mutate state or persist reviews; the
/// caller owns the review queue and applies the returned status.
#[derive(Clone, Debug)]
pub struct ReviewWorkflow {
    /// Number of accepting reviews required to accept a submission.
    required_reviews: usize,
    /// Minimum trust tier for a reviewer's [`ReviewDecision::Accept`] to be
    /// valid and to count toward `required_reviews`.
    auto_accept_tier: TrustTier,
}

impl ReviewWorkflow {
    /// Creates a review workflow with the default policy:
    ///
    /// - 2 accepting reviews required.
    /// - [`TrustTier::Registered`] minimum tier to render an Accept.
    #[must_use]
    pub fn new() -> Self {
        Self::with_policy(2, TrustTier::Registered)
    }

    /// Creates a review workflow with custom thresholds.
    ///
    /// Set `required_reviews` to the number of accepting reviews needed to
    /// accept a submission. Set `auto_accept_tier` to the minimum trust tier
    /// a reviewer must hold for their Accept to count toward that number.
    #[must_use]
    pub fn with_policy(required_reviews: usize, auto_accept_tier: TrustTier) -> Self {
        Self {
            required_reviews,
            auto_accept_tier,
        }
    }

    /// Validates a review against policy before it is processed.
    ///
    /// # Errors
    ///
    /// Returns [`ValidationError::RationaleTooShort`] if `rationale` is fewer
    /// than 10 characters after trimming. Returns
    /// [`ValidationError::InsufficientTrustTier`] if the reviewer's trust tier
    /// is insufficient for the rendered decision:
    /// - [`ReviewDecision::Accept`] requires ≥ [`TrustTier::Registered`].
    /// - [`ReviewDecision::Reject`] requires ≥ [`TrustTier::Verified`].
    /// - [`ReviewDecision::Escalate`] requires ≥ [`TrustTier::Registered`].
    /// - [`ReviewDecision::RequestChanges`] is permitted at any tier.
    pub fn validate_review(&self, review: &Review) -> Result<(), ValidationError> {
        if review.rationale.trim().chars().count() < MIN_RATIONALE_LEN {
            return Err(ValidationError::RationaleTooShort);
        }
        if !self.tier_permits_decision(review.reviewer.trust_tier, review.decision) {
            return Err(ValidationError::InsufficientTrustTier);
        }
        Ok(())
    }

    /// Returns `true` if the trust tier is sufficient for the decision.
    fn tier_permits_decision(&self, tier: TrustTier, decision: ReviewDecision) -> bool {
        match decision {
            ReviewDecision::Accept => tier >= self.auto_accept_tier,
            ReviewDecision::Reject => tier >= TrustTier::Verified,
            ReviewDecision::Escalate => tier >= TrustTier::Registered,
            ReviewDecision::RequestChanges => true,
        }
    }

    /// Processes a review decision and returns the resulting submission status.
    ///
    /// `review_count` is the number of accepting reviews already recorded for
    /// the submission from reviewers at or above `auto_accept_tier`.
    /// This method is infallible and does not re-validate the review; call
    /// [`Self::validate_review`] first.
    ///
    /// # Decision effects
    ///
    /// - [`ReviewDecision::Escalate`] → [`UnderReview`](SubmissionStatus::UnderReview):
    ///   escalation always suspends a final decision, even from a terminal state.
    /// - [`ReviewDecision::Reject`] → [`Rejected`](SubmissionStatus::Rejected):
    ///   a reject is terminal unless later escalated.
    /// - [`ReviewDecision::RequestChanges`] → [`UnderReview`](SubmissionStatus::UnderReview).
    /// - [`ReviewDecision::Accept`] → [`Accepted`](SubmissionStatus::Accepted)
    ///   once `review_count + 1` reaches `required_reviews`, otherwise
    ///   [`UnderReview`](SubmissionStatus::UnderReview). An accept does not
    ///   revive a submission that is already
    ///   [`Rejected`](SubmissionStatus::Rejected) or
    ///   [`Expired`](SubmissionStatus::Expired).
    #[must_use]
    pub fn process_review(
        &self,
        current_status: SubmissionStatus,
        review: &Review,
        review_count: usize,
    ) -> SubmissionStatus {
        match review.decision {
            ReviewDecision::Escalate | ReviewDecision::RequestChanges => {
                SubmissionStatus::UnderReview
            }
            ReviewDecision::Reject => SubmissionStatus::Rejected,
            ReviewDecision::Accept => {
                if matches!(
                    current_status,
                    SubmissionStatus::Rejected | SubmissionStatus::Expired
                ) {
                    current_status
                } else if review_count + 1 >= self.required_reviews {
                    SubmissionStatus::Accepted
                } else {
                    SubmissionStatus::UnderReview
                }
            }
        }
    }

    /// Returns `true` if the submission has enough accepting reviews to be
    /// accepted.
    ///
    /// Only reviews whose decision is [`ReviewDecision::Accept`] **and** whose
    /// reviewer trust tier is at least `auto_accept_tier` are counted.
    #[must_use]
    pub fn is_accepted(&self, reviews: &[Review]) -> bool {
        let accepting = reviews
            .iter()
            .filter(|r| {
                r.decision == ReviewDecision::Accept
                    && r.reviewer.trust_tier >= self.auto_accept_tier
            })
            .count();
        accepting >= self.required_reviews
    }

    /// Returns `true` if the submission has a valid rejection.
    ///
    /// Only reviews whose decision is [`ReviewDecision::Reject`] **and** whose
    /// reviewer trust tier is at least [`TrustTier::Verified`] are considered,
    /// matching the rule that rejection requires a verified reviewer.
    #[must_use]
    pub fn is_rejected(&self, reviews: &[Review]) -> bool {
        reviews.iter().any(|r| {
            r.decision == ReviewDecision::Reject && r.reviewer.trust_tier >= TrustTier::Verified
        })
    }

    /// Validates a dispute filing.
    ///
    /// # Errors
    ///
    /// Returns [`ValidationError::MissingEvidence`] if `evidence` is empty or
    /// whitespace-only.
    pub fn validate_dispute(&self, dispute: &Dispute) -> Result<(), ValidationError> {
        if dispute.evidence.trim().is_empty() {
            return Err(ValidationError::MissingEvidence);
        }
        Ok(())
    }

    /// Returns the triage priority for a dispute.
    ///
    /// [`DisputeReason::MaliciousSubmission`] is [`DisputePriority::High`]
    /// because it alleges deliberate feed poisoning and warrants expedited
    /// review; all other reasons are [`DisputePriority::Normal`].
    #[must_use]
    pub fn dispute_priority(&self, dispute: &Dispute) -> DisputePriority {
        match dispute.reason {
            DisputeReason::MaliciousSubmission => DisputePriority::High,
            DisputeReason::FalsePositive
            | DisputeReason::Outdated
            | DisputeReason::IncorrectClassification
            | DisputeReason::InsufficientEvidence => DisputePriority::Normal,
        }
    }
}

impl Default for ReviewWorkflow {
    fn default() -> Self {
        Self::new()
    }
}

/// Anti-abuse rate limiter for community intelligence contributions
/// (spec §22.3).
///
/// Enforces per-handle ceilings on submission and dispute frequency. The
/// caller tracks the recent count per handle (e.g. via the transparency log,
/// tracked separately in #155); the checker is a pure policy gate over the
/// supplied count.
#[derive(Clone, Debug)]
pub struct AntiAbuseChecker {
    /// Maximum submissions permitted per handle per hour.
    max_submissions_per_hour: usize,
    /// Maximum disputes permitted per handle per day.
    max_disputes_per_day: usize,
}

impl AntiAbuseChecker {
    /// Creates a checker with the default policy:
    ///
    /// - 10 submissions per handle per hour.
    /// - 5 disputes per handle per day.
    #[must_use]
    pub fn new() -> Self {
        Self::with_limits(10, 5)
    }

    /// Creates a checker with custom rate ceilings.
    #[must_use]
    pub fn with_limits(max_submissions_per_hour: usize, max_disputes_per_day: usize) -> Self {
        Self {
            max_submissions_per_hour,
            max_disputes_per_day,
        }
    }

    /// Returns `Ok` if the submitter has not exceeded the hourly submission
    /// ceiling.
    ///
    /// `recent_count` is the number of submissions already recorded for
    /// `handle` in the current hour. The check blocks the contribution that
    /// would exceed the ceiling (the 11th submission when the limit is 10).
    ///
    /// # Errors
    ///
    /// Returns [`RateLimitError::SubmissionsExceeded`] if `recent_count` is
    /// greater than or equal to the configured hourly ceiling.
    pub fn check_submission_rate(
        &self,
        handle: &str,
        recent_count: usize,
    ) -> Result<(), RateLimitError> {
        let _ = handle;
        if recent_count >= self.max_submissions_per_hour {
            return Err(RateLimitError::SubmissionsExceeded(
                self.max_submissions_per_hour,
            ));
        }
        Ok(())
    }

    /// Returns `Ok` if the submitter has not exceeded the daily dispute
    /// ceiling.
    ///
    /// `recent_count` is the number of disputes already recorded for `handle`
    /// in the current day. The check blocks the dispute that would exceed the
    /// ceiling (the 6th dispute when the limit is 5).
    ///
    /// # Errors
    ///
    /// Returns [`RateLimitError::DisputesExceeded`] if `recent_count` is
    /// greater than or equal to the configured daily ceiling.
    pub fn check_dispute_rate(
        &self,
        handle: &str,
        recent_count: usize,
    ) -> Result<(), RateLimitError> {
        let _ = handle;
        if recent_count >= self.max_disputes_per_day {
            return Err(RateLimitError::DisputesExceeded(self.max_disputes_per_day));
        }
        Ok(())
    }
}

impl Default for AntiAbuseChecker {
    fn default() -> Self {
        Self::new()
    }
}

/// Errors produced by review and dispute validation.
#[derive(Debug, Eq, Error, PartialEq)]
pub enum ValidationError {
    /// Review rationale is fewer than 10 characters after trimming.
    #[error("rationale must be at least 10 characters")]
    RationaleTooShort,
    /// Reviewer trust tier is insufficient for the rendered decision.
    #[error("reviewer trust tier too low for this decision")]
    InsufficientTrustTier,
    /// Dispute evidence is empty or whitespace-only.
    #[error("dispute evidence must be provided")]
    MissingEvidence,
}

/// Errors produced by [`AntiAbuseChecker`] rate-limit checks.
#[derive(Debug, Eq, Error, PartialEq)]
pub enum RateLimitError {
    /// Hourly submission ceiling exceeded; the inner value is the configured
    /// ceiling.
    #[error("submission rate limit exceeded: {0} per hour")]
    SubmissionsExceeded(usize),
    /// Daily dispute ceiling exceeded; the inner value is the configured
    /// ceiling.
    #[error("dispute rate limit exceeded: {0} per day")]
    DisputesExceeded(usize),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::submission::{SubmitterIdentity, TrustTier};

    /// Minimum trust tier required to render a Reject (spec §22.5).
    const REJECT_MIN_TIER: TrustTier = TrustTier::Verified;

    /// Builds a review with sensible defaults for test customization.
    fn review(tier: TrustTier, decision: ReviewDecision) -> Review {
        Review {
            reviewer: ReviewerIdentity {
                handle: "reviewer".to_owned(),
                trust_tier: tier,
            },
            decision,
            rationale: "Indicator verified against sandbox telemetry.".to_owned(),
            reviewed_at: 0,
        }
    }

    /// Builds a dispute with non-empty evidence for test customization.
    fn dispute(reason: DisputeReason) -> Dispute {
        Dispute {
            submitter: SubmitterIdentity {
                handle: "analyst".to_owned(),
                trust_tier: TrustTier::Registered,
                key_fingerprint: None,
            },
            indicator_value: "https://evil.example/payload".to_owned(),
            reason,
            evidence: "Reproduced in isolated sandbox; no malicious behavior.".to_owned(),
            filed_at: 0,
        }
    }

    #[test]
    fn accept_after_required_reviews() {
        // Given a default workflow (2 accepts required) and two accepting
        // reviews from registered reviewers
        let workflow = ReviewWorkflow::new();
        let accept = review(TrustTier::Registered, ReviewDecision::Accept);

        // When the first accept is processed
        let after_first = workflow.process_review(SubmissionStatus::Pending, &accept, 0);
        // Then the submission is under review (not yet enough accepts)
        assert_eq!(after_first, SubmissionStatus::UnderReview);

        // When the second accept is processed
        let after_second = workflow.process_review(after_first, &accept, 1);
        // Then the submission is accepted
        assert_eq!(after_second, SubmissionStatus::Accepted);
        assert!(workflow.is_accepted(&[accept.clone(), accept]));
    }

    #[test]
    fn reject_overrides_accepts() {
        // Given a default workflow and one prior accept
        let workflow = ReviewWorkflow::new();
        let accept = review(TrustTier::Registered, ReviewDecision::Accept);
        let reject = review(REJECT_MIN_TIER, ReviewDecision::Reject);

        // When an accept then a reject are processed
        let after_accept = workflow.process_review(SubmissionStatus::Pending, &accept, 0);
        let after_reject = workflow.process_review(after_accept, &reject, 1);

        // Then the submission is rejected
        assert_eq!(after_reject, SubmissionStatus::Rejected);
        assert!(workflow.is_rejected(&[accept, reject]));
    }

    #[test]
    fn low_tier_cannot_reject() {
        // Given a default workflow and a reject from an anonymous reviewer
        let workflow = ReviewWorkflow::new();
        let reject = review(TrustTier::Anonymous, ReviewDecision::Reject);

        // When the review is validated
        let result = workflow.validate_review(&reject);

        // Then validation fails due to insufficient trust tier
        assert_eq!(result, Err(ValidationError::InsufficientTrustTier));
        // And the submission is not considered rejected by the low-tier review
        assert!(!workflow.is_rejected(&[reject]));
    }

    #[test]
    fn escalate_suspends_decision() {
        // Given a default workflow and an escalation from a registered reviewer
        let workflow = ReviewWorkflow::new();
        let escalate = review(TrustTier::Registered, ReviewDecision::Escalate);

        // When the escalation is processed from a pending submission
        let status = workflow.process_review(SubmissionStatus::Pending, &escalate, 0);

        // Then the submission moves to under review
        assert_eq!(status, SubmissionStatus::UnderReview);
    }

    #[test]
    fn escalate_overrides_terminal_rejected() {
        // Given a default workflow and a submission that is already rejected
        let workflow = ReviewWorkflow::new();
        let escalate = review(TrustTier::Registered, ReviewDecision::Escalate);

        // When an escalation is processed against the rejected submission
        let status = workflow.process_review(SubmissionStatus::Rejected, &escalate, 0);

        // Then escalation reopens the submission for review
        assert_eq!(status, SubmissionStatus::UnderReview);
    }

    #[test]
    fn accept_does_not_revive_rejected() {
        // Given a default workflow and a submission that is already rejected
        let workflow = ReviewWorkflow::new();
        let accept = review(TrustTier::Registered, ReviewDecision::Accept);

        // When an accept is processed against the rejected submission
        let status = workflow.process_review(SubmissionStatus::Rejected, &accept, 0);

        // Then the submission stays rejected
        assert_eq!(status, SubmissionStatus::Rejected);
    }

    #[test]
    fn short_rationale_rejected() {
        // Given a default workflow and a review with a terse rationale
        let workflow = ReviewWorkflow::new();
        let mut accept = review(TrustTier::Registered, ReviewDecision::Accept);
        accept.rationale = "ok".to_owned();

        // When the review is validated
        let result = workflow.validate_review(&accept);

        // Then validation fails due to the short rationale
        assert_eq!(result, Err(ValidationError::RationaleTooShort));
    }

    #[test]
    fn anonymous_can_request_changes() {
        // Given a default workflow and a request-changes from an anonymous
        // reviewer (any tier may request changes)
        let workflow = ReviewWorkflow::new();
        let request = review(TrustTier::Anonymous, ReviewDecision::RequestChanges);

        // When the review is validated
        let result = workflow.validate_review(&request);

        // Then validation passes
        assert!(result.is_ok());
    }

    #[test]
    fn verified_tier_can_reject() {
        // Given a default workflow and a reject from a verified reviewer
        let workflow = ReviewWorkflow::new();
        let reject = review(REJECT_MIN_TIER, ReviewDecision::Reject);

        // When the review is validated
        let result = workflow.validate_review(&reject);

        // Then validation passes
        assert!(result.is_ok());
    }

    #[test]
    fn dispute_requires_evidence() {
        // Given a default workflow and a dispute with empty evidence
        let workflow = ReviewWorkflow::new();
        let mut dispute = dispute(DisputeReason::FalsePositive);
        dispute.evidence = "   ".to_owned();

        // When the dispute is validated
        let result = workflow.validate_dispute(&dispute);

        // Then validation fails due to missing evidence
        assert_eq!(result, Err(ValidationError::MissingEvidence));
    }

    #[test]
    fn dispute_with_evidence_passes() {
        // Given a default workflow and a valid dispute
        let workflow = ReviewWorkflow::new();
        let dispute = dispute(DisputeReason::Outdated);

        // When the dispute is validated
        let result = workflow.validate_dispute(&dispute);

        // Then validation passes
        assert!(result.is_ok());
    }

    #[test]
    fn rate_limit_blocks_excess_submissions() {
        // Given a default anti-abuse checker (10 submissions/hour)
        let checker = AntiAbuseChecker::new();

        // When an 11th submission is checked (10 already recorded)
        let result = checker.check_submission_rate("spammer", 10);

        // Then the check rejects the submission
        assert_eq!(result, Err(RateLimitError::SubmissionsExceeded(10)));
    }

    #[test]
    fn rate_limit_allows_within_limit() {
        // Given a default anti-abuse checker (10 submissions/hour)
        let checker = AntiAbuseChecker::new();

        // When a 10th submission is checked (9 already recorded)
        let result = checker.check_submission_rate("analyst", 9);

        // Then the check passes
        assert!(result.is_ok());
    }

    #[test]
    fn dispute_rate_limit() {
        // Given a default anti-abuse checker (5 disputes/day)
        let checker = AntiAbuseChecker::new();

        // When a 6th dispute is checked (5 already recorded)
        let result = checker.check_dispute_rate("analyst", 5);

        // Then the check rejects the dispute
        assert_eq!(result, Err(RateLimitError::DisputesExceeded(5)));
    }

    #[test]
    fn dispute_rate_allows_within_limit() {
        // Given a default anti-abuse checker (5 disputes/day)
        let checker = AntiAbuseChecker::new();

        // When a 5th dispute is checked (4 already recorded)
        let result = checker.check_dispute_rate("analyst", 4);

        // Then the check passes
        assert!(result.is_ok());
    }

    #[test]
    fn malicious_submission_dispute_allows_high_priority() {
        // Given a default workflow and a dispute alleging malicious submission
        let workflow = ReviewWorkflow::new();
        let dispute = dispute(DisputeReason::MaliciousSubmission);

        // When the dispute priority is computed
        let priority = workflow.dispute_priority(&dispute);

        // Then the dispute is high priority for expedited review
        assert_eq!(priority, DisputePriority::High);
        // And the dispute still passes evidence validation
        assert!(workflow.validate_dispute(&dispute).is_ok());
    }

    #[test]
    fn non_malicious_disputes_are_normal_priority() {
        // Given a default workflow and a non-malicious dispute
        let workflow = ReviewWorkflow::new();

        // When priorities are computed for every other reason
        for reason in [
            DisputeReason::FalsePositive,
            DisputeReason::Outdated,
            DisputeReason::IncorrectClassification,
            DisputeReason::InsufficientEvidence,
        ] {
            // Then the dispute is normal priority
            let dispute = dispute(reason);
            assert_eq!(
                workflow.dispute_priority(&dispute),
                DisputePriority::Normal,
                "reason {reason:?} should be normal priority"
            );
        }
    }

    #[test]
    fn custom_required_reviews_threshold() {
        // Given a workflow requiring 3 accepting reviews
        let workflow = ReviewWorkflow::with_policy(3, TrustTier::Registered);
        let accept = review(TrustTier::Registered, ReviewDecision::Accept);

        // When two accepts are processed
        let after_second = workflow.process_review(
            workflow.process_review(SubmissionStatus::Pending, &accept, 0),
            &accept,
            1,
        );

        // Then the submission is still under review (needs a third accept)
        assert_eq!(after_second, SubmissionStatus::UnderReview);
        assert!(!workflow.is_accepted(&[accept.clone(), accept]));

        // And a third accept accepts it
        let after_third = workflow.process_review(
            after_second,
            &review(TrustTier::Registered, ReviewDecision::Accept),
            2,
        );
        assert_eq!(after_third, SubmissionStatus::Accepted);
    }

    #[test]
    fn low_tier_accept_does_not_count() {
        // Given a default workflow (auto_accept_tier = Registered)
        let workflow = ReviewWorkflow::new();

        // When an anonymous reviewer accepts
        let anonymous_accept = review(TrustTier::Anonymous, ReviewDecision::Accept);

        // Then the accept does not count toward acceptance (tier too low),
        // even though RequestChanges is the only decision any tier may render
        assert!(!workflow.is_accepted(&[anonymous_accept]));
    }

    #[test]
    fn deny_unknown_fields_rejects_extra_keys() {
        let json = r#"{
            "reviewer": {
                "handle": "r",
                "trust_tier": "registered",
                "extra": true
            },
            "decision": "accept",
            "rationale": "valid rationale here",
            "reviewed_at": 0,
            "unexpected": 1
        }"#;
        assert!(serde_json::from_str::<Review>(json).is_err());
    }

    #[test]
    fn review_round_trips() -> Result<(), Box<dyn std::error::Error>> {
        let original = review(TrustTier::Verified, ReviewDecision::Accept);
        let json = serde_json::to_string(&original)?;
        let decoded: Review = serde_json::from_str(&json)?;
        assert_eq!(decoded, original);
        Ok(())
    }
}
