//! Community governance controls for the threat-intelligence feed (spec §22).
//!
//! Complements [`crate::submission`], [`crate::review`], and
//! [`crate::transparency`] with the missing governance pieces called out in
//! issue #525:
//!
//! - [`duplicate_collapse`] merges feed entries that describe the same
//!   indicator, preserving the earliest observation, the latest activity,
//!   the highest confidence, the union of corroborating sources, and any
//!   previously-missing evidence. This implements the anti-abuse control
//!   required to keep a deduplicated, reproducible feed.
//! - [`SignedModerationAction`] carries moderator-driven add/remove/revoke
//!   actions over the feed with a detached signature, giving moderation an
//!   audit trail indistinguishable in shape from the existing
//!   [`crate::SignedFeedEntry`].
//! - [`RevocationEntry`] records that an indicator has been revoked from
//!   the feed, paired with a [`crate::FeedSignature`] so the public
//!   revocation history is tamper-evident.
//!
//! All public types use [`serde`] with `deny_unknown_fields` so unexpected
//! keys are rejected at the deserialization boundary, matching the crate
//! convention for security-critical untrusted input (see
//! `docs/conventions.md`).

use serde::{Deserialize, Serialize};

use crate::{FeedEntry, FeedSignature};

/// The kind of moderation action being applied to an indicator.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ModerationAction {
    /// Add a new indicator to the feed (post-review acceptance).
    Add,
    /// Remove an indicator from the feed without invalidating its history.
    Remove,
    /// Revoke an indicator: mark it permanently withdrawn and surface it
    /// in the public revocation history.
    Revoke,
}

/// A moderator-driven action over a feed indicator, signed for audit
/// (spec §22 community governance).
///
/// The detached [`FeedSignature`] attests that the moderator with
/// `moderator_id` produced the action at `timestamp`. Verifiers can
/// reconstruct a tamper-evident chain of moderation decisions by ordering
/// these records by `timestamp` and validating each signature out-of-band.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SignedModerationAction {
    /// The moderation operation being performed.
    pub action_type: ModerationAction,
    /// Stable feed entry identifier the action targets.
    pub target_indicator_id: String,
    /// Stable identifier (handle or key fingerprint) of the moderator
    /// that produced the action.
    pub moderator_id: String,
    /// Detached signature over the canonical action payload.
    pub signature: FeedSignature,
    /// Unix timestamp (seconds since epoch) when the action was produced.
    pub timestamp: u64,
}

/// Public record that an indicator has been revoked from the feed
/// (spec §22 revocation history).
///
/// Revocation is permanent: a revoked indicator is removed from active
/// matching and surfaced in the public revocation list. The detached
/// [`FeedSignature`] binds `indicator_id`, `reason`, `moderator_id`, and
/// `revoked_at` so consumers can verify the record was produced by a
/// legitimate moderator.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RevocationEntry {
    /// Stable feed entry identifier that has been revoked.
    pub indicator_id: String,
    /// Human-readable reason the indicator was revoked.
    pub reason: String,
    /// Stable identifier (handle or key fingerprint) of the moderator
    /// that recorded the revocation.
    pub moderator_id: String,
    /// Unix timestamp (seconds since epoch) when the revocation took
    /// effect.
    pub revoked_at: u64,
    /// Detached signature over the canonical revocation payload.
    pub signature: FeedSignature,
}

/// Collapses feed entries describing the same indicator into a single
/// record per indicator.
///
/// Two entries are considered duplicates when their
/// [`Indicator`](crate::Indicator) (type and value) matches. The collapse
/// preserves:
///
/// - the **earliest** `first_seen` (earliest observation across reports),
/// - the **latest** `last_seen` (most recent corroboration),
/// - the **highest**
///   [`Confidence`](arbitraitor_model::verdict::Confidence) (strongest
///   signal across reports),
/// - the **latest** non-`None` `expires_at` (corroboration can extend
///   lifetime),
/// - the **union** of [`FeedSource`](crate::FeedSource) records
///   (de-duplicated by `source_type` + `reference`),
/// - the **first non-`None`** `malware_family` and `notes` in evidence.
///
/// The order of the output matches the order of first appearance in
/// `submissions`; non-duplicate entries are passed through unchanged.
#[must_use]
pub fn duplicate_collapse(submissions: &[FeedEntry]) -> Vec<FeedEntry> {
    let mut collapsed: Vec<FeedEntry> = Vec::with_capacity(submissions.len());
    for entry in submissions {
        if let Some(existing) = collapsed
            .iter_mut()
            .find(|stored| stored.indicator == entry.indicator)
        {
            merge_duplicate_into(existing, entry);
        } else {
            collapsed.push(entry.clone());
        }
    }
    collapsed
}

fn merge_duplicate_into(target: &mut FeedEntry, other: &FeedEntry) {
    if other.first_seen.as_str() < target.first_seen.as_str() {
        target.first_seen.clone_from(&other.first_seen);
    }
    if other.last_seen.as_str() > target.last_seen.as_str() {
        target.last_seen.clone_from(&other.last_seen);
    }

    if confidence_rank(other.confidence) > confidence_rank(target.confidence) {
        target.confidence = other.confidence;
    }

    if let (_, Some(new_expires)) = (target.expires_at.as_ref(), other.expires_at.as_ref()) {
        let keep_new = target
            .expires_at
            .as_deref()
            .is_none_or(|current| new_expires.as_str() > current);
        if keep_new {
            target.expires_at = Some(new_expires.clone());
        }
    }

    for source in &other.sources {
        let already_present = target.sources.iter().any(|existing| {
            existing.source_type == source.source_type && existing.reference == source.reference
        });
        if !already_present {
            target.sources.push(source.clone());
        }
    }

    if target.evidence.malware_family.is_none() {
        target
            .evidence
            .malware_family
            .clone_from(&other.evidence.malware_family);
    }
    if target.evidence.notes.is_none() {
        target.evidence.notes.clone_from(&other.evidence.notes);
    }
}

/// Ranks [`Confidence`](arbitraitor_model::verdict::Confidence) on a
/// 0..=4 scale (lowest to highest) for use in duplicate-collapse merges.
///
/// `Confidence` does not derive `Ord` upstream, so a local ranking keeps
/// the comparison explicit and stable without adding new dependencies.
fn confidence_rank(confidence: crate::Confidence) -> u8 {
    use crate::Confidence;
    match confidence {
        Confidence::Speculative => 0,
        Confidence::Low => 1,
        Confidence::Medium => 2,
        Confidence::High => 3,
        Confidence::Confirmed => 4,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        CURRENT_SCHEMA_VERSION, Classification, Confidence, Disposition, FeedEvidence, FeedSource,
        FeedSourceClass, Indicator, IndicatorType, ReviewState, ReviewStatus, Severity,
    };

    fn make_entry(
        value: &str,
        first_seen: &str,
        last_seen: &str,
        confidence: Confidence,
    ) -> FeedEntry {
        FeedEntry {
            schema_version: CURRENT_SCHEMA_VERSION,
            id: format!("entry:hostname:{value}"),
            indicator: Indicator {
                indicator_type: IndicatorType::Hostname,
                value: value.to_owned(),
            },
            classification: Classification::Malicious,
            severity: Severity::High,
            confidence,
            disposition: Disposition::Block,
            source_class: FeedSourceClass::ArbitraitorReviewed,
            first_seen: first_seen.to_owned(),
            last_seen: last_seen.to_owned(),
            source_update_time: None,
            expires_at: None,
            sources: Vec::new(),
            evidence: FeedEvidence {
                malware_family: None,
                notes: None,
            },
            review: ReviewStatus {
                status: ReviewState::Reviewed,
                reviewers: vec!["analyst@example.com".to_owned()],
            },
        }
    }

    fn empty_signature() -> FeedSignature {
        FeedSignature {
            algorithm: "ed25519".to_owned(),
            key_id: "mod-1".to_owned(),
            signature_bytes: Vec::new(),
        }
    }

    #[test]
    fn collapse_empty_input_returns_empty() {
        assert!(duplicate_collapse(&[]).is_empty());
    }

    #[test]
    fn collapse_preserves_single_entry_unchanged() {
        let only = make_entry(
            "evil.example",
            "2026-06-01T00:00:00Z",
            "2026-06-10T00:00:00Z",
            Confidence::Medium,
        );
        let collapsed = duplicate_collapse(std::slice::from_ref(&only));
        assert_eq!(collapsed, vec![only]);
    }

    #[test]
    fn collapse_merges_duplicates_by_indicator() {
        let a = make_entry(
            "evil.example",
            "2026-06-01T00:00:00Z",
            "2026-06-10T00:00:00Z",
            Confidence::Medium,
        );
        let b = make_entry(
            "evil.example",
            "2026-06-05T00:00:00Z",
            "2026-06-17T00:00:00Z",
            Confidence::High,
        );
        let other = make_entry(
            "other.example",
            "2026-06-02T00:00:00Z",
            "2026-06-09T00:00:00Z",
            Confidence::Low,
        );

        let collapsed = duplicate_collapse(&[a, b, other.clone()]);
        assert_eq!(collapsed.len(), 2);

        let evil_first_seen: Vec<&str> = collapsed.iter().map(|e| e.first_seen.as_str()).collect();
        let evil_last_seen: Vec<&str> = collapsed.iter().map(|e| e.last_seen.as_str()).collect();
        let evil_confidence: Vec<Confidence> = collapsed.iter().map(|e| e.confidence).collect();
        let evil_values: Vec<&str> = collapsed
            .iter()
            .map(|e| e.indicator.value.as_str())
            .collect();

        assert_eq!(evil_values, vec!["evil.example", "other.example"]);
        assert_eq!(
            evil_first_seen,
            vec!["2026-06-01T00:00:00Z", "2026-06-02T00:00:00Z"]
        );
        assert_eq!(
            evil_last_seen,
            vec!["2026-06-17T00:00:00Z", "2026-06-09T00:00:00Z"]
        );
        assert_eq!(evil_confidence, vec![Confidence::High, Confidence::Low]);
    }

    #[test]
    fn collapse_keeps_highest_confidence_across_duplicates() {
        let low = make_entry(
            "evil.example",
            "2026-06-01T00:00:00Z",
            "2026-06-10T00:00:00Z",
            Confidence::Low,
        );
        let high = make_entry(
            "evil.example",
            "2026-06-02T00:00:00Z",
            "2026-06-11T00:00:00Z",
            Confidence::High,
        );
        let confirmed = make_entry(
            "evil.example",
            "2026-06-03T00:00:00Z",
            "2026-06-12T00:00:00Z",
            Confidence::Confirmed,
        );

        let collapsed = duplicate_collapse(&[low, high, confirmed]);
        assert_eq!(collapsed.len(), 1);
        assert_eq!(collapsed[0].confidence, Confidence::Confirmed);
        assert_eq!(collapsed[0].first_seen, "2026-06-01T00:00:00Z");
        assert_eq!(collapsed[0].last_seen, "2026-06-12T00:00:00Z");
    }

    #[test]
    fn collapse_unions_sources_without_duplication() {
        let mut a = make_entry(
            "evil.example",
            "2026-06-01T00:00:00Z",
            "2026-06-10T00:00:00Z",
            Confidence::Medium,
        );
        a.sources = vec![FeedSource {
            source_type: "analyst".to_owned(),
            reference: "case-1".to_owned(),
        }];

        let mut b = make_entry(
            "evil.example",
            "2026-06-02T00:00:00Z",
            "2026-06-11T00:00:00Z",
            Confidence::Medium,
        );
        b.sources = vec![
            FeedSource {
                source_type: "analyst".to_owned(),
                reference: "case-1".to_owned(),
            },
            FeedSource {
                source_type: "osint".to_owned(),
                reference: "case-2".to_owned(),
            },
        ];

        let collapsed = duplicate_collapse(&[a, b]);
        assert_eq!(collapsed.len(), 1);
        assert_eq!(collapsed[0].sources.len(), 2);
        assert!(
            collapsed[0]
                .sources
                .iter()
                .any(|s| s.source_type == "analyst" && s.reference == "case-1")
        );
        assert!(
            collapsed[0]
                .sources
                .iter()
                .any(|s| s.source_type == "osint" && s.reference == "case-2")
        );
    }

    #[test]
    fn collapse_extends_expiry_with_later_value() {
        let mut a = make_entry(
            "evil.example",
            "2026-06-01T00:00:00Z",
            "2026-06-10T00:00:00Z",
            Confidence::Medium,
        );
        a.expires_at = Some("2026-07-01T00:00:00Z".to_owned());
        let mut b = make_entry(
            "evil.example",
            "2026-06-02T00:00:00Z",
            "2026-06-11T00:00:00Z",
            Confidence::Medium,
        );
        b.expires_at = Some("2026-08-15T00:00:00Z".to_owned());

        let collapsed = duplicate_collapse(&[a, b]);
        assert_eq!(
            collapsed[0].expires_at.as_deref(),
            Some("2026-08-15T00:00:00Z")
        );
    }

    #[test]
    fn collapse_fills_missing_evidence_from_peer() {
        let mut a = make_entry(
            "evil.example",
            "2026-06-01T00:00:00Z",
            "2026-06-10T00:00:00Z",
            Confidence::Medium,
        );
        a.evidence = FeedEvidence {
            malware_family: None,
            notes: Some("first observation".to_owned()),
        };
        let mut b = make_entry(
            "evil.example",
            "2026-06-02T00:00:00Z",
            "2026-06-11T00:00:00Z",
            Confidence::Medium,
        );
        b.evidence = FeedEvidence {
            malware_family: Some("ExampleRat".to_owned()),
            notes: None,
        };

        let collapsed = duplicate_collapse(&[a, b]);
        assert_eq!(
            collapsed[0].evidence.malware_family.as_deref(),
            Some("ExampleRat")
        );
        assert_eq!(
            collapsed[0].evidence.notes.as_deref(),
            Some("first observation")
        );
    }

    #[test]
    fn collapse_keeps_first_observed_malware_family() {
        let mut a = make_entry(
            "evil.example",
            "2026-06-01T00:00:00Z",
            "2026-06-10T00:00:00Z",
            Confidence::Medium,
        );
        a.evidence = FeedEvidence {
            malware_family: Some("FamilyA".to_owned()),
            notes: None,
        };
        let mut b = make_entry(
            "evil.example",
            "2026-06-02T00:00:00Z",
            "2026-06-11T00:00:00Z",
            Confidence::Medium,
        );
        b.evidence = FeedEvidence {
            malware_family: Some("FamilyB".to_owned()),
            notes: None,
        };

        let collapsed = duplicate_collapse(&[a, b]);
        assert_eq!(
            collapsed[0].evidence.malware_family.as_deref(),
            Some("FamilyA")
        );
    }

    #[test]
    fn collapse_does_not_mutate_distinct_indicators() {
        let a = make_entry(
            "evil.example",
            "2026-06-01T00:00:00Z",
            "2026-06-10T00:00:00Z",
            Confidence::Medium,
        );
        let b = make_entry(
            "other.example",
            "2026-06-02T00:00:00Z",
            "2026-06-11T00:00:00Z",
            Confidence::Medium,
        );
        let collapsed = duplicate_collapse(&[a.clone(), b.clone()]);
        assert_eq!(collapsed, vec![a, b]);
    }

    #[test]
    fn signed_moderation_action_round_trips() -> Result<(), serde_json::Error> {
        let action = SignedModerationAction {
            action_type: ModerationAction::Revoke,
            target_indicator_id: "entry:sha256:abc".to_owned(),
            moderator_id: "moderator-7".to_owned(),
            signature: empty_signature(),
            timestamp: 1_700_000_000,
        };
        let json = serde_json::to_string(&action)?;
        let decoded: SignedModerationAction = serde_json::from_str(&json)?;
        assert_eq!(decoded, action);
        Ok(())
    }

    #[test]
    fn signed_moderation_action_rejects_unknown_fields() {
        let json = r#"{
            "action_type": "add",
            "target_indicator_id": "entry-1",
            "moderator_id": "mod-1",
            "signature": {
                "algorithm": "ed25519",
                "key_id": "k1",
                "signature_bytes": []
            },
            "timestamp": 0,
            "unexpected": 1
        }"#;
        assert!(serde_json::from_str::<SignedModerationAction>(json).is_err());
    }

    #[test]
    fn revocation_entry_round_trips() -> Result<(), serde_json::Error> {
        let entry = RevocationEntry {
            indicator_id: "entry:sha256:abc".to_owned(),
            reason: "false positive after investigation".to_owned(),
            moderator_id: "moderator-7".to_owned(),
            revoked_at: 1_700_000_000,
            signature: empty_signature(),
        };
        let json = serde_json::to_string(&entry)?;
        let decoded: RevocationEntry = serde_json::from_str(&json)?;
        assert_eq!(decoded, entry);
        Ok(())
    }

    #[test]
    fn revocation_entry_rejects_unknown_fields() {
        let json = r#"{
            "indicator_id": "entry-1",
            "reason": "stale",
            "moderator_id": "mod-1",
            "revoked_at": 0,
            "signature": {
                "algorithm": "ed25519",
                "key_id": "k1",
                "signature_bytes": []
            },
            "extra": "nope"
        }"#;
        assert!(serde_json::from_str::<RevocationEntry>(json).is_err());
    }
}
