//! Explanation trace types for policy evaluation (spec §41.14).
//!
//! Every call to [`crate::PolicyEngine::evaluate_with_trace`] returns a
//! [`PolicyTrace`] alongside the [`Verdict`](arbitraitor_model::verdict::Verdict).
//! The trace records which rules were considered, whether each matched,
//! and a short human-readable reason. Receipts and the `arbitraitor explain`
//! command consume this structure so operators can audit *why* a verdict
//! was produced without re-evaluating the policy.
//!
//! # Properties
//!
//! - **Total**: the trace always has exactly one entry per network
//!   constraint considered + one entry per rule in declaration order.
//! - **Deterministic**: ordering follows policy source order.
//! - **Stable IDs**: `rule_id` is the same identifier declared in TOML.
//! - **Receipt-friendly**: types serialize to JSON via serde.

use std::time::SystemTime;

use serde::{Deserialize, Serialize};

use crate::schema::PolicyAction;

// ---------------------------------------------------------------------------
// RuleEvaluation
// ---------------------------------------------------------------------------

/// The outcome of evaluating a single rule against the inputs.
///
/// One entry per rule in the compiled policy (in declaration order) plus,
/// when relevant, one entry per hard network constraint. The trace is
/// exhaustive: there is exactly one [`RuleEvaluation`] per source-order
/// rule, so consumers can correlate positions without inspecting the
/// policy itself.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuleEvaluation {
    /// The rule identifier from the TOML source.
    ///
    /// For hard network constraints (which have no rule id in the source),
    /// the synthetic identifier `"__network__"` is used so the trace
    /// distinguishes them from named rules.
    pub rule_id: String,

    /// Whether this rule produced the final verdict.
    ///
    /// `true` when the rule's condition matched and its action was
    /// selected (either as a terminal match or as `best_non_block` when
    /// later unavailable evidence caused a fail-closed return), or when
    /// the rule's condition matched but the engine kept evaluating for
    /// fail-closed bookkeeping.
    ///
    /// `false` when the condition did not match, when required evidence
    /// was unavailable (three-valued `Unavailable`), or when the rule was
    /// skipped because an earlier rule already produced a terminal match.
    pub matched: bool,

    /// Human-readable explanation of why the rule did or did not match.
    ///
    /// Suitable for inclusion in receipts and `arbitraitor explain`
    /// output. Not a structured log; consumers should treat it as opaque
    /// text for end users.
    pub reason: String,
}

/// Metadata attached to an allow rule that produced a policy pass decision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AllowRuleMetadata {
    /// Rule identifier that supplied this metadata.
    pub rule_id: String,

    /// Expiration time for the allow, when declared.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expiry: Option<SystemTime>,

    /// Scope for the allow: `user`, `project`, or `org`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,

    /// Identity that created the allow.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub creator: Option<String>,

    /// Reason why the allow was granted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

// ---------------------------------------------------------------------------
// PolicyTrace
// ---------------------------------------------------------------------------

/// Full explanation of a single policy evaluation.
///
/// Produced by [`crate::PolicyEngine::evaluate_with_trace`] and suitable
/// for embedding in receipts. The trace captures:
///
/// - every [`RuleEvaluation`] in source order,
/// - the [`PolicyAction`] that was ultimately selected, and
/// - the policy's [`default_action`](PolicyTrace::default_action) so
///   consumers can tell whether the verdict came from a rule or from
///   the default.
///
/// `final_decision` reflects the action *after* the non-interactive
/// prompt upgrade: a `Prompt` action in a non-interactive context is
/// reported as `Block` (or whatever `non_interactive_prompt_action` is
/// configured to), matching the [`Verdict`](arbitraitor_model::verdict::Verdict)
/// returned to the caller.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyTrace {
    /// Per-rule evaluation record, in source declaration order.
    pub rules_evaluated: Vec<RuleEvaluation>,

    /// The action that produced the final verdict.
    ///
    /// Equal to the matched rule's `action` when a rule matched, the
    /// `default_action` when no rule matched, and `Block` when the
    /// decision was forced by `fail_closed_on_unavailable` or by a hard
    /// network constraint.
    pub final_decision: PolicyAction,

    /// The policy's configured default action.
    ///
    /// Recorded separately from `final_decision` so consumers can
    /// distinguish "default fired because nothing matched" from "a rule
    /// produced this action".
    pub default_action: PolicyAction,

    /// Metadata from matching allow rules, if the final decision allowed release.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allow_rule_metadata: Vec<AllowRuleMetadata>,
}

impl PolicyTrace {
    /// Returns `true` when the final decision came from the default
    /// action (no rule matched).
    ///
    /// Note: this does not account for hard network constraints or
    /// fail-closed upgrades, both of which force `Block`. For an exact
    /// answer to "which rule produced this verdict", inspect
    /// `rules_evaluated` for entries with `matched == true`.
    #[must_use]
    pub fn used_default(&self) -> bool {
        self.final_decision == self.default_action
    }
}
