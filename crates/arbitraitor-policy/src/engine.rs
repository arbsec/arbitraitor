//! Policy engine: loading, evaluation, and digest computation.

use sha2::{Digest, Sha256};

use arbitraitor_model::finding::{Finding, FindingCategory};
use arbitraitor_model::verdict::{Confidence, Severity, Verdict};

use crate::context::EvalContext;
use crate::error::PolicyError;
use crate::schema::{Condition, FieldMatch, MatchOp, Policy, PolicyAction, Rule, ScalarValue};
use crate::trace::{PolicyTrace, RuleEvaluation};

/// Synthetic rule identifier used in [`RuleEvaluation::rule_id`] when a hard
/// network constraint produced the final block.
const NETWORK_CONSTRAINT_ID: &str = "__network__";

/// Ordered policy precedence level from spec §23.5.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum PolicyPrecedence {
    /// Organization-managed policy.
    Organization,
    /// Project-local policy, which may only tighten organization policy.
    Project,
    /// User policy, which may only tighten inherited organization/project policy.
    User,
    /// Command-line tightening policy.
    CliTightening,
    /// Command-line override policy, allowed only with audit consent.
    CliOverride,
}

/// One policy document tagged with its precedence level.
#[derive(Debug, Clone)]
pub struct PolicyLayer {
    /// Precedence level for this policy.
    pub precedence: PolicyPrecedence,
    /// Parsed policy document for this layer.
    pub policy: Policy,
}

/// Effective layered policy plus audit entries produced while merging.
#[derive(Debug, Clone)]
pub struct LayeredPolicy {
    /// Effective policy after ordered layering.
    pub policy: Policy,
    /// Audit records for policy override decisions.
    pub audit_trail: Vec<String>,
}

// ---------------------------------------------------------------------------
// PolicyEngine
// ---------------------------------------------------------------------------

/// Compiled policy engine.
///
/// Created once from a TOML document and reused for every evaluation.
/// The digest is computed at load time so it is available for every receipt
/// without re-hashing.
#[derive(Debug, Clone)]
pub struct PolicyEngine {
    policy: Policy,
    digest: String,
}

impl PolicyEngine {
    /// Parses, validates, and compiles a policy from a TOML string.
    ///
    /// # Errors
    ///
    /// Returns [`PolicyError::Parse`] for malformed TOML, and
    /// [`PolicyError::Invalid`] for structurally valid but semantically
    /// incorrect policies (wrong version, duplicate rule IDs, unknown fields).
    pub fn load(toml_str: &str) -> Result<Self, PolicyError> {
        let policy: Policy = toml::from_str(toml_str)?;

        validate_policy(&policy)?;

        let digest = compute_digest(&policy)?;

        Ok(Self { policy, digest })
    }

    /// Compiles an already parsed policy document.
    ///
    /// # Errors
    ///
    /// Returns [`PolicyError::Invalid`] when the policy version, rule IDs, or
    /// field references are invalid.
    pub fn from_policy(policy: Policy) -> Result<Self, PolicyError> {
        validate_policy(&policy)?;
        let digest = compute_digest(&policy)?;
        Ok(Self { policy, digest })
    }

    /// Merges ordered policy layers and compiles the effective policy.
    ///
    /// Lower-precedence scopes may replace an inherited policy only when the
    /// replacement is monotonic: actions become stricter, constraints are more
    /// selective, limits shrink, scopes narrow, and inherited rules remain present.
    /// [`PolicyPrecedence::CliOverride`] is the only weakening layer and is
    /// rejected unless `audit_override` is `true`; when accepted, an audit
    /// record is emitted in the returned [`LayeredPolicy`].
    ///
    /// # Errors
    ///
    /// Returns [`PolicyError::Invalid`] for malformed layers,
    /// [`PolicyError::Weakening`] for non-override weakening, or
    /// [`PolicyError::AuditOverrideRequired`] when a CLI override lacks audit
    /// consent.
    pub fn merge_layers(
        layers: impl IntoIterator<Item = PolicyLayer>,
        audit_override: bool,
    ) -> Result<LayeredPolicy, PolicyError> {
        let mut layers = layers.into_iter().collect::<Vec<_>>();
        layers.sort_by_key(|layer| layer.precedence);

        let mut iter = layers.into_iter();
        let first = iter.next().ok_or_else(|| {
            PolicyError::Invalid("at least one policy layer is required".to_owned())
        })?;
        validate_policy(&first.policy)?;

        let mut effective = first.policy;
        let mut inherited_precedence = first.precedence;
        let mut audit_trail = Vec::new();
        for layer in iter {
            validate_policy(&layer.policy)?;
            if layer.precedence == PolicyPrecedence::CliOverride {
                if !audit_override {
                    return Err(PolicyError::AuditOverrideRequired);
                }
                audit_trail.push(format!(
                    "CLI override applied over inherited {inherited_precedence:?} policy with --audit-override"
                ));
                effective = layer.policy;
                inherited_precedence = layer.precedence;
                continue;
            }
            ensure_tightening(&effective, &layer.policy, layer.precedence)?;
            effective = layer.policy;
            inherited_precedence = layer.precedence;
        }

        Ok(LayeredPolicy {
            policy: effective,
            audit_trail,
        })
    }

    /// Returns the SHA-256 digest of the canonical policy representation.
    ///
    /// Two semantically equivalent policies produce the same digest.
    #[must_use]
    pub fn digest(&self) -> String {
        self.digest.clone()
    }

    /// Returns a reference to the compiled [`Policy`].
    #[must_use]
    pub fn policy(&self) -> &Policy {
        &self.policy
    }

    /// Evaluates findings and context against the policy, producing a verdict.
    ///
    /// Evaluation order:
    /// 1. Hard network constraints (`require_https`, `block_private_networks`).
    /// 2. Rules in declaration order — first match wins.
    /// 3. Default action when no rule matches.
    ///
    /// Any `Prompt` verdict in a non-interactive context is upgraded to the
    /// configured `non_interactive_prompt_action` (default: `Block`).
    #[must_use]
    pub fn evaluate(&self, findings: &[Finding], context: &EvalContext) -> Verdict {
        self.evaluate_with_trace(findings, context).0
    }

    /// Evaluates findings and context against the policy, producing both a
    /// verdict and a [`PolicyTrace`] explaining which rules were considered
    /// and why each matched or did not (spec §41.14).
    ///
    /// The trace records every rule in source order plus a synthetic
    /// `__network__` entry whenever a hard network constraint produced the
    /// final block. `final_decision` reflects the action *after* the
    /// non-interactive prompt upgrade, matching the [`Verdict`] returned
    /// here.
    #[must_use]
    pub fn evaluate_with_trace(
        &self,
        findings: &[Finding],
        context: &EvalContext,
    ) -> (Verdict, PolicyTrace) {
        let default_action = self.policy.defaults.action;
        let mut evaluations: Vec<RuleEvaluation> = Vec::new();

        // --- Hard network constraints (checked first, fail-closed) ---
        let net = &self.policy.network;
        if net.require_https && !context.is_https {
            evaluations.push(RuleEvaluation {
                rule_id: NETWORK_CONSTRAINT_ID.to_owned(),
                matched: true,
                reason: "network constraint failed: HTTPS required but request is not HTTPS"
                    .to_owned(),
            });
            return (
                Verdict::Block,
                finalize_trace(evaluations, PolicyAction::Block, default_action),
            );
        }
        if net.block_private_networks && context.is_private_network {
            evaluations.push(RuleEvaluation {
                rule_id: NETWORK_CONSTRAINT_ID.to_owned(),
                matched: true,
                reason: "network constraint failed: private/loopback network is blocked".to_owned(),
            });
            return (
                Verdict::Block,
                finalize_trace(evaluations, PolicyAction::Block, default_action),
            );
        }

        let fail_closed_on_unavailable = self.policy.defaults.fail_closed_on_unavailable;
        let mut saw_unavailable = false;
        let mut best_non_block: Option<(Verdict, PolicyAction)> = None;

        for rule in &self.policy.rules {
            match rule_matches(&rule.when, findings, context) {
                TriState::Matched => {
                    let verdict = resolve_action(rule.action, context, &self.policy.defaults);
                    let resolved_action = resolved_policy_action(
                        rule.action,
                        verdict,
                        context,
                        &self.policy.defaults,
                    );
                    let reason = match_reason_for_match(rule, resolved_action);
                    evaluations.push(RuleEvaluation {
                        rule_id: rule.id.clone(),
                        matched: true,
                        reason,
                    });

                    if verdict == Verdict::Block {
                        return (
                            verdict,
                            finalize_trace(evaluations, resolved_action, default_action),
                        );
                    }
                    if !saw_unavailable || !fail_closed_on_unavailable {
                        return (
                            verdict,
                            finalize_trace(evaluations, resolved_action, default_action),
                        );
                    }
                    best_non_block = Some((verdict, resolved_action));
                }
                TriState::Unavailable => {
                    saw_unavailable = true;
                    evaluations.push(RuleEvaluation {
                        rule_id: rule.id.clone(),
                        matched: false,
                        reason: "skipped: required evidence unavailable".to_owned(),
                    });
                }
                TriState::NotMatched => {
                    evaluations.push(RuleEvaluation {
                        rule_id: rule.id.clone(),
                        matched: false,
                        reason: "condition not satisfied".to_owned(),
                    });
                }
            }
        }

        if saw_unavailable && fail_closed_on_unavailable {
            return (
                Verdict::Block,
                finalize_trace(evaluations, PolicyAction::Block, default_action),
            );
        }

        if let Some((verdict, action)) = best_non_block {
            return (verdict, finalize_trace(evaluations, action, default_action));
        }

        // --- Default action ---
        let verdict = resolve_action(self.policy.defaults.action, context, &self.policy.defaults);
        let resolved_action = resolved_policy_action(
            self.policy.defaults.action,
            verdict,
            context,
            &self.policy.defaults,
        );
        (
            verdict,
            finalize_trace(evaluations, resolved_action, default_action),
        )
    }
}

fn validate_policy(policy: &Policy) -> Result<(), PolicyError> {
    if policy.version != 1 {
        return Err(PolicyError::Invalid(format!(
            "unsupported policy version: {} (only version 1 is supported)",
            policy.version
        )));
    }
    validate_rules(&policy.rules)
}

fn ensure_tightening(
    inherited: &Policy,
    candidate: &Policy,
    layer: PolicyPrecedence,
) -> Result<(), PolicyError> {
    let mut violations = Vec::new();
    check_defaults(&inherited.defaults, &candidate.defaults, &mut violations);
    check_network(&inherited.network, &candidate.network, &mut violations);
    check_limits(&inherited.limits, &candidate.limits, &mut violations);
    check_integrity(&inherited.integrity, &candidate.integrity, &mut violations);
    check_provenance(
        &inherited.provenance,
        &candidate.provenance,
        &mut violations,
    );
    check_detectors(&inherited.detectors, &candidate.detectors, &mut violations);
    check_rules(&inherited.rules, &candidate.rules, &mut violations);

    if violations.is_empty() {
        Ok(())
    } else {
        Err(PolicyError::Weakening {
            layer,
            detail: violations.join("; "),
        })
    }
}

fn action_rank(action: PolicyAction) -> u8 {
    match action {
        PolicyAction::Pass => 0,
        PolicyAction::Warn => 1,
        PolicyAction::Prompt => 2,
        PolicyAction::Block => 3,
    }
}

fn check_action(
    inherited: PolicyAction,
    candidate: PolicyAction,
    field: &str,
    violations: &mut Vec<String>,
) {
    if action_rank(candidate) < action_rank(inherited) {
        violations.push(format!(
            "{field}: cannot weaken from {inherited:?} to {candidate:?}"
        ));
    }
}

fn check_defaults(
    inherited: &crate::schema::DefaultsConfig,
    candidate: &crate::schema::DefaultsConfig,
    violations: &mut Vec<String>,
) {
    check_action(
        inherited.action,
        candidate.action,
        "defaults.action",
        violations,
    );
    check_action(
        inherited.non_interactive_prompt_action,
        candidate.non_interactive_prompt_action,
        "defaults.non_interactive_prompt_action",
        violations,
    );
    if inherited.fail_closed_on_unavailable && !candidate.fail_closed_on_unavailable {
        violations
            .push("defaults.fail_closed_on_unavailable: cannot disable fail-closed".to_owned());
    }
}

fn check_network(
    inherited: &crate::schema::NetworkConfig,
    candidate: &crate::schema::NetworkConfig,
    violations: &mut Vec<String>,
) {
    if inherited.require_https && !candidate.require_https {
        violations.push("network.require_https: cannot relax HTTPS requirement".to_owned());
    }
    if inherited.block_private_networks && !candidate.block_private_networks {
        violations.push("network.block_private_networks: cannot allow private networks".to_owned());
    }
    if candidate.redirects.max > inherited.redirects.max {
        violations.push(format!(
            "network.redirects.max: cannot raise redirect limit from {} to {}",
            inherited.redirects.max, candidate.redirects.max
        ));
    }
    if !inherited.redirects.allow_https_to_http && candidate.redirects.allow_https_to_http {
        violations.push(
            "network.redirects.allow_https_to_http: cannot allow HTTPS to HTTP redirects"
                .to_owned(),
        );
    }
    if !inherited.redirects.allow_cross_origin && candidate.redirects.allow_cross_origin {
        violations
            .push("network.redirects.allow_cross_origin: cannot widen redirect scope".to_owned());
    }
    if !inherited.redirects.forward_authorization_cross_origin
        && candidate.redirects.forward_authorization_cross_origin
    {
        violations.push("network.redirects.forward_authorization_cross_origin: cannot forward credentials cross-origin".to_owned());
    }
}

fn check_limits(
    inherited: &crate::schema::LimitsConfig,
    candidate: &crate::schema::LimitsConfig,
    violations: &mut Vec<String>,
) {
    check_parseable_limit(
        &inherited.max_download_bytes,
        &candidate.max_download_bytes,
        "limits.max_download_bytes",
        parse_bytes,
        violations,
    );
    check_parseable_limit(
        &inherited.max_analysis_time,
        &candidate.max_analysis_time,
        "limits.max_analysis_time",
        parse_seconds,
        violations,
    );
}

fn check_parseable_limit(
    inherited: &str,
    candidate: &str,
    field: &str,
    parse: fn(&str) -> Option<u64>,
    violations: &mut Vec<String>,
) {
    match (parse(inherited), parse(candidate)) {
        (Some(before), Some(after)) if after > before => violations.push(format!(
            "{field}: cannot raise limit from {inherited:?} to {candidate:?}"
        )),
        (Some(_), None) if candidate != inherited => {
            violations.push(format!("{field}: unparseable replacement {candidate:?}"));
        }
        _ => {}
    }
}

fn parse_bytes(value: &str) -> Option<u64> {
    parse_unit(
        value,
        &[
            ("tib", 1_u64 << 40),
            ("gib", 1_u64 << 30),
            ("mib", 1_u64 << 20),
            ("kib", 1_u64 << 10),
            ("b", 1),
        ],
    )
}

fn parse_seconds(value: &str) -> Option<u64> {
    parse_unit(value, &[("s", 1), ("m", 60), ("h", 3_600)])
}

fn parse_unit(value: &str, units: &[(&str, u64)]) -> Option<u64> {
    let normalized = value.trim().to_ascii_lowercase();
    for &(suffix, multiplier) in units {
        if let Some(number) = normalized.strip_suffix(suffix) {
            let count = number.trim().parse::<u64>().ok()?;
            return count.checked_mul(multiplier);
        }
    }
    normalized.parse::<u64>().ok()
}

fn check_integrity(
    inherited: &crate::schema::IntegrityConfig,
    candidate: &crate::schema::IntegrityConfig,
    violations: &mut Vec<String>,
) {
    if inherited.require_digest && !candidate.require_digest {
        violations.push("integrity.require_digest: cannot relax digest requirement".to_owned());
    }
}

fn check_provenance(
    inherited: &crate::schema::ProvenanceConfig,
    candidate: &crate::schema::ProvenanceConfig,
    violations: &mut Vec<String>,
) {
    for class in &inherited.require_signature_for {
        if !candidate.require_signature_for.contains(class) {
            violations.push(format!(
                "provenance.require_signature_for: cannot remove inherited scope {class:?}"
            ));
        }
    }
    if !inherited.trusted_sigstore_identities.is_empty() {
        for identity in &candidate.trusted_sigstore_identities {
            if inherited.trusted_sigstore_identities.contains(identity) {
                continue;
            }
            violations.push(format!(
                "provenance.trusted_sigstore_identities: cannot add trusted identity {}",
                identity.subject
            ));
        }
    }
}

fn check_detectors(
    inherited: &std::collections::BTreeMap<String, crate::schema::DetectorConfig>,
    candidate: &std::collections::BTreeMap<String, crate::schema::DetectorConfig>,
    violations: &mut Vec<String>,
) {
    for (name, inherited_detector) in inherited {
        let Some(candidate_detector) = candidate.get(name) else {
            violations.push(format!(
                "detectors.{name}: cannot remove inherited detector policy"
            ));
            continue;
        };
        if inherited_detector.required && !candidate_detector.required {
            violations.push(format!(
                "detectors.{name}.required: cannot disable required detector"
            ));
        }
        for class in &inherited_detector.required_for {
            if !candidate_detector.required_for.contains(class) {
                violations.push(format!(
                    "detectors.{name}.required_for: cannot remove inherited class {class:?}"
                ));
            }
        }
        for platform in &inherited_detector.required_on {
            if !candidate_detector.required_on.contains(platform) {
                violations.push(format!(
                    "detectors.{name}.required_on: cannot remove inherited platform {platform:?}"
                ));
            }
        }
    }
}

fn check_rules(inherited: &[Rule], candidate: &[Rule], violations: &mut Vec<String>) {
    for inherited_rule in inherited {
        let Some(candidate_rule) = candidate.iter().find(|rule| rule.id == inherited_rule.id)
        else {
            let rule_id = &inherited_rule.id;
            violations.push(format!("rules: cannot remove inherited rule {rule_id:?}"));
            continue;
        };
        check_action(
            inherited_rule.action,
            candidate_rule.action,
            &format!("rules.{}.action", inherited_rule.id),
            violations,
        );
        if !condition_tightens(&inherited_rule.when, &candidate_rule.when) {
            violations.push(format!(
                "rules.{}.when: replacement must preserve inherited condition or add conditions",
                inherited_rule.id
            ));
        }
    }
}

fn condition_tightens(inherited: &Condition, candidate: &Condition) -> bool {
    match (inherited, candidate) {
        (same_inherited, same_candidate) if same_inherited == same_candidate => true,
        (Condition::All(inherited_conditions), Condition::All(candidate_conditions)) => {
            inherited_conditions
                .iter()
                .all(|condition| candidate_conditions.contains(condition))
        }
        (inherited_condition, Condition::All(candidate_conditions)) => {
            candidate_conditions.contains(inherited_condition)
        }
        (
            Condition::All(_) | Condition::Any(_) | Condition::Match(_),
            Condition::Any(_) | Condition::Match(_),
        ) => false,
    }
}

/// Builds the final [`PolicyTrace`] from the collected rule evaluations.
fn finalize_trace(
    rules_evaluated: Vec<RuleEvaluation>,
    final_decision: PolicyAction,
    default_action: PolicyAction,
) -> PolicyTrace {
    PolicyTrace {
        rules_evaluated,
        final_decision,
        default_action,
    }
}

/// Returns the [`PolicyAction`] that actually produced the verdict, after
/// applying the non-interactive prompt upgrade.
fn resolved_policy_action(
    declared: PolicyAction,
    verdict: Verdict,
    context: &EvalContext,
    defaults: &crate::schema::DefaultsConfig,
) -> PolicyAction {
    if verdict == Verdict::Prompt && !context.is_interactive {
        match defaults.non_interactive_prompt_action {
            // Prompt cannot survive in non-interactive mode — the engine
            // would loop. resolve_action upgrades it to Block here.
            PolicyAction::Prompt => PolicyAction::Block,
            other => other,
        }
    } else {
        declared
    }
}

/// Builds the human-readable reason string for a rule whose condition matched.
fn match_reason_for_match(rule: &Rule, resolved_action: PolicyAction) -> String {
    if resolved_action == rule.action {
        format!("matched; action={:?}", rule.action)
    } else {
        format!(
            "matched; declared action={:?}, upgraded to {:?} in non-interactive context",
            rule.action, resolved_action
        )
    }
}

// ---------------------------------------------------------------------------
// Rule matching
// ---------------------------------------------------------------------------

/// Checks whether any finding (or the context alone) satisfies the condition.
fn rule_matches(condition: &Condition, findings: &[Finding], context: &EvalContext) -> TriState {
    // Context-only pass: handles conditions without finding references, or
    // when there are zero findings.
    let context_result = evaluate_condition(condition, None, context);
    if context_result == TriState::Matched {
        return TriState::Matched;
    }
    if findings.is_empty() {
        return context_result;
    }

    let mut saw_unavailable = false;
    // Per-finding pass: each finding is checked individually so that
    // multi-field conditions apply to the *same* finding.
    for finding in findings {
        match evaluate_condition(condition, Some(finding), context) {
            TriState::Matched => return TriState::Matched,
            TriState::Unavailable => saw_unavailable = true,
            TriState::NotMatched => {}
        }
    }
    if saw_unavailable {
        TriState::Unavailable
    } else {
        TriState::NotMatched
    }
}

/// Resolves a policy action to a final verdict, applying the non-interactive
/// prompt upgrade.
fn resolve_action(
    action: PolicyAction,
    context: &EvalContext,
    defaults: &crate::schema::DefaultsConfig,
) -> Verdict {
    let verdict: Verdict = action.into();
    if verdict == Verdict::Prompt && !context.is_interactive {
        match defaults.non_interactive_prompt_action {
            PolicyAction::Prompt => Verdict::Block,
            action => action.into(),
        }
    } else {
        verdict
    }
}

// ---------------------------------------------------------------------------
// Three-valued logic
// ---------------------------------------------------------------------------

/// Three-valued evaluation result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TriState {
    /// The condition is definitively satisfied.
    Matched,
    /// The condition is definitively not satisfied.
    NotMatched,
    /// Required evidence is unavailable; the rule should be skipped.
    Unavailable,
}

/// Kleene AND: any `NotMatched` → `NotMatched`; else any `Unavailable` →
/// `Unavailable`; else `Matched`.
fn kleene_and(mut iter: impl Iterator<Item = TriState>) -> TriState {
    let mut has_unavailable = false;
    for v in iter.by_ref() {
        match v {
            TriState::NotMatched => return TriState::NotMatched,
            TriState::Unavailable => has_unavailable = true,
            TriState::Matched => {}
        }
    }
    if has_unavailable {
        TriState::Unavailable
    } else {
        TriState::Matched
    }
}

/// Kleene OR: any `Matched` → `Matched`; else any `Unavailable` →
/// `Unavailable`; else `NotMatched`.
fn kleene_or(iter: impl Iterator<Item = TriState>) -> TriState {
    let mut has_unavailable = false;
    for v in iter {
        match v {
            TriState::Matched => return TriState::Matched,
            TriState::Unavailable => has_unavailable = true,
            TriState::NotMatched => {}
        }
    }
    if has_unavailable {
        TriState::Unavailable
    } else {
        TriState::NotMatched
    }
}

/// Evaluates a condition against an optional finding and the context.
fn evaluate_condition(
    cond: &Condition,
    finding: Option<&Finding>,
    context: &EvalContext,
) -> TriState {
    match cond {
        Condition::All(conditions) => kleene_and(
            conditions
                .iter()
                .map(|c| evaluate_condition(c, finding, context)),
        ),
        Condition::Any(conditions) => kleene_or(
            conditions
                .iter()
                .map(|c| evaluate_condition(c, finding, context)),
        ),
        Condition::Match(fm) => evaluate_field_match(fm, finding, context),
    }
}

/// Evaluates a single field match.
fn evaluate_field_match(
    fm: &FieldMatch,
    finding: Option<&Finding>,
    context: &EvalContext,
) -> TriState {
    match resolve_field(&fm.field, finding, context) {
        FieldValue::Unavailable => TriState::Unavailable,
        value => {
            if fm.op.matches(&value) {
                TriState::Matched
            } else {
                TriState::NotMatched
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Field resolution
// ---------------------------------------------------------------------------

/// A resolved field value ready for comparison.
#[derive(Debug, Clone)]
enum FieldValue {
    /// Textual value with an optional ordinal rank (for severity / confidence).
    Text {
        /// Canonical lowercase-hyphenated form.
        canonical: String,
        /// Ordinal rank for ordered comparison (`severity`, `confidence`).
        rank: Option<u8>,
    },
    /// Boolean value.
    Bool(bool),
    /// Integer value.
    Int(i64),
    /// List of strings (e.g. `finding.tags`).
    List(Vec<String>),
    /// Evidence not available for this evaluation target.
    Unavailable,
}

/// Resolves a dotted field path against the evaluation target.
fn resolve_field(field: &str, finding: Option<&Finding>, context: &EvalContext) -> FieldValue {
    if let Some(rest) = field.strip_prefix("finding.") {
        return resolve_finding_field(rest, finding);
    }
    if let Some(rest) = field.strip_prefix("context.") {
        return resolve_context_field(rest, context);
    }
    // Unknown prefix — treat as unavailable so the rule is skipped.
    FieldValue::Unavailable
}

fn resolve_finding_field(name: &str, finding: Option<&Finding>) -> FieldValue {
    let Some(finding) = finding else {
        return FieldValue::Unavailable;
    };
    match name {
        "category" => {
            let (canonical, rank) = category_info(finding.category);
            FieldValue::Text {
                canonical,
                rank: Some(rank),
            }
        }
        "severity" => {
            let (canonical, rank) = severity_info(finding.severity);
            FieldValue::Text {
                canonical,
                rank: Some(rank),
            }
        }
        "confidence" => {
            let (canonical, rank) = confidence_info(finding.confidence);
            FieldValue::Text {
                canonical,
                rank: Some(rank),
            }
        }
        "id" => FieldValue::Text {
            canonical: normalize_str(&finding.id),
            rank: None,
        },
        "detector" => FieldValue::Text {
            canonical: normalize_str(&finding.detector),
            rank: None,
        },
        "title" => FieldValue::Text {
            canonical: normalize_str(&finding.title),
            rank: None,
        },
        "description" => FieldValue::Text {
            canonical: normalize_str(&finding.description),
            rank: None,
        },
        "tags" => FieldValue::List(finding.tags.clone()),
        _ => FieldValue::Unavailable,
    }
}

fn resolve_context_field(name: &str, context: &EvalContext) -> FieldValue {
    match name {
        "operation_mode" => FieldValue::Text {
            canonical: normalize_str(context.operation_mode.as_str()),
            rank: None,
        },
        "artifact_digest" => match &context.artifact_digest {
            Some(digest) => FieldValue::Text {
                canonical: digest.to_string(),
                rank: None,
            },
            None => FieldValue::Unavailable,
        },
        "redirect_chain" => FieldValue::List(context.redirect_chain.clone()),
        "provenance_verified" => FieldValue::Bool(context.provenance_verified),
        "provenance_signer" => match &context.provenance_signer {
            Some(signer) => FieldValue::Text {
                canonical: normalize_str(signer),
                rank: None,
            },
            None => FieldValue::Unavailable,
        },
        "findings_count" => FieldValue::Int(usize_to_i64(context.findings_count)),
        "block_findings_count" => FieldValue::Int(usize_to_i64(context.block_findings_count)),
        "intel_matches" => FieldValue::List(context.intel_matches.clone()),
        "detector_health" => FieldValue::Text {
            canonical: normalize_str(context.detector_health.as_str()),
            rank: None,
        },
        "recursive_graph_complete" => FieldValue::Bool(context.recursive_graph_complete),
        "execution_interpreter" => match &context.execution_interpreter {
            Some(interpreter) => FieldValue::Text {
                canonical: normalize_str(interpreter),
                rank: None,
            },
            None => FieldValue::Unavailable,
        },
        "execution_network" => FieldValue::Bool(context.execution_network),
        "is_https" => FieldValue::Bool(context.is_https),
        "is_private_network" => FieldValue::Bool(context.is_private_network),
        "is_interactive" => FieldValue::Bool(context.is_interactive),
        "caller_origin" => FieldValue::Text {
            canonical: normalize_str(context.caller_origin.as_str()),
            rank: None,
        },
        "source_url" => match &context.source_url {
            Some(url) => FieldValue::Text {
                canonical: normalize_str(url),
                rank: None,
            },
            None => FieldValue::Unavailable,
        },
        "artifact_type" => match &context.artifact_type {
            Some(t) => FieldValue::Text {
                canonical: normalize_str(t),
                rank: None,
            },
            None => FieldValue::Unavailable,
        },
        _ => FieldValue::Unavailable,
    }
}

// ---------------------------------------------------------------------------
// Match operator evaluation
// ---------------------------------------------------------------------------

impl MatchOp {
    /// Tests whether this operator matches the resolved field value.
    fn matches(&self, value: &FieldValue) -> bool {
        match (self, value) {
            // --- Equals ---
            (MatchOp::Equals(scalar), FieldValue::Text { canonical, .. }) => {
                normalize_scalar(scalar) == *canonical
            }
            (MatchOp::Equals(scalar), FieldValue::Bool(b)) => match scalar {
                ScalarValue::Bool(v) => *v == *b,
                ScalarValue::Str(s) => parse_bool(s).is_some_and(|v| v == *b),
                ScalarValue::Int(_) => false,
            },
            (MatchOp::Equals(scalar), FieldValue::Int(n)) => match scalar {
                ScalarValue::Int(v) => *v == *n,
                ScalarValue::Str(s) => s.parse::<i64>().is_ok_and(|v| v == *n),
                ScalarValue::Bool(_) => false,
            },

            // --- OneOf ---
            (MatchOp::OneOf(scalars), FieldValue::Text { canonical, .. }) => {
                scalars.iter().any(|s| normalize_scalar(s) == *canonical)
            }
            (MatchOp::OneOf(scalars), FieldValue::Bool(b)) => scalars.iter().any(|s| match s {
                ScalarValue::Bool(v) => *v == *b,
                ScalarValue::Str(text) => parse_bool(text).is_some_and(|v| v == *b),
                ScalarValue::Int(_) => false,
            }),
            (MatchOp::OneOf(scalars), FieldValue::Int(n)) => scalars.iter().any(|s| match s {
                ScalarValue::Int(v) => *v == *n,
                ScalarValue::Str(text) => text.parse::<i64>().is_ok_and(|v| v == *n),
                ScalarValue::Bool(_) => false,
            }),

            // --- NotIn (complement of OneOf; spec §23.1.1 example) ---
            (MatchOp::NotIn(scalars), FieldValue::Text { canonical, .. }) => {
                !scalars.iter().any(|s| normalize_scalar(s) == *canonical)
            }
            (MatchOp::NotIn(scalars), FieldValue::Bool(b)) => !scalars.iter().any(|s| match s {
                ScalarValue::Bool(v) => *v == *b,
                ScalarValue::Str(text) => parse_bool(text).is_some_and(|v| v == *b),
                ScalarValue::Int(_) => false,
            }),
            (MatchOp::NotIn(scalars), FieldValue::Int(n)) => !scalars.iter().any(|s| match s {
                ScalarValue::Int(v) => *v == *n,
                ScalarValue::Str(text) => text.parse::<i64>().is_ok_and(|v| v == *n),
                ScalarValue::Bool(_) => false,
            }),

            // --- Contains ---
            (MatchOp::Contains(needle), FieldValue::Text { canonical, .. }) => {
                canonical.contains(&normalize_str(needle))
            }
            (MatchOp::Contains(needle), FieldValue::List(items)) => {
                let normalized_needle = normalize_str(needle);
                items
                    .iter()
                    .any(|item| normalize_str(item) == normalized_needle)
            }

            // --- GreaterThan ---
            (MatchOp::GreaterThan(scalar), FieldValue::Text { rank: Some(r), .. }) => {
                scalar_rank(scalar).is_some_and(|target| *r > target)
            }
            (MatchOp::GreaterThan(scalar), FieldValue::Int(n)) => {
                scalar_int(scalar).is_some_and(|target| *n > target)
            }

            // --- Type mismatches: never match ---
            _ => false,
        }
    }
}

// ---------------------------------------------------------------------------
// Normalization helpers
// ---------------------------------------------------------------------------

/// Normalizes a string for comparison: lowercase, `_` → `-`.
fn normalize_str(s: &str) -> String {
    s.to_lowercase().replace('_', "-")
}

/// Normalizes a [`ScalarValue`] to its canonical string form.
fn normalize_scalar(scalar: &ScalarValue) -> String {
    match scalar {
        ScalarValue::Str(s) => normalize_str(s),
        ScalarValue::Int(n) => n.to_string(),
        ScalarValue::Bool(b) => b.to_string(),
    }
}

/// Parses a boolean from a string ("true"/"false", case-insensitive).
fn parse_bool(s: &str) -> Option<bool> {
    match s.to_lowercase().as_str() {
        "true" => Some(true),
        "false" => Some(false),
        _ => None,
    }
}

fn scalar_int(scalar: &ScalarValue) -> Option<i64> {
    match scalar {
        ScalarValue::Int(n) => Some(*n),
        ScalarValue::Str(s) => s.parse::<i64>().ok(),
        ScalarValue::Bool(_) => None,
    }
}

fn usize_to_i64(value: usize) -> i64 {
    i64::try_from(value).unwrap_or(i64::MAX)
}

/// Looks up the ordinal rank of a scalar value (for severity / confidence).
///
/// String values are looked up in the combined severity + confidence name
/// table. Integer values are used directly.
fn scalar_rank(scalar: &ScalarValue) -> Option<u8> {
    match scalar {
        ScalarValue::Int(n) => u8::try_from(*n).ok(),
        ScalarValue::Str(s) => {
            let normalized = normalize_str(s);
            severity_rank_by_name(&normalized).or_else(|| confidence_rank_by_name(&normalized))
        }
        ScalarValue::Bool(_) => None,
    }
}

// ---------------------------------------------------------------------------
// Enum canonical names and ranks
// ---------------------------------------------------------------------------

/// Returns the canonical name and rank for a [`FindingCategory`].
///
/// Categories are not inherently ordered; the rank is a stable hash of the
/// discriminant used only for `greater_than` comparisons (rarely meaningful
/// for categories, but provided for completeness).
fn category_info(cat: FindingCategory) -> (String, u8) {
    let (name, rank) = match cat {
        FindingCategory::Provenance => ("provenance", 0),
        FindingCategory::Reputation => ("reputation", 1),
        FindingCategory::Transport => ("transport", 2),
        FindingCategory::ContentMismatch => ("content-mismatch", 3),
        FindingCategory::MalwareSignature => ("malware-signature", 4),
        FindingCategory::SuspiciousScriptBehavior => ("suspicious-script-behavior", 5),
        FindingCategory::Obfuscation => ("obfuscation", 6),
        FindingCategory::CredentialAccess => ("credential-access", 7),
        FindingCategory::Persistence => ("persistence", 8),
        FindingCategory::PrivilegeEscalation => ("privilege-escalation", 9),
        FindingCategory::DestructiveBehavior => ("destructive-behavior", 10),
        FindingCategory::NetworkBehavior => ("network-behavior", 11),
        FindingCategory::DynamicCodeExecution => ("dynamic-code-execution", 12),
        FindingCategory::ArchiveHazard => ("archive-hazard", 13),
        FindingCategory::ParserDifferential => ("parser-differential", 14),
        FindingCategory::PackageRisk => ("package-risk", 15),
        FindingCategory::PolicyViolation => ("policy-violation", 16),
        FindingCategory::ParserError => ("parser-error", 17),
        FindingCategory::ResourceLimitEvent => ("resource-limit-event", 18),
        FindingCategory::SupplyChain => ("supply-chain", 19),
    };
    (name.to_owned(), rank)
}

/// Returns the canonical name and rank for a [`Severity`].
fn severity_info(sev: Severity) -> (String, u8) {
    let (name, rank) = match sev {
        Severity::Informational => ("informational", 0),
        Severity::Low => ("low", 1),
        Severity::Medium => ("medium", 2),
        Severity::High => ("high", 3),
        Severity::Critical => ("critical", 4),
    };
    (name.to_owned(), rank)
}

/// Returns the canonical name and rank for a [`Confidence`].
fn confidence_info(conf: Confidence) -> (String, u8) {
    let (name, rank) = match conf {
        Confidence::Speculative => ("speculative", 0),
        Confidence::Low => ("low", 1),
        Confidence::Medium => ("medium", 2),
        Confidence::High => ("high", 3),
        Confidence::Confirmed => ("confirmed", 4),
    };
    (name.to_owned(), rank)
}

/// Looks up a severity rank by canonical name.
fn severity_rank_by_name(name: &str) -> Option<u8> {
    match name {
        "informational" => Some(0),
        "low" => Some(1),
        "medium" => Some(2),
        "high" => Some(3),
        "critical" => Some(4),
        _ => None,
    }
}

/// Looks up a confidence rank by canonical name.
fn confidence_rank_by_name(name: &str) -> Option<u8> {
    match name {
        "speculative" => Some(0),
        "low" => Some(1),
        "medium" => Some(2),
        "high" => Some(3),
        "confirmed" => Some(4),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

/// Validates all rules: non-empty unique IDs and known field references.
fn validate_rules(rules: &[Rule]) -> Result<(), PolicyError> {
    let mut seen_ids = std::collections::HashSet::new();
    for rule in rules {
        if rule.id.trim().is_empty() {
            return Err(PolicyError::Invalid("rule has an empty id".to_owned()));
        }
        if !seen_ids.insert(&rule.id) {
            return Err(PolicyError::Invalid(format!(
                "duplicate rule id: {}",
                rule.id
            )));
        }
        validate_condition(&rule.when)?;
    }
    Ok(())
}

/// Recursively validates that all field references are known.
fn validate_condition(cond: &Condition) -> Result<(), PolicyError> {
    match cond {
        Condition::All(conditions) | Condition::Any(conditions) => {
            for c in conditions {
                validate_condition(c)?;
            }
            Ok(())
        }
        Condition::Match(fm) => validate_field(&fm.field),
    }
}

/// Checks that a dotted field path references a known field.
///
/// All field paths must start with one of the recognized namespace
/// prefixes. Recognized prefixes whose specific fields are not yet wired
/// into the [`EvalContext`](crate::EvalContext) still parse — they
/// resolve to `FieldValue::Unavailable` at evaluation time, which
/// triggers the configured fail-closed behaviour. This lets policy
/// authors write forward-compatible TOML referencing features that are
/// still being implemented (tracked in #488).
fn validate_field(field: &str) -> Result<(), PolicyError> {
    const FINDING_FIELDS: &[&str] = &[
        "category",
        "severity",
        "confidence",
        "id",
        "detector",
        "title",
        "description",
        "tags",
    ];
    const CONTEXT_FIELDS: &[&str] = &[
        "operation_mode",
        "artifact_digest",
        "redirect_chain",
        "provenance_verified",
        "provenance_signer",
        "findings_count",
        "block_findings_count",
        "intel_matches",
        "detector_health",
        "recursive_graph_complete",
        "execution_interpreter",
        "execution_network",
        "is_https",
        "is_private_network",
        "is_interactive",
        "caller_origin",
        "source_url",
        "artifact_type",
    ];
    // Forward-compatible namespaces accepted per spec §23.1, §23.1.1, §23.3.
    // Field paths within these namespaces are accepted by the parser but
    // only resolve to values when the caller's EvalContext carries the
    // corresponding data (tracked in #488).
    const FORWARD_COMPATIBLE_PREFIXES: &[&str] =
        &["caller_origin.", "execution.", "integrity.", "findings."];

    if let Some(rest) = field.strip_prefix("finding.") {
        if FINDING_FIELDS.contains(&rest) {
            return Ok(());
        }
        return Err(PolicyError::Invalid(format!(
            "unknown finding field: '{field}'"
        )));
    }
    if let Some(rest) = field.strip_prefix("context.") {
        if CONTEXT_FIELDS.contains(&rest) {
            return Ok(());
        }
        return Err(PolicyError::Invalid(format!(
            "unknown context field: '{field}'"
        )));
    }
    if FORWARD_COMPATIBLE_PREFIXES
        .iter()
        .any(|prefix| field.starts_with(prefix))
    {
        return Ok(());
    }
    Err(PolicyError::Invalid(format!(
        "field path must start with 'finding.', 'context.', 'caller_origin.', \
         'execution.', 'integrity.', or 'findings.': '{field}'"
    )))
}

// ---------------------------------------------------------------------------
// Digest
// ---------------------------------------------------------------------------

/// Computes the SHA-256 digest of the canonical (JSON) policy representation.
fn compute_digest(policy: &Policy) -> Result<String, PolicyError> {
    let canonical =
        serde_json::to_string(policy).map_err(|e| PolicyError::Digest(e.to_string()))?;
    let mut hasher = Sha256::new();
    hasher.update(canonical.as_bytes());
    let hash = hasher.finalize();
    Ok(hex_encode(&hash))
}

/// Hex-encodes a byte slice without external dependencies.
fn hex_encode(bytes: &[u8]) -> String {
    const HEX_CHARS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        out.push(HEX_CHARS[(byte >> 4) as usize] as char);
        out.push(HEX_CHARS[(byte & 0x0f) as usize] as char);
    }
    out
}
