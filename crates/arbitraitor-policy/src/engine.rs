//! Policy engine: loading, evaluation, and digest computation.

use sha2::{Digest, Sha256};

use arbitraitor_model::finding::{Finding, FindingCategory};
use arbitraitor_model::verdict::{Confidence, Severity, Verdict};

use crate::context::EvalContext;
use crate::error::PolicyError;
use crate::schema::{Condition, FieldMatch, MatchOp, Policy, PolicyAction, Rule, ScalarValue};

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

        if policy.version != 1 {
            return Err(PolicyError::Invalid(format!(
                "unsupported policy version: {} (only version 1 is supported)",
                policy.version
            )));
        }

        validate_rules(&policy.rules)?;

        let digest = compute_digest(&policy)?;

        Ok(Self { policy, digest })
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
        // --- Hard network constraints (checked first, fail-closed) ---
        let net = &self.policy.network;
        if net.require_https && !context.is_https {
            return Verdict::Block;
        }
        if net.block_private_networks && context.is_private_network {
            return Verdict::Block;
        }

        let fail_closed_on_unavailable = self.policy.defaults.fail_closed_on_unavailable;
        let mut saw_unavailable = false;
        let mut best_non_block = None;
        for rule in &self.policy.rules {
            match rule_matches(&rule.when, findings, context) {
                TriState::Matched => {
                    let verdict = resolve_action(rule.action, context, &self.policy.defaults);
                    if verdict == Verdict::Block {
                        return verdict;
                    }
                    if !saw_unavailable || !fail_closed_on_unavailable {
                        return verdict;
                    }
                    best_non_block = Some(verdict);
                }
                TriState::Unavailable => saw_unavailable = true,
                TriState::NotMatched => {}
            }
        }

        if saw_unavailable && fail_closed_on_unavailable {
            return Verdict::Block;
        }

        if let Some(verdict) = best_non_block {
            return verdict;
        }

        // --- Default action ---
        resolve_action(self.policy.defaults.action, context, &self.policy.defaults)
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

            // --- OneOf ---
            (MatchOp::OneOf(scalars), FieldValue::Text { canonical, .. }) => {
                scalars.iter().any(|s| normalize_scalar(s) == *canonical)
            }
            (MatchOp::OneOf(scalars), FieldValue::Bool(b)) => scalars.iter().any(|s| match s {
                ScalarValue::Bool(v) => *v == *b,
                ScalarValue::Str(text) => parse_bool(text).is_some_and(|v| v == *b),
                ScalarValue::Int(_) => false,
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
        FindingCategory::PackageRisk => ("package-risk", 14),
        FindingCategory::PolicyViolation => ("policy-violation", 15),
        FindingCategory::ParserError => ("parser-error", 16),
        FindingCategory::ResourceLimitEvent => ("resource-limit-event", 17),
        FindingCategory::SupplyChain => ("supply-chain", 18),
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
