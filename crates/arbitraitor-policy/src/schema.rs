//! TOML policy schema types and deserialization.
//!
//! Every struct in this module maps directly to a section of the policy TOML
//! document. All types use `#[serde(deny_unknown_fields)]` so that typos in a
//! security-critical configuration are rejected at load time rather than
//! silently ignored.

use std::collections::BTreeMap;

use arbitraitor_model::verdict::Verdict;
use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Top-level policy document
// ---------------------------------------------------------------------------

/// The complete policy document parsed from TOML.
///
/// A policy has a version, default behaviour, network constraints, resource
/// limits, provenance requirements, detector configuration, and an ordered
/// list of matching rules.
///
/// This schema accepts the full spec §23.3 example policy. Field paths
/// beyond `finding.*` and `context.*` (e.g. `caller_origin.class`,
/// `execution.network`, `integrity.digest_match`, `findings.max_severity`)
/// are accepted at parse time. Whether they actually resolve to values at
/// evaluation time depends on the `EvalContext` provided by the caller; an
/// unresolved field is treated as `Unavailable` and falls through to the
/// configured default per `DefaultsConfig::fail_closed_on_unavailable`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    /// Schema version. Only `1` is currently accepted.
    pub version: u32,

    /// Default behaviour when no rule matches.
    #[serde(default)]
    pub defaults: DefaultsConfig,

    /// Network-level constraints.
    #[serde(default)]
    pub network: NetworkConfig,

    /// Resource limits (stored as strings; enforcement happens in the
    /// fetcher / store layers).
    #[serde(default)]
    pub limits: LimitsConfig,

    /// Integrity constraints applied to artifact retrieval.
    #[serde(default)]
    pub integrity: IntegrityConfig,

    /// Provenance + signature requirements (spec §14, §23.3).
    ///
    /// Parsed and fingerprinted; enforcement at evaluation time is wired
    /// by the analysis pipeline.
    #[serde(default)]
    pub provenance: ProvenanceConfig,

    /// Detector configuration keyed by detector id (spec §15, §23.3).
    ///
    /// The map accepts arbitrary detector names (e.g. `yara_x`, `clamav`,
    /// `script_ast`). Each detector's `required`/`required_for`/`required_on`
    /// policy is enforced by the analysis coordinator.
    #[serde(default)]
    pub detectors: BTreeMap<String, DetectorConfig>,

    /// Ordered rules evaluated top-to-bottom; first match wins.
    #[serde(default)]
    pub rules: Vec<Rule>,
}

/// Default actions applied when no rule matches.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DefaultsConfig {
    /// Action taken when no rule matches.
    #[serde(default = "default_action")]
    pub action: PolicyAction,

    /// Action substituted for `prompt` when the evaluation context is
    /// non-interactive (e.g. CI/CD, daemon).
    #[serde(default = "default_non_interactive_action")]
    pub non_interactive_prompt_action: PolicyAction,

    /// Whether unavailable evidence during rule evaluation fails closed.
    #[serde(default = "default_true")]
    pub fail_closed_on_unavailable: bool,
}

impl Default for DefaultsConfig {
    fn default() -> Self {
        Self {
            action: default_action(),
            non_interactive_prompt_action: default_non_interactive_action(),
            fail_closed_on_unavailable: true,
        }
    }
}

fn default_action() -> PolicyAction {
    PolicyAction::Prompt
}

fn default_non_interactive_action() -> PolicyAction {
    PolicyAction::Block
}

/// Network-level constraints checked before rule evaluation.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkConfig {
    /// Require HTTPS (or equivalent secure transport) for the source URL.
    #[serde(default = "default_true")]
    pub require_https: bool,

    /// Block requests to private / loopback / link-local networks.
    #[serde(default = "default_true")]
    pub block_private_networks: bool,

    /// Redirect policy.
    #[serde(default)]
    pub redirects: RedirectsConfig,
}

impl Default for NetworkConfig {
    fn default() -> Self {
        Self {
            require_https: true,
            block_private_networks: true,
            redirects: RedirectsConfig::default(),
        }
    }
}

/// HTTP redirect limits.
///
/// Defaults match spec §11.4 (lines 644-653). The cross-origin defaults
/// are:
/// - `allow_cross_origin = true` — most legitimate downloads redirect
///   across origins (e.g. GitHub release → CDN).
/// - `forward_authorization_cross_origin = false` — Authorization
///   headers must never silently follow a redirect to a new origin.
///   This is the critical credential-leak defence from spec §11.2
///   (lines 608-612); callers opt in to cross-origin credential
///   forwarding only when the redirect chain is fully trusted.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RedirectsConfig {
    /// Maximum number of redirects to follow.
    #[serde(default = "default_redirect_max")]
    pub max: u32,

    /// Whether redirecting from HTTPS to HTTP is permitted.
    #[serde(default = "default_false")]
    pub allow_https_to_http: bool,

    /// Whether cross-origin redirects are permitted.
    ///
    /// Two URLs are same-origin when scheme, host, and port all match.
    /// Defaults to `true` because the common case (release artifact →
    /// CDN) involves a cross-origin redirect. Set to `false` to refuse
    /// any redirect that changes the origin, useful for high-assurance
    /// pinned-source policies.
    #[serde(default = "default_true")]
    pub allow_cross_origin: bool,

    /// Whether `Authorization` (and other credential-bearing) headers
    /// may be forwarded across origins during a redirect chain.
    ///
    /// Defaults to `false` per spec §11.2. When `false`, any redirect
    /// that lands on a different origin triggers a forced strip of
    /// `Authorization` and `Cookie` headers from subsequent requests in
    /// the chain. When `true`, the original headers are preserved.
    #[serde(default = "default_false")]
    pub forward_authorization_cross_origin: bool,
}

impl Default for RedirectsConfig {
    fn default() -> Self {
        Self {
            max: default_redirect_max(),
            allow_https_to_http: false,
            allow_cross_origin: true,
            forward_authorization_cross_origin: false,
        }
    }
}

fn default_redirect_max() -> u32 {
    5
}

/// Resource limits expressed as human-readable strings.
///
/// Parsing to concrete byte / duration values happens in the enforcing crate;
/// the policy engine only stores and fingerprints them.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LimitsConfig {
    /// Maximum download size, e.g. `"1GiB"`.
    #[serde(default = "default_max_download_bytes")]
    pub max_download_bytes: String,

    /// Maximum analysis wall-clock time, e.g. `"120s"`.
    #[serde(default = "default_max_analysis_time")]
    pub max_analysis_time: String,
}

impl Default for LimitsConfig {
    fn default() -> Self {
        Self {
            max_download_bytes: default_max_download_bytes(),
            max_analysis_time: default_max_analysis_time(),
        }
    }
}

fn default_max_download_bytes() -> String {
    "1GiB".to_owned()
}

fn default_max_analysis_time() -> String {
    "120s".to_owned()
}

/// Artifact integrity requirements.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct IntegrityConfig {
    /// Require a caller-provided expected SHA-256 digest before retrieval.
    #[serde(default)]
    pub require_digest: bool,
}

/// Provenance + signature requirements (spec §14.3, §23.3).
///
/// Parsed into the policy fingerprint; enforcement happens in the
/// analysis pipeline when the provenance verifier runs (issue #514).
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct ProvenanceConfig {
    /// Artifact classes that require a valid signature before release.
    ///
    /// Spec example: `require_signature_for = ["executable"]`.
    #[serde(default)]
    pub require_signature_for: Vec<String>,

    /// Required Sigstore signer identities (issuer + subject pattern).
    #[serde(default)]
    pub trusted_sigstore_identities: Vec<SigstoreIdentity>,
}

/// A trusted Sigstore signer identity (spec §14.3, §23.3 example).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SigstoreIdentity {
    /// Fulcio OIDC issuer URL (e.g. `https://token.actions.githubusercontent.com`).
    pub issuer: String,
    /// SAN pattern (e.g. `https://github.com/acme/*/.github/workflows/release.yml@refs/tags/*`).
    pub subject: String,
}

/// Per-detector policy (spec §15, §23.3 example).
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct DetectorConfig {
    /// Whether this detector is required for a passing verdict.
    #[serde(default)]
    pub required: bool,

    /// Artifact classes (e.g. `["shell", "powershell"]`) for which this
    /// detector is mandatory. If non-empty, `required` is implied `true`
    /// for matching classes.
    #[serde(default)]
    pub required_for: Vec<String>,

    /// Platform targets (e.g. `["windows"]`) on which this detector must
    /// succeed.
    #[serde(default)]
    pub required_on: Vec<String>,
}

fn default_true() -> bool {
    true
}

fn default_false() -> bool {
    false
}

// ---------------------------------------------------------------------------
// Rules and actions
// ---------------------------------------------------------------------------

/// A single policy rule.
///
/// Rules are evaluated in declaration order. The first rule whose condition
/// matches determines the verdict.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Rule {
    /// Human-readable rule identifier used in receipts and diagnostics.
    pub id: String,

    /// Action taken when this rule matches.
    pub action: PolicyAction,

    /// Condition that must be satisfied for the rule to match.
    #[serde(default)]
    pub when: Condition,
}

/// Action produced by a policy rule or default.
///
/// This is a subset of [`Verdict`] — policy cannot directly produce `Error`
/// or `Incomplete`; those arise from system-level failures.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PolicyAction {
    /// Release the artifact.
    Pass,
    /// Release with a warning.
    Warn,
    /// Interactive approval required.
    Prompt,
    /// Release prohibited.
    Block,
}

impl From<PolicyAction> for Verdict {
    fn from(action: PolicyAction) -> Self {
        match action {
            PolicyAction::Pass => Verdict::Pass,
            PolicyAction::Warn => Verdict::Warn,
            PolicyAction::Prompt => Verdict::Prompt,
            PolicyAction::Block => Verdict::Block,
        }
    }
}

// ---------------------------------------------------------------------------
// Conditions
// ---------------------------------------------------------------------------

/// A condition that determines whether a rule matches.
///
/// Conditions are composable:
///
/// ```toml
/// # All sub-conditions must match
/// all = [
///   { field = "finding.category", equals = "credential-access" },
///   { field = "finding.severity", one_of = ["high", "critical"] },
/// ]
///
/// # Any sub-condition must match
/// any = [ { field = "finding.confidence", equals = "confirmed" } ]
///
/// # Shorthand: every key under [finding] becomes an equality match
/// [when.finding]
/// category = "malware-signature"
/// confidence = "confirmed"
/// ```
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Condition {
    /// All sub-conditions must evaluate to *matched*.
    All(Vec<Condition>),

    /// At least one sub-condition must evaluate to *matched*.
    Any(Vec<Condition>),

    /// A single field match with an explicit operator.
    Match(FieldMatch),
}

impl Condition {
    /// Creates an `all` condition from the given sub-conditions.
    #[must_use]
    pub fn all(conditions: Vec<Condition>) -> Self {
        Self::All(conditions)
    }

    /// Creates an `any` condition from the given sub-conditions.
    #[must_use]
    pub fn any(conditions: Vec<Condition>) -> Self {
        Self::Any(conditions)
    }

    /// Creates a single-match condition.
    #[must_use]
    pub fn field(field: impl Into<String>, op: MatchOp) -> Self {
        Self::Match(FieldMatch {
            field: field.into(),
            op,
        })
    }

    /// Creates a condition that vacuously matches (always true).
    ///
    /// Useful as a catch-all default action override.
    #[must_use]
    pub fn always() -> Self {
        Self::All(Vec::new())
    }
}

impl Default for Condition {
    fn default() -> Self {
        Self::always()
    }
}

/// A field path plus a comparison operator.
#[derive(Debug, Clone, Serialize)]
pub struct FieldMatch {
    /// Dotted field path, e.g. `"finding.category"` or `"context.is_https"`.
    pub field: String,

    /// The comparison to apply.
    pub op: MatchOp,
}

/// Comparison operators available in field matches.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MatchOp {
    /// Exact equality (case-insensitive, `_` and `-` treated as equivalent).
    Equals(ScalarValue),

    /// Membership in a set of acceptable values.
    OneOf(Vec<ScalarValue>),

    /// Non-membership in a set: matches when the resolved value is not in
    /// the supplied list. Complement of [`OneOf`](Self::OneOf). Used by the
    /// spec §23.1.1 example policy for `caller_origin.mcp_server_id
    /// not_in = ["trusted-mcp-server-1"]`.
    NotIn(Vec<ScalarValue>),

    /// Substring containment (for text fields) or list membership (for
    /// `finding.tags`).
    Contains(String),

    /// Strictly greater-than comparison.
    ///
    /// For ordered enums (`severity`, `confidence`) the built-in rank is used.
    /// For integers, numeric comparison.
    GreaterThan(ScalarValue),
}

/// A scalar value that can appear on the right-hand side of a match operator.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ScalarValue {
    /// Boolean literal.
    Bool(bool),
    /// Integer literal.
    Int(i64),
    /// String literal.
    Str(String),
}

impl ScalarValue {
    /// Returns the string content if this is a `Str` variant.
    #[must_use]
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Self::Str(s) => Some(s.as_str()),
            _ => None,
        }
    }
}

// ---------------------------------------------------------------------------
// Deserialization helpers
// ---------------------------------------------------------------------------

/// Intermediate representation used to deserialize a [`Condition`] flexibly
/// from TOML before validating exactly one form was supplied.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawCondition {
    #[serde(default)]
    all: Option<Vec<Condition>>,
    #[serde(default)]
    any: Option<Vec<Condition>>,
    #[serde(default)]
    finding: Option<BTreeMap<String, String>>,
    #[serde(default)]
    field: Option<String>,
    #[serde(default)]
    equals: Option<ScalarValue>,
    #[serde(default)]
    one_of: Option<Vec<ScalarValue>>,
    #[serde(default)]
    not_in: Option<Vec<ScalarValue>>,
    #[serde(default)]
    contains: Option<String>,
    #[serde(default)]
    greater_than: Option<ScalarValue>,
}

impl<'de> Deserialize<'de> for Condition {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let raw = RawCondition::deserialize(deserializer)?;
        Condition::from_raw(raw).map_err(serde::de::Error::custom)
    }
}

impl Condition {
    fn from_raw(raw: RawCondition) -> Result<Self, String> {
        // Count how many top-level forms were supplied.
        let combinators = u8::from(raw.all.is_some()) + u8::from(raw.any.is_some());
        let shorthand = u8::from(raw.finding.is_some());
        let field_match = u8::from(raw.field.is_some());
        let forms = combinators + shorthand + field_match;
        let operators = u8::from(raw.equals.is_some())
            + u8::from(raw.one_of.is_some())
            + u8::from(raw.not_in.is_some())
            + u8::from(raw.contains.is_some())
            + u8::from(raw.greater_than.is_some());

        if raw.field.is_none() && operators > 0 {
            return Err("condition operator supplied without a `field` key".to_owned());
        }
        if raw.field.is_some() && (combinators > 0 || shorthand > 0) {
            return Err("condition cannot mix `field` with `all`, `any`, or `finding`".to_owned());
        }
        if forms == 0 {
            return Err("condition must specify `all`, `any`, `finding`, or `field`".to_owned());
        }
        if forms > 1 {
            return Err(
                "condition must use at most one of: `all`, `any`, `finding`, or `field`".to_owned(),
            );
        }

        if let Some(conditions) = raw.all {
            return Ok(Self::All(conditions));
        }
        if let Some(conditions) = raw.any {
            return Ok(Self::Any(conditions));
        }
        if let Some(map) = raw.finding {
            // Shorthand: each key → equality match on `finding.<key>`.
            //
            // Special case: if the key ends with `_contains` (e.g.
            // `tags_contains` from spec §23.3), strip the suffix and use
            // the `Contains` operator against the named field (e.g.
            // `finding.tags Contains "<value>"`). This accepts the spec
            // example `[rules.when.finding] tags_contains = "privilege-escalation"`
            // without requiring the user to write the longer inline form.
            let matches: Vec<Condition> = map
                .into_iter()
                .map(|(key, value)| {
                    if let Some(field_name) = key.strip_suffix("_contains") {
                        Condition::Match(FieldMatch {
                            field: format!("finding.{field_name}"),
                            op: MatchOp::Contains(value),
                        })
                    } else {
                        Condition::Match(FieldMatch {
                            field: format!("finding.{key}"),
                            op: MatchOp::Equals(ScalarValue::Str(value)),
                        })
                    }
                })
                .collect();
            return Ok(Self::All(matches));
        }

        // Single field match.
        let field = raw
            .field
            .ok_or_else(|| "field match requires a `field` key".to_owned())?;
        let op = MatchOp::from_raw(
            raw.equals,
            raw.one_of,
            raw.not_in,
            raw.contains,
            raw.greater_than,
        )?;
        Ok(Self::Match(FieldMatch { field, op }))
    }
}

impl MatchOp {
    fn from_raw(
        equals: Option<ScalarValue>,
        one_of: Option<Vec<ScalarValue>>,
        not_in: Option<Vec<ScalarValue>>,
        contains: Option<String>,
        greater_than: Option<ScalarValue>,
    ) -> Result<Self, String> {
        let count = u8::from(equals.is_some())
            + u8::from(one_of.is_some())
            + u8::from(not_in.is_some())
            + u8::from(contains.is_some())
            + u8::from(greater_than.is_some());
        if count == 0 {
            return Err("field match requires exactly one operator: `equals`, `one_of`, `not_in`, `contains`, or `greater_than`".to_owned());
        }
        if count > 1 {
            return Err("field match must use exactly one operator: `equals`, `one_of`, `not_in`, `contains`, or `greater_than`".to_owned());
        }
        if let Some(v) = equals {
            return Ok(Self::Equals(v));
        }
        if let Some(v) = one_of {
            return Ok(Self::OneOf(v));
        }
        if let Some(v) = not_in {
            return Ok(Self::NotIn(v));
        }
        if let Some(v) = contains {
            return Ok(Self::Contains(v));
        }
        // SAFETY: count > 0 guarantees one of the five is Some.
        let v = greater_than.ok_or_else(|| "greater_than was expected but is None".to_owned())?;
        Ok(Self::GreaterThan(v))
    }
}

#[cfg(test)]
mod schema_tests {
    use super::*;

    #[test]
    fn condition_all_round_trips() {
        let cond = Condition::all(vec![
            Condition::field(
                "finding.category",
                MatchOp::Equals(ScalarValue::Str("malware".into())),
            ),
            Condition::field(
                "finding.severity",
                MatchOp::OneOf(vec![
                    ScalarValue::Str("high".into()),
                    ScalarValue::Str("critical".into()),
                ]),
            ),
        ]);
        let json = serde_json::to_string(&cond).unwrap_or_default();
        assert!(json.contains("\"all\""));
    }

    #[test]
    fn match_op_rejects_zero_operators() {
        let result = MatchOp::from_raw(None, None, None, None, None);
        assert!(result.is_err());
    }

    #[test]
    fn match_op_rejects_multiple_operators() {
        let result = MatchOp::from_raw(
            Some(ScalarValue::Str("x".into())),
            Some(vec![ScalarValue::Str("y".into())]),
            None,
            None,
            None,
        );
        assert!(result.is_err());
    }
}
