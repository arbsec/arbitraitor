//! Comprehensive tests for the policy engine.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use arbitraitor_model::finding::{Evidence, Finding, FindingCategory};
use arbitraitor_model::ids::Sha256Digest;
use arbitraitor_model::verdict::{Confidence, Severity, Verdict};

use crate::{DetectorHealth, EvalContext, OperationMode, PolicyEngine};
use arbitraitor_model::origin::CallerOrigin;

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

const EXAMPLE_POLICY: &str = r#"
version = 1

[defaults]
action = "prompt"
non_interactive_prompt_action = "block"

[network]
require_https = true
block_private_networks = true

[network.redirects]
max = 5
allow_https_to_http = false

[limits]
max_download_bytes = "1GiB"
max_analysis_time = "120s"

[integrity]
require_digest = false

[[rules]]
id = "block-confirmed-malware"
action = "block"
[rules.when.finding]
category = "malware-signature"
confidence = "confirmed"

[[rules]]
id = "block-credential-access"
action = "block"
[rules.when]
all = [
  { field = "finding.category", equals = "credential-access" },
  { field = "finding.severity", one_of = ["high", "critical"] },
]

[[rules]]
id = "prompt-privilege-escalation"
action = "prompt"
[rules.when]
all = [
  { field = "finding.category", equals = "privilege-escalation" },
]

[[rules]]
id = "pass-low-severity"
action = "pass"
[rules.when]
all = [
  { field = "finding.severity", greater_than = "low" },
]
"#;

const ZERO_DIGEST: Sha256Digest = Sha256Digest::new([0; 32]);

fn make_finding(category: FindingCategory, severity: Severity, confidence: Confidence) -> Finding {
    Finding {
        id: format!("test-{category:?}"),
        detector: "test-detector".to_owned(),
        category,
        severity,
        confidence,
        title: "test finding".to_owned(),
        description: "a test finding".to_owned(),
        evidence: Vec::<Evidence>::new(),
        artifact_sha256: ZERO_DIGEST,
        location: None,
        remediation: None,
        references: Vec::new(),
        tags: Vec::new(),
        taxonomies: Vec::new(),
    }
}

fn interactive_https_ctx() -> EvalContext {
    EvalContext::new(true).with_https(true)
}

fn full_eval_context() -> EvalContext {
    EvalContext {
        operation_mode: OperationMode::Contained,
        artifact_digest: Some(Sha256Digest::new([1; 32])),
        artifact_type: Some("python-package".to_owned()),
        source_url: Some("https://origin.example/artifact".to_owned()),
        redirect_chain: vec![
            "https://origin.example/artifact".to_owned(),
            "https://mirror.example/artifact".to_owned(),
        ],
        provenance_verified: true,
        provenance_signer: Some("builder@example.com".to_owned()),
        findings_count: 7,
        block_findings_count: 2,
        intel_matches: vec!["ioc-123".to_owned(), "feed-7".to_owned()],
        detector_health: DetectorHealth::SomeUnhealthy,
        recursive_graph_complete: true,
        execution_interpreter: Some("/usr/bin/python3".to_owned()),
        execution_network: true,
        is_interactive: true,
        is_https: true,
        is_private_network: false,
        caller_origin: CallerOrigin::DaemonLocal,
    }
}

// ---------------------------------------------------------------------------
// Required tests
// ---------------------------------------------------------------------------

#[test]
fn parses_example_policy_from_spec() {
    let engine = PolicyEngine::load(EXAMPLE_POLICY).expect("example policy should parse");
    let policy = engine.policy();
    assert_eq!(policy.version, 1);
    assert_eq!(policy.rules.len(), 4);
    assert_eq!(policy.rules[0].id, "block-confirmed-malware");
    assert_eq!(policy.rules[1].id, "block-credential-access");
    assert_eq!(policy.rules[2].id, "prompt-privilege-escalation");
    assert_eq!(policy.rules[3].id, "pass-low-severity");
    // Network config
    assert!(policy.network.require_https);
    assert!(policy.network.block_private_networks);
    assert_eq!(policy.network.redirects.max, 5);
    assert!(!policy.network.redirects.allow_https_to_http);
    // Limits
    assert_eq!(policy.limits.max_download_bytes, "1GiB");
    assert_eq!(policy.limits.max_analysis_time, "120s");
    assert!(!policy.integrity.require_digest);
}

#[test]
fn parses_integrity_require_digest() {
    let policy = r"
version = 1

[integrity]
require_digest = true
";
    let engine = PolicyEngine::load(policy).unwrap();

    assert!(engine.policy().integrity.require_digest);
}

#[test]
fn integrity_require_digest_defaults_to_false() {
    let policy = r"
version = 1
";
    let engine = PolicyEngine::load(policy).unwrap();

    assert!(!engine.policy().integrity.require_digest);
}

#[test]
fn allow_rule_with_sha256_digest_without_expiry_is_accepted() {
    let policy = r#"
version = 1

[[rules]]
id = "allow-pinned-digest"
action = "pass"
[rules.when]
all = [{ field = "integrity.sha256", equals = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef" }]
"#;

    let engine = PolicyEngine::load(policy).unwrap();

    assert_eq!(engine.policy().rules[0].id, "allow-pinned-digest");
    assert!(engine.policy().rules[0].expiry.is_none());
}

#[test]
fn allow_rule_with_url_pattern_without_expiry_is_rejected() {
    let policy = r#"
version = 1

[[rules]]
id = "allow-url-pattern"
action = "pass"
[rules.when]
all = [{ field = "context.source_url", contains = "example.invalid/tools/" }]
"#;

    let error = PolicyEngine::load(policy).unwrap_err();

    assert!(
        error
            .to_string()
            .contains("broad indicators (URL patterns) require expiry")
    );
}

#[test]
fn allow_rule_with_url_pattern_and_expiry_is_accepted() {
    let policy = r#"
version = 1

[[rules]]
id = "allow-url-pattern"
action = "pass"
expiry = 2026-12-31T23:59:59Z
[rules.when]
all = [{ field = "context.source_url", contains = "example.invalid/tools/" }]
"#;

    let engine = PolicyEngine::load(policy).unwrap();

    assert!(engine.policy().rules[0].expiry.is_some());
}

#[test]
fn allow_rule_metadata_fields_round_trip_through_toml_parse() {
    let policy = r#"
version = 1

[[rules]]
id = "allow-url-pattern"
action = "pass"
expiry = 2026-12-31T23:59:59Z
scope = "project"
creator = "security@example.invalid"
reason = "temporary exception while upstream release is fixed"
[rules.when]
all = [{ field = "context.source_url", contains = "example.invalid/tools/" }]
"#;

    let engine = PolicyEngine::load(policy).unwrap();
    let rule = &engine.policy().rules[0];

    assert!(rule.expiry.is_some());
    assert_eq!(rule.scope.as_deref(), Some("project"));
    assert_eq!(rule.creator.as_deref(), Some("security@example.invalid"));
    assert_eq!(
        rule.reason.as_deref(),
        Some("temporary exception while upstream release is fixed")
    );
}

#[test]
fn blocks_on_confirmed_malware_finding() {
    let engine = PolicyEngine::load(EXAMPLE_POLICY).unwrap();
    let finding = make_finding(
        FindingCategory::MalwareSignature,
        Severity::High,
        Confidence::Confirmed,
    );
    let verdict = engine.evaluate(&[finding], &interactive_https_ctx());
    assert_eq!(verdict, Verdict::Block);
}

#[test]
fn blocks_on_high_severity_credential_access() {
    let engine = PolicyEngine::load(EXAMPLE_POLICY).unwrap();
    let finding = make_finding(
        FindingCategory::CredentialAccess,
        Severity::High,
        Confidence::Medium,
    );
    let verdict = engine.evaluate(&[finding], &interactive_https_ctx());
    assert_eq!(verdict, Verdict::Block);
}

#[test]
fn blocks_on_critical_severity_credential_access() {
    let engine = PolicyEngine::load(EXAMPLE_POLICY).unwrap();
    let finding = make_finding(
        FindingCategory::CredentialAccess,
        Severity::Critical,
        Confidence::Low,
    );
    let verdict = engine.evaluate(&[finding], &interactive_https_ctx());
    assert_eq!(verdict, Verdict::Block);
}

#[test]
fn does_not_block_low_severity_credential_access() {
    // credential-access + low severity → does not match block rule (needs high+).
    // Falls through to the pass-low-severity rule (low is not > low).
    // Falls through to default prompt.
    let engine = PolicyEngine::load(EXAMPLE_POLICY).unwrap();
    let finding = make_finding(
        FindingCategory::CredentialAccess,
        Severity::Low,
        Confidence::Medium,
    );
    let verdict = engine.evaluate(&[finding], &interactive_https_ctx());
    assert_eq!(verdict, Verdict::Prompt);
}

#[test]
fn prompts_for_privilege_escalation() {
    let engine = PolicyEngine::load(EXAMPLE_POLICY).unwrap();
    let finding = make_finding(
        FindingCategory::PrivilegeEscalation,
        Severity::Medium,
        Confidence::Medium,
    );
    let verdict = engine.evaluate(&[finding], &interactive_https_ctx());
    assert_eq!(verdict, Verdict::Prompt);
}

#[test]
fn passes_when_low_severity_rule_matches() {
    let engine = PolicyEngine::load(EXAMPLE_POLICY).unwrap();
    // severity > low → matches pass-low-severity rule
    // But category is not malware/credential-access/privilege-escalation
    // so earlier block/prompt rules don't match.
    let finding = make_finding(
        FindingCategory::Reputation,
        Severity::Medium,
        Confidence::Medium,
    );
    let verdict = engine.evaluate(&[finding], &interactive_https_ctx());
    assert_eq!(verdict, Verdict::Pass);
}

#[test]
fn blocks_when_no_rule_matches_because_evidence_is_unavailable() {
    let engine = PolicyEngine::load(EXAMPLE_POLICY).unwrap();
    let verdict = engine.evaluate(&[], &interactive_https_ctx());
    assert_eq!(verdict, Verdict::Block);
}

#[test]
fn unavailable_evidence_not_overridden_by_later_pass_rule() {
    let policy = r#"
version = 1

[defaults]
action = "block"
fail_closed_on_unavailable = true

[[rules]]
id = "block-malware"
action = "block"
[rules.when.finding]
category = "malware-signature"

[[rules]]
id = "allow-context"
action = "pass"
[rules.when]
all = [{ field = "context.artifact_type", equals = "shell-script" }]
"#;
    let engine = PolicyEngine::load(policy).unwrap();
    let ctx = interactive_https_ctx().with_artifact_type("shell-script");
    let verdict = engine.evaluate(&[], &ctx);
    assert_eq!(verdict, Verdict::Block);
}

#[test]
fn resolves_all_eval_context_fields_when_populated() {
    let policy = r#"
version = 1

[defaults]
action = "block"

[[rules]]
id = "allow-rich-context"
action = "pass"
expiry = 2026-12-31T23:59:59Z
[rules.when]
all = [
  { field = "context.operation_mode", equals = "contained" },
  { field = "context.artifact_digest", equals = "0101010101010101010101010101010101010101010101010101010101010101" },
  { field = "context.artifact_type", equals = "python-package" },
  { field = "context.source_url", equals = "https://origin.example/artifact" },
  { field = "context.redirect_chain", contains = "https://mirror.example/artifact" },
  { field = "context.provenance_verified", equals = true },
  { field = "context.provenance_signer", equals = "builder@example.com" },
  { field = "context.findings_count", equals = 7 },
  { field = "context.block_findings_count", greater_than = 1 },
  { field = "context.intel_matches", contains = "ioc-123" },
  { field = "context.detector_health", equals = "some-unhealthy" },
  { field = "context.recursive_graph_complete", equals = true },
  { field = "context.execution_interpreter", equals = "/usr/bin/python3" },
  { field = "context.execution_network", equals = true },
]
"#;
    let engine = PolicyEngine::load(policy).unwrap();

    let verdict = engine.evaluate(&[], &full_eval_context());

    assert_eq!(verdict, Verdict::Pass);
}

#[test]
fn eval_context_absent_optional_fields_are_unavailable_not_panics() {
    let policy = r#"
version = 1

[defaults]
action = "block"

[[rules]]
id = "optional-context-fields"
action = "pass"
[rules.when]
any = [
  { field = "context.artifact_digest", equals = "0101010101010101010101010101010101010101010101010101010101010101" },
  { field = "context.provenance_signer", equals = "builder@example.com" },
  { field = "context.execution_interpreter", equals = "/usr/bin/python3" },
]
"#;
    let engine = PolicyEngine::load(policy).unwrap();

    let verdict = engine.evaluate(&[], &EvalContext::new(true));

    assert_eq!(verdict, Verdict::Block);
}

#[test]
fn policy_rule_can_match_new_eval_context_field() {
    let policy = r#"
version = 1

[defaults]
action = "pass"

[[rules]]
id = "block-mediated-operation"
action = "block"
[rules.when]
all = [{ field = "context.operation_mode", equals = "mediated" }]
"#;
    let engine = PolicyEngine::load(policy).unwrap();
    let ctx = EvalContext {
        operation_mode: OperationMode::Mediated,
        ..EvalContext::new(true)
    };

    let verdict = engine.evaluate(&[], &ctx);

    assert_eq!(verdict, Verdict::Block);
}

#[test]
fn non_interactive_prompt_becomes_block() {
    let engine = PolicyEngine::load(EXAMPLE_POLICY).unwrap();
    // Non-interactive context → prompt upgraded to block
    let ctx = EvalContext::new(false).with_https(true);
    let verdict = engine.evaluate(&[], &ctx);
    assert_eq!(verdict, Verdict::Block);
}

#[test]
fn non_interactive_rule_prompt_becomes_block() {
    let engine = PolicyEngine::load(EXAMPLE_POLICY).unwrap();
    let finding = make_finding(
        FindingCategory::PrivilegeEscalation,
        Severity::Medium,
        Confidence::Medium,
    );
    let ctx = EvalContext::new(false).with_https(true);
    let verdict = engine.evaluate(&[finding], &ctx);
    assert_eq!(verdict, Verdict::Block);
}

#[test]
fn digest_is_deterministic() {
    let engine_a = PolicyEngine::load(EXAMPLE_POLICY).unwrap();
    let engine_b = PolicyEngine::load(EXAMPLE_POLICY).unwrap();
    assert_eq!(engine_a.digest(), engine_b.digest());

    // Digest should be a 64-character hex string.
    let digest = engine_a.digest();
    assert_eq!(digest.len(), 64);
    assert!(digest.chars().all(|c| c.is_ascii_hexdigit()));
}

#[test]
fn digest_differs_for_different_policies() {
    let policy_a = r#"
version = 1
[[rules]]
id = "a"
action = "block"
[rules.when.finding]
category = "malware-signature"
"#;
    let policy_b = r#"
version = 1
[[rules]]
id = "b"
action = "pass"
[rules.when.finding]
category = "malware-signature"
"#;
    let engine_a = PolicyEngine::load(policy_a).unwrap();
    let engine_b = PolicyEngine::load(policy_b).unwrap();
    assert_ne!(engine_a.digest(), engine_b.digest());
}

// ---------------------------------------------------------------------------
// Edge-case and invariant tests
// ---------------------------------------------------------------------------

#[test]
fn https_requirement_blocks_non_https() {
    let engine = PolicyEngine::load(EXAMPLE_POLICY).unwrap();
    let ctx = EvalContext::new(true).with_https(false);
    let verdict = engine.evaluate(&[], &ctx);
    assert_eq!(verdict, Verdict::Block);
}

#[test]
fn private_network_blocks_when_blocked() {
    let engine = PolicyEngine::load(EXAMPLE_POLICY).unwrap();
    let ctx = EvalContext::new(true)
        .with_https(true)
        .with_private_network(true);
    let verdict = engine.evaluate(&[], &ctx);
    assert_eq!(verdict, Verdict::Block);
}

#[test]
fn snake_case_policy_values_match_kebab_case_fields() {
    // Policy uses snake_case (finding.category = "malware_signature")
    // while the model serializes to kebab-case ("malware-signature").
    // Normalization should make them match.
    let policy = r#"
version = 1
[[rules]]
id = "block-malware"
action = "block"
[rules.when.finding]
category = "malware_signature"
confidence = "confirmed"
"#;
    let engine = PolicyEngine::load(policy).unwrap();
    let finding = make_finding(
        FindingCategory::MalwareSignature,
        Severity::Critical,
        Confidence::Confirmed,
    );
    let verdict = engine.evaluate(&[finding], &interactive_https_ctx());
    assert_eq!(verdict, Verdict::Block);
}

#[test]
fn first_match_wins() {
    let policy = r#"
version = 1
[[rules]]
id = "rule-a"
action = "block"
[rules.when.finding]
category = "malware-signature"

[[rules]]
id = "rule-b"
action = "pass"
[rules.when.finding]
category = "malware-signature"
"#;
    let engine = PolicyEngine::load(policy).unwrap();
    let finding = make_finding(
        FindingCategory::MalwareSignature,
        Severity::Low,
        Confidence::Speculative,
    );
    let verdict = engine.evaluate(&[finding], &interactive_https_ctx());
    assert_eq!(verdict, Verdict::Block);
}

#[test]
fn any_condition_matches_if_any_sub_matches() {
    let policy = r#"
version = 1
[[rules]]
id = "block-high-or-confirmed"
action = "block"
[rules.when]
any = [
  { field = "finding.severity", one_of = ["critical"] },
  { field = "finding.confidence", equals = "confirmed" },
]
"#;
    let engine = PolicyEngine::load(policy).unwrap();

    // severity=critical matches
    let f1 = make_finding(
        FindingCategory::Reputation,
        Severity::Critical,
        Confidence::Low,
    );
    assert_eq!(
        engine.evaluate(&[f1], &interactive_https_ctx()),
        Verdict::Block
    );

    // confidence=confirmed matches
    let f2 = make_finding(
        FindingCategory::Reputation,
        Severity::Low,
        Confidence::Confirmed,
    );
    assert_eq!(
        engine.evaluate(&[f2], &interactive_https_ctx()),
        Verdict::Block
    );

    // neither matches → default prompt
    let f3 = make_finding(FindingCategory::Reputation, Severity::Low, Confidence::Low);
    assert_eq!(
        engine.evaluate(&[f3], &interactive_https_ctx()),
        Verdict::Prompt
    );
}

#[test]
fn all_condition_applies_to_same_finding() {
    // Two findings: one has category=credential-access but low severity,
    // another has high severity but different category.
    // The all-condition must NOT match across different findings.
    let policy = r#"
version = 1
[[rules]]
id = "block-cred-high"
action = "block"
[rules.when]
all = [
  { field = "finding.category", equals = "credential-access" },
  { field = "finding.severity", one_of = ["high", "critical"] },
]
"#;
    let engine = PolicyEngine::load(policy).unwrap();

    let f1 = make_finding(
        FindingCategory::CredentialAccess,
        Severity::Low,
        Confidence::Medium,
    );
    let f2 = make_finding(
        FindingCategory::Reputation,
        Severity::High,
        Confidence::Medium,
    );
    // Neither finding individually satisfies both conditions.
    let verdict = engine.evaluate(&[f1, f2], &interactive_https_ctx());
    assert_eq!(verdict, Verdict::Prompt); // default
}

#[test]
fn tags_contains_match() {
    let policy = r#"
version = 1
[[rules]]
id = "block-tagged"
action = "block"
[rules.when]
all = [{ field = "finding.tags", contains = "exploit" }]
"#;
    let engine = PolicyEngine::load(policy).unwrap();

    let mut finding = make_finding(
        FindingCategory::NetworkBehavior,
        Severity::Medium,
        Confidence::Medium,
    );
    finding.tags = vec!["exploit".to_owned(), "remote".to_owned()];
    let verdict = engine.evaluate(&[finding], &interactive_https_ctx());
    assert_eq!(verdict, Verdict::Block);
}

#[test]
fn severity_greater_than() {
    let policy = r#"
version = 1
[[rules]]
id = "block-high-severity"
action = "block"
[rules.when]
all = [{ field = "finding.severity", greater_than = "medium" }]
"#;
    let engine = PolicyEngine::load(policy).unwrap();

    // high > medium → block
    let f_high = make_finding(
        FindingCategory::Reputation,
        Severity::High,
        Confidence::Medium,
    );
    assert_eq!(
        engine.evaluate(&[f_high], &interactive_https_ctx()),
        Verdict::Block
    );

    // medium > medium → false → default prompt
    let f_med = make_finding(
        FindingCategory::Reputation,
        Severity::Medium,
        Confidence::Medium,
    );
    assert_eq!(
        engine.evaluate(&[f_med], &interactive_https_ctx()),
        Verdict::Prompt
    );
}

#[test]
fn empty_findings_with_context_only_rule() {
    let policy = r#"
version = 1
[network]
require_https = false

[[rules]]
id = "block-private"
action = "block"
[rules.when]
all = [{ field = "context.is_private_network", equals = true }]
"#;
    let engine = PolicyEngine::load(policy).unwrap();

    // Private network → block
    let ctx_private = EvalContext::new(true)
        .with_https(true)
        .with_private_network(true);
    assert_eq!(engine.evaluate(&[], &ctx_private), Verdict::Block);

    // Not private → default prompt
    let ctx_normal = EvalContext::new(true).with_https(true);
    assert_eq!(engine.evaluate(&[], &ctx_normal), Verdict::Prompt);
}

#[test]
fn unavailable_evidence_does_not_pass() {
    let policy = r#"
version = 1
[defaults]
action = "pass"

[network]
require_https = false

[[rules]]
id = "finding-only"
action = "block"
[rules.when.finding]
category = "malware-signature"
"#;
    let engine = PolicyEngine::load(policy).unwrap();
    let ctx = EvalContext::new(true).with_https(true);
    let verdict = engine.evaluate(&[], &ctx);
    assert_ne!(verdict, Verdict::Pass);
    assert_eq!(verdict, Verdict::Block);
}

#[test]
fn non_interactive_prompt_resolves_to_block() {
    let policy = r#"
version = 1
[defaults]
action = "prompt"
non_interactive_prompt_action = "prompt"

[network]
require_https = false
"#;
    let engine = PolicyEngine::load(policy).unwrap();
    let ctx = EvalContext::new(false).with_https(true);
    let verdict = engine.evaluate(&[], &ctx);
    assert_eq!(verdict, Verdict::Block);
}

#[test]
fn rejects_unsupported_version() {
    let policy = r"version = 2";
    assert!(PolicyEngine::load(policy).is_err());
}

#[test]
fn rejects_duplicate_rule_ids() {
    let policy = r#"
version = 1
[[rules]]
id = "dup"
action = "block"
[rules.when.finding]
category = "malware-signature"

[[rules]]
id = "dup"
action = "pass"
[rules.when.finding]
category = "reputation"
"#;
    assert!(PolicyEngine::load(policy).is_err());
}

#[test]
fn rejects_empty_rule_id() {
    let policy = r#"
version = 1
[[rules]]
id = ""
action = "block"
"#;
    assert!(PolicyEngine::load(policy).is_err());
}

#[test]
fn rejects_unknown_field_reference() {
    let policy = r#"
version = 1
[[rules]]
id = "bad-field"
action = "block"
[rules.when]
all = [{ field = "finding.nonexistent", equals = "x" }]
"#;
    assert!(PolicyEngine::load(policy).is_err());
}

#[test]
fn rejects_unknown_toml_fields() {
    let policy = r"
version = 1
unknown_field = true
";
    assert!(PolicyEngine::load(policy).is_err());
}

#[test]
fn typo_in_field_name_rejected() {
    let policy = r#"
version = 1
[[rules]]
id = "typo-field"
action = "block"
[rules.when]
fiel = "finding.detector"
equals = "trusted"
"#;
    assert!(PolicyEngine::load(policy).is_err());
}

#[test]
fn operator_without_field_rejected() {
    let policy = r#"
version = 1
[[rules]]
id = "operator-only"
action = "pass"
[rules.when]
equals = "trusted"
"#;
    assert!(PolicyEngine::load(policy).is_err());
}

#[test]
fn unknown_nested_field_rejected() {
    let policy = r#"
version = 1
[[rules]]
id = "unknown-nested"
action = "block"
[rules.when]
field = "finding.detector"
equals = "trusted"
unexpected = true
"#;
    assert!(PolicyEngine::load(policy).is_err());
}

#[test]
fn rejects_multiple_operators_in_field_match() {
    let policy = r#"
version = 1
[[rules]]
id = "multi-op"
action = "block"
[rules.when]
all = [{ field = "finding.severity", equals = "high", one_of = ["high"] }]
"#;
    assert!(PolicyEngine::load(policy).is_err());
}

#[test]
fn caller_origin_field_blocks_agent_session() {
    let policy = r#"
version = 1
[network]
require_https = false

[[rules]]
id = "block-agent"
action = "block"
[rules.when]
all = [{ field = "context.caller_origin", equals = "agent_session" }]
"#;
    let engine = PolicyEngine::load(policy).unwrap();
    let ctx = EvalContext::new(false)
        .with_https(true)
        .with_caller_origin(CallerOrigin::AgentSession);
    let verdict = engine.evaluate(&[], &ctx);
    assert_eq!(verdict, Verdict::Block);
}

#[test]
fn caller_origin_passes_for_human_tty() {
    let policy = r#"
version = 1
[network]
require_https = false

[[rules]]
id = "block-agent"
action = "block"
[rules.when]
all = [{ field = "context.caller_origin", equals = "agent_session" }]

[defaults]
action = "pass"
non_interactive_prompt_action = "pass"
"#;
    let engine = PolicyEngine::load(policy).unwrap();
    let ctx = EvalContext::new(false)
        .with_https(true)
        .with_caller_origin(CallerOrigin::HumanTty);
    let verdict = engine.evaluate(&[], &ctx);
    assert_ne!(verdict, Verdict::Block);
}

#[test]
fn caller_origin_defaults_to_unknown() {
    let ctx = EvalContext::default();
    assert_eq!(ctx.caller_origin, CallerOrigin::Unknown);
}

#[test]
fn empty_all_condition_always_matches() {
    let policy = r#"
version = 1
[network]
require_https = false

[[rules]]
id = "catch-all"
action = "warn"
[rules.when]
all = []
"#;
    let engine = PolicyEngine::load(policy).unwrap();
    let ctx = EvalContext::new(true).with_https(true);
    let verdict = engine.evaluate(&[], &ctx);
    assert_eq!(verdict, Verdict::Warn);
}

#[test]
fn multiple_findings_first_matching_rule_wins() {
    let policy = r#"
version = 1
[[rules]]
id = "block-malware"
action = "block"
[rules.when.finding]
category = "malware-signature"
"#;
    let engine = PolicyEngine::load(policy).unwrap();

    let f_low = make_finding(FindingCategory::Reputation, Severity::Low, Confidence::Low);
    let f_malware = make_finding(
        FindingCategory::MalwareSignature,
        Severity::Critical,
        Confidence::Confirmed,
    );
    // The malware finding should trigger the block rule.
    let verdict = engine.evaluate(&[f_low, f_malware], &interactive_https_ctx());
    assert_eq!(verdict, Verdict::Block);
}

// ---------------------------------------------------------------------------
// Property test: monotonicity
// ---------------------------------------------------------------------------

mod proptest_tests {
    use super::*;
    use proptest::prelude::*;

    fn any_severity() -> impl Strategy<Value = Severity> {
        prop_oneof![
            Just(Severity::Informational),
            Just(Severity::Low),
            Just(Severity::Medium),
            Just(Severity::High),
            Just(Severity::Critical),
        ]
    }

    fn any_confidence() -> impl Strategy<Value = Confidence> {
        prop_oneof![
            Just(Confidence::Speculative),
            Just(Confidence::Low),
            Just(Confidence::Medium),
            Just(Confidence::High),
            Just(Confidence::Confirmed),
        ]
    }

    fn any_category() -> impl Strategy<Value = FindingCategory> {
        prop_oneof![
            Just(FindingCategory::Provenance),
            Just(FindingCategory::Reputation),
            Just(FindingCategory::Transport),
            Just(FindingCategory::ContentMismatch),
            Just(FindingCategory::MalwareSignature),
            Just(FindingCategory::SuspiciousScriptBehavior),
            Just(FindingCategory::Obfuscation),
            Just(FindingCategory::CredentialAccess),
            Just(FindingCategory::Persistence),
            Just(FindingCategory::PrivilegeEscalation),
            Just(FindingCategory::DestructiveBehavior),
            Just(FindingCategory::NetworkBehavior),
            Just(FindingCategory::DynamicCodeExecution),
            Just(FindingCategory::ArchiveHazard),
            Just(FindingCategory::PackageRisk),
            Just(FindingCategory::PolicyViolation),
        ]
    }

    /// Restrictiveness ordering: higher = more restrictive.
    fn restrictiveness(v: Verdict) -> u8 {
        match v {
            Verdict::Pass => 0,
            Verdict::Warn => 1,
            Verdict::Prompt => 2,
            Verdict::Incomplete => 3,
            Verdict::Error => 4,
            Verdict::Block => 5,
        }
    }

    proptest! {
        /// Adding a block rule to the end of a policy never weakens the verdict.
        #[test]
        fn monotonicity_adding_block_rule_never_weakens(
            sev in any_severity(),
            conf in any_confidence(),
            cat in any_category(),
            is_interactive in any::<bool>(),
            is_https in any::<bool>(),
            is_private in any::<bool>(),
        ) {
            // Base policy with a single prompt rule.
            let base_policy = r#"
version = 1
[network]
require_https = false
block_private_networks = false

[[rules]]
id = "prompt-on-malware"
action = "prompt"
[rules.when.finding]
category = "malware-signature"
"#;

            // Policy with an additional block-everything rule at the end.
            let extended_policy = r#"
version = 1
[network]
require_https = false
block_private_networks = false

[[rules]]
id = "prompt-on-malware"
action = "prompt"
[rules.when.finding]
category = "malware-signature"

[[rules]]
id = "block-all"
action = "block"
[rules.when]
all = []
"#;

            let base = PolicyEngine::load(base_policy).unwrap();
            let extended = PolicyEngine::load(extended_policy).unwrap();

            let finding = make_finding(cat, sev, conf);
            let findings = [finding];
            let ctx = EvalContext::new(is_interactive)
                .with_https(is_https)
                .with_private_network(is_private);

            let v1 = base.evaluate(&findings, &ctx);
            let v2 = extended.evaluate(&findings, &ctx);

            // v2 must be at least as restrictive as v1.
            prop_assert!(
                restrictiveness(v2) >= restrictiveness(v1),
                "monotonicity violated: v1={v1:?} ({}), v2={v2:?} ({})",
                restrictiveness(v1),
                restrictiveness(v2)
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Spec §23.3 example policy parser regression
// ---------------------------------------------------------------------------

/// Verbatim copy of the spec §23.3 example policy (lines 1828-1897 of
/// `.spec/spec.md`). Used to assert the engine loads the documented
/// example without parse or validation errors. Adding a new operator,
/// field, or top-level section to the spec example requires extending
/// this constant alongside the schema change so accidental drift is
/// caught at test time.
const SPEC_SECTION_23_3_EXAMPLE_POLICY: &str = r#"
version = 1

[defaults]
action = "prompt"
non_interactive_prompt_action = "block"

[network]
require_https = true
block_private_networks = true

[network.redirects]
max = 5
allow_https_to_http = false

[limits]
max_download_bytes = "1GiB"
max_analysis_time = "120s"

[provenance]
require_signature_for = ["executable"]

[[provenance.trusted_sigstore_identities]]
issuer = "https://token.actions.githubusercontent.com"
subject = "https://github.com/acme/*/.github/workflows/release.yml@refs/tags/*"

[detectors.yara_x]
required = true

[detectors.clamav]
required = false

[detectors.script_ast]
required_for = ["shell", "powershell"]

[[rules]]
id = "block-confirmed-malware"
action = "block"

[rules.when.finding]
category = "malware_signature"
confidence = "confirmed"

[[rules]]
id = "block-credential-access"
action = "block"

[rules.when]
all = [
  { field = "finding.category", equals = "credential_access" },
  { field = "finding.severity", one_of = ["high", "critical"] },
]

[[rules]]
id = "require-prompt-for-sudo"
action = "prompt"

[rules.when.finding]
tags_contains = "privilege-escalation"

[[rules]]
id = "allow-pinned-release"
action = "pass"

[rules.when]
all = [
  { field = "integrity.digest_match", equals = true },
  { field = "findings.max_severity", equals = "low" },
]
"#;

/// Verbatim copy of the spec §23.1.1 example policy (lines 1793-1813 of
/// `.spec/spec.md`). Exercises the `not_in` operator and `caller_origin.*`
/// nested field access.
const SPEC_SECTION_23_1_1_EXAMPLE_POLICY: &str = r#"
version = 1

[[rules]]
id = "agent-network-denied"
action = "block"

[rules.when]
all = [
  { field = "caller_origin.class", equals = "agent_session" },
  { field = "execution.network", equals = "allow" },
]

[[rules]]
id = "mcp-server-requires-human-approval"
action = "prompt"

[rules.when]
all = [
  { field = "caller_origin.class", equals = "mcp_server" },
  { field = "caller_origin.mcp_server_id", not_in = ["trusted-mcp-server-1"] },
]
"#;

#[test]
fn loads_spec_section_23_3_example_policy() {
    let engine = PolicyEngine::load(SPEC_SECTION_23_3_EXAMPLE_POLICY)
        .expect("spec §23.3 example policy must parse without errors");
    let digest = engine.digest();
    assert!(!digest.is_empty(), "policy digest must be computed");
}

#[test]
fn loads_spec_section_23_1_1_example_policy_with_not_in_and_nested_fields() {
    let engine = PolicyEngine::load(SPEC_SECTION_23_1_1_EXAMPLE_POLICY)
        .expect("spec §23.1.1 example policy must parse without errors");
    let digest = engine.digest();
    assert!(!digest.is_empty(), "policy digest must be computed");
}
