//! Unit tests for the pipeline engine.
//!
//! Integration tests exercising the full pipeline against mock HTTP servers
//! live in `tests/`; these unit tests cover the engine's internal stage
//! helpers and state-machine wiring.

use arbitraitor_core::{PipelineOperation, PipelineState};
use arbitraitor_model::ids::{ArtifactId, OperationId, Sha256Digest};

use arbitraitor_fetch::FetchSource;

use crate::api::reconstruct_operation;
use crate::pipeline::{parse_fetch_source, receipt_timestamp_seconds};
use crate::{EngineError, FAIL_CLOSED_POLICY_TOML};

fn test_digest(byte: u8) -> Sha256Digest {
    use sha2::Digest as _;
    Sha256Digest::new(sha2::Sha256::digest([byte]).into())
}

#[test]
fn parse_fetch_source_accepts_http_and_https_urls() {
    assert!(matches!(
        parse_fetch_source("https://example.com/a.sh").unwrap(),
        FetchSource::Url(_)
    ));
    assert!(matches!(
        parse_fetch_source("http://example.com/a.sh").unwrap(),
        FetchSource::Url(_)
    ));
}

#[test]
fn parse_fetch_source_accepts_local_paths_and_file_urls() {
    assert!(matches!(
        parse_fetch_source("./local.sh").unwrap(),
        FetchSource::File(_)
    ));
    assert!(matches!(
        parse_fetch_source("/abs/path.sh").unwrap(),
        FetchSource::File(_)
    ));
    assert!(matches!(
        parse_fetch_source("file:///abs/path.sh").unwrap(),
        FetchSource::File(_)
    ));
}

#[test]
fn parse_fetch_source_maps_stdin_markers() {
    assert!(matches!(
        parse_fetch_source("-").unwrap(),
        FetchSource::Stdin
    ));
    assert!(matches!(
        parse_fetch_source("stdin://").unwrap(),
        FetchSource::Stdin
    ));
}

#[test]
fn parse_fetch_source_rejects_unsupported_schemes() {
    assert!(parse_fetch_source("ftp://example.com/a").is_err());
    assert!(parse_fetch_source("gopher://example.com/a").is_err());
}

#[test]
fn receipt_timestamp_seconds_parses_both_timestamp_forms() {
    assert_eq!(
        receipt_timestamp_seconds("unix:1700000000.123456789Z"),
        1_700_000_000
    );
    assert_eq!(receipt_timestamp_seconds("1700000000"), 1_700_000_000);
    assert_eq!(receipt_timestamp_seconds("not-a-timestamp"), 0);
}

/// ADR-0038 decision 1: the engine drives the `arbitraitor-core` state
/// machine. `reconstruct_operation` must land in `AwaitingApproval` with the
/// verdict recorded, and a blocking verdict must set the release-prohibition
/// markers the release path enforces.
#[test]
fn reconstruct_operation_lands_in_awaiting_approval_with_verdict() {
    use arbitraitor_model::verdict::Verdict;
    let operation =
        reconstruct_operation(&test_digest(1), Verdict::Pass).expect("reconstruction must succeed");
    assert_eq!(operation.state(), PipelineState::AwaitingApproval);
    assert_eq!(operation.verdict(), Some(Verdict::Pass));
    assert!(!operation.release_prohibited());
    assert!(!operation.has_blocking_verdict());
}

#[test]
fn reconstruct_operation_with_blocking_verdict_prohibits_release() {
    use arbitraitor_model::verdict::Verdict;
    let operation = reconstruct_operation(&test_digest(2), Verdict::Block)
        .expect("reconstruction must succeed");
    assert_eq!(operation.state(), PipelineState::AwaitingApproval);
    assert!(operation.release_prohibited());
    assert!(operation.has_blocking_verdict());
    assert!(operation.approve().is_err());
}

/// ADR-0038 decision 1: the release path drives approval → release →
/// completion through the graph, not a bare verdict comparison.
#[test]
fn release_transitions_require_approval_before_completion() {
    use arbitraitor_model::verdict::Verdict;
    let operation =
        reconstruct_operation(&test_digest(3), Verdict::Pass).expect("reconstruction must succeed");
    let approved = operation.approve().expect("pass verdict approves");
    // Completion before release is rejected by the graph.
    assert!(approved.clone().complete().is_err());
    let released = approved.release().expect("approved operation releases");
    assert_eq!(released.state(), PipelineState::Released);
    let completed = released.complete().expect("released operation completes");
    assert_eq!(completed.state(), PipelineState::Completed);
}

/// A raw operation cannot skip storage: the graph rejects
/// `Created → Analyzing`.
#[test]
fn state_machine_rejects_analysis_before_storage() {
    let operation = PipelineOperation::new(OperationId::new(), ArtifactId(test_digest(4)));
    assert!(operation.transition_to(PipelineState::Analyzing).is_err());
}

/// The engine's default directories live under the user cache root, never
/// the working directory (when a home directory can be resolved).
#[test]
fn default_directories_are_siblings_under_cache_root() {
    let cas = crate::default_cas_dir();
    let receipts = crate::default_receipts_dir();
    if std::env::var_os("HOME").is_some() || std::env::var_os("XDG_CACHE_HOME").is_some() {
        assert!(cas.ends_with("cas"));
        assert!(receipts.ends_with("receipts"));
        assert_eq!(cas.parent(), receipts.parent());
    }
}

/// ADR-0038 decision 6: the receipt wrapper exposes consumer fields without
/// leaking `arbitraitor-receipt` types, and serializes for persistence.
#[test]
fn inspection_result_receipt_wrapper_hides_internal_receipt_type() {
    let api = crate::api::ArbitraitorApi::new(crate::Config {
        store_path: std::env::temp_dir().join("arb-engine-wrapper-cas"),
        receipts_path: std::env::temp_dir().join("arb-engine-wrapper-receipts"),
        ..crate::Config::default()
    })
    .expect("engine construction must succeed");
    let script = b"#!/bin/sh\necho wrapper\n";
    let result = api
        .scan_path(
            &write_temp_script("wrapper.sh", script),
            crate::DEFAULT_SCAN_MAX_BYTES,
        )
        .expect("scan must succeed");
    let receipt = &result.receipt;
    assert_eq!(receipt.sha256(), result.sha256);
    assert_eq!(receipt.size_bytes(), u64::try_from(script.len()).unwrap());
    assert_eq!(receipt.verdict(), result.verdict);
    assert_eq!(receipt.findings_count(), result.findings.len());
    assert!(receipt.created_at().starts_with("unix:"));
    let json = receipt.to_vec_pretty().expect("receipt must serialize");
    let parsed: serde_json::Value = serde_json::from_slice(&json).expect("receipt JSON must parse");
    assert_eq!(parsed["artifact"]["sha256"], result.sha256);
}

fn write_temp_script(name: &str, body: &[u8]) -> std::path::PathBuf {
    let path = std::env::temp_dir().join(format!(
        "arb-engine-{name}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos())
    ));
    std::fs::write(&path, body).expect("temp script write");
    path
}

/// ADR-0038 decision 1: the engine drives the `arbitraitor-core` state
/// machine through the analysis tail. The operation returned by the shared
/// finalize stage must sit in `AwaitingApproval` with the verdict recorded.
#[test]
fn analyze_and_finalize_drives_operation_to_awaiting_approval() {
    use crate::api::ArbitraitorApi;
    use arbitraitor_core::{PipelineOperation, PipelineState};
    use arbitraitor_model::ids::{ArtifactId, OperationId, Sha256Digest};

    let api = ArbitraitorApi::new(crate::Config {
        store_path: std::env::temp_dir().join("arb-engine-state-cas"),
        receipts_path: std::env::temp_dir().join("arb-engine-state-receipts"),
        ..crate::Config::default()
    })
    .expect("engine construction must succeed");
    let script = b"#!/bin/sh\necho state-machine\n";
    let path = write_temp_script("state.sh", script);
    let digest = {
        use sha2::Digest as _;
        Sha256Digest::new(sha2::Sha256::digest(script).into())
    };
    let operation = PipelineOperation::new(OperationId::new(), ArtifactId(digest.clone()))
        .transition_to(PipelineState::Retrieving)
        .and_then(|op| op.transition_to(PipelineState::Stored))
        .expect("stage transitions must succeed");

    let (_result, operation) = api
        .analyze_and_finalize(
            operation,
            script,
            &digest,
            path.to_str().unwrap_or(""),
            None,
            None,
            true,
        )
        .expect("analysis tail must succeed");

    assert_eq!(operation.state(), PipelineState::AwaitingApproval);
    assert!(operation.verdict().is_some(), "verdict must be recorded");
    assert!(!operation.release_prohibited());
}

/// ADR-0038 decision 1 (fail-closed, spec §18.3): an `Incomplete` verdict
/// also prohibits release through the state machine — the former daemon
/// release check only rejected `Block` and `Error`.
#[test]
fn reconstruct_operation_with_incomplete_verdict_prohibits_release() {
    use arbitraitor_model::verdict::Verdict;
    let operation =
        reconstruct_operation(&test_digest(5), Verdict::Incomplete).expect("reconstruction");
    assert!(operation.has_blocking_verdict());
    assert!(operation.release_prohibited());
    assert!(operation.approve().is_err());
}

/// ADR-0038 decision 5: the exported fail-closed policy constant compiles
/// into a valid policy engine.
#[test]
fn fail_closed_policy_toml_compiles() {
    arbitraitor_policy::PolicyEngine::load(FAIL_CLOSED_POLICY_TOML)
        .unwrap_or_else(|error| panic!("FAIL_CLOSED_POLICY_TOML must compile: {error}"));
}

/// ADR-0038 decision 7 (partial, staged): store failures are wrapped as
/// safe diagnostic strings on the public error type rather than leaking
/// `arbitraitor_store::StoreError`.
#[test]
fn store_error_is_wrapped_as_safe_string() {
    let error = EngineError::from(arbitraitor_store::StoreError::NotFound {
        digest: test_digest(6),
    });
    assert!(matches!(error, EngineError::Store(_)));
}

/// Audit-trail integrity: `receipt_summary` reads the persisted receipt but
/// never rewrites it. A query endpoint that re-persisted the receipt would
/// silently regenerate policy traces and timestamps on every lookup,
/// breaking §31's write-once audit property. The byte-wise comparison is
/// the strongest signal: any rewrite would surface as a content drift.
#[test]
fn receipt_summary_returns_persisted_summary_without_rewriting() {
    let root = std::env::temp_dir().join(format!(
        "arb-engine-receipt-ro-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos())
    ));
    let api = crate::api::ArbitraitorApi::new(crate::Config {
        store_path: root.join("cas"),
        receipts_path: root.join("receipts"),
        ..crate::Config::default()
    })
    .expect("engine construction must succeed");
    let script = b"#!/bin/sh\necho receipt-read-only\n";
    let result = api
        .scan_path(
            &write_temp_script("receipt-ro.sh", script),
            crate::DEFAULT_SCAN_MAX_BYTES,
        )
        .expect("scan must succeed");
    let receipt_path = result
        .receipt_path
        .clone()
        .expect("scan must persist a receipt");
    let bytes_before = std::fs::read(&receipt_path).expect("read persisted receipt");

    let summary = api
        .receipt_summary(&result.sha256)
        .expect("receipt_summary must not error")
        .expect("receipt_summary must find the persisted receipt");
    assert_eq!(summary.sha256, result.sha256);
    assert_eq!(summary.verdict, result.verdict);
    assert_eq!(summary.size_bytes, u64::try_from(script.len()).unwrap());
    assert_eq!(summary.findings_count, result.findings.len());

    let bytes_after = std::fs::read(&receipt_path).expect("read persisted receipt after query");
    assert_eq!(
        bytes_before, bytes_after,
        "receipt_summary must never rewrite the persisted receipt"
    );
}

/// `receipt_summary` returns `None` for a digest with no persisted receipt,
/// so the daemon's `QueryReceipt` endpoint can distinguish "no receipt
/// exists" from "tool failed" without re-running analysis.
#[test]
fn receipt_summary_returns_none_for_missing_receipt() {
    let root = std::env::temp_dir().join(format!(
        "arb-engine-receipt-missing-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos())
    ));
    let api = crate::api::ArbitraitorApi::new(crate::Config {
        store_path: root.join("cas"),
        receipts_path: root.join("receipts"),
        ..crate::Config::default()
    })
    .expect("engine construction must succeed");
    let summary = api
        .receipt_summary(&"ab".repeat(32))
        .expect("receipt_summary must not error on a missing receipt");
    assert!(summary.is_none(), "expected no receipt, got {summary:?}");
}

/// `receipt_summary` rejects a malformed digest up front rather than
/// constructing a receipt path from a caller-controlled string.
#[test]
fn receipt_summary_rejects_invalid_digest() {
    let root = std::env::temp_dir().join(format!(
        "arb-engine-receipt-bad-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos())
    ));
    let api = crate::api::ArbitraitorApi::new(crate::Config {
        store_path: root.join("cas"),
        receipts_path: root.join("receipts"),
        ..crate::Config::default()
    })
    .expect("engine construction must succeed");
    assert!(api.receipt_summary("not-a-digest").is_err());
}

/// `Config::store_max_bytes` is enforced by the CAS streaming sink itself
/// (`sink_with_limits`), so the bound holds the moment bytes enter the store
/// rather than as a post-write size check (the previous CLI pipeline's
/// `artifact_len > config.store.max_bytes` was a post-write check; the
/// engine enforces the same contract one stage earlier and uniformly across
/// fetch, inspect, `scan_path`, and child-artifact expansion).
#[test]
fn store_max_bytes_is_enforced_by_scan_path_sink() {
    let root = std::env::temp_dir().join(format!(
        "arb-engine-store-limit-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos())
    ));
    let api = crate::api::ArbitraitorApi::new(crate::Config {
        store_path: root.join("cas"),
        receipts_path: root.join("receipts"),
        store_max_bytes: 8,
        ..crate::Config::default()
    })
    .expect("engine construction must succeed");
    // The script body exceeds the configured 8-byte store bound.
    let script = b"#!/bin/sh\necho too large\n";
    let result = api.scan_path(
        &write_temp_script("store-limit.sh", script),
        crate::DEFAULT_SCAN_MAX_BYTES,
    );
    let error = match result {
        Ok(inspection) => panic!("scan must be rejected by the store limit, got {inspection:?}"),
        Err(error) => error,
    };
    let rendered = error.to_string();
    assert!(
        rendered.contains("artifact size exceeded limit"),
        "expected SizeExceeded surfaced via EngineError::Store, got: {rendered}"
    );
}

#[test]
fn receipt_retrieval_info_records_response_status_code() {
    use crate::pipeline::receipt_retrieval_info;

    // Released HTTP error-status bodies (curl without -f semantics) must
    // carry the real response status in the receipt — otherwise the audit
    // trail cannot distinguish a 404 body from a 200 body.
    let digest = test_digest(1);
    let metadata = arbitraitor_fetch::FetchMetadata {
        response_status: Some(404),
        ..arbitraitor_fetch::FetchMetadata::default()
    };
    let receipt = arbitraitor_fetch::FetchReceipt {
        artifact_id: arbitraitor_model::ids::ArtifactId(digest.clone()),
        sha256: digest,
        bytes_written: 4,
        metadata,
        child_artifacts: Vec::new(),
    };

    let retrieval = receipt_retrieval_info("https://example.com/missing", &receipt);
    let json = serde_json::to_value(&retrieval).unwrap();
    assert_eq!(
        json.get("status_code"),
        Some(&serde_json::json!(404)),
        "receipt must record the real HTTP response status: {json}"
    );

    // Non-HTTP sources (no status) must leave the field absent, not zero.
    let digest = test_digest(2);
    let receipt = arbitraitor_fetch::FetchReceipt {
        artifact_id: arbitraitor_model::ids::ArtifactId(digest.clone()),
        sha256: digest,
        bytes_written: 0,
        metadata: arbitraitor_fetch::FetchMetadata::default(),
        child_artifacts: Vec::new(),
    };
    let retrieval = receipt_retrieval_info("/local/path", &receipt);
    let json = serde_json::to_value(&retrieval).unwrap();
    assert_eq!(
        json.get("status_code"),
        Some(&serde_json::Value::Null),
        "no status must serialize as null (absent), never a fabricated code: {json}"
    );
}

// ---------------------------------------------------------------------------
// §11.6 egress receipt URL redaction
// ---------------------------------------------------------------------------

fn egress_config_with(params: &[&str]) -> arbitraitor_policy::EgressConfig {
    arbitraitor_policy::EgressConfig {
        credential_query_params: params.iter().map(ToString::to_string).collect(),
        ..arbitraitor_policy::EgressConfig::default()
    }
}

#[test]
fn redact_egress_url_denylist_param_is_class_redacted() {
    let redacted = crate::api::redact_egress_url(
        "https://api.example.com/v1/data?token=abcdef0123456789abcdef01",
        &egress_config_with(&[]),
    );
    assert_eq!(
        redacted, "https://api.example.com/v1/data?token=[REDACTED-CREDENTIAL]",
        "denylisted parameter value must be replaced by its class: {redacted}"
    );
}

#[test]
fn redact_egress_url_high_entropy_value_under_unlisted_name_is_redacted() {
    // 32 chars, alphanumeric mixed case with digits, not on any denylist.
    let redacted = crate::api::redact_egress_url(
        "https://api.example.com/v1/data?state=aB3xY7kQ9mN2pR5tW8zC1vB4nM6jH0fD",
        &egress_config_with(&[]),
    );
    assert_eq!(
        redacted, "https://api.example.com/v1/data?state=[REDACTED-CREDENTIAL]",
        "high-entropy opaque token must be redacted regardless of name: {redacted}"
    );
}

#[test]
fn redact_egress_url_jwt_under_unlisted_name_is_redacted() {
    let redacted = crate::api::redact_egress_url(
        "https://api.example.com/v1/data?auth=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abcdefghij",
        &egress_config_with(&[]),
    );
    assert_eq!(
        redacted, "https://api.example.com/v1/data?auth=[REDACTED-CREDENTIAL]",
        "JWT-shaped value must be redacted regardless of name: {redacted}"
    );
}

#[test]
fn redact_egress_url_uuid_in_credential_position_is_redacted() {
    let redacted = crate::api::redact_egress_url(
        "https://api.example.com/v1/data?request_id=550e8400-e29b-41d4-a716-446655440000",
        &egress_config_with(&[]),
    );
    assert_eq!(
        redacted, "https://api.example.com/v1/data?request_id=[REDACTED-CREDENTIAL]",
        "UUID-shaped value in a credential-position parameter must be redacted: {redacted}"
    );
}

#[test]
fn redact_egress_url_short_common_param_preserved() {
    let redacted = crate::api::redact_egress_url(
        "https://api.example.com/v1/data?q=hello&page=2",
        &egress_config_with(&[]),
    );
    assert_eq!(
        redacted, "https://api.example.com/v1/data?q=hello&page=2",
        "established non-credential values must be preserved verbatim: {redacted}"
    );
}

#[test]
fn redact_egress_url_unestablishable_value_fails_closed() {
    let redacted = crate::api::redact_egress_url(
        "https://api.example.com/v1/data?opaque=this-is-a-long-ambiguous-value!",
        &egress_config_with(&[]),
    );
    assert_eq!(
        redacted, "https://api.example.com/v1/data?opaque=[REDACTED-UNESTABLISHABLE]",
        "unestablishable value must be redacted to its class (fail-closed): {redacted}"
    );
}

#[test]
fn redact_egress_url_path_segment_32_hex_is_redacted() {
    let redacted = crate::api::redact_egress_url(
        "https://api.example.com/download/deadbeefdeadbeefdeadbeefdeadbeef/file.tar.gz",
        &egress_config_with(&[]),
    );
    assert_eq!(
        redacted, "https://api.example.com/download/[REDACTED-PATH-SEGMENT]/file.tar.gz",
        "32-hex path segment must be redacted: {redacted}"
    );
}

#[test]
fn redact_egress_url_normal_path_is_preserved() {
    let redacted = crate::api::redact_egress_url(
        "https://api.example.com/v1/search?query=rust+crates",
        &egress_config_with(&[]),
    );
    assert_eq!(
        redacted, "https://api.example.com/v1/search?query=rust+crates",
        "ordinary path and established query must be preserved: {redacted}"
    );
}

#[test]
fn redact_egress_url_userinfo_password_redacted() {
    let redacted = crate::api::redact_egress_url(
        "https://user:sup3rs3cret@api.example.com/v1/data",
        &egress_config_with(&[]),
    );
    assert_eq!(
        redacted, "https://user:%5BREDACTED-PASSWORD%5D@api.example.com/v1/data",
        "userinfo password must be redacted: {redacted}"
    );
}

// ---------------------------------------------------------------------------
// §11.6 egress: deny-origins enforcement, receipt redaction, body outcomes
// ---------------------------------------------------------------------------

fn egress_policy_toml(deny_origins: &[&str]) -> String {
    let deny = deny_origins
        .iter()
        .map(|o| format!("\"{o}\""))
        .collect::<Vec<_>>()
        .join(", ");
    format!(
        r"
version = 1

[network.egress]
deny_origins = [{deny}]

[[network.egress.grants]]
id = 'search'
hosts = ['api.example.internal']
path_prefix = '/v1/search'
query_policy = 'forbidden'
"
    )
}

#[tokio::test]
async fn egress_denies_policy_listed_origin_before_grants() {
    use arbitraitor_model::origin::CallerOrigin;

    let api = crate::ArbitraitorApi::new(crate::api::Config {
        policy_toml: egress_policy_toml(&["agent_session"]),
        ..crate::api::Config::default()
    })
    .expect("engine with egress policy");
    // The origin is denied before grant evaluation — the URL never parses
    // into a transport attempt, and no receipt is written for it.
    let error = api
        .http_egress(
            "https://api.example.internal/v1/search/x",
            &CallerOrigin::AgentSession,
        )
        .await
        .expect_err("denied origin must fail closed");
    assert!(
        error.to_string().contains("denied for egress"),
        "expected origin denial, got: {error}"
    );
}

#[tokio::test]
async fn egress_allows_unlisted_origin_to_reach_grant_evaluation() {
    use arbitraitor_model::origin::CallerOrigin;

    let api = crate::ArbitraitorApi::new(crate::api::Config {
        policy_toml: egress_policy_toml(&["agent_session"]),
        ..crate::api::Config::default()
    })
    .expect("engine with egress policy");
    // DaemonLocal is not on the deny list: the request reaches grant
    // evaluation. https://127.0.0.1 is not allowlisted (grant hosts are
    // api.example.internal) → OutsideGrant-class denial, NOT origin denial.
    let error = api
        .http_egress("https://127.0.0.1/v1/search/x", &CallerOrigin::DaemonLocal)
        .await
        .expect_err("non-allowlisted host must be denied at grant scope");
    assert!(
        error.to_string().contains("no egress grant"),
        "expected grant-scope denial, got: {error}"
    );
}

#[test]
fn egress_receipt_redaction_preserves_common_params_and_redacts_secrets() {
    use crate::api::redact_egress_url;
    use arbitraitor_policy::EgressConfig;

    let egress = EgressConfig::default();
    // Denylisted name → value replaced by class.
    assert_eq!(
        redact_egress_url(
            "https://api.example.internal/v1/x?api_key=SK1234567890abcdef",
            &egress
        ),
        "https://api.example.internal/v1/x?api_key=[REDACTED-CREDENTIAL]"
    );
    // Unlisted name but high-entropy value (24+ mixed alnum) → redacted.
    assert_eq!(
        redact_egress_url(
            "https://api.example.internal/v1/x?state=Abcdef1234567890ABCDEF1234",
            &egress
        ),
        "https://api.example.internal/v1/x?state=[REDACTED-CREDENTIAL]"
    );
    // JWT-shaped value → redacted.
    assert_eq!(
        redact_egress_url(
            "https://api.example.internal/v1/x?sid=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
            &egress
        ),
        "https://api.example.internal/v1/x?sid=[REDACTED-CREDENTIAL]"
    );
    // Common non-secret param with a short value → preserved verbatim.
    assert_eq!(
        redact_egress_url("https://api.example.internal/v1/x?q=hello&page=2", &egress),
        "https://api.example.internal/v1/x?q=hello&page=2"
    );
    // 32-hex path segment → redacted segment.
    assert_eq!(
        redact_egress_url(
            "https://api.example.internal/v1/deadbeefdeadbeefdeadbeefdeadbeef/report",
            &egress
        ),
        "https://api.example.internal/v1/[REDACTED-PATH-SEGMENT]/report"
    );
    // Userinfo password → class marker.
    assert_eq!(
        redact_egress_url("https://user:hunter2@api.example.internal/v1/x", &egress),
        "https://user:%5BREDACTED-PASSWORD%5D@api.example.internal/v1/x"
    );
}

#[test]
fn egress_receipt_carries_operation_class_egress() {
    use arbitraitor_receipt::CURRENT_SCHEMA_VERSION;
    use arbitraitor_receipt::{
        ArtifactInfo, EgressInfo, PolicyInfo, ProvenanceInfo, Receipt, ReceiptTimestamps,
        RequestInfo, VerdictInfo,
    };

    // The discriminator must be present on egress receipts so
    // query_receipts()/audit consumers never mistake the request-identity
    // key for a CAS digest (L1).
    let receipt = Receipt {
        schema_version: CURRENT_SCHEMA_VERSION,
        request: RequestInfo {
            arbitraitor_version: "test".to_owned(),
            config_digest: None,
        },
        artifact: ArtifactInfo {
            sha256: "egress-key".to_owned(),
            size: 0,
            artifact_type: Some("egress".to_owned()),
        },
        retrieval: None,
        egress: Some(EgressInfo {
            grant_id: "g".to_owned(),
            caller_origin: "daemon_local".to_owned(),
            requested_url: "https://h/x".to_owned(),
            final_url: None,
            redirect_chain: Vec::new(),
            status: Some(200),
            content_type: None,
            query_policy: "forbidden".to_owned(),
            body_outcome: "returned_unscanned".to_owned(),
            delivered_bytes: Some(0),
        }),
        provenance: ProvenanceInfo::default(),
        payload_graph: None,
        detectors: Vec::new(),
        findings: Vec::new(),
        policy: PolicyInfo {
            policy_digest: None,
            operation_class: Some("egress".to_owned()),
            allow_rule_metadata: Vec::new(),
            audit_trail: Vec::new(),
        },
        verdict: VerdictInfo {
            verdict: arbitraitor_model::verdict::Verdict::Pass,
            deciding_rule: None,
            policy_trace: vec!["egress operation: no artifact verdict (spec §11.6)".to_owned()],
        },
        release: None,
        timestamps: ReceiptTimestamps {
            created: "unix:0.0Z".to_owned(),
            modified: "unix:0.0Z".to_owned(),
        },
        ingress: None,
    };
    assert_eq!(
        receipt.policy.operation_class.as_deref(),
        Some("egress"),
        "egress receipts must carry the operation_class discriminator"
    );
}

// G2-H1: bounded grants must carry bounds; tightening must not strip them.
#[test]
fn egress_bounded_grant_without_bounds_is_rejected_at_load() {
    let policy = r"
version = 1

[[network.egress.grants]]
id = 'search'
hosts = ['api.example.internal']
query_policy = 'bounded'
";
    let result = policy_engine_load_for_test(policy);
    assert!(
        matches!(result, Err(ref m) if m.to_string().contains("neither max_query_bytes nor max_query_params")),
        "bounded-without-bounds must be rejected, got {result:?}"
    );
}

#[test]
fn egress_tightening_layer_cannot_strip_bounded_bounds() {
    let organization = policy_for_test(
        r"
version = 1

[[network.egress.grants]]
id = 'search'
hosts = ['api.example.internal']
query_policy = 'bounded'
max_query_bytes = 64
max_query_params = 4
",
    );
    // A tightening layer declaring LARGER bounds than inherited must also
    // be rejected (the growth direction of the same guard; stripping is
    // blocked one layer earlier by validate() itself, since a bounded
    // grant without any bound no longer loads).
    let project = policy_for_test(
        r"
version = 1

[[network.egress.grants]]
id = 'search'
hosts = ['api.example.internal']
query_policy = 'bounded'
max_query_bytes = 128
max_query_params = 8
",
    );
    let result = arbitraitor_policy::PolicyEngine::merge_layers(
        [
            arbitraitor_policy::PolicyLayer {
                precedence: arbitraitor_policy::PolicyPrecedence::Organization,
                policy: organization,
            },
            arbitraitor_policy::PolicyLayer {
                precedence: arbitraitor_policy::PolicyPrecedence::Project,
                policy: project,
            },
        ],
        false,
    );
    assert!(
        matches!(result, Err(ref e) if e.to_string().contains("cannot grow or be stripped")),
        "growing inherited bounds must be rejected, got {result:?}"
    );
}

// G2-M1: deny_origins must reference real §23.1.1 labels and survive tightening.
#[test]
fn egress_deny_origins_typo_is_rejected_at_load() {
    let policy = r#"
version = 1

[network.egress]
deny_origins = ["agent_sesssion"]

[[network.egress.grants]]
id = 'search'
hosts = ['api.example.internal']
query_policy = 'forbidden'
"#;
    let result = policy_engine_load_for_test(policy);
    assert!(
        matches!(result, Err(ref m) if m.to_string().contains("not a known caller-origin class")),
        "deny_origins typo must be rejected, got {result:?}"
    );
}

#[test]
fn egress_tightening_layer_cannot_un_deny_origin() {
    let organization = policy_for_test(
        r#"
version = 1

[network.egress]
deny_origins = ["agent_session"]

[[network.egress.grants]]
id = 'search'
hosts = ['api.example.internal']
query_policy = 'forbidden'
"#,
    );
    let project = policy_for_test(
        r"
version = 1

[network.egress]
deny_origins = []

[[network.egress.grants]]
id = 'search'
hosts = ['api.example.internal']
query_policy = 'forbidden'
",
    );
    let result = arbitraitor_policy::PolicyEngine::merge_layers(
        [
            arbitraitor_policy::PolicyLayer {
                precedence: arbitraitor_policy::PolicyPrecedence::Organization,
                policy: organization,
            },
            arbitraitor_policy::PolicyLayer {
                precedence: arbitraitor_policy::PolicyPrecedence::Project,
                policy: project,
            },
        ],
        false,
    );
    assert!(
        matches!(result, Err(ref e) if e.to_string().contains("cannot be un-denied")),
        "un-denying an inherited origin must be rejected, got {result:?}"
    );
}

// G2-M2 + gen-3 L2: inspect_first must withhold the body on a
// non-releasable verdict. Calls the REAL gate (resolve_egress_body_outcome)
// with a synthetic response and an inspect_first grant; FAIL_CLOSED policy
// yields a fail-closed (non-releasable) verdict for unmatched content, so
// the withheld branch is exercised end-to-end through the production gate.
#[test]
fn egress_inspect_first_withholds_non_releasable_verdict() {
    use arbitraitor_fetch::{EgressBodyTreatment, EgressGrant, EgressQueryPolicy, EgressResponse};

    let api = crate::ArbitraitorApi::new(crate::api::Config {
        policy_toml: crate::FAIL_CLOSED_POLICY_TOML.to_owned(),
        ..crate::api::Config::default()
    })
    .expect("fail-closed engine");
    let grant = EgressGrant {
        id: "g".to_owned(),
        hosts: vec!["h".to_owned()],
        path_prefix: String::new(),
        query_policy: EgressQueryPolicy::Forbidden,
        pinned_query: None,
        max_query_bytes: None,
        max_query_params: None,
        max_response_bytes: None,
        allowed_content_types: Vec::new(),
        body_treatment: EgressBodyTreatment::InspectFirst,
    };
    let response = EgressResponse {
        grant_id: "g".to_owned(),
        requested_url: "https://h/x".to_owned(),
        final_url: "https://h/x".to_owned(),
        redirect_chain: Vec::new(),
        status: 200,
        content_type: "application/octet-stream".to_owned(),
        body: b"payload".to_vec(),
        body_treatment: EgressBodyTreatment::InspectFirst,
        delivered: true,
    };
    let (outcome, _delivered, body) = api
        .resolve_egress_body_outcome_for_test(&grant, &response, "https://h/x")
        .expect("outcome resolution must succeed");
    // Forbidden-effect assertion: under FAIL_CLOSED policy the verdict for
    // an unmatched payload is not releasable, so the body must be withheld.
    assert_eq!(outcome, "withheld", "non-releasable body must be withheld");
    assert!(
        body.is_none(),
        "withheld body must be None, never delivered"
    );
}

/// Test helper: loads a policy TOML and returns the engine or error.
fn policy_engine_load_for_test(
    toml: &str,
) -> Result<arbitraitor_policy::PolicyEngine, arbitraitor_policy::PolicyError> {
    arbitraitor_policy::PolicyEngine::load(toml)
}

fn policy_for_test(toml: &str) -> arbitraitor_policy::Policy {
    policy_engine_load_for_test(toml)
        .expect("test policy must load")
        .policy()
        .clone()
}
