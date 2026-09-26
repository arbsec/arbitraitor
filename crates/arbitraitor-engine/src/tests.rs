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
