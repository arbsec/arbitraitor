//! Integration tests for [`HealthChecker`] and report serialization.

#![forbid(unsafe_code)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use super::{
    ComponentHealth, HealthChecker, HealthReport, HealthStatus, YaraRulesProbe,
    parse_cosign_version, parse_version_tuple,
};

fn unique_temp_dir(label: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    let path = std::env::temp_dir().join(format!(
        "arbitraitor-health-{label}-{}-{nanos}",
        std::process::id(),
    ));
    let _ = fs::remove_dir_all(&path);
    fs::create_dir_all(&path).expect("temp dir should be creatable");
    path
}

fn missing_path(label: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    std::env::temp_dir().join(format!(
        "arbitraitor-health-{label}-absent-{}-{nanos}",
        std::process::id(),
    ))
}

fn seed_object(root: &std::path::Path, shard: &str, name: &str, bytes: &[u8]) {
    let dir = root.join("objects").join(shard);
    fs::create_dir_all(&dir).unwrap();
    fs::write(dir.join(name), bytes).unwrap();
}

#[test]
fn healthy_report_when_store_exists() {
    let root = unique_temp_dir("healthy");
    seed_object(&root, "ab", "abcd1234", b"artifact bytes");

    let report = HealthChecker::new()
        .with_store(root.clone())
        .with_rule_pack("v2024.6".to_owned())
        .check();

    assert_eq!(report.overall, HealthStatus::Warn);
    let store = report.checks.get("store").expect("store check present");
    assert_eq!(store.status, HealthStatus::Pass);
    assert!(store.message.contains("1 objects"));
    let _ = fs::remove_dir_all(root);
}

#[test]
fn unhealthy_when_store_missing() {
    let root = missing_path("missing");

    let report = HealthChecker::new().with_store(root).check();

    assert_eq!(report.overall, HealthStatus::Fail);
    let store = report.checks.get("store").expect("store check present");
    assert_eq!(store.status, HealthStatus::Fail);
    assert!(store.message.contains("missing"));
}

#[test]
fn degraded_when_no_detectors() {
    let root = unique_temp_dir("no-detectors");
    let report = HealthChecker::new().with_store(root.clone()).check();

    assert_eq!(report.overall, HealthStatus::Warn);
    let detectors = report
        .checks
        .get("detectors")
        .expect("detectors check present");
    assert_eq!(detectors.status, HealthStatus::Warn);
    let _ = fs::remove_dir_all(root);
}

#[test]
fn degraded_when_store_is_empty() {
    let root = unique_temp_dir("empty-store");
    fs::create_dir_all(root.join("objects").join("ab")).unwrap();

    let report = HealthChecker::new().with_store(root.clone()).check();

    let store = report.checks.get("store").expect("store check present");
    assert_eq!(store.status, HealthStatus::Warn);
    assert!(store.message.contains("zero objects"));
    let _ = fs::remove_dir_all(root);
}

#[test]
fn json_report_serializes() -> Result<(), Box<dyn std::error::Error>> {
    let report = HealthChecker::new()
        .with_rule_pack("v2024.6".to_owned())
        .check();

    let encoded = serde_json::to_string(&report)?;
    let decoded: HealthReport = serde_json::from_str(&encoded)?;

    assert_eq!(decoded.version, report.version);
    assert_eq!(decoded.overall, report.overall);
    assert_eq!(decoded.checks.len(), report.checks.len());
    assert!(decoded.checks.contains_key("store"));
    assert!(decoded.checks.contains_key("detectors"));
    assert!(decoded.checks.contains_key("version"));
    assert_eq!(decoded.checks["version"].status, HealthStatus::Pass);
    Ok(())
}

#[test]
fn status_worst_is_ordered() {
    assert_eq!(
        HealthStatus::Pass.worst(HealthStatus::Warn),
        HealthStatus::Warn,
    );
    assert_eq!(
        HealthStatus::Warn.worst(HealthStatus::Pass),
        HealthStatus::Warn,
    );
    assert_eq!(
        HealthStatus::Fail.worst(HealthStatus::Pass),
        HealthStatus::Fail,
    );
    assert_eq!(
        HealthStatus::Pass.worst(HealthStatus::Pass),
        HealthStatus::Pass,
    );
}

#[test]
fn version_check_is_always_healthy() {
    let report = HealthChecker::new().check();
    let version = report.checks.get("version").expect("version check present");
    assert_eq!(version.status, HealthStatus::Pass);
    assert!(version.message.starts_with("arbitraitor v"));
}

#[test]
fn component_health_with_details_attaches_payload() {
    let health = ComponentHealth::new(HealthStatus::Pass, "ok")
        .with_details(serde_json::json!({"count": 42}));
    let details = health.details.expect("details should be attached");
    assert_eq!(details["count"], 42);
}

#[test]
fn detector_versions_reported_in_message() {
    let report = HealthChecker::new()
        .with_detector_versions(vec!["detector-a v1.0".to_owned()])
        .check();
    let detectors = report
        .checks
        .get("detectors")
        .expect("detectors check present");
    assert_eq!(detectors.status, HealthStatus::Pass);
    assert!(detectors.message.contains("detector-a v1.0"));
}

#[test]
fn policy_validity_reports_pass_and_fail() {
    let root = unique_temp_dir("policy");
    let policy = root.join("policy.toml");
    fs::write(&policy, "version = 1\n").unwrap();

    let result = HealthChecker::new()
        .with_policy_file(policy)
        .check_policy_validity();

    assert_eq!(result.status, HealthStatus::Pass);
    fs::write(root.join("bad.toml"), "version = 2").unwrap();
    let bad = HealthChecker::new()
        .with_policy_file(root.join("bad.toml"))
        .check_policy_validity();
    assert_eq!(bad.status, HealthStatus::Fail);
    let _ = fs::remove_dir_all(root);
}

#[test]
fn yara_rules_report_parse_result() {
    let root = unique_temp_dir("yara");
    fs::write(root.join("rule.yar"), "rule ok { condition: true }").unwrap();

    let result = HealthChecker::new()
        .with_yara_rules(YaraRulesProbe::parsed(root.clone(), vec!["v1".to_owned()]))
        .check_yara_rules();

    assert_eq!(result.status, HealthStatus::Pass);
    let failed = HealthChecker::new()
        .with_yara_rules(YaraRulesProbe::failed(root.clone(), "syntax"))
        .check_yara_rules();
    assert_eq!(failed.status, HealthStatus::Fail);
    let _ = fs::remove_dir_all(root);
}

#[test]
fn configured_key_checks_require_non_empty_files() {
    let root = unique_temp_dir("keys");
    let key = root.join("key.pub");
    fs::write(&key, b"public-key").unwrap();

    assert_eq!(
        HealthChecker::new()
            .with_update_trust_root(key.clone())
            .check_update_trust_root()
            .status,
        HealthStatus::Pass,
    );
    assert_eq!(
        HealthChecker::new()
            .with_receipt_signing_key(key)
            .check_receipt_signing_key()
            .status,
        HealthStatus::Pass,
    );
    let _ = fs::remove_dir_all(root);
}

#[test]
fn plugin_checks_cover_manifests_and_protocol() {
    let root = unique_temp_dir("plugins");
    let plugin = root.join("demo");
    fs::create_dir_all(&plugin).unwrap();
    fs::write(plugin.join("manifest.toml"), "protocol_version = 1\n").unwrap();

    let checker = HealthChecker::new().with_plugin_dir(root.clone());

    assert_eq!(checker.check_plugin_manifests().status, HealthStatus::Pass);
    assert_eq!(checker.check_plugin_protocol().status, HealthStatus::Pass);
    fs::write(plugin.join("manifest.toml"), "protocol_version = 99\n").unwrap();
    assert_eq!(checker.check_plugin_protocol().status, HealthStatus::Fail);
    let _ = fs::remove_dir_all(root);
}

#[test]
fn feed_signature_and_scanner_freshness_checks_pass_for_readable_files() {
    let root = unique_temp_dir("feeds");
    let sig = root.join("feed.sig");
    fs::write(&sig, b"signature").unwrap();

    let checker = HealthChecker::new()
        .with_feed_signature_path(sig.clone())
        .with_scanner_signature_path(sig);

    assert_eq!(checker.check_feed_signatures().status, HealthStatus::Pass);
    assert_eq!(checker.check_scanner_freshness().status, HealthStatus::Pass);
    let _ = fs::remove_dir_all(root);
}

#[test]
fn remaining_doctor_checks_return_typed_statuses() {
    let checker = HealthChecker::new();
    assert!(matches!(
        checker.check_av_adapters().status,
        HealthStatus::Pass | HealthStatus::Warn
    ));
    assert!(matches!(
        checker.check_sandbox_adapters().status,
        HealthStatus::Pass | HealthStatus::Warn | HealthStatus::Skipped
    ));
    assert!(matches!(
        checker.check_wrapper_coverage().status,
        HealthStatus::Pass | HealthStatus::Warn | HealthStatus::Skipped
    ));
    assert_eq!(checker.check_clock_skew().status, HealthStatus::Pass);
    assert!(matches!(
        checker.check_proxy_settings().status,
        HealthStatus::Pass | HealthStatus::Skipped
    ));
    assert_eq!(
        checker.check_shim_path_order().status,
        HealthStatus::Skipped
    );
}

#[test]
fn sigstore_version_check_returns_typed_status() {
    let checker = HealthChecker::new();
    let result = checker.check_sigstore_version();
    assert!(
        matches!(
            result.status,
            HealthStatus::Pass | HealthStatus::Fail | HealthStatus::Warn | HealthStatus::Skipped
        ),
        "sigstore_version check must return a valid status, got {:?}",
        result.status
    );
    assert_eq!(result.name, "sigstore_version");
}

#[test]
fn parse_cosign_version_handles_v2_gitversion_format() {
    let output = "N/A\nGitVersion: v2.6.2\nGitCommit: abc123\n";
    assert_eq!(parse_cosign_version(output), Some("2.6.2".to_owned()));
}

#[test]
fn parse_cosign_version_handles_v3_bare_format() {
    let output = "v3.0.5\n";
    assert_eq!(parse_cosign_version(output), Some("3.0.5".to_owned()));
}

#[test]
fn parse_cosign_version_returns_none_for_garbage() {
    assert_eq!(parse_cosign_version("not a version\n"), None);
    assert_eq!(parse_cosign_version(""), None);
}

#[test]
fn parse_version_tuple_parses_valid_versions() {
    assert_eq!(parse_version_tuple("3.0.5"), Some((3, 0, 5)));
    assert_eq!(parse_version_tuple("v2.6.2"), Some((2, 6, 2)));
}

#[test]
fn parse_version_tuple_rejects_invalid_versions() {
    assert_eq!(parse_version_tuple("3.0"), None);
    assert_eq!(parse_version_tuple("abc"), None);
    assert_eq!(parse_version_tuple(""), None);
}
