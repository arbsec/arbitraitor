//! Integration tests for [`HealthChecker`] and report serialization.

#![forbid(unsafe_code)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use super::{ComponentHealth, HealthChecker, HealthReport, HealthStatus};

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

    assert_eq!(report.overall, HealthStatus::Healthy);
    let store = report.checks.get("store").expect("store check present");
    assert_eq!(store.status, HealthStatus::Healthy);
    assert!(store.message.contains("1 objects"));
    let _ = fs::remove_dir_all(root);
}

#[test]
fn unhealthy_when_store_missing() {
    let root = missing_path("missing");

    let report = HealthChecker::new().with_store(root).check();

    assert_eq!(report.overall, HealthStatus::Unhealthy);
    let store = report.checks.get("store").expect("store check present");
    assert_eq!(store.status, HealthStatus::Unhealthy);
    assert!(store.message.contains("missing"));
}

#[test]
fn degraded_when_no_detectors() {
    let root = unique_temp_dir("no-detectors");
    let report = HealthChecker::new().with_store(root.clone()).check();

    assert_eq!(report.overall, HealthStatus::Degraded);
    let detectors = report
        .checks
        .get("detectors")
        .expect("detectors check present");
    assert_eq!(detectors.status, HealthStatus::Degraded);
    let _ = fs::remove_dir_all(root);
}

#[test]
fn degraded_when_store_is_empty() {
    let root = unique_temp_dir("empty-store");
    fs::create_dir_all(root.join("objects").join("ab")).unwrap();

    let report = HealthChecker::new().with_store(root.clone()).check();

    let store = report.checks.get("store").expect("store check present");
    assert_eq!(store.status, HealthStatus::Degraded);
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
    assert_eq!(decoded.checks["version"].status, HealthStatus::Healthy);
    Ok(())
}

#[test]
fn status_worst_is_ordered() {
    assert_eq!(
        HealthStatus::Healthy.worst(HealthStatus::Degraded),
        HealthStatus::Degraded,
    );
    assert_eq!(
        HealthStatus::Degraded.worst(HealthStatus::Healthy),
        HealthStatus::Degraded,
    );
    assert_eq!(
        HealthStatus::Unhealthy.worst(HealthStatus::Healthy),
        HealthStatus::Unhealthy,
    );
    assert_eq!(
        HealthStatus::Healthy.worst(HealthStatus::Healthy),
        HealthStatus::Healthy,
    );
}

#[test]
fn version_check_is_always_healthy() {
    let report = HealthChecker::new().check();
    let version = report.checks.get("version").expect("version check present");
    assert_eq!(version.status, HealthStatus::Healthy);
    assert!(version.message.starts_with("arbitraitor v"));
}

#[test]
fn component_health_with_details_attaches_payload() {
    let health = ComponentHealth::new(HealthStatus::Healthy, "ok")
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
    assert_eq!(detectors.status, HealthStatus::Healthy);
    assert!(detectors.message.contains("detector-a v1.0"));
}
