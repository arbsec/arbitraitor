//! Integration tests for [`InspectionCache`].

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::time::Duration;

use arbitraitor_daemon::api::{ArbitraitorApi, Config, InspectionResult};
use arbitraitor_daemon::cache::InspectionCache;

/// Builds a real inspection result through the engine so the cache is
/// exercised with the same values production code stores.
fn sample_result(label: &str) -> InspectionResult {
    let root = std::env::temp_dir().join(format!(
        "arb-daemon-cache-{label}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos())
    ));
    let script = root.join("sample.sh");
    std::fs::create_dir_all(&root).unwrap();
    std::fs::write(&script, b"#!/bin/sh\necho cache-sample\n").unwrap();
    let api = ArbitraitorApi::new(Config {
        store_path: root.join("cas"),
        receipts_path: root.join("receipts"),
        ..Config::default()
    })
    .unwrap();
    let result = api
        .scan_path(&script, arbitraitor_engine::DEFAULT_SCAN_MAX_BYTES)
        .unwrap();
    std::fs::remove_dir_all(&root).ok();
    result
}

#[test]
fn cache_returns_hit() {
    let cache = InspectionCache::new(Duration::from_mins(1));
    let sample = sample_result("hit");
    cache.put("http://example.com/artifact", sample.clone());

    let result = cache.get("http://example.com/artifact");

    assert_eq!(
        result.as_ref().map(|r| r.sha256.as_str()),
        Some(sample.sha256.as_str())
    );
}

#[test]
fn cache_expires_after_ttl() {
    let cache = InspectionCache::new(Duration::from_millis(1));
    cache.put("http://example.com/expired", sample_result("expired"));

    std::thread::sleep(Duration::from_millis(10));

    assert!(cache.get("http://example.com/expired").is_none());
}
