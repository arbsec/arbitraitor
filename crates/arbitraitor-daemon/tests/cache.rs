//! Integration tests for [`InspectionCache`].

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::PathBuf;
use std::time::Duration;

use arbitraitor_daemon::api::InspectionResult;
use arbitraitor_daemon::cache::InspectionCache;
use arbitraitor_model::verdict::Verdict;

fn sample_result(sha256: &str) -> InspectionResult {
    InspectionResult {
        sha256: sha256.to_owned(),
        size_bytes: 42,
        content_type: Some("text/plain".to_owned()),
        verdict: Verdict::Pass,
        findings: Vec::new(),
        receipt_path: Some(PathBuf::from("/tmp/receipt.json")),
    }
}

#[test]
fn cache_returns_hit() {
    let cache = InspectionCache::new(Duration::from_mins(1));
    cache.put("http://example.com/artifact", sample_result("abc123"));

    let result = cache.get("http://example.com/artifact");

    assert_eq!(result.as_ref().map(|r| r.sha256.as_str()), Some("abc123"));
}

#[test]
fn cache_expires_after_ttl() {
    let cache = InspectionCache::new(Duration::from_millis(1));
    cache.put("http://example.com/expired", sample_result("expired123"));

    std::thread::sleep(Duration::from_millis(10));

    assert!(cache.get("http://example.com/expired").is_none());
}
