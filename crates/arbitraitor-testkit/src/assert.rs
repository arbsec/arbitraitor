//! Assertion helpers for receipts, findings, and release invariants.

use serde_json::Value;

/// Asserts that a receipt-shaped JSON object contains the minimal required fields.
///
/// # Panics
///
/// Panics when any required receipt field is absent.
pub fn assert_receipt_valid(receipt: &Value) {
    assert!(
        receipt.get("schema_version").is_some(),
        "missing schema_version"
    );
    assert!(receipt.get("artifact").is_some(), "missing artifact");
    assert!(receipt.get("verdict").is_some(), "missing verdict");
    assert!(receipt.get("findings").is_some(), "missing findings");
}

/// Asserts that a finding has the expected category string.
///
/// # Panics
///
/// Panics when the finding category is absent or does not match `expected`.
pub fn assert_finding_category(finding: &Value, expected: &str) {
    assert_eq!(
        finding.get("category").and_then(Value::as_str),
        Some(expected),
        "finding category mismatch"
    );
}

/// Asserts that a receipt has the expected verdict string.
///
/// # Panics
///
/// Panics when the receipt verdict is absent or does not match `expected`.
pub fn assert_verdict(receipt: &Value, expected: &str) {
    assert_eq!(
        receipt.get("verdict").and_then(Value::as_str),
        Some(expected),
        "receipt verdict mismatch"
    );
}

/// Asserts that no release transition occurs before a verdict transition.
///
/// # Panics
///
/// Panics when a `release` transition appears before a `verdict` transition.
pub fn assert_no_release_before_verdict(transitions: &[&str]) {
    let verdict_index = transitions
        .iter()
        .position(|transition| *transition == "verdict");
    let release_index = transitions
        .iter()
        .position(|transition| *transition == "release");

    if let Some(release) = release_index {
        assert!(
            verdict_index.is_some_and(|verdict| verdict < release),
            "release transition occurred before verdict"
        );
    }
}

#[cfg(test)]
mod tests {
    use std::panic::catch_unwind;

    use serde_json::json;

    use super::{
        assert_finding_category, assert_no_release_before_verdict, assert_receipt_valid,
        assert_verdict,
    };

    #[test]
    fn receipt_valid_accepts_minimal_receipt_and_rejects_missing_fields() {
        let valid = json!({
            "schema_version": "0.1.0",
            "artifact": {},
            "verdict": "allow",
            "findings": []
        });
        assert_receipt_valid(&valid);

        let invalid = json!({ "schema_version": "0.1.0" });
        assert!(catch_unwind(|| assert_receipt_valid(&invalid)).is_err());
    }

    #[test]
    fn finding_category_accepts_match_and_rejects_mismatch() {
        let finding = json!({ "category": "network" });
        assert_finding_category(&finding, "network");
        assert!(catch_unwind(|| assert_finding_category(&finding, "archive")).is_err());
    }

    #[test]
    fn verdict_accepts_match_and_rejects_mismatch() {
        let receipt = json!({ "verdict": "block" });
        assert_verdict(&receipt, "block");
        assert!(catch_unwind(|| assert_verdict(&receipt, "allow")).is_err());
    }

    #[test]
    fn release_order_accepts_safe_order_and_rejects_early_release() {
        assert_no_release_before_verdict(&["fetch", "scan", "verdict", "release"]);
        assert!(
            catch_unwind(|| assert_no_release_before_verdict(&["fetch", "release", "verdict"]))
                .is_err()
        );
    }
}
