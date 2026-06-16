//! Assertion helpers for receipts, findings, and release invariants.

use serde_json::Value;

/// Asserts that a receipt-shaped JSON object contains well-typed required fields.
///
/// # Panics
///
/// Panics when any required receipt field is absent or malformed.
pub fn assert_receipt_valid(receipt: &Value) {
    let artifact_id = receipt.get("artifact_id").and_then(Value::as_str);
    assert!(
        artifact_id.is_some_and(|value| !value.is_empty()),
        "artifact_id must be a non-empty string"
    );

    let verdict = receipt.get("verdict").and_then(Value::as_str);
    assert!(
        verdict.is_some_and(is_valid_verdict),
        "verdict must be allow, deny, or quarantine"
    );

    let sha256 = receipt.get("sha256").and_then(Value::as_str);
    assert!(
        sha256.is_some_and(is_lowercase_sha256),
        "sha256 must be exactly 64 lowercase hexadecimal characters"
    );

    let timestamp = receipt.get("timestamp").and_then(Value::as_str);
    assert!(
        timestamp.is_some_and(is_rfc3339_timestamp),
        "timestamp must be a valid RFC 3339 string"
    );

    if let Some(findings) = receipt.get("findings") {
        assert!(
            findings.is_array(),
            "findings must be an array when present"
        );
    }
}

fn is_valid_verdict(value: &str) -> bool {
    value.eq_ignore_ascii_case("allow")
        || value.eq_ignore_ascii_case("deny")
        || value.eq_ignore_ascii_case("quarantine")
}

fn is_lowercase_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
}

fn is_rfc3339_timestamp(value: &str) -> bool {
    let bytes = value.as_bytes();
    if bytes.len() < 20 {
        return false;
    }

    let date_time_shape = bytes.get(4) == Some(&b'-')
        && bytes.get(7) == Some(&b'-')
        && bytes.get(10) == Some(&b'T')
        && bytes.get(13) == Some(&b':')
        && bytes.get(16) == Some(&b':')
        && bytes[..4].iter().all(u8::is_ascii_digit)
        && bytes[5..7].iter().all(u8::is_ascii_digit)
        && bytes[8..10].iter().all(u8::is_ascii_digit)
        && bytes[11..13].iter().all(u8::is_ascii_digit)
        && bytes[14..16].iter().all(u8::is_ascii_digit)
        && bytes[17..19].iter().all(u8::is_ascii_digit);
    if !date_time_shape {
        return false;
    }

    let Some(year) = four_digits(bytes, 0) else {
        return false;
    };
    let Some(month) = two_digits(bytes, 5) else {
        return false;
    };
    let Some(day) = two_digits(bytes, 8) else {
        return false;
    };
    let Some(hour) = two_digits(bytes, 11) else {
        return false;
    };
    let Some(minute) = two_digits(bytes, 14) else {
        return false;
    };
    let Some(second) = two_digits(bytes, 17) else {
        return false;
    };
    if !(1..=12).contains(&month)
        || day == 0
        || day > days_in_month(year, month)
        || hour > 23
        || minute > 59
        || second > 59
    {
        return false;
    }

    let mut suffix_index = 19;
    if bytes.get(suffix_index) == Some(&b'.') {
        suffix_index += 1;
        let fraction_start = suffix_index;
        while bytes.get(suffix_index).is_some_and(u8::is_ascii_digit) {
            suffix_index += 1;
        }
        if suffix_index == fraction_start {
            return false;
        }
    }

    if matches!(bytes.get(suffix_index), Some(b'Z')) {
        return suffix_index + 1 == bytes.len();
    }

    if !matches!(bytes.get(suffix_index), Some(b'+' | b'-'))
        || suffix_index + 6 != bytes.len()
        || bytes.get(suffix_index + 3) != Some(&b':')
    {
        return false;
    }

    let Some(offset_hour) = two_digits(bytes, suffix_index + 1) else {
        return false;
    };
    let Some(offset_minute) = two_digits(bytes, suffix_index + 4) else {
        return false;
    };
    offset_hour <= 23 && offset_minute <= 59
}

fn four_digits(bytes: &[u8], start: usize) -> Option<u16> {
    let thousands = u16::from(*bytes.get(start)?).checked_sub(u16::from(b'0'))?;
    let hundreds = u16::from(*bytes.get(start + 1)?).checked_sub(u16::from(b'0'))?;
    let tens = u16::from(*bytes.get(start + 2)?).checked_sub(u16::from(b'0'))?;
    let ones = u16::from(*bytes.get(start + 3)?).checked_sub(u16::from(b'0'))?;
    if thousands > 9 || hundreds > 9 || tens > 9 || ones > 9 {
        return None;
    }
    Some(thousands * 1_000 + hundreds * 100 + tens * 10 + ones)
}

fn two_digits(bytes: &[u8], start: usize) -> Option<u8> {
    let tens = (*bytes.get(start)?).checked_sub(b'0')?;
    let ones = (*bytes.get(start + 1)?).checked_sub(b'0')?;
    if tens > 9 || ones > 9 {
        return None;
    }
    Some(tens * 10 + ones)
}

fn days_in_month(year: u16, month: u8) -> u8 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if is_leap_year(year) => 29,
        2 => 28,
        _ => 0,
    }
}

fn is_leap_year(year: u16) -> bool {
    (year.is_multiple_of(4) && !year.is_multiple_of(100)) || year.is_multiple_of(400)
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

/// Asserts that no release transition occurs before an allow verdict transition.
///
/// # Panics
///
/// Panics when a `release` transition appears before `verdict:allow`, or when the verdict
/// immediately preceding the first release is not `verdict:allow`.
pub fn assert_no_release_before_verdict(transitions: &[&str]) {
    let mut preceding_verdict = None;
    for transition in transitions {
        if transition.starts_with("verdict:") {
            preceding_verdict = Some(*transition);
        }
        if *transition == "release" {
            assert_eq!(
                preceding_verdict,
                Some("verdict:allow"),
                "release transition must be immediately preceded by verdict:allow"
            );
            return;
        }
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
    fn receipt_valid_accepts_well_typed_receipt_and_rejects_missing_fields() {
        let valid = json!({
            "artifact_id": "artifact-1",
            "verdict": "allow",
            "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "timestamp": "2026-06-16T12:34:56Z",
            "findings": []
        });
        assert_receipt_valid(&valid);

        let invalid = json!({ "artifact_id": "artifact-1" });
        assert!(catch_unwind(|| assert_receipt_valid(&invalid)).is_err());
    }

    #[test]
    fn receipt_valid_rejects_malformed_receipt_fields() {
        let valid = json!({
            "artifact_id": "artifact-1",
            "verdict": "ALLOW",
            "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "timestamp": "2026-06-16T12:34:56+00:00",
            "findings": []
        });
        assert_receipt_valid(&valid);

        let invalid_cases = [
            json!({
                "artifact_id": "",
                "verdict": "allow",
                "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                "timestamp": "2026-06-16T12:34:56Z"
            }),
            json!({
                "artifact_id": "artifact-1",
                "verdict": "block",
                "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                "timestamp": "2026-06-16T12:34:56Z"
            }),
            json!({
                "artifact_id": "artifact-1",
                "verdict": "allow",
                "sha256": "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855",
                "timestamp": "2026-06-16T12:34:56Z"
            }),
            json!({
                "artifact_id": "artifact-1",
                "verdict": "allow",
                "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                "timestamp": "not-rfc3339"
            }),
            json!({
                "artifact_id": "artifact-1",
                "verdict": "allow",
                "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                "timestamp": "2026-13-16T12:34:56Z"
            }),
            json!({
                "artifact_id": "artifact-1",
                "verdict": "allow",
                "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                "timestamp": "2026-06-16T12:34:56Z",
                "findings": null
            }),
        ];

        for invalid in invalid_cases {
            assert!(catch_unwind(|| assert_receipt_valid(&invalid)).is_err());
        }
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
        assert_no_release_before_verdict(&["fetch", "scan", "verdict:allow", "release"]);
        assert!(
            catch_unwind(|| assert_no_release_before_verdict(&[
                "fetch",
                "release",
                "verdict:allow"
            ]))
            .is_err()
        );
        assert!(
            catch_unwind(|| assert_no_release_before_verdict(&[
                "fetch",
                "verdict:deny",
                "release"
            ]))
            .is_err()
        );
    }
}
