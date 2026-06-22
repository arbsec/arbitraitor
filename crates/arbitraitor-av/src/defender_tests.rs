//! Unit tests for [`super::DefenderScanner`]. No test invokes the real
//! Defender binary; parsing is exercised against fixture strings and process
//! availability against stable system files such as `/bin/true`.

use super::*;
use std::error::Error;
use std::path::{Path, PathBuf};
use std::time::Duration;

/// On hosts without Defender installed, `detect()` finds no candidate binary.
///
/// CI runners are Linux/macOS without Defender for Endpoint, so detection is
/// expected to return `None` and degrade gracefully.
#[test]
fn detect_returns_none_when_not_installed() {
    assert!(DefenderScanner::detect().is_none());
}

/// A scanner with no configured binary cannot scan.
#[test]
fn scan_returns_error_when_binary_missing() {
    let scanner = DefenderScanner::new(PathBuf::new());
    let result = scanner.scan(Path::new("/nonexistent/artifact"));

    assert!(matches!(result, Err(DefenderError::BinaryNotFound(_))));
}

/// Exit code 0 with clean stdout reports no threat.
#[test]
fn parse_clean_output() -> Result<(), Box<dyn Error>> {
    let result = parse_scan_output(Some(0), "Scan finished.\nNo threats found.")?;

    assert!(!result.threat_found);
    assert!(result.threat_names.is_empty());
    assert_eq!(result.exit_code, Some(0));
    Ok(())
}

/// Exit code 2 with a threat line reports the threat and extracts its name.
#[test]
fn parse_threat_output() -> Result<(), Box<dyn Error>> {
    let stdout = "Scanning /tmp/artifact...\nThreat Name: Trojan:Win32/EICAR\nScan finished.";
    let result = parse_scan_output(Some(2), stdout)?;

    assert!(result.threat_found);
    assert_eq!(result.threat_names, vec!["Trojan:Win32/EICAR".to_owned()]);
    assert_eq!(result.exit_code, Some(2));
    Ok(())
}

/// An unexpected exit code is surfaced as an internal Defender error.
#[test]
fn parse_error_exit_code() {
    let result = parse_scan_output(Some(80), "platform error");

    assert!(matches!(result, Err(DefenderError::InternalError(_))));
}

/// A signal termination (no exit code) is also an internal error.
#[test]
fn parse_signal_termination() {
    let result = parse_scan_output(None, "");

    assert!(matches!(result, Err(DefenderError::InternalError(_))));
}

/// An empty or nonexistent binary path is reported as unavailable.
#[test]
fn is_available_returns_false_for_missing_binary() {
    let scanner = DefenderScanner::new(PathBuf::from("/definitely/not/defender"));

    assert!(!scanner.is_available());
}

/// A real, executable file on the host is reported as available.
#[test]
fn is_available_returns_true_for_existing_binary() {
    let exe = std::env::current_exe().unwrap_or_else(|_| PathBuf::from("/usr/bin/env"));
    let scanner = DefenderScanner::new(exe);

    assert!(scanner.is_available());
}

/// `with_timeout` stores the supplied duration on the scanner.
#[test]
fn with_timeout_sets_timeout() {
    let scanner =
        DefenderScanner::new(PathBuf::from("/usr/bin/env")).with_timeout(Duration::from_secs(42));

    assert_eq!(scanner.timeout, Duration::from_secs(42));
}

/// Multiple threat lines are all extracted, preserving order.
#[test]
fn extract_multiple_threat_names() {
    let stdout = "Threat Name: Virus:A\nThreat Name: Virus:B\nThreat: Virus:C\njunk line";
    let names = extract_threat_names(stdout);

    assert_eq!(
        names,
        vec![
            "Virus:A".to_owned(),
            "Virus:B".to_owned(),
            "Virus:C".to_owned()
        ]
    );
}
