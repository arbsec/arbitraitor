//! Microsoft Defender command-line adapter.
//!
//! See `.spec/` §18 for the antivirus integration specification. This adapter
//! is intentionally separate from the byte-oriented [`crate::AntivirusAdapter`]
//! trait: Defender's CLI scans a file *path* rather than an inbound byte stream,
//! so it exposes a path-oriented API and degrades gracefully when the binary is
//! absent (e.g. on CI runners).

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};
use thiserror::Error;

/// Default per-scan timeout. A single-file Defender scan is I/O-bound on the
/// signature database; two minutes is a generous ceiling for the CLI.
const DEFENDER_DEFAULT_TIMEOUT: Duration = Duration::from_mins(2);
/// Polling interval while waiting for the Defender process to exit.
const POLL_INTERVAL: Duration = Duration::from_millis(50);
/// Defender reports threats by writing family names to stdout.
const THREAT_LINE_PREFIXES: &[&str] = &["Threat Name:", "Threat:"];

/// Errors produced by [`DefenderScanner`].
#[derive(Debug, Error)]
pub enum DefenderError {
    /// The Defender binary could not be found at the configured path.
    #[error("Defender binary not found at {0}")]
    BinaryNotFound(PathBuf),
    /// The scan did not complete within the configured timeout.
    #[error("Defender scan timed out after {0:?}")]
    Timeout(Duration),
    /// Spawning or waiting on the Defender process failed.
    #[error("Defender spawn failed: {0}")]
    Spawn(#[from] std::io::Error),
    /// Defender reported an unexpected, non-success exit code.
    #[error("Defender reported an internal error: {0}")]
    InternalError(String),
}

/// Verdict returned by a single Defender file scan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScanResult {
    /// Whether Defender reported at least one threat for the scanned file.
    pub threat_found: bool,
    /// Malware family names extracted from Defender's stdout, if any.
    pub threat_names: Vec<String>,
    /// Raw process exit code reported by the Defender binary, when available.
    pub exit_code: Option<i32>,
}

/// Microsoft Defender command-line scanner adapter.
///
/// Invokes the platform-specific Defender binary (`mdatp` on Linux/macOS,
/// `MpCmdRun.exe` on Windows) to scan files. When Defender is not installed,
/// [`DefenderScanner::detect`] returns `None` and scans fail with
/// [`DefenderError::BinaryNotFound`], so CI environments without Defender
/// degrade gracefully instead of panicking.
pub struct DefenderScanner {
    binary_path: PathBuf,
    timeout: Duration,
}

impl DefenderScanner {
    /// Creates a scanner with an explicit Defender binary path.
    ///
    /// The binary is not validated until a scan runs; use
    /// [`Self::is_available`] to check presence eagerly.
    #[must_use]
    pub fn new(binary_path: PathBuf) -> Self {
        Self {
            binary_path,
            timeout: DEFENDER_DEFAULT_TIMEOUT,
        }
    }

    /// Attempts to locate the Defender binary on the current host.
    ///
    /// On Linux this probes the Microsoft Defender for Endpoint (`mdatp`)
    /// install paths; on macOS it probes the conventional `mdatp` location;
    /// on Windows it probes the built-in `MpCmdRun.exe` path. Returns `None`
    /// when no candidate is present so callers can skip Defender scanning.
    #[must_use]
    pub fn detect() -> Option<Self> {
        CANDIDATE_BINARIES
            .iter()
            .map(PathBuf::from)
            .find(|path| path.is_file())
            .map(Self::new)
    }

    /// Sets the per-scan timeout (builder style).
    #[must_use]
    pub fn with_timeout(self, timeout: Duration) -> Self {
        Self { timeout, ..self }
    }

    /// Returns `true` when the configured binary exists as a regular file.
    ///
    /// This does not invoke Defender; it only confirms the binary is present so
    /// callers can decide whether to attempt a scan.
    #[must_use]
    pub fn is_available(&self) -> bool {
        !self.binary_path.as_os_str().is_empty() && self.binary_path.is_file()
    }

    /// Scans a single file with Defender and returns the parsed verdict.
    ///
    /// The file path is passed as a discrete argv element (no shell), so
    /// hostile file names cannot inject arguments. `-DisableRemediation`
    /// (Windows) or the equivalent non-remediating mode keeps the artifact
    /// intact for downstream inspection.
    ///
    /// # Errors
    ///
    /// Returns [`DefenderError::BinaryNotFound`] when the binary is missing,
    /// [`DefenderError::Timeout`] when the scan exceeds the configured timeout,
    /// [`DefenderError::Spawn`] on process management failures, and
    /// [`DefenderError::InternalError`] for unexpected Defender exit codes.
    pub fn scan(&self, path: &Path) -> Result<ScanResult, DefenderError> {
        if !self.is_available() {
            return Err(DefenderError::BinaryNotFound(self.binary_path.clone()));
        }
        let mut child = build_command(&self.binary_path, path)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;
        let deadline = Instant::now() + self.timeout;
        loop {
            if child.try_wait()?.is_some() {
                break;
            }
            if Instant::now() >= deadline {
                let _ = child.kill();
                let _ = child.wait();
                return Err(DefenderError::Timeout(self.timeout));
            }
            std::thread::sleep(POLL_INTERVAL);
        }
        let output = child.wait_with_output()?;
        let stdout = String::from_utf8_lossy(&output.stdout);
        parse_scan_output(output.status.code(), &stdout)
    }
}

impl Default for DefenderScanner {
    fn default() -> Self {
        Self::detect().unwrap_or_else(|| Self::new(PathBuf::new()))
    }
}

/// Builds the platform-appropriate Defender scan command for `target`.
///
/// `MpCmdRun.exe` uses flag-style arguments; the `mdatp` CLI uses subcommands.
/// The binary is selected by file name so a non-default install path still
/// produces the correct invocation.
fn build_command(binary: &Path, target: &Path) -> Command {
    let mut command = Command::new(binary);
    if is_windows_defender(binary) {
        command
            .arg("-Scan")
            .arg("-ScanType")
            .arg("3")
            .arg("-File")
            .arg(target)
            .arg("-DisableRemediation");
    } else {
        command.arg("scan").arg("file").arg("--path").arg(target);
    }
    command
}

/// Returns `true` when `binary` is the Windows Defender command-line tool.
fn is_windows_defender(binary: &Path) -> bool {
    binary
        .file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| name.eq_ignore_ascii_case("MpCmdRun.exe"))
}

/// Parses Defender's exit code and stdout into a [`ScanResult`].
///
/// Exit code `0` is clean, `2` means a threat was found, and any other code is
/// treated as an internal Defender failure. Threat names are extracted from
/// stdout lines that begin with a known threat prefix.
fn parse_scan_output(exit_code: Option<i32>, stdout: &str) -> Result<ScanResult, DefenderError> {
    match exit_code {
        Some(0) => Ok(ScanResult {
            threat_found: false,
            threat_names: Vec::new(),
            exit_code,
        }),
        Some(2) => Ok(ScanResult {
            threat_found: true,
            threat_names: extract_threat_names(stdout),
            exit_code,
        }),
        Some(code) => Err(DefenderError::InternalError(format!(
            "defender exited with code {code}"
        ))),
        None => Err(DefenderError::InternalError(
            "defender terminated by signal".to_owned(),
        )),
    }
}

/// Extracts malware family names from Defender stdout.
///
/// Recognizes the `Threat Name:` and `Threat:` line prefixes used by the
/// `mdatp` and `MpCmdRun.exe` reporters. Empty names are discarded.
fn extract_threat_names(stdout: &str) -> Vec<String> {
    stdout
        .lines()
        .filter_map(|line| {
            let trimmed = line.trim();
            THREAT_LINE_PREFIXES
                .iter()
                .find_map(|prefix| trimmed.strip_prefix(prefix))
                .map(|rest| rest.trim().to_owned())
        })
        .filter(|name| !name.is_empty())
        .collect()
}

/// Platform-specific candidate Defender binary paths, most specific first.
#[cfg(target_os = "linux")]
const CANDIDATE_BINARIES: &[&str] = &[
    "/opt/microsoft/mdatp/bin/mdatp",
    "/usr/bin/mdatp",
    "/opt/microsoft/mdatp/bin/wdavcli",
    "/usr/bin/mdef",
];

/// Platform-specific candidate Defender binary paths on macOS.
#[cfg(target_os = "macos")]
const CANDIDATE_BINARIES: &[&str] = &["/usr/local/bin/mdatp", "/opt/microsoft/mdatp/bin/mdatp"];

/// Platform-specific candidate Defender binary paths on Windows.
#[cfg(target_os = "windows")]
const CANDIDATE_BINARIES: &[&str] = &[
    r"C:\Program Files\Windows Defender\MpCmdRun.exe",
    r"C:\Program Files (x86)\Windows Defender\MpCmdRun.exe",
];

/// No known Defender install paths on unsupported platforms.
#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
const CANDIDATE_BINARIES: &[&str] = &[];

#[cfg(test)]
#[path = "defender_tests.rs"]
mod tests;
