//! Optional `ShellCheck` subprocess adapter.

use std::io::{self, Read, Write};
use std::process::{Child, ChildStdout, Command, Stdio};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use thiserror::Error;

const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);
const POLL_INTERVAL: Duration = Duration::from_millis(25);
const MAX_OUTPUT_BYTES: usize = 4 * 1024 * 1024;
const MAX_OUTPUT_READ_BYTES: u64 = 4 * 1024 * 1024 + 1;

/// A normalized advisory emitted by `ShellCheck`.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ShellCheckFinding {
    /// Stable `ShellCheck` rule identifier, such as `SC2086`.
    pub code: String,
    /// One-based source line.
    pub line: usize,
    /// One-based source column.
    pub column: usize,
    /// `ShellCheck` severity level.
    pub level: String,
    /// Human-readable diagnostic.
    pub message: String,
}

/// Errors produced while invoking or decoding `ShellCheck`.
#[derive(Debug, Error)]
pub enum ShellCheckError {
    /// The `shellcheck` executable was not found on `PATH`.
    #[error("shellcheck binary not found on PATH")]
    NotFound,
    /// The subprocess exceeded the adapter's execution deadline.
    #[error("shellcheck subprocess timed out")]
    Timeout,
    /// The subprocess output was not valid bounded `ShellCheck` JSON.
    #[error("invalid shellcheck output: {0}")]
    InvalidOutput(String),
    /// Process or pipe I/O failed.
    #[error("shellcheck I/O error: {0}")]
    IoError(#[from] io::Error),
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ShellCheckOutputFinding {
    line: usize,
    column: usize,
    level: String,
    code: u32,
    message: String,
}

impl From<ShellCheckOutputFinding> for ShellCheckFinding {
    fn from(value: ShellCheckOutputFinding) -> Self {
        Self {
            code: format!("SC{}", value.code),
            line: value.line,
            column: value.column,
            level: value.level,
            message: value.message,
        }
    }
}

/// Runs the optional `shellcheck` binary against Bash-compatible source.
///
/// The source is sent over stdin and diagnostics are parsed from bounded JSON
/// output. A missing binary remains an advisory capability failure rather than
/// a panic or hard installation requirement.
///
/// # Errors
///
/// Returns [`ShellCheckError::NotFound`] when `shellcheck` is absent,
/// [`ShellCheckError::Timeout`] when it exceeds the execution deadline,
/// [`ShellCheckError::InvalidOutput`] for malformed or oversized output, and
/// [`ShellCheckError::IoError`] for process or pipe failures.
pub fn run_shellcheck(
    script_content: &str,
    shell: &str,
) -> Result<Vec<ShellCheckFinding>, ShellCheckError> {
    let mut command = Command::new("shellcheck");
    command
        .arg("--format=json")
        .arg(format!("--shell={shell}"))
        .arg("-");
    run_shellcheck_command(command, script_content, DEFAULT_TIMEOUT)
}

fn run_shellcheck_command(
    mut command: Command,
    script_content: &str,
    timeout: Duration,
) -> Result<Vec<ShellCheckFinding>, ShellCheckError> {
    command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    let mut child = command.spawn().map_err(|error| match error.kind() {
        io::ErrorKind::NotFound => ShellCheckError::NotFound,
        _ => ShellCheckError::IoError(error),
    })?;

    let Some(stdin) = child.stdin.take() else {
        terminate_child(&mut child);
        return Err(ShellCheckError::IoError(io::Error::other(
            "shellcheck stdin pipe was unavailable",
        )));
    };
    let Some(stdout) = child.stdout.take() else {
        terminate_child(&mut child);
        return Err(ShellCheckError::IoError(io::Error::other(
            "shellcheck stdout pipe was unavailable",
        )));
    };

    let output = std::thread::scope(|scope| -> Result<Vec<u8>, ShellCheckError> {
        let writer = scope.spawn(move || {
            let mut stdin = stdin;
            stdin.write_all(script_content.as_bytes())
        });
        let reader = scope.spawn(move || read_bounded_output(stdout));
        let wait_result = wait_for_child(&mut child, timeout);
        let writer_result = writer
            .join()
            .map_err(|_| io::Error::other("shellcheck stdin writer thread panicked"));
        let reader_result = reader
            .join()
            .map_err(|_| io::Error::other("shellcheck stdout reader thread panicked"));

        wait_result?;
        writer_result??;
        Ok(reader_result??)
    })?;

    if output.len() > MAX_OUTPUT_BYTES {
        return Err(ShellCheckError::InvalidOutput(format!(
            "output exceeded {MAX_OUTPUT_BYTES} bytes"
        )));
    }
    parse_shellcheck_output(&output)
}

fn read_bounded_output(stdout: ChildStdout) -> io::Result<Vec<u8>> {
    let mut output = Vec::new();
    stdout
        .take(MAX_OUTPUT_READ_BYTES)
        .read_to_end(&mut output)?;
    Ok(output)
}

fn wait_for_child(child: &mut Child, timeout: Duration) -> Result<(), ShellCheckError> {
    let deadline = Instant::now().checked_add(timeout).ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidInput, "timeout exceeds Instant range")
    })?;
    loop {
        match child.try_wait() {
            Ok(Some(_status)) => return Ok(()),
            Ok(None) if Instant::now() >= deadline => {
                terminate_child(child);
                return Err(ShellCheckError::Timeout);
            }
            Ok(None) => {
                let remaining = deadline.saturating_duration_since(Instant::now());
                std::thread::sleep(POLL_INTERVAL.min(remaining));
            }
            Err(error) => {
                terminate_child(child);
                return Err(ShellCheckError::IoError(error));
            }
        }
    }
}

fn terminate_child(child: &mut Child) {
    let _ = child.kill();
    let _ = child.wait();
}

fn parse_shellcheck_output(output: &[u8]) -> Result<Vec<ShellCheckFinding>, ShellCheckError> {
    serde_json::from_slice::<Vec<ShellCheckOutputFinding>>(output)
        .map(|findings| findings.into_iter().map(Into::into).collect())
        .map_err(|error| ShellCheckError::InvalidOutput(error.to_string()))
}

#[cfg(test)]
mod tests {
    use std::process::{Command, Stdio};
    use std::time::Duration;

    use super::{ShellCheckError, parse_shellcheck_output, run_shellcheck, run_shellcheck_command};

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    #[test]
    fn parses_shellcheck_json_into_normalized_findings() -> TestResult {
        // Given
        let output = br#"[{"file":"-","line":3,"endLine":3,"column":6,"endColumn":11,"level":"info","code":2086,"message":"Double quote to prevent globbing and word splitting."}]"#;

        // When
        let findings = parse_shellcheck_output(output)?;

        // Then
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].code, "SC2086");
        assert_eq!(findings[0].line, 3);
        assert_eq!(findings[0].column, 6);
        assert_eq!(findings[0].level, "info");
        assert_eq!(
            findings[0].message,
            "Double quote to prevent globbing and word splitting."
        );
        Ok(())
    }

    #[test]
    fn rejects_invalid_shellcheck_json() {
        // Given
        let output = b"not json";

        // When
        let result = parse_shellcheck_output(output);

        // Then
        assert!(matches!(result, Err(ShellCheckError::InvalidOutput(_))));
    }

    #[test]
    fn reports_not_found_for_missing_binary() {
        // Given
        let missing_binary = std::env::temp_dir().join("arbitraitor-shellcheck-missing-505");
        let command = Command::new(missing_binary);

        // When
        let result = run_shellcheck_command(command, "", Duration::from_millis(50));

        // Then
        assert!(matches!(result, Err(ShellCheckError::NotFound)));
    }

    #[cfg(unix)]
    #[test]
    fn reports_timeout_for_slow_subprocess() {
        // Given
        let mut command = Command::new("sh");
        command.arg("-c").arg("sleep 1");

        // When
        let result = run_shellcheck_command(command, "", Duration::from_millis(10));

        // Then
        assert!(matches!(result, Err(ShellCheckError::Timeout)));
    }

    #[test]
    fn subprocess_reports_unquoted_expansion_when_shellcheck_is_installed() -> TestResult {
        // Given
        if !shellcheck_available() {
            return Ok(());
        }
        let script = "#!/usr/bin/env bash\nname='hello world'\necho $name\n";

        // When
        let findings = run_shellcheck(script, "bash")?;

        // Then
        let finding = findings
            .iter()
            .find(|finding| finding.code == "SC2086")
            .ok_or("ShellCheck did not report SC2086")?;
        assert_eq!(finding.line, 3);
        assert!(finding.column > 0);
        assert_eq!(finding.level, "info");
        assert!(!finding.message.is_empty());
        Ok(())
    }

    fn shellcheck_available() -> bool {
        Command::new("shellcheck")
            .arg("--version")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .is_ok()
    }
}
