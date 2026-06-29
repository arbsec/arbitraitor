//! Error types for package-manager adapter operations.

use thiserror::Error;

/// Errors produced by registry-based package-manager adapters.
#[derive(Debug, Error)]
pub enum AdapterManagerError {
    /// The wrapped tool is not installed or not on PATH.
    #[error("package manager not found: {tool}")]
    ToolNotFound {
        /// Tool name (e.g. "cargo", "npm").
        tool: String,
    },

    /// The lockfile could not be parsed.
    #[error("lockfile parse error ({format:?}): {message}")]
    LockfileParse {
        /// The lockfile format that failed to parse.
        format: crate::recipe::LockfileFormat,
        /// Human-readable parse error message.
        message: String,
    },

    /// A required adapter capability is not available.
    #[error("adapter capability unavailable: {message}")]
    CapabilityUnavailable {
        /// What capability was unavailable and why.
        message: String,
    },

    /// The adapter encountered an unsupported tool version.
    #[error("unsupported {tool} version: {version}")]
    UnsupportedToolVersion {
        /// Tool name.
        tool: String,
        /// Detected version string.
        version: String,
    },

    /// The wrapped tool exited with a non-zero status.
    #[error("{tool} exited with code {code}: {stderr}")]
    ToolFailed {
        /// Tool name.
        tool: String,
        /// Process exit code.
        code: i32,
        /// Captured stderr output (truncated).
        stderr: String,
    },
}
