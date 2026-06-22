//! Error types for wrapper translators.

use thiserror::Error;

/// Errors produced while translating wget command-line arguments.
#[derive(Debug, Clone, Eq, PartialEq, Error)]
pub enum WrapperError {
    /// No URL was present on the wget command line.
    #[error("no URL provided")]
    MissingUrl,
    /// The flag is outside the supported wget subset.
    #[error("unsupported wget flag: {0}")]
    UnsupportedFlag(String),
    /// A flag value was missing or could not be parsed.
    #[error("invalid argument value for {flag}: {message}")]
    InvalidValue {
        /// The flag that received the bad value.
        flag: String,
        /// Safe diagnostic message describing the failure.
        message: String,
    },
}
