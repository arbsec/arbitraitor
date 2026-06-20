//! Error types for the subprocess plugin protocol.

#![forbid(unsafe_code)]

/// Error returned while reading, writing, or validating protocol frames.
#[derive(Debug, thiserror::Error)]
pub enum ProtocolError {
    /// Frame payload length exceeded the configured maximum.
    #[error("frame exceeded maximum size: {actual} > {max}")]
    FrameTooLarge {
        /// Payload length observed on the stream or produced by serialization.
        actual: u64,
        /// Maximum permitted payload length.
        max: u64,
    },
    /// Message version did not match the supported protocol version.
    #[error("protocol version mismatch: expected {expected}, got {actual}")]
    VersionMismatch {
        /// Supported protocol version.
        expected: u32,
        /// Version found in the message envelope.
        actual: u32,
    },
    /// Length prefix could not be interpreted as a valid frame length.
    #[error("invalid frame length prefix: {0}")]
    InvalidLengthPrefix(String),
    /// JSON payload bytes were not valid UTF-8.
    #[error("frame payload is not valid UTF-8")]
    InvalidUtf8(#[from] std::string::FromUtf8Error),
    /// UTF-8 payload text was not valid JSON for a protocol message.
    #[error("frame payload is not valid JSON")]
    InvalidJson(#[from] serde_json::Error),
    /// Underlying stream returned an I/O error.
    #[error("i/o error on protocol stream: {0}")]
    Io(#[from] std::io::Error),
}

#[cfg(test)]
mod tests {
    use super::ProtocolError;

    #[test]
    fn frame_too_large_error_reports_bounds() {
        let error = ProtocolError::FrameTooLarge { actual: 2, max: 1 };

        assert_eq!(error.to_string(), "frame exceeded maximum size: 2 > 1");
    }
}
