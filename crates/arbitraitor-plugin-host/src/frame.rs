//! Binary frame reader and writer for subprocess plugin messages.

#![forbid(unsafe_code)]

use std::io::{Read, Write};

use crate::error::ProtocolError;
use crate::protocol::ProtocolMessage;

/// Maximum JSON payload length accepted by the subprocess protocol.
pub const MAX_FRAME_SIZE_BYTES: u64 = 1024 * 1024;

const LENGTH_PREFIX_BYTES: usize = 4;

/// Reads length-prefixed JSON protocol messages from a byte stream.
pub struct FrameReader<R: Read> {
    reader: R,
    max_frame_size_bytes: u64,
}

impl<R: Read> FrameReader<R> {
    /// Creates a reader using the default 1 MiB frame limit.
    #[must_use]
    pub const fn new(reader: R) -> Self {
        Self {
            reader,
            max_frame_size_bytes: MAX_FRAME_SIZE_BYTES,
        }
    }

    /// Reads and validates one protocol message from the stream.
    ///
    /// # Errors
    ///
    /// Returns [`ProtocolError`] when the stream is truncated, the frame exceeds
    /// the size limit, the payload is not UTF-8 JSON, or the message version is
    /// unsupported.
    pub fn read_frame(&mut self) -> Result<ProtocolMessage, ProtocolError> {
        let mut prefix = [0_u8; LENGTH_PREFIX_BYTES];
        self.reader.read_exact(&mut prefix)?;

        let length = u64::from(u32::from_be_bytes(prefix));
        if length > self.max_frame_size_bytes {
            return Err(ProtocolError::FrameTooLarge {
                actual: length,
                max: self.max_frame_size_bytes,
            });
        }

        let mut payload = vec![
            0_u8;
            usize::try_from(length).map_err(|error| {
                ProtocolError::InvalidLengthPrefix(error.to_string())
            })?
        ];
        self.reader.read_exact(&mut payload)?;

        let json = String::from_utf8(payload)?;
        let message: ProtocolMessage = serde_json::from_str(&json)?;
        message.validate_version()?;
        Ok(message)
    }
}

/// Writes length-prefixed JSON protocol messages to a byte stream.
pub struct FrameWriter<W: Write> {
    writer: W,
    max_frame_size_bytes: u64,
}

impl<W: Write> FrameWriter<W> {
    /// Creates a writer using the default 1 MiB frame limit.
    #[must_use]
    pub const fn new(writer: W) -> Self {
        Self {
            writer,
            max_frame_size_bytes: MAX_FRAME_SIZE_BYTES,
        }
    }

    /// Serializes and writes one protocol message to the stream.
    ///
    /// # Errors
    ///
    /// Returns [`ProtocolError`] when serialization fails, the encoded frame is
    /// too large, the message version is unsupported, or the underlying stream
    /// returns an I/O error.
    pub fn write_frame(&mut self, msg: &ProtocolMessage) -> Result<(), ProtocolError> {
        msg.validate_version()?;
        let payload = serde_json::to_vec(msg)?;
        let payload_length = u64::try_from(payload.len())
            .map_err(|error| ProtocolError::InvalidLengthPrefix(error.to_string()))?;

        if payload_length > self.max_frame_size_bytes {
            return Err(ProtocolError::FrameTooLarge {
                actual: payload_length,
                max: self.max_frame_size_bytes,
            });
        }

        let prefix = u32::try_from(payload.len())
            .map_err(|error| ProtocolError::InvalidLengthPrefix(error.to_string()))?
            .to_be_bytes();
        self.writer.write_all(&prefix)?;
        self.writer.write_all(&payload)?;
        self.writer.flush()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::{FrameReader, FrameWriter, MAX_FRAME_SIZE_BYTES};
    use crate::error::ProtocolError;
    use crate::protocol::{MessageKind, ProtocolMessage};
    use serde_json::json;
    use std::io::Cursor;

    #[test]
    fn write_then_read_round_trips_message() -> Result<(), Box<dyn std::error::Error>> {
        let message = ProtocolMessage::new(MessageKind::HelloRequest, json!({ "host": "test" }));
        let mut stream = Vec::new();

        FrameWriter::new(&mut stream).write_frame(&message)?;
        let decoded = FrameReader::new(Cursor::new(stream)).read_frame()?;

        assert_eq!(decoded, message);
        Ok(())
    }

    #[test]
    fn writing_oversized_payload_returns_frame_too_large() {
        let large_payload = "x".repeat(usize::try_from(MAX_FRAME_SIZE_BYTES).unwrap_or(0));
        let message = ProtocolMessage::new(
            MessageKind::AnalyzeRequest,
            json!({
                "artifact": large_payload,
            }),
        );
        let mut stream = Vec::new();

        let result = FrameWriter::new(&mut stream).write_frame(&message);

        assert!(matches!(
            result,
            Err(ProtocolError::FrameTooLarge { actual, max })
                if actual > MAX_FRAME_SIZE_BYTES && max == MAX_FRAME_SIZE_BYTES
        ));
    }

    #[test]
    fn reading_oversized_length_returns_frame_too_large() {
        let length = u32::try_from(MAX_FRAME_SIZE_BYTES + 1).unwrap_or(u32::MAX);
        let stream = length.to_be_bytes().to_vec();

        let result = FrameReader::new(Cursor::new(stream)).read_frame();

        assert!(matches!(
            result,
            Err(ProtocolError::FrameTooLarge { actual, max })
                if actual == MAX_FRAME_SIZE_BYTES + 1 && max == MAX_FRAME_SIZE_BYTES
        ));
    }

    #[test]
    fn receiving_version_zero_returns_version_mismatch() -> Result<(), Box<dyn std::error::Error>> {
        let message = ProtocolMessage {
            version: 0,
            kind: MessageKind::HelloRequest,
            payload: json!({}),
        };
        let payload = serde_json::to_vec(&message)?;
        let mut stream = Vec::new();
        stream.extend_from_slice(&u32::try_from(payload.len())?.to_be_bytes());
        stream.extend_from_slice(&payload);

        let result = FrameReader::new(Cursor::new(stream)).read_frame();

        assert!(matches!(
            result,
            Err(ProtocolError::VersionMismatch {
                expected: 1,
                actual: 0
            })
        ));
        Ok(())
    }

    #[test]
    fn eof_mid_frame_returns_io_error() {
        let mut stream = 16_u32.to_be_bytes().to_vec();
        stream.extend_from_slice(br#"{"version""#);

        let result = FrameReader::new(Cursor::new(stream)).read_frame();

        assert!(matches!(result, Err(ProtocolError::Io(_))));
    }
}
