//! Versioned JSON message envelope for subprocess plugins.

#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::error::ProtocolError;

/// Current subprocess plugin protocol version.
pub const PROTOCOL_VERSION: u32 = 1;

/// Versioned protocol message exchanged over a framed subprocess channel.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProtocolMessage {
    /// Protocol version. The only currently supported value is [`PROTOCOL_VERSION`].
    pub version: u32,
    /// Message role within the request/response protocol.
    pub kind: MessageKind,
    /// Message-specific JSON payload.
    pub payload: Value,
}

impl ProtocolMessage {
    /// Creates a protocol-version-1 message.
    #[must_use]
    pub const fn new(kind: MessageKind, payload: Value) -> Self {
        Self {
            version: PROTOCOL_VERSION,
            kind,
            payload,
        }
    }

    /// Ensures this message uses the supported protocol version.
    ///
    /// # Errors
    ///
    /// Returns [`ProtocolError::VersionMismatch`] when the message version is not
    /// [`PROTOCOL_VERSION`].
    pub const fn validate_version(&self) -> Result<(), ProtocolError> {
        if self.version == PROTOCOL_VERSION {
            Ok(())
        } else {
            Err(ProtocolError::VersionMismatch {
                expected: PROTOCOL_VERSION,
                actual: self.version,
            })
        }
    }
}

/// Request and response message kinds supported by the subprocess protocol.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub enum MessageKind {
    /// Host asks a plugin to identify itself and declare protocol capabilities.
    HelloRequest,
    /// Plugin returns its identity, adapter type, and supported capabilities.
    HelloResponse,
    /// Host passes configuration and per-instance setup data.
    InitRequest,
    /// Plugin reports that initialization completed and it is ready for calls.
    InitResponse,
    /// Host asks a detector plugin to analyze immutable artifact bytes.
    AnalyzeRequest,
    /// Detector plugin returns structured findings.
    AnalyzeResponse,
    /// Host asks a wrapper plugin to translate command arguments.
    TranslateRequest,
    /// Wrapper plugin returns a normalized operation plan.
    TranslateResponse,
    /// Host asks an intelligence plugin to look up an indicator.
    LookupRequest,
    /// Intelligence plugin returns reputation or feed entries.
    LookupResponse,
    /// Host asks the plugin to exit; no response is expected.
    ShutdownRequest,
    /// Plugin reports a structured error for a prior request.
    ErrorResponse,
}

#[cfg(test)]
mod tests {
    use super::{MessageKind, PROTOCOL_VERSION, ProtocolMessage};
    use crate::error::ProtocolError;
    use serde_json::json;

    #[test]
    fn protocol_message_round_trips() -> Result<(), Box<dyn std::error::Error>> {
        let message = ProtocolMessage::new(MessageKind::HelloRequest, json!({ "host": "test" }));

        let encoded = serde_json::to_string(&message)?;
        let decoded: ProtocolMessage = serde_json::from_str(&encoded)?;

        assert_eq!(decoded, message);
        Ok(())
    }

    #[test]
    fn version_mismatch_is_rejected() {
        let message = ProtocolMessage {
            version: 0,
            kind: MessageKind::HelloRequest,
            payload: json!({}),
        };

        assert_eq!(
            message
                .validate_version()
                .map_err(|error| error.to_string()),
            Err(ProtocolError::VersionMismatch {
                expected: PROTOCOL_VERSION,
                actual: 0,
            }
            .to_string())
        );
    }

    #[test]
    fn every_message_kind_round_trips() -> Result<(), Box<dyn std::error::Error>> {
        let kinds = [
            MessageKind::HelloRequest,
            MessageKind::HelloResponse,
            MessageKind::InitRequest,
            MessageKind::InitResponse,
            MessageKind::AnalyzeRequest,
            MessageKind::AnalyzeResponse,
            MessageKind::TranslateRequest,
            MessageKind::TranslateResponse,
            MessageKind::LookupRequest,
            MessageKind::LookupResponse,
            MessageKind::ShutdownRequest,
            MessageKind::ErrorResponse,
        ];

        for kind in kinds {
            let message = ProtocolMessage::new(kind, json!({ "kind": format!("{kind:?}") }));
            let encoded = serde_json::to_string(&message)?;
            let decoded: ProtocolMessage = serde_json::from_str(&encoded)?;
            assert_eq!(decoded, message);
        }
        Ok(())
    }
}
