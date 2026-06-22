//! Protocol message helpers for subprocess plugin lifecycle calls.

#![forbid(unsafe_code)]

use arbitraitor_plugin_api::{
    CapabilitySet, PluginIdentity, PluginManifest, PluginTrustClass, PluginType,
};

use crate::protocol::MessageKind;

pub(super) fn expected_response_kind(kind: MessageKind) -> Option<MessageKind> {
    match kind {
        MessageKind::HelloRequest => Some(MessageKind::HelloResponse),
        MessageKind::InitRequest => Some(MessageKind::InitResponse),
        MessageKind::AnalyzeRequest => Some(MessageKind::AnalyzeResponse),
        MessageKind::TranslateRequest => Some(MessageKind::TranslateResponse),
        MessageKind::LookupRequest => Some(MessageKind::LookupResponse),
        MessageKind::VerifyRequest => Some(MessageKind::VerifyResponse),
        MessageKind::HelloResponse
        | MessageKind::InitResponse
        | MessageKind::AnalyzeResponse
        | MessageKind::TranslateResponse
        | MessageKind::LookupResponse
        | MessageKind::VerifyResponse
        | MessageKind::ShutdownRequest
        | MessageKind::ErrorResponse => None,
    }
}

pub(super) fn placeholder_manifest() -> PluginManifest {
    PluginManifest {
        identity: PluginIdentity {
            id: "plugin.pending-handshake".to_owned(),
            version: "0.0.0".to_owned(),
            trust_class: PluginTrustClass::CommunityUnreviewed,
        },
        capabilities: CapabilitySet::default(),
        plugin_type: PluginType::Detector,
        description: "pending handshake".to_owned(),
    }
}
