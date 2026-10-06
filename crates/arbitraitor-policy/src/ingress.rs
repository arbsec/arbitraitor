//! Ingress-envelope authentication (ADR: capability request #752).
//!
//! Consume-side authentication for inbound event envelopes, per
//! arbsec/orchestraitor spec §9.47: the embedder's transport endpoint
//! implements transport ONLY — relay-credential validation and the
//! per-envelope accept/deny decision live HERE, in Arbitraitor. The
//! embedder never makes an independent trust decision.
//!
//! Contract:
//! - The relay credential is resolved by the embedder through its secret-URI
//!   resolver and handed over as [`secrecy::SecretString`]; it is never
//!   returned, logged, or surfaced in errors.
//! - Validation is constant-time ([`subtle::ConstantTimeEq`]) to resist
//!   timing oracles.
//! - The tailnet node identity supplied by the embedder is defense-in-depth
//!   INPUT to the decision, never a sole authentication factor.
//! - Every decision returns an [`IngressDecision`] carrying the
//!   [`IngressReceipt`] needed for the embedder's §9.17 audit store.

use secrecy::ExposeSecret;
use subtle::ConstantTimeEq;

use crate::context::IngressContext;

/// The outcome of authenticating one inbound event envelope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IngressDecision {
    /// The envelope is authenticated; delivery may proceed into the
    /// embedder's ingress queue.
    Accepted(IngressReceipt),
    /// Authentication failed. `reason` is a static, log-safe code — it
    /// carries no credential material, envelope content, or node identity.
    Denied {
        /// Static refusal code for logs and metrics.
        reason: IngressDenyReason,
    },
}

/// Static, log-safe refusal codes (never envelope content).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IngressDenyReason {
    /// The presented credential did not match the configured relay
    /// credential.
    CredentialMismatch,
    /// The envelope's delivery key was empty — a delivery identity is
    /// required for dedup and audit.
    MissingDeliveryKey,
    /// The envelope's event type was empty — routing needs it.
    MissingEventType,
    /// The envelope's repository was empty — the dedup key needs it.
    MissingRepository,
}

/// Audit record for one accepted delivery (embedder persists it in its
/// event/receipt store; orchestraitor §9.17).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IngressReceipt {
    /// The platform delivery identifier (webhook `X-GitHub-Delivery` GUID,
    /// or run id + attempt for the Actions push path). Dedup key input.
    pub delivery_id: String,
    /// Repository the envelope pertains to, as self-reported by the relay.
    pub repository: String,
    /// Event type, as self-reported by the relay.
    pub event_type: String,
    /// Tailnet node identity, when the transport could observe it.
    /// Defense-in-depth input recorded for audit; never a sole factor.
    pub node_identity: Option<String>,
}

impl IngressReceipt {
    /// Builds the receipt from the self-reported envelope metadata.
    #[must_use]
    pub fn from_context(context: &IngressContext) -> Self {
        Self {
            delivery_id: context.delivery_id.clone(),
            repository: context.repository.clone(),
            event_type: context.event_type.clone(),
            node_identity: context.node_identity.clone(),
        }
    }
}

/// Validates the relay credential in constant time.
///
/// Both sides are compared as bytes through [`subtle::ConstantTimeEq`];
/// the boolean result is converted with [`bool::from`] so early exits on
/// mismatch are impossible regardless of length differences (the length
/// gate leaks only the length, which is not secret).
#[must_use]
pub fn verify_relay_credential(
    presented: &secrecy::SecretString,
    configured: &secrecy::SecretString,
) -> bool {
    let presented = presented.expose_secret();
    let configured = configured.expose_secret();
    bool::from(presented.as_bytes().ct_eq(configured.as_bytes()))
}

/// Authenticates one inbound envelope: credential check, then minimal
/// required-content validation, then the receipt. The per-envelope
/// accept/deny decision is intentionally mechanical — content-level
/// security classification of the payload stays with the pipeline
/// (`sanitize_for_agent`), and the embedder's policy tuning enters through
/// [`IngressContext`] fields resolved in the policy engine.
///
/// `node_identity` is defense-in-depth input recorded in the receipt; this
/// function never accepts or rejects on it alone.
#[must_use]
pub fn authenticate_envelope(
    presented_credential: &secrecy::SecretString,
    configured_credential: &secrecy::SecretString,
    context: &IngressContext,
) -> IngressDecision {
    if !verify_relay_credential(presented_credential, configured_credential) {
        return IngressDecision::Denied {
            reason: IngressDenyReason::CredentialMismatch,
        };
    }
    if context.delivery_id.trim().is_empty() {
        return IngressDecision::Denied {
            reason: IngressDenyReason::MissingDeliveryKey,
        };
    }
    if context.event_type.trim().is_empty() {
        return IngressDecision::Denied {
            reason: IngressDenyReason::MissingEventType,
        };
    }
    if context.repository.trim().is_empty() {
        return IngressDecision::Denied {
            reason: IngressDenyReason::MissingRepository,
        };
    }
    IngressDecision::Accepted(IngressReceipt::from_context(context))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;

    fn secret(value: &str) -> secrecy::SecretString {
        secrecy::SecretString::from(value.to_owned())
    }

    fn context() -> IngressContext {
        IngressContext {
            event_type: "pull_request".to_owned(),
            repository: "arbsec/orchestraitor".to_owned(),
            head_sha: Some("abc".to_owned()),
            delivery_id: "delivery-1".to_owned(),
            run_id: None,
            attempt: None,
            node_identity: Some("node:relay-runner".to_owned()),
            payload_size: 0,
        }
    }

    #[test]
    fn valid_credential_and_complete_context_is_accepted() {
        let decision =
            authenticate_envelope(&secret("relay-key-1"), &secret("relay-key-1"), &context());
        match decision {
            IngressDecision::Accepted(receipt) => {
                assert_eq!(receipt.delivery_id, "delivery-1");
                assert_eq!(receipt.event_type, "pull_request");
                assert_eq!(receipt.node_identity.as_deref(), Some("node:relay-runner"));
            }
            IngressDecision::Denied { reason } => {
                panic!("expected acceptance, got deny: {reason:?}")
            }
        }
    }

    #[test]
    fn credential_mismatch_denies_without_content_leak() {
        let decision = authenticate_envelope(&secret("wrong"), &secret("relay-key-1"), &context());
        assert_eq!(
            decision,
            IngressDecision::Denied {
                reason: IngressDenyReason::CredentialMismatch
            }
        );
    }

    #[test]
    fn empty_delivery_key_denies_even_with_valid_credential() {
        let mut envelope = context();
        envelope.delivery_id = "  ".to_owned();
        let decision = authenticate_envelope(&secret("k"), &secret("k"), &envelope);
        assert_eq!(
            decision,
            IngressDecision::Denied {
                reason: IngressDenyReason::MissingDeliveryKey
            }
        );
    }

    #[test]
    fn empty_event_type_denies_even_with_valid_credential() {
        let mut envelope = context();
        envelope.event_type = String::new();
        let decision = authenticate_envelope(&secret("k"), &secret("k"), &envelope);
        assert_eq!(
            decision,
            IngressDecision::Denied {
                reason: IngressDenyReason::MissingEventType
            }
        );
    }

    #[test]
    fn empty_repository_denies_even_with_valid_credential() {
        let mut envelope = context();
        envelope.repository = "  ".to_owned();
        let decision = authenticate_envelope(&secret("k"), &secret("k"), &envelope);
        assert_eq!(
            decision,
            IngressDecision::Denied {
                reason: IngressDenyReason::MissingRepository
            }
        );
    }

    #[test]
    fn node_identity_is_input_not_factor() {
        // No node identity at all: acceptance depends on the credential only.
        let mut envelope = context();
        envelope.node_identity = None;
        let decision = authenticate_envelope(&secret("k"), &secret("k"), &envelope);
        assert!(matches!(decision, IngressDecision::Accepted(_)));
    }
}
