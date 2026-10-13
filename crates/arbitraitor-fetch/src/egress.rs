//! Mediated HTTP egress (spec §11.6, ADR-0041).
//!
//! Egress is a second, sharply bounded operation class next to artifact
//! retrieval: a daemon-side GET whose bounded response body returns to the
//! calling tool without becoming an artifact. The grant type here is the
//! fetch-layer view of the policy grant (defined in `arbitraitor-policy`);
//! the engine maps between them.
//!
//! Everything fails closed: a request outside any grant dimension produces
//! a typed [`EgressOutcome`], never an HTTP attempt.

use std::time::Duration;

use url::Url;

/// Query-string policy carried by an egress grant (spec §11.6).
///
/// Mirrors `arbitraitor_policy::schema::EgressQueryPolicy` without making
/// `arbitraitor-fetch` depend on the policy crate (the dependency points
/// the other way).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum EgressQueryPolicy {
    /// No query string permitted.
    #[default]
    Forbidden,
    /// The request query must exactly equal the pinned query.
    Pinned,
    /// Query permitted up to the configured byte and parameter bounds.
    Bounded,
    /// Any query permitted.
    Allowed,
}

/// Response-body treatment carried by an egress grant (spec §11.6).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum EgressBodyTreatment {
    /// Deliver the bounded body to the caller without inspection.
    #[default]
    Unscanned,
    /// Submit the body through the inspection pipeline before delivery;
    /// only a passing verdict releases it to the caller.
    InspectFirst,
}

/// Fetch-layer view of one policy egress grant.
///
/// The engine derives this from `arbitraitor_policy::schema::EgressGrant`;
/// constructing one directly is reserved for tests and embedders that own
/// their policy mapping.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EgressGrant {
    /// Stable grant identity recorded in egress receipts.
    pub id: String,
    /// Allowlisted hosts (exact, lowercase).
    pub hosts: Vec<String>,
    /// Path prefix the request URL must be under.
    pub path_prefix: String,
    /// Query policy for this grant.
    pub query_policy: EgressQueryPolicy,
    /// Exact query required when the policy is `Pinned`.
    pub pinned_query: Option<String>,
    /// Maximum query-string bytes when the policy is `Bounded`.
    pub max_query_bytes: Option<usize>,
    /// Maximum query parameter count when the policy is `Bounded`.
    pub max_query_params: Option<usize>,
    /// Maximum response body bytes (defaults to
    /// [`EGRESS_DEFAULT_RESPONSE_BYTES`] when unset).
    pub max_response_bytes: Option<u64>,
    /// Permitted response media-type prefixes; empty means any.
    pub allowed_content_types: Vec<String>,
    /// Body treatment before delivery to the caller.
    pub body_treatment: EgressBodyTreatment,
}

/// Default response-size bound for egress (1 MiB): deliberately far below
/// the CAS retrieval default so egress never becomes a bulk-transfer path.
pub const EGRESS_DEFAULT_RESPONSE_BYTES: u64 = 1024 * 1024;

impl EgressGrant {
    /// Returns the effective response-size bound for this grant.
    #[must_use]
    pub fn effective_max_response_bytes(&self) -> u64 {
        self.max_response_bytes
            .unwrap_or(EGRESS_DEFAULT_RESPONSE_BYTES)
    }

    /// Returns true when `url` is inside this grant's host and path scope.
    #[must_use]
    pub fn covers(&self, url: &Url) -> bool {
        let Some(host) = url.host_str() else {
            return false;
        };
        if !self.hosts.iter().any(|h| h.as_str() == host.to_lowercase()) {
            return false;
        }
        let path = url.path();
        self.path_prefix.is_empty() || path.starts_with(&self.path_prefix)
    }

    /// Validates the request URL against this grant.
    ///
    /// # Errors
    ///
    /// Returns [`EgressError::OutsideGrant`] when host or path are out of
    /// scope, and [`EgressError::QueryPolicy`] when the query violates the
    /// grant's query policy.
    pub fn authorize(&self, url: &Url) -> Result<(), EgressError> {
        if !self.covers(url) {
            return Err(EgressError::OutsideGrant {
                grant_id: self.id.clone(),
            });
        }
        let query = url.query();
        match self.query_policy {
            EgressQueryPolicy::Forbidden => {
                if query.is_some() {
                    return Err(EgressError::QueryPolicy {
                        grant_id: self.id.clone(),
                        reason: "grant forbids query strings".to_owned(),
                    });
                }
            }
            EgressQueryPolicy::Pinned => {
                let pinned = self.pinned_query.as_deref().unwrap_or_default();
                if query == Some(pinned) {
                    return Ok(());
                }
                return Err(EgressError::QueryPolicy {
                    grant_id: self.id.clone(),
                    reason: format!("query must be exactly {pinned:?}"),
                });
            }
            EgressQueryPolicy::Bounded => {
                let Some(q) = query else {
                    // A bounded policy with no query is trivially within
                    // bounds.
                    return Ok(());
                };
                let bytes = q.len();
                let params = q.split('&').count();
                let max_bytes = self.max_query_bytes.unwrap_or(usize::MAX);
                let max_params = self.max_query_params.unwrap_or(usize::MAX);
                if bytes > max_bytes || params > max_params {
                    return Err(EgressError::QueryPolicy {
                        grant_id: self.id.clone(),
                        reason: format!(
                            "query exceeds bounds ({bytes} bytes > {max_bytes}, {params} params > {max_params})"
                        ),
                    });
                }
            }
            EgressQueryPolicy::Allowed => {}
        }
        Ok(())
    }
}

/// Egress failure modes (spec §11.6 "Deterministic failure").
///
/// These are typed, egress-owned outcomes — not generic fetch errors — so
/// callers can distinguish "denied by policy" from "transport failed" and
/// receipts can record the exact denial reason.
#[derive(Debug, thiserror::Error)]
pub enum EgressError {
    /// The URL is outside every configured grant's host/path scope.
    #[error("egress request outside grant scope (grant {grant_id})")]
    OutsideGrant {
        /// Identifier of the grant the request was evaluated against.
        grant_id: String,
    },
    /// The query string violates the grant's query policy.
    #[error("egress query policy violation (grant {grant_id}): {reason}")]
    QueryPolicy {
        /// Identifier of the grant the request was evaluated against.
        grant_id: String,
        /// Safe, non-secret denial reason.
        reason: String,
    },
    /// The request URL carries userinfo credentials; egress strips them by
    /// rejecting rather than silently rewriting the URL.
    #[error("egress request URL carries userinfo credentials")]
    UserinfoCredentials,
    /// The response content type is not permitted by the grant.
    #[error("egress response content type not permitted (grant {grant_id})")]
    ContentTypeDenied {
        /// Identifier of the grant the request was evaluated against.
        grant_id: String,
    },
    /// No grant matches the request and egress is therefore denied.
    #[error("no egress grant matches the request")]
    NoGrant,
    /// The transport layer denied or failed the request after grant
    /// authorization (peer mismatch, redirect boundary, size bound,
    /// timeout, HTTP status, I/O). The message is a safe diagnostic.
    #[error("egress transport boundary: {message}")]
    TransportBoundary {
        /// Safe diagnostic message from the transport layer.
        message: String,
    },
}

/// Successful egress result: the bounded response body plus the metadata
/// the receipt layer needs.
#[derive(Debug)]
pub struct EgressResponse {
    /// Grant the request executed under.
    pub grant_id: String,
    /// Requested URL (credential-redacted by the receipt layer, never by
    /// the transport).
    pub requested_url: String,
    /// Final URL after redirects.
    pub final_url: String,
    /// Redirect chain (absolute URLs).
    pub redirect_chain: Vec<String>,
    /// Response status code.
    pub status: u16,
    /// Response media type as received.
    pub content_type: String,
    /// Response body, bounded by the grant.
    pub body: Vec<u8>,
    /// Body treatment applied (recorded on the receipt).
    pub body_treatment: EgressBodyTreatment,
    /// Whether the caller may receive the body (false when a bound was hit
    /// after connect — the body is withheld, the receipt records why).
    pub delivered: bool,
}

/// Egress timeouts, derived from the grant-owning deployment's fetch
/// policy; egress reuses retrieval's transport floor (spec §11.6).
#[derive(Debug, Clone)]
pub struct EgressTimeouts {
    /// TCP/TLS connect timeout.
    pub connect: Duration,
    /// Per-read idle timeout.
    pub read: Duration,
    /// Whole-operation timeout.
    pub total: Duration,
}
