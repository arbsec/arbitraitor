//! Egress executor: grant-mapped GETs over the hardened HTTP path.

use url::Url;

use super::egress::{EgressError, EgressGrant, EgressQueryPolicy, EgressResponse};
use super::{FetchPolicy, FetchRequest, FetchScheme, HttpFetcher, VecSink};
use crate::Fetcher;

pub use super::egress::EgressTimeouts;

/// Executes mediated egress requests (spec §11.6, ADR-0041).
///
/// The executor authorizes the request against a grant, then runs it
/// through the same hardened HTTP path as retrieval (per-hop resolution +
/// address validation, connected-peer verification, redirect policy,
/// credential stripping, size bounds). Differences from retrieval:
///
/// - the response body is collected in memory under the grant's bound and
///   returned to the caller instead of streamed into the CAS;
/// - the method is always GET (type-level: there is no body parameter);
/// - redirects must stay inside the grant's host/path scope;
/// - userinfo-credential URLs are rejected, not rewritten.
#[derive(Clone, Debug, Default)]
pub struct EgressExecutor;

impl EgressExecutor {
    /// Creates a new egress executor.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Executes one egress request under `grant`.
    ///
    /// # Errors
    ///
    /// Returns [`EgressError`] for every pre-transport denial. Transport
    /// failures surface as [`EgressError::Transport`]; the caller records
    /// the outcome on the egress receipt either way.
    pub async fn execute(
        &self,
        grant: &EgressGrant,
        url: &str,
        timeouts: &EgressTimeouts,
    ) -> Result<EgressResponse, EgressError> {
        let parsed = Url::parse(url).map_err(|_| EgressError::OutsideGrant {
            grant_id: grant.id.clone(),
        })?;

        // §11.3: egress never carries userinfo credentials; reject rather
        // than silently strip so the caller sees the misconfiguration.
        if !parsed.username().is_empty() || parsed.password().is_some() {
            return Err(EgressError::UserinfoCredentials);
        }

        // Pre-transport grant authorization (host, path, query policy).
        grant.authorize(&parsed)?;

        let policy = Self::egress_policy(grant, timeouts);
        let fetcher = HttpFetcher;

        // The request is GET-only by construction: FetchRequest has no body
        // parameter reachable from here, and `FetchRequest::url` defaults
        // the method to GET. A body-bearing capability cannot be expressed
        // against this API (ADR-0041 type-level rejection).
        let request = FetchRequest::url(super::FetchUrl::from_parsed(parsed), policy);

        let mut sink = VecSink::new();
        let receipt = fetcher
            .fetch(request, &mut sink)
            .await
            .map_err(|error| egress_transport_error(&error))?;

        let content_type = receipt.metadata.content_type.clone().unwrap_or_default();
        if !grant.allowed_content_types.is_empty()
            && !grant
                .allowed_content_types
                .iter()
                .any(|allowed| content_type.starts_with(allowed.as_str()))
        {
            return Err(EgressError::ContentTypeDenied {
                grant_id: grant.id.clone(),
            });
        }

        // §11.6: every hop must stay inside the grant. The fetcher's
        // redirect policy already denies cross-origin hops
        // (allow_cross_origin_redirect = false) and HTTPS downgrades, but a
        // same-origin hop can still leave the grant's path prefix
        // (/v1/x → /admin). Re-authorize the final URL against the grant's
        // host + path scope before any delivery; the query policy is NOT
        // re-checked here because the final URL's query is the response of
        // the redirect, not caller-controlled data — the caller-controlled
        // query was authorized pre-transport.
        if let Some(final_url) = receipt.metadata.final_url.as_ref()
            && !grant.covers(final_url.as_url())
        {
            return Err(EgressError::OutsideGrant {
                grant_id: grant.id.clone(),
            });
        }

        let body = sink.into_bytes();
        let delivered =
            u64::try_from(body.len()).is_ok_and(|n| n <= grant.effective_max_response_bytes());

        Ok(EgressResponse {
            grant_id: grant.id.clone(),
            requested_url: url.to_owned(),
            final_url: receipt
                .metadata
                .final_url
                .as_ref()
                .map_or_else(|| url.to_owned(), |u| u.as_url().to_string()),
            redirect_chain: receipt
                .metadata
                .redirect_chain
                .iter()
                .map(|u| u.as_url().to_string())
                .collect(),
            status: receipt.metadata.response_status.unwrap_or_default(),
            content_type,
            body,
            body_treatment: grant.body_treatment,
            delivered,
        })
    }

    /// Builds the retrieval policy an egress request runs under: the
    /// transport floor from §11.2/§11.4/ADR-0018 with egress-specific
    /// bounds from the grant.
    fn egress_policy(grant: &EgressGrant, timeouts: &EgressTimeouts) -> FetchPolicy {
        FetchPolicy {
            tls_verifier: super::TlsVerifier::PlatformVerifier,
            connect_timeout: timeouts.connect,
            read_timeout: timeouts.read,
            total_timeout: timeouts.total,
            // Egress responses are bounded by the grant, not the CAS
            // default; the sink-side limit enforces the same bound.
            max_compressed_size: grant.effective_max_response_bytes(),
            max_uncompressed_size: grant.effective_max_response_bytes(),
            // Redirects stay inside the grant scope (see `redirect_guard`).
            max_redirects: 5,
            allowed_schemes: vec![FetchScheme::Https],
            allow_loopback_addresses: false,
            allow_https_to_http_redirect: false,
            // Cross-origin redirects are denied: the grant scopes hosts,
            // and a cross-origin hop would execute under the wrong grant.
            allow_cross_origin_redirect: false,
            forward_authorization_cross_origin: false,
            proxy_url: None,
            behind_proxy: false,
            require_digest: false,
            first_byte_timeout: None,
            // §11.6 deterministic-failure semantics: an error-status
            // response is a transport-boundary outcome, not a body to
            // deliver — a 500 error page is not the content the grant
            // authorized, and delivering it as a success would let a
            // hostile origin dress arbitrary bytes as a clean result.
            http_error_status_is_failure: true,
        }
    }

    /// Test-only view of the egress policy floor (pins the §11.6 transport
    /// guarantees against silent widening).
    #[doc(hidden)]
    #[must_use]
    pub fn egress_policy_for_test(
        &self,
        grant: &EgressGrant,
        timeouts: &EgressTimeouts,
    ) -> FetchPolicy {
        Self::egress_policy(grant, timeouts)
    }
}

/// Maps retrieval errors onto egress outcomes.
///
/// Most retrieval failures are transport-level from egress's perspective;
/// the typed denials that matter (peer mismatch, prohibited address,
/// scheme) are preserved as their egress counterparts where one exists so
/// receipts can distinguish policy denial from transport failure.
fn egress_transport_error(error: &super::FetchError) -> EgressError {
    use super::FetchError as FE;
    match error {
        // Grant-adjacent denials (ADR-0018): report as policy denial, with
        // the underlying reason in the transport log.
        FE::ProhibitedAddress { .. } | FE::PeerAddressMismatch => {
            tracing::debug!(%error, "egress request denied by address policy");
            EgressError::NoGrant
        }
        _ => EgressError::TransportBoundary {
            message: error.to_string(),
        },
    }
}

impl EgressQueryPolicy {
    /// Returns true when this policy permits the given query string.
    #[must_use]
    pub fn permits(&self, query: Option<&str>, grant: &EgressGrant) -> bool {
        grant.authorize_query_for_policy(*self, query).is_ok()
    }
}

impl EgressGrant {
    /// Query-policy check separated from URL authorization so
    /// [`EgressQueryPolicy::permits`] can reuse it.
    pub(crate) fn authorize_query_for_policy(
        &self,
        policy: EgressQueryPolicy,
        query: Option<&str>,
    ) -> Result<(), EgressError> {
        match policy {
            EgressQueryPolicy::Forbidden => {
                if query.is_some() {
                    Err(EgressError::QueryPolicy {
                        grant_id: self.id.clone(),
                        reason: "grant forbids query strings".to_owned(),
                    })
                } else {
                    Ok(())
                }
            }
            EgressQueryPolicy::Pinned => {
                let pinned = self.pinned_query.as_deref().unwrap_or_default();
                if query == Some(pinned) {
                    Ok(())
                } else {
                    Err(EgressError::QueryPolicy {
                        grant_id: self.id.clone(),
                        reason: format!("query must be exactly {pinned:?}"),
                    })
                }
            }
            EgressQueryPolicy::Bounded => {
                let Some(q) = query else {
                    return Ok(());
                };
                let bytes = q.len();
                let params = q.split('&').count();
                if bytes > self.max_query_bytes.unwrap_or(usize::MAX)
                    || params > self.max_query_params.unwrap_or(usize::MAX)
                {
                    Err(EgressError::QueryPolicy {
                        grant_id: self.id.clone(),
                        reason: format!("query exceeds bounds ({bytes} bytes, {params} params)"),
                    })
                } else {
                    Ok(())
                }
            }
            EgressQueryPolicy::Allowed => Ok(()),
        }
    }
}
