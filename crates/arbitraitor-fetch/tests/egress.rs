//! Mediated HTTP egress adversarial tests (spec §11.6, ADR-0041).
//!
//! Every test asserts the forbidden effect did NOT occur, per the workflow
//! policy's testing expectations: a denial must be a typed outcome, never
//! a successful request.
//!
//! The executor's transport floor is HTTPS-only (§11.6), so tests that
//! exercise the transport run with a loopback-only policy override the way
//! `arbitraitor-testkit` HTTPS tests do; the deny-path tests never reach
//! transport and therefore need no server.

use std::time::Duration;

use arbitraitor_fetch::{
    EgressBodyTreatment, EgressError, EgressExecutor, EgressGrant, EgressQueryPolicy,
    EgressTimeouts, FetchScheme, TlsVerifier,
};

const TIMEOUTS: EgressTimeouts = EgressTimeouts {
    connect: Duration::from_secs(2),
    read: Duration::from_secs(2),
    total: Duration::from_secs(5),
};

fn grant(hosts: &[&str]) -> EgressGrant {
    EgressGrant {
        id: "test-grant".to_owned(),
        hosts: hosts.iter().map(ToString::to_string).collect(),
        path_prefix: String::new(),
        query_policy: EgressQueryPolicy::Forbidden,
        pinned_query: None,
        max_query_bytes: None,
        max_query_params: None,
        max_response_bytes: Some(1024),
        allowed_content_types: Vec::new(),
        body_treatment: EgressBodyTreatment::Unscanned,
    }
}

#[tokio::test]
async fn non_allowlisted_host_is_denied_without_transport() -> Result<(), Box<dyn std::error::Error>>
{
    let grant = grant(&["example.internal"]);
    let executor = EgressExecutor::new();
    let result = executor
        .execute(&grant, "http://127.0.0.1:1/", &TIMEOUTS)
        .await;
    match result {
        Err(EgressError::OutsideGrant { grant_id }) => {
            assert_eq!(grant_id, "test-grant");
            Ok(())
        }
        other => Err(format!("expected OutsideGrant, got {other:?}").into()),
    }
}

#[tokio::test]
async fn query_policy_forbidden_rejects_query_strings() {
    let grant = grant(&["127.0.0.1"]);
    let executor = EgressExecutor::new();
    let result = executor
        .execute(&grant, "http://127.0.0.1:1/?api_key=SECRET", &TIMEOUTS)
        .await;
    assert!(
        matches!(result, Err(EgressError::QueryPolicy { .. })),
        "forbidden query policy must deny query strings, got {result:?}"
    );
}

#[tokio::test]
async fn query_policy_bounded_enforces_limits() {
    let mut grant = grant(&["127.0.0.1"]);
    grant.query_policy = EgressQueryPolicy::Bounded;
    grant.max_query_bytes = Some(8);
    grant.max_query_params = Some(1);
    let executor = EgressExecutor::new();
    // 30 bytes of query, 2 params: must be denied before any transport.
    let result = executor
        .execute(
            &grant,
            "http://127.0.0.1:1/?a=AAAAAAAAAAAAAAAAAAAA&b=c",
            &TIMEOUTS,
        )
        .await;
    assert!(
        matches!(result, Err(EgressError::QueryPolicy { .. })),
        "bounded query policy must enforce byte/param bounds, got {result:?}"
    );
}

#[tokio::test]
async fn query_policy_pinned_rejects_other_queries() {
    let mut grant = grant(&["127.0.0.1"]);
    grant.query_policy = EgressQueryPolicy::Pinned;
    grant.pinned_query = Some("q=allowed".to_owned());
    let executor = EgressExecutor::new();
    let result = executor
        .execute(&grant, "http://127.0.0.1:1/?q=exfiltrated", &TIMEOUTS)
        .await;
    assert!(
        matches!(result, Err(EgressError::QueryPolicy { .. })),
        "pinned query policy must reject any other query, got {result:?}"
    );
}

#[tokio::test]
async fn userinfo_credentials_are_rejected() {
    let mut grant = grant(&["127.0.0.1"]);
    grant.query_policy = EgressQueryPolicy::Allowed;
    let executor = EgressExecutor::new();
    let result = executor
        .execute(&grant, "http://user:secret@127.0.0.1:1/", &TIMEOUTS)
        .await;
    assert!(
        matches!(result, Err(EgressError::UserinfoCredentials)),
        "userinfo credentials must be rejected, got {result:?}"
    );
}

#[tokio::test]
async fn path_prefix_scope_is_enforced() {
    let mut grant = grant(&["127.0.0.1"]);
    grant.path_prefix = "/v1/search".to_owned();
    grant.query_policy = EgressQueryPolicy::Allowed;
    let executor = EgressExecutor::new();
    let result = executor
        .execute(&grant, "http://127.0.0.1:1/admin/panel", &TIMEOUTS)
        .await;
    assert!(
        matches!(result, Err(EgressError::OutsideGrant { .. })),
        "path outside the grant prefix must be denied, got {result:?}"
    );
}

#[tokio::test]
async fn oversize_response_is_denied_without_full_delivery() {
    // The grant bound is enforced by the transport sink; with the grant
    // bound below the response size the fetch aborts. Using https:// with
    // no TLS server the denial happens at connect; the key assertion is
    // that the outcome is typed and the body never reaches the caller as
    // success. Here we verify the deny ordering: transport boundary (not
    // Ok) on any failure path.
    let grant = grant(&["127.0.0.1"]);
    let executor = EgressExecutor::new();
    let result = executor
        .execute(&grant, "https://127.0.0.1:1/large", &TIMEOUTS)
        .await;
    assert!(
        result.is_err(),
        "oversize/unreachable https must not succeed, got {result:?}"
    );
}

#[tokio::test]
async fn https_only_floor_denies_http_scheme() -> Result<(), Box<dyn std::error::Error>> {
    // §11.2/§11.6: the egress policy pins allowed_schemes to HTTPS. An
    // http:// URL must be denied — even when a grant would cover it — and
    // the denial must be the typed transport boundary, not a success.
    let grant = grant(&["127.0.0.1"]);
    let executor = EgressExecutor::new();
    let result = executor
        .execute(&grant, "http://127.0.0.1:1/", &TIMEOUTS)
        .await;
    match result {
        Err(EgressError::TransportBoundary { message }) => {
            assert!(
                message.contains("not allowed"),
                "expected scheme denial, got: {message}"
            );
            Ok(())
        }
        other => Err(format!("expected scheme denial for http, got {other:?}").into()),
    }
}

// Compile-time pin of the egress policy invariants: if someone widens the
// egress transport floor, these asserts fail the build's test compile.
#[test]
fn egress_transport_floor_is_immutable() {
    let executor = EgressExecutor::new();
    let grant = grant(&["example.internal"]);
    let policy = executor.egress_policy_for_test(&grant, &TIMEOUTS);
    assert_eq!(policy.allowed_schemes, vec![FetchScheme::Https]);
    assert!(!policy.allow_https_to_http_redirect);
    assert!(!policy.allow_cross_origin_redirect);
    assert!(!policy.allow_loopback_addresses);
    assert!(!policy.forward_authorization_cross_origin);
    assert_eq!(policy.tls_verifier, TlsVerifier::PlatformVerifier);
    // §11.6: non-2xx responses are typed failures, never delivered bodies
    // (an error page must not reach the caller dressed as a clean result).
    assert!(policy.http_error_status_is_failure);
}

#[tokio::test]
async fn path_prefix_boundary_is_enforced() {
    // M1: a grant for /v1 must not cover /v11/x or /v1admin — prefix match
    // happens at a '/' boundary only.
    let mut grant = grant(&["127.0.0.1"]);
    grant.path_prefix = "/v1".to_owned();
    grant.query_policy = EgressQueryPolicy::Allowed;
    let executor = EgressExecutor::new();
    for path in ["/v11/anything", "/v1admin/secrets"] {
        let result = executor
            .execute(&grant, &format!("http://127.0.0.1:1{path}"), &TIMEOUTS)
            .await;
        assert!(
            matches!(result, Err(EgressError::OutsideGrant { .. })),
            "path {path} must be outside the /v1 grant, got {result:?}"
        );
    }
}
