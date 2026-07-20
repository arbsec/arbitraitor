//! HTTP retrieval and transport policy.
//!
//! This crate owns artifact retrieval. It deliberately keeps `reqwest` behind
//! [`Fetcher`] so storage, scanning, and execution code cannot depend on a
//! concrete HTTP client or inherit unsafe transport defaults.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use std::collections::HashSet;
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::PathBuf;
use std::time::Duration;

use arbitraitor_model::ids::{ArtifactId, Sha256Digest};
use async_trait::async_trait;
use reqwest::header::{ACCEPT_ENCODING, CONTENT_LENGTH, CONTENT_TYPE, HeaderValue};
use sha2::{Digest, Sha256};
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt};
use tracing::{debug, instrument, trace, warn};
use url::Url;

const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const DEFAULT_READ_TIMEOUT: Duration = Duration::from_secs(30);
const DEFAULT_TOTAL_TIMEOUT: Duration = Duration::from_mins(5);
const DEFAULT_MAX_BYTES: u64 = 512 * 1024 * 1024;
const USER_AGENT_PREFIX: &str = "Arbitraitor/";

/// A parsed artifact URL.
///
/// Arbitraitor code should pass this newtype rather than raw URL strings so the
/// parse/normalization boundary is explicit.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct FetchUrl(Url);

impl FetchUrl {
    /// Parses a URL for use as a fetch source.
    ///
    /// The scheme is checked by [`FetchPolicy`] at fetch time because different
    /// fetchers support different schemes.
    ///
    /// # Errors
    ///
    /// Returns [`FetchError::InvalidUrl`] when `value` is not an absolute URL.
    pub fn parse(value: &str) -> Result<Self, FetchError> {
        Url::parse(value)
            .map(Self)
            .map_err(|source| FetchError::InvalidUrl {
                message: source.to_string(),
            })
    }

    /// Returns the normalized URL.
    #[must_use]
    pub const fn as_url(&self) -> &Url {
        &self.0
    }

    fn into_url(self) -> Url {
        self.0
    }
}

impl fmt::Display for FetchUrl {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

/// Supported source schemes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum FetchScheme {
    /// Plain HTTP, intended for tests and explicitly approved local use.
    Http,
    /// HTTPS transport.
    Https,
    /// Local filesystem input.
    File,
    /// Standard input.
    Stdin,
}

impl FetchScheme {
    fn as_str(self) -> &'static str {
        match self {
            Self::Http => "http",
            Self::Https => "https",
            Self::File => "file",
            Self::Stdin => "stdin",
        }
    }

    fn from_str(value: &str) -> Option<Self> {
        match value {
            "http" => Some(Self::Http),
            "https" => Some(Self::Https),
            "file" => Some(Self::File),
            "stdin" => Some(Self::Stdin),
            _ => None,
        }
    }
}

/// Artifact input source.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FetchSource {
    /// HTTP or HTTPS URL source.
    Url(FetchUrl),
    /// Local file source.
    File(PathBuf),
    /// Standard input source.
    Stdin,
}

impl FetchSource {
    fn scheme(&self) -> FetchScheme {
        match self {
            Self::Url(url) => {
                FetchScheme::from_str(url.as_url().scheme()).unwrap_or(FetchScheme::Http)
            }
            Self::File(_) => FetchScheme::File,
            Self::Stdin => FetchScheme::Stdin,
        }
    }
}

/// Fetch request passed to a [`Fetcher`].
#[derive(Clone, Debug)]
pub struct FetchRequest {
    /// Artifact source.
    pub source: FetchSource,
    /// Transport and byte-limit policy.
    pub policy: FetchPolicy,
    /// Expected SHA-256 digest of the fetched artifact bytes.
    pub expected_sha256: Option<Sha256Digest>,
}

impl FetchRequest {
    /// Builds a URL fetch request.
    #[must_use]
    pub fn url(url: FetchUrl, policy: FetchPolicy) -> Self {
        Self {
            source: FetchSource::Url(url),
            policy,
            expected_sha256: None,
        }
    }

    /// Builds a local file fetch request.
    #[must_use]
    pub fn file(path: PathBuf, policy: FetchPolicy) -> Self {
        Self {
            source: FetchSource::File(path),
            policy,
            expected_sha256: None,
        }
    }

    /// Builds a standard input fetch request.
    #[must_use]
    pub const fn stdin(policy: FetchPolicy) -> Self {
        Self {
            source: FetchSource::Stdin,
            policy,
            expected_sha256: None,
        }
    }

    /// Sets the expected SHA-256 digest for integrity pinning.
    #[must_use]
    pub fn with_expected_sha256(mut self, digest: Sha256Digest) -> Self {
        self.expected_sha256 = Some(digest);
        self
    }
}

/// Transport policy applied by fetchers.
///
/// Each bool field is a documented security policy axis with an explicit
/// fail-closed or fail-open default tied to a spec section. Clippy's
/// `struct_excessive_bools` lint is allowed here because converting these
/// to two-variant enums would obscure the TOML deserialization surface
/// (a TOML bool is the natural authoring shape for a security policy)
/// and make the relationship between a policy field and its spec
/// citation harder to audit.
#[allow(clippy::struct_excessive_bools)]
#[derive(Clone, Debug)]
pub struct FetchPolicy {
    /// TCP/TLS connection timeout.
    pub connect_timeout: Duration,
    /// Per-read idle timeout.
    pub read_timeout: Duration,
    /// Whole-operation timeout.
    pub total_timeout: Duration,
    /// Maximum encoded representation bytes accepted from transport.
    pub max_compressed_size: u64,
    /// Maximum decoded bytes accepted.
    ///
    /// HTTP auto-decompression is disabled, so HTTP encoded and decoded counts
    /// are identical in the MVP. This second limit is retained to keep policy
    /// shape stable for future explicit decoder stages.
    pub max_uncompressed_size: u64,
    /// Maximum redirect hops. The default is zero for fail-closed retrieval.
    pub max_redirects: usize,
    /// Schemes this operation may access.
    pub allowed_schemes: Vec<FetchScheme>,
    /// Allows loopback addresses for explicitly approved local fetches.
    ///
    /// This is fail-closed by default. It does not allow private, link-local,
    /// metadata, multicast, benchmarking, or other IANA special-purpose ranges.
    pub allow_loopback_addresses: bool,
    /// Allows a redirect to downgrade from HTTPS to HTTP.
    ///
    /// Fail-closed by default (ADR-0018 §Redirect handling). Even when both
    /// schemes are permitted by [`FetchPolicy::allowed_schemes`], a downgrade
    /// from HTTPS to HTTP strips transport encryption and is blocked unless a
    /// caller explicitly opts in here.
    pub allow_https_to_http_redirect: bool,
    /// Allows redirect chains that cross origin boundaries (scheme/host/port).
    ///
    /// Defaults to `true` per spec §11.4 — the common case (release artifact
    /// hosted on a different CDN) legitimately crosses origins. When `false`,
    /// any redirect to a different origin is rejected with
    /// [`FetchError::CrossOriginRedirect`].
    pub allow_cross_origin_redirect: bool,
    /// Allows `Authorization` and `Cookie` headers to be forwarded across
    /// origins during a redirect chain.
    ///
    /// Fail-closed by default (`false`) per spec §11.2. When `false`, any
    /// redirect that lands on a different origin triggers a forced strip of
    /// credential-bearing headers from subsequent requests in the chain.
    /// When `true`, the original headers are preserved.
    ///
    /// Note: as of the current MVP, [`execute_request`] sends a bare GET
    /// with no Authorization header (user-supplied headers are tracked in
    /// issue #498). The strip logic below is therefore forward-compatible —
    /// when #498 wires header input, this policy is the gate that prevents
    /// credential leakage.
    pub forward_authorization_cross_origin: bool,
    /// Optional proxy URL (spec §11.2, ADR-0018). When `None` (default),
    /// all proxy behavior is disabled via `.no_proxy()`. When `Some`,
    /// reqwest is configured with the given proxy URL.
    pub proxy_url: Option<String>,
    /// Whether DNS resolution and target address selection are performed
    /// by the proxy rather than locally (spec §11.2, ADR-0018). When
    /// `true`, the receipt records that connected-peer verification
    /// observes the proxy, not the actual target.
    pub behind_proxy: bool,
    /// Requires callers to provide an expected SHA-256 digest before fetching.
    pub require_digest: bool,
}

impl Default for FetchPolicy {
    fn default() -> Self {
        Self {
            connect_timeout: DEFAULT_CONNECT_TIMEOUT,
            read_timeout: DEFAULT_READ_TIMEOUT,
            total_timeout: DEFAULT_TOTAL_TIMEOUT,
            max_compressed_size: DEFAULT_MAX_BYTES,
            max_uncompressed_size: DEFAULT_MAX_BYTES,
            max_redirects: 0,
            allowed_schemes: vec![FetchScheme::Https, FetchScheme::File, FetchScheme::Stdin],
            allow_loopback_addresses: false,
            allow_https_to_http_redirect: false,
            allow_cross_origin_redirect: true,
            forward_authorization_cross_origin: false,
            proxy_url: None,
            behind_proxy: false,
            require_digest: false,
        }
    }
}

impl FetchPolicy {
    /// Returns true when `scheme` is permitted by this policy.
    #[must_use]
    pub fn allows_scheme(&self, scheme: FetchScheme) -> bool {
        self.allowed_schemes.contains(&scheme)
    }
}

/// Metadata recorded during retrieval.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct FetchMetadata {
    /// TLS protocol version when exposed by the transport backend.
    pub tls_version: Option<String>,
    /// SHA-256 fingerprint of the DER-encoded peer leaf certificate.
    pub peer_certificate_fingerprint: Option<Sha256Digest>,
    /// DNS addresses resolved before the request.
    pub resolved_ips: Vec<IpAddr>,
    /// Connected peer address reported by the HTTP client.
    pub connected_ip: Option<IpAddr>,
    /// Response content type, if present and valid UTF-8.
    pub content_type: Option<String>,
    /// Response content length, if provided.
    pub content_length: Option<u64>,
    /// Final URL after manual redirect handling.
    pub final_url: Option<FetchUrl>,
    /// Redirect chain followed by Arbitraitor policy.
    pub redirect_chain: Vec<FetchUrl>,
    /// HTTP response status code (spec §11.5). `None` for non-HTTP sources.
    pub response_status: Option<u16>,
    /// Selected response headers (spec §11.5). Only headers safe for
    /// receipt recording (no Authorization, Cookie, Set-Cookie).
    pub selected_headers: Vec<(String, String)>,
    /// Transfer encoding as observed by the transport (spec §11.5).
    pub transfer_encoding: Option<String>,
    /// Final origin (scheme + host + port) after all redirects (spec §11.5).
    pub final_origin: Option<String>,
    /// Retriever version string (spec §11.5).
    pub retriever_version: String,
}

/// Receipt returned after bytes have been streamed into an [`ArtifactSink`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FetchReceipt {
    /// Stable artifact identifier derived from [`Self::sha256`].
    pub artifact_id: ArtifactId,
    /// SHA-256 digest of the exact bytes delivered to the sink.
    pub sha256: Sha256Digest,
    /// Number of bytes delivered to the sink.
    pub bytes_written: u64,
    /// Transport metadata captured during retrieval.
    pub metadata: FetchMetadata,
}

/// Sink that receives artifact bytes as they arrive.
#[async_trait]
pub trait ArtifactSink: Send {
    /// Writes one chunk of artifact bytes.
    async fn write_chunk(&mut self, chunk: &[u8]) -> Result<(), ArtifactSinkError>;
}

/// Mockable artifact retrieval abstraction.
#[async_trait]
pub trait Fetcher: Send + Sync {
    /// Fetches `request` and streams artifact bytes into `sink`.
    async fn fetch(
        &self,
        request: FetchRequest,
        sink: &mut dyn ArtifactSink,
    ) -> Result<FetchReceipt, FetchError>;
}

/// Error returned by an [`ArtifactSink`].
#[derive(Debug, Error)]
#[error("artifact sink failed: {message}")]
pub struct ArtifactSinkError {
    message: String,
}

impl ArtifactSinkError {
    /// Creates a sink error with a safe diagnostic message.
    #[must_use]
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

/// Fetch-layer error.
#[derive(Debug, Error)]
pub enum FetchError {
    /// URL parsing failed.
    #[error("invalid fetch URL: {message}")]
    InvalidUrl {
        /// Safe parse failure context.
        message: String,
    },
    /// A source scheme was not allowed by policy.
    #[error("scheme `{scheme}` is not allowed by fetch policy")]
    InvalidScheme {
        /// Rejected scheme.
        scheme: String,
    },
    /// Fetch timed out.
    #[error("fetch timed out during {stage}")]
    Timeout {
        /// Stage that timed out.
        stage: &'static str,
    },
    /// Configured byte limit was exceeded.
    #[error("{kind} size limit exceeded: limit {limit} bytes, observed {observed} bytes")]
    SizeExceeded {
        /// Limit kind.
        kind: SizeLimitKind,
        /// Configured limit.
        limit: u64,
        /// Observed byte count.
        observed: u64,
    },
    /// Connection was refused.
    #[error("connection refused")]
    ConnectionRefused,
    /// TLS handshake or validation failed.
    #[error("TLS failure")]
    TlsFailure,
    /// HTTP returned an error status.
    #[error("HTTP error status {status}")]
    HttpStatus {
        /// HTTP status code.
        status: u16,
    },
    /// Redirect chain exceeded policy.
    #[error("redirect limit exceeded: limit {limit}")]
    RedirectLimitExceeded {
        /// Configured redirect limit.
        limit: usize,
    },
    /// Redirect loop was detected.
    #[error("redirect loop detected")]
    RedirectLoop,
    /// Redirect response was malformed.
    #[error("malformed redirect response")]
    MalformedRedirect,
    /// Connected peer address differs from approved resolved addresses.
    ///
    /// A DNS rebinding attack resolved to an approved IP during the policy
    /// check but connected to a different IP. The error message is
    /// deliberately redacted — it never includes the connected or resolved
    /// addresses, which could leak internal topology.
    #[error("connected peer address does not match a resolved address (possible DNS rebinding)")]
    PeerAddressMismatch,
    /// Redirect downgraded from HTTPS to HTTP without explicit opt-in.
    #[error("redirect downgrades from HTTPS to HTTP, which is blocked by policy")]
    InsecureRedirectDowngrade,
    /// Redirect crossed origin boundaries (scheme/host/port) without explicit opt-in.
    ///
    /// Returned when [`FetchPolicy::allow_cross_origin_redirect`] is `false`
    /// and a redirect target has a different scheme, host, or port than the
    /// current request URL. The error message does not include the redirect
    /// URLs themselves; those are recorded in the receipt's redacted redirect
    /// chain rather than bypassed to a diagnostic channel.
    #[error("redirect crosses origin boundaries, which is blocked by policy")]
    CrossOriginRedirect,
    /// DNS resolution reached a prohibited address range.
    #[error("resolved address is prohibited by fetch policy: {address}")]
    ProhibitedAddress {
        /// Blocked address.
        address: IpAddr,
    },
    /// Policy requires a pinned digest but none was provided.
    #[error("fetch policy requires an expected SHA-256 digest")]
    RequiredDigestMissing,
    /// Fetched bytes did not match the pinned digest.
    #[error("SHA-256 digest mismatch: expected {expected}, actual {actual}")]
    DigestMismatch {
        /// Expected pinned digest.
        expected: Sha256Digest,
        /// Actual digest of bytes delivered to the sink.
        actual: Sha256Digest,
    },
    /// Local I/O failed.
    #[error("I/O failure during {stage}: {source}")]
    Io {
        /// I/O stage.
        stage: &'static str,
        /// Underlying I/O error.
        source: std::io::Error,
    },
    /// Sink rejected artifact bytes.
    #[error(transparent)]
    Sink(#[from] ArtifactSinkError),
    /// HTTP client failed without a more specific classification.
    #[error("HTTP transport failure during {stage}: {message}")]
    Transport {
        /// Transport stage.
        stage: &'static str,
        /// Safe diagnostic message.
        message: String,
    },
    /// Server sent fewer bytes than declared in `Content-Length`.
    #[error("truncated response body: Content-Length declared {declared} bytes, received {actual}")]
    TruncatedBody {
        /// Declared byte count from `Content-Length`.
        declared: u64,
        /// Actual byte count received.
        actual: u64,
    },
}

/// Size limit category.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SizeLimitKind {
    /// Encoded transport representation size.
    Compressed,
    /// Decoded representation size.
    Uncompressed,
}

impl fmt::Display for SizeLimitKind {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Compressed => formatter.write_str("compressed"),
            Self::Uncompressed => formatter.write_str("uncompressed"),
        }
    }
}

/// In-memory sink useful for tests and small callers.
#[derive(Debug, Default)]
pub struct VecSink {
    bytes: Vec<u8>,
}

impl VecSink {
    /// Creates an empty sink.
    #[must_use]
    pub const fn new() -> Self {
        Self { bytes: Vec::new() }
    }

    /// Returns all received bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Consumes the sink and returns received bytes.
    #[must_use]
    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }
}

#[async_trait]
impl ArtifactSink for VecSink {
    async fn write_chunk(&mut self, chunk: &[u8]) -> Result<(), ArtifactSinkError> {
        self.bytes.extend_from_slice(chunk);
        Ok(())
    }
}

/// HTTP fetcher implemented with reqwest and rustls.
#[derive(Clone, Debug, Default)]
pub struct HttpFetcher;

impl HttpFetcher {
    /// Creates a new HTTP fetcher.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

#[async_trait]
impl Fetcher for HttpFetcher {
    #[instrument(skip(self, request, sink), fields(source = "http"))]
    async fn fetch(
        &self,
        request: FetchRequest,
        sink: &mut dyn ArtifactSink,
    ) -> Result<FetchReceipt, FetchError> {
        let FetchSource::Url(url) = request.source else {
            return Err(FetchError::InvalidScheme {
                scheme: request.source.scheme().as_str().to_owned(),
            });
        };

        ensure_required_digest(request.expected_sha256.as_ref(), &request.policy)?;
        let future = self.fetch_inner(url, &request.policy, request.expected_sha256.as_ref(), sink);
        tokio::time::timeout(request.policy.total_timeout, future)
            .await
            .map_err(|_| FetchError::Timeout { stage: "total" })?
    }
}

impl HttpFetcher {
    async fn fetch_inner(
        &self,
        url: FetchUrl,
        policy: &FetchPolicy,
        expected_sha256: Option<&Sha256Digest>,
        sink: &mut dyn ArtifactSink,
    ) -> Result<FetchReceipt, FetchError> {
        ensure_scheme_allowed(
            FetchScheme::from_str(url.as_url().scheme()),
            url.as_url().scheme(),
            policy,
        )?;
        let mut current = url.into_url();
        let mut visited = HashSet::new();
        let mut redirect_chain = Vec::new();

        for redirect_count in 0..=policy.max_redirects {
            if !visited.insert(current.clone()) {
                return Err(FetchError::RedirectLoop);
            }
            let resolved_addrs = resolve_url_addrs(&current, policy).await?;
            let resolved_ips = unique_ips(&resolved_addrs);
            debug!(url = %redact_parsed_url(&current), resolved_count = resolved_ips.len(), "resolved fetch host");
            let client = build_http_client(policy, &current, &resolved_addrs)?;
            let response = execute_request(&client, current.clone()).await?;
            let status = response.status();

            if status.is_redirection() {
                if redirect_count == policy.max_redirects {
                    return Err(FetchError::RedirectLimitExceeded {
                        limit: policy.max_redirects,
                    });
                }
                let next = redirect_target(&current, response.headers())?;
                ensure_scheme_allowed(FetchScheme::from_str(next.scheme()), next.scheme(), policy)?;
                ensure_no_insecure_downgrade(current.scheme(), next.scheme(), policy)?;
                ensure_cross_origin_allowed(&current, &next, policy)?;
                trace!(from = %redact_parsed_url(&current), to = %redact_parsed_url(&next), "following policy-approved redirect");
                redirect_chain.push(FetchUrl(current));
                current = next;
                continue;
            }

            if status.is_client_error() || status.is_server_error() {
                return Err(FetchError::HttpStatus {
                    status: status.as_u16(),
                });
            }

            return stream_response(
                response,
                policy,
                expected_sha256,
                sink,
                resolved_ips,
                FetchUrl(current),
                redirect_chain,
            )
            .await;
        }

        Err(FetchError::RedirectLimitExceeded {
            limit: policy.max_redirects,
        })
    }
}

/// Local file fetcher.
#[derive(Clone, Debug, Default)]
pub struct FileFetcher;

impl FileFetcher {
    /// Creates a new file fetcher.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

#[async_trait]
impl Fetcher for FileFetcher {
    #[instrument(skip(self, request, sink), fields(source = "file"))]
    async fn fetch(
        &self,
        request: FetchRequest,
        sink: &mut dyn ArtifactSink,
    ) -> Result<FetchReceipt, FetchError> {
        ensure_policy_allows(FetchScheme::File, &request.policy)?;
        let FetchSource::File(path) = request.source else {
            return Err(FetchError::InvalidScheme {
                scheme: request.source.scheme().as_str().to_owned(),
            });
        };
        ensure_required_digest(request.expected_sha256.as_ref(), &request.policy)?;
        let file = tokio::fs::File::open(path)
            .await
            .map_err(|source| FetchError::Io {
                stage: "open",
                source,
            })?;
        stream_reader(
            file,
            &request.policy,
            request.expected_sha256.as_ref(),
            sink,
            FetchMetadata::default(),
        )
        .await
    }
}

/// Standard input fetcher.
#[derive(Clone, Debug, Default)]
pub struct StdinFetcher;

impl StdinFetcher {
    /// Creates a new stdin fetcher.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

#[async_trait]
impl Fetcher for StdinFetcher {
    #[instrument(skip(self, request, sink), fields(source = "stdin"))]
    async fn fetch(
        &self,
        request: FetchRequest,
        sink: &mut dyn ArtifactSink,
    ) -> Result<FetchReceipt, FetchError> {
        ensure_policy_allows(FetchScheme::Stdin, &request.policy)?;
        if !matches!(request.source, FetchSource::Stdin) {
            return Err(FetchError::InvalidScheme {
                scheme: request.source.scheme().as_str().to_owned(),
            });
        }
        ensure_required_digest(request.expected_sha256.as_ref(), &request.policy)?;
        stream_reader(
            tokio::io::stdin(),
            &request.policy,
            request.expected_sha256.as_ref(),
            sink,
            FetchMetadata::default(),
        )
        .await
    }
}

fn build_http_client(
    policy: &FetchPolicy,
    url: &Url,
    resolved_addrs: &[SocketAddr],
) -> Result<reqwest::Client, FetchError> {
    let Some(host) = url.host_str() else {
        return Err(FetchError::InvalidUrl {
            message: "URL must include a host".to_owned(),
        });
    };
    let mut builder = reqwest::Client::builder()
        .use_rustls_tls()
        .connect_timeout(policy.connect_timeout)
        .read_timeout(policy.read_timeout)
        .timeout(policy.total_timeout)
        .redirect(reqwest::redirect::Policy::none())
        .no_gzip()
        .no_brotli()
        .no_deflate()
        .no_zstd()
        .tls_info(true)
        .user_agent(format!("{USER_AGENT_PREFIX}{}", env!("CARGO_PKG_VERSION")));

    if let Some(ref proxy_url) = policy.proxy_url {
        let proxy = reqwest::Proxy::all(proxy_url).map_err(|error| FetchError::InvalidUrl {
            message: format!("invalid proxy URL: {error}"),
        })?;
        builder = builder.proxy(proxy);
    } else {
        builder = builder.no_proxy();
    }

    if policy.behind_proxy {
        // When behind a proxy, we cannot verify the connected peer address
        // against resolved addresses because the proxy is the peer. Skip
        // resolve_to_addrs so reqwest uses the proxy's DNS resolution.
    } else {
        builder = builder.resolve_to_addrs(host, resolved_addrs);
    }

    builder
        .build()
        .map_err(|error| classify_reqwest_error("client build", error))
}

async fn execute_request(
    client: &reqwest::Client,
    url: Url,
) -> Result<reqwest::Response, FetchError> {
    // Exact-byte semantics: Arbitraitor stores and hashes the HTTP representation
    // bytes after HTTP transfer framing is removed by the HTTP stack. It does
    // not apply content codings such as gzip/br/deflate/zstd here. Sending
    // `Accept-Encoding: identity` and disabling all reqwest auto-decoders keeps
    // `Content-Encoding` bytes intact for CAS storage and later explicit wrapper
    // decoding into a separate child artifact.
    client
        .get(url)
        .header(ACCEPT_ENCODING, HeaderValue::from_static("identity"))
        .send()
        .await
        .map_err(|error| classify_reqwest_error("request", error))
}

async fn stream_response(
    mut response: reqwest::Response,
    policy: &FetchPolicy,
    expected_sha256: Option<&Sha256Digest>,
    sink: &mut dyn ArtifactSink,
    resolved_ips: Vec<IpAddr>,
    final_url: FetchUrl,
    redirect_chain: Vec<FetchUrl>,
) -> Result<FetchReceipt, FetchError> {
    let content_type = header_to_string(response.headers(), CONTENT_TYPE.as_str());
    let content_length = response
        .headers()
        .get(CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<u64>().ok());
    let connected_ip = response.remote_addr().map(|addr| addr.ip());
    verify_connected_peer(connected_ip, &resolved_ips)?;
    let peer_certificate_fingerprint = response
        .extensions()
        .get::<reqwest::tls::TlsInfo>()
        .and_then(reqwest::tls::TlsInfo::peer_certificate)
        .map(sha256_digest);

    let metadata = FetchMetadata {
        tls_version: None,
        peer_certificate_fingerprint,
        resolved_ips,
        connected_ip,
        content_type,
        content_length,
        final_url: Some(final_url.clone()),
        redirect_chain,
        response_status: Some(response.status().as_u16()),
        selected_headers: extract_safe_headers(response.headers()),
        transfer_encoding: header_to_string(response.headers(), "transfer-encoding"),
        final_origin: final_url
            .as_url()
            .host_str()
            .map(|h| format!("{}://{}", final_url.as_url().scheme(), h)),
        retriever_version: format!("arbitraitor-fetch/{}", env!("CARGO_PKG_VERSION")),
    };

    let mut state = StreamState::default();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|error| classify_reqwest_error("read", error))?
    {
        write_checked_chunk(&mut state, policy, sink, &chunk).await?;
    }

    if let Some(declared) = content_length
        && state.bytes_written != declared
    {
        return Err(FetchError::TruncatedBody {
            declared,
            actual: state.bytes_written,
        });
    }

    state.finish(metadata, expected_sha256)
}

async fn stream_reader<R: AsyncRead + Unpin>(
    mut reader: R,
    policy: &FetchPolicy,
    expected_sha256: Option<&Sha256Digest>,
    sink: &mut dyn ArtifactSink,
    metadata: FetchMetadata,
) -> Result<FetchReceipt, FetchError> {
    let mut state = StreamState::default();
    let mut buffer = [0_u8; 8192];
    loop {
        let read = tokio::time::timeout(policy.read_timeout, reader.read(&mut buffer))
            .await
            .map_err(|_| FetchError::Timeout { stage: "read" })?
            .map_err(|source| FetchError::Io {
                stage: "read",
                source,
            })?;
        if read == 0 {
            return state.finish(metadata, expected_sha256);
        }
        write_checked_chunk(&mut state, policy, sink, &buffer[..read]).await?;
    }
}

#[derive(Default)]
struct StreamState {
    hasher: Sha256,
    bytes_written: u64,
}

impl StreamState {
    fn finish(
        self,
        metadata: FetchMetadata,
        expected_sha256: Option<&Sha256Digest>,
    ) -> Result<FetchReceipt, FetchError> {
        let digest = Sha256Digest::new(self.hasher.finalize().into());
        if let Some(expected) = expected_sha256
            && expected != &digest
        {
            return Err(FetchError::DigestMismatch {
                expected: expected.clone(),
                actual: digest,
            });
        }
        Ok(FetchReceipt {
            artifact_id: ArtifactId(digest.clone()),
            sha256: digest,
            bytes_written: self.bytes_written,
            metadata,
        })
    }
}

async fn write_checked_chunk(
    state: &mut StreamState,
    policy: &FetchPolicy,
    sink: &mut dyn ArtifactSink,
    chunk: &[u8],
) -> Result<(), FetchError> {
    let chunk_len = u64::try_from(chunk.len()).map_err(|_| FetchError::SizeExceeded {
        kind: SizeLimitKind::Compressed,
        limit: policy.max_compressed_size,
        observed: u64::MAX,
    })?;
    let observed = state.bytes_written.saturating_add(chunk_len);
    enforce_size(
        observed,
        policy.max_compressed_size,
        SizeLimitKind::Compressed,
    )?;
    enforce_size(
        observed,
        policy.max_uncompressed_size,
        SizeLimitKind::Uncompressed,
    )?;
    sink.write_chunk(chunk).await?;
    state.hasher.update(chunk);
    state.bytes_written = observed;
    Ok(())
}

fn enforce_size(observed: u64, limit: u64, kind: SizeLimitKind) -> Result<(), FetchError> {
    if observed > limit {
        return Err(FetchError::SizeExceeded {
            kind,
            limit,
            observed,
        });
    }
    Ok(())
}

async fn resolve_url_addrs(url: &Url, policy: &FetchPolicy) -> Result<Vec<SocketAddr>, FetchError> {
    let Some(host) = url.host_str() else {
        return Ok(Vec::new());
    };
    let port = url.port_or_known_default().unwrap_or(443);

    // If the host is an IP literal, validate it directly before any DNS
    // resolution. This ensures consistent SSRF enforcement across platforms
    // (tokio::net::lookup_host behaves differently for IP literals on Windows).
    if let Ok(ip) = host.parse::<IpAddr>() {
        validate_ip_for_policy(ip, policy)?;
        return Ok(vec![SocketAddr::new(ip, port)]);
    }

    let addrs = tokio::net::lookup_host((host, port))
        .await
        .map_err(|source| FetchError::Io {
            stage: "resolve",
            source,
        })?;
    let mut socket_addrs = Vec::new();
    for addr in addrs {
        let ip = addr.ip();
        validate_ip_for_policy(ip, policy)?;
        if !socket_addrs.contains(&addr) {
            socket_addrs.push(addr);
        }
    }
    Ok(socket_addrs)
}

fn unique_ips(addrs: &[SocketAddr]) -> Vec<IpAddr> {
    let mut ips = Vec::new();
    for addr in addrs {
        let ip = addr.ip();
        if !ips.contains(&ip) {
            ips.push(ip);
        }
    }
    ips
}

fn validate_ip_for_policy(ip: IpAddr, policy: &FetchPolicy) -> Result<(), FetchError> {
    if validate_ip(ip) || policy.allow_loopback_addresses && ip.is_loopback() {
        return Ok(());
    }
    Err(FetchError::ProhibitedAddress { address: ip })
}

/// Returns true when `ip` is globally routable under Arbitraitor's SSRF policy.
#[must_use]
pub fn validate_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => validate_ipv4(ip),
        IpAddr::V6(ip) => validate_ipv6(ip),
    }
}

fn validate_ipv4(ip: Ipv4Addr) -> bool {
    !(ip.is_private()
        || ip.is_loopback()
        || ip.is_link_local()
        || ip.is_unspecified()
        || ip.is_multicast()
        || ipv4_in(ip, [0, 0, 0, 0], 8)
        || ipv4_in(ip, [100, 64, 0, 0], 10)
        || ipv4_in(ip, [192, 0, 0, 0], 24)
        || ipv4_in(ip, [192, 0, 2, 0], 24)
        || ipv4_in(ip, [192, 88, 99, 0], 24)
        || ipv4_in(ip, [198, 18, 0, 0], 15)
        || ipv4_in(ip, [198, 51, 100, 0], 24)
        || ipv4_in(ip, [203, 0, 113, 0], 24)
        || ipv4_in(ip, [240, 0, 0, 0], 4))
}

fn validate_ipv6(ip: Ipv6Addr) -> bool {
    if let Some(mapped) = ip.to_ipv4_mapped() {
        return validate_ipv4(mapped);
    }
    !(ip.is_loopback()
        || ip.is_unspecified()
        || ip.is_multicast()
        || ipv6_in(ip, [0, 0, 0, 0, 0, 0, 0, 0], 8)
        || ipv6_in(ip, [0xfc00, 0, 0, 0, 0, 0, 0, 0], 7)
        || ipv6_in(ip, [0xfe80, 0, 0, 0, 0, 0, 0, 0], 10)
        || ipv6_in(ip, [0x0064, 0xff9b, 0, 0, 0, 0, 0, 0], 96)
        || ipv6_in(ip, [0x0100, 0, 0, 0, 0, 0, 0, 0], 64)
        || ipv6_in(ip, [0x2001, 0, 0, 0, 0, 0, 0, 0], 23)
        || ipv6_in(ip, [0x2001, 0x0db8, 0, 0, 0, 0, 0, 0], 32)
        || ipv6_in(ip, [0x2002, 0, 0, 0, 0, 0, 0, 0], 16))
}

fn ipv4_in(ip: Ipv4Addr, network: [u8; 4], prefix: u32) -> bool {
    let ip = u32::from(ip);
    let network = u32::from(Ipv4Addr::from(network));
    let mask = u32::MAX.checked_shl(32 - prefix).unwrap_or(0);
    ip & mask == network & mask
}

fn ipv6_in(ip: Ipv6Addr, network: [u16; 8], prefix: u32) -> bool {
    let ip = u128::from(ip);
    let network = u128::from(Ipv6Addr::from(network));
    let mask = u128::MAX.checked_shl(128 - prefix).unwrap_or(0);
    ip & mask == network & mask
}

fn redirect_target(current: &Url, headers: &reqwest::header::HeaderMap) -> Result<Url, FetchError> {
    let location = headers
        .get(reqwest::header::LOCATION)
        .ok_or(FetchError::MalformedRedirect)?
        .to_str()
        .map_err(|_| FetchError::MalformedRedirect)?;
    current
        .join(location)
        .map_err(|_| FetchError::MalformedRedirect)
}

fn header_to_string(headers: &reqwest::header::HeaderMap, name: &str) -> Option<String> {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned)
}

/// Extracts response headers safe for receipt recording (spec §11.5).
/// Excludes Authorization, Cookie, Set-Cookie, and other credential-bearing headers.
fn extract_safe_headers(headers: &reqwest::header::HeaderMap) -> Vec<(String, String)> {
    const SAFE_HEADER_NAMES: &[&str] = &[
        "content-type",
        "content-length",
        "content-encoding",
        "cache-control",
        "etag",
        "last-modified",
        "server",
        "x-content-type-options",
        "x-frame-options",
        "strict-transport-security",
    ];
    let mut result = Vec::new();
    for name in SAFE_HEADER_NAMES {
        if let Some(value) = header_to_string(headers, name) {
            result.push(((*name).to_owned(), value));
        }
    }
    result
}

fn ensure_policy_allows(scheme: FetchScheme, policy: &FetchPolicy) -> Result<(), FetchError> {
    if policy.allows_scheme(scheme) {
        return Ok(());
    }
    Err(FetchError::InvalidScheme {
        scheme: scheme.as_str().to_owned(),
    })
}

fn ensure_required_digest(
    expected_sha256: Option<&Sha256Digest>,
    policy: &FetchPolicy,
) -> Result<(), FetchError> {
    if policy.require_digest && expected_sha256.is_none() {
        return Err(FetchError::RequiredDigestMissing);
    }
    Ok(())
}

fn ensure_scheme_allowed(
    scheme: Option<FetchScheme>,
    raw_scheme: &str,
    policy: &FetchPolicy,
) -> Result<(), FetchError> {
    let Some(scheme) = scheme else {
        return Err(FetchError::InvalidScheme {
            scheme: raw_scheme.to_owned(),
        });
    };
    ensure_policy_allows(scheme, policy)
}

/// Verifies the post-connect peer address matches an approved resolved address.
///
/// ADR-0018 §DNS rebinding defense: after the transport connects, the actual
/// peer address (reported via `getpeername` by reqwest) must be one of the
/// addresses that passed policy validation during resolution. A mismatch
/// indicates DNS rebinding between resolution and connection.
///
/// The error is redacted — it never includes addresses, preventing internal
/// topology leakage through diagnostics. When `connected` is `None` the peer
/// address could not be observed, so verification is skipped (the transport
/// backend did not expose it). When `resolved` is empty, verification fails
/// closed because there is no approved address to match against.
///
/// # Errors
///
/// Returns [`FetchError::PeerAddressMismatch`] when `connected` is present but
/// not contained in `resolved`, or when `resolved` is empty.
pub(crate) fn verify_connected_peer(
    connected: Option<IpAddr>,
    resolved: &[IpAddr],
) -> Result<(), FetchError> {
    let Some(connected) = connected else {
        return Ok(());
    };
    if resolved.is_empty() || !resolved.contains(&connected) {
        return Err(FetchError::PeerAddressMismatch);
    }
    Ok(())
}

/// Enforces HTTPS→HTTP redirect downgrade policy (ADR-0018 §Redirect handling).
///
/// A redirect from HTTPS to HTTP removes transport encryption. This is blocked
/// by default even when both schemes are allowed by policy. Callers must
/// explicitly opt in via [`FetchPolicy::allow_https_to_http_redirect`].
/// HTTP→HTTPS is always permitted (it is an upgrade, not a downgrade).
///
/// # Errors
///
/// Returns [`FetchError::InsecureRedirectDowngrade`] when the redirect
/// downgrades from `https` to `http` and the policy does not allow it.
pub(crate) fn ensure_no_insecure_downgrade(
    from_scheme: &str,
    to_scheme: &str,
    policy: &FetchPolicy,
) -> Result<(), FetchError> {
    if from_scheme == "https" && to_scheme == "http" && !policy.allow_https_to_http_redirect {
        return Err(FetchError::InsecureRedirectDowngrade);
    }
    Ok(())
}

/// Enforces cross-origin redirect policy (spec §11.2 lines 608-612, §11.4
/// lines 644-653).
///
/// Two URLs are same-origin when scheme, host, and port all match. When
/// [`FetchPolicy::allow_cross_origin_redirect`] is `false`, any redirect to
/// a different origin returns [`FetchError::CrossOriginRedirect`]. When
/// `true` (the default), cross-origin redirects are permitted, but
/// [`FetchPolicy::forward_authorization_cross_origin`] gates whether
/// credential-bearing headers survive across the boundary.
///
/// The same-origin comparison is deliberately strict: a redirect from
/// `https://example.com` to `https://example.com:443` is treated as
/// cross-origin because the explicit port differs from the implicit one.
/// This is more conservative than the web-origin model but safer for a
/// download gate that has no `SameSite` cookie semantics to worry about.
///
/// # Errors
///
/// Returns [`FetchError::CrossOriginRedirect`] when the redirect crosses
/// an origin boundary and the policy does not allow it.
pub(crate) fn ensure_cross_origin_allowed(
    from: &Url,
    to: &Url,
    policy: &FetchPolicy,
) -> Result<(), FetchError> {
    if policy.allow_cross_origin_redirect {
        return Ok(());
    }
    if same_origin(from, to) {
        return Ok(());
    }
    Err(FetchError::CrossOriginRedirect)
}

/// Reports whether two URLs share the same origin (scheme + host + port).
///
/// Port comparison is explicit rather than scheme-defaulting —
/// `https://h` and `https://h:443` are treated as different origins
/// because the textual port differs. This is conservative but
/// predictable.
fn same_origin(a: &Url, b: &Url) -> bool {
    a.scheme() == b.scheme() && a.host_str() == b.host_str() && a.port() == b.port()
}

/// Strips credential-bearing headers when the redirect crosses origin
/// boundaries and the policy does not allow forwarding (spec §11.2).
///
/// When `forward_authorization_cross_origin` is `false`, any redirect
/// that lands on a different origin (scheme + host + port) triggers
/// removal of `Authorization` and `Cookie` headers from the header map.
/// When `true`, headers are preserved unchanged.
///
/// Not yet called from the redirect loop because `execute_request`
/// sends a bare GET with no user-supplied headers (tracked in #498).
/// When #498 wires header input, this function becomes the gate that
/// prevents credential leakage on cross-origin redirects.
#[allow(dead_code)]
pub(crate) fn strip_credentials_on_cross_origin(
    headers: &mut reqwest::header::HeaderMap,
    from: &Url,
    to: &Url,
    policy: &FetchPolicy,
) {
    if policy.forward_authorization_cross_origin {
        return;
    }
    if same_origin(from, to) {
        return;
    }
    headers.remove(reqwest::header::AUTHORIZATION);
    headers.remove(reqwest::header::COOKIE);
}

fn classify_reqwest_error(stage: &'static str, error: reqwest::Error) -> FetchError {
    if error.is_timeout() {
        return FetchError::Timeout { stage };
    }
    if error.is_status()
        && let Some(status) = error.status()
    {
        return FetchError::HttpStatus {
            status: status.as_u16(),
        };
    }
    let message = error.without_url().to_string();
    if message.contains("Connection refused") || message.contains("connection refused") {
        return FetchError::ConnectionRefused;
    }
    if message.contains("tls") || message.contains("certificate") || message.contains("rustls") {
        return FetchError::TlsFailure;
    }
    warn!(
        stage,
        "HTTP transport error classified as generic transport failure"
    );
    FetchError::Transport { stage, message }
}

fn sha256_digest(bytes: &[u8]) -> Sha256Digest {
    Sha256Digest::new(Sha256::digest(bytes).into())
}

/// Redacts credentials and secret-bearing URL components for safe diagnostics.
#[must_use]
pub fn redact_url(value: &str) -> String {
    Url::parse(value).map_or_else(
        |_| "<invalid-url>".to_owned(),
        |url| redact_parsed_url(&url),
    )
}

fn redact_parsed_url(url: &Url) -> String {
    let mut redacted = url.clone();
    redacted.set_query(None);
    let _ = redacted.set_username("");
    let _ = redacted.set_password(None);
    if should_redact_host(&redacted) {
        let _ = redacted.set_host(Some("redacted-host.invalid"));
    }
    let sanitized_path = sanitized_path(redacted.path_segments());
    redacted.set_path(&sanitized_path);
    redacted.to_string()
}

fn should_redact_host(url: &Url) -> bool {
    let Some(host) = url.host_str() else {
        return false;
    };
    host.parse::<IpAddr>().is_err() && !host.contains('.')
}

fn sanitized_path<'a>(segments: Option<impl Iterator<Item = &'a str>>) -> String {
    let Some(segments) = segments else {
        return String::new();
    };
    let mut redact_next = false;
    let mut sanitized = Vec::new();
    for segment in segments {
        let lower = segment.to_ascii_lowercase();
        if redact_next || is_sensitive_path_segment(&lower) {
            sanitized.push("redacted".to_owned());
            redact_next = !redact_next;
        } else {
            sanitized.push(segment.to_owned());
            redact_next = lower == "token" || lower == "secret" || lower == "key";
        }
    }
    sanitized.join("/")
}

fn is_sensitive_path_segment(segment: &str) -> bool {
    matches!(
        segment,
        "token" | "secret" | "password" | "passwd" | "credential" | "credentials" | "apikey"
    )
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use std::net::{IpAddr, Ipv4Addr};

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    use super::{
        FetchError, FetchPolicy, FetchScheme, build_http_client, ensure_cross_origin_allowed,
        ensure_no_insecure_downgrade, execute_request, strip_credentials_on_cross_origin,
        verify_connected_peer,
    };
    use url::Url;

    #[tokio::test]
    async fn client_pins_validated_address_for_request() -> Result<(), Box<dyn std::error::Error>> {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await?;
        let addr = listener.local_addr()?;
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await?;
            let mut request = Vec::new();
            let mut buffer = [0_u8; 1024];
            loop {
                let read = stream.read(&mut buffer).await?;
                if read == 0 {
                    break;
                }
                request.extend_from_slice(&buffer[..read]);
                if request.windows(4).any(|window| window == b"\r\n\r\n") {
                    break;
                }
            }
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
                .await?;
            stream.shutdown().await?;
            Ok::<String, std::io::Error>(String::from_utf8_lossy(&request).to_ascii_lowercase())
        });

        let url = format!("http://rebind.invalid:{}/artifact", addr.port()).parse()?;
        let policy = FetchPolicy {
            allow_loopback_addresses: true,
            ..FetchPolicy::default()
        };
        let client = build_http_client(&policy, &url, &[addr])?;

        let response = execute_request(&client, url).await?;

        assert_eq!(response.status(), reqwest::StatusCode::OK);
        let request = server.await??;
        assert!(request.contains(&format!("host: rebind.invalid:{}", addr.port())));
        Ok(())
    }

    // --- ADR-0018: post-connect peer verification (Issue #383) ---

    #[test]
    fn verify_connected_peer_accepts_matching_address() {
        let resolved = vec![
            IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10)),
            IpAddr::V4(Ipv4Addr::new(198, 51, 100, 5)),
        ];
        let result =
            verify_connected_peer(Some(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10))), &resolved);
        assert!(
            result.is_ok(),
            "connected IP in resolved set must pass: {result:?}"
        );
    }

    #[test]
    fn verify_connected_peer_rejects_mismatch() {
        let resolved = vec![IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10))];
        let connected = IpAddr::V4(Ipv4Addr::LOCALHOST); // DNS rebinding to loopback
        let result = verify_connected_peer(Some(connected), &resolved);
        assert!(
            matches!(result, Err(FetchError::PeerAddressMismatch)),
            "rebinding to non-resolved IP must be blocked, got {result:?}"
        );
    }

    #[test]
    fn verify_connected_peer_rejects_when_resolved_empty() {
        // No approved addresses to compare against — fail closed.
        let result = verify_connected_peer(Some(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10))), &[]);
        assert!(
            matches!(result, Err(FetchError::PeerAddressMismatch)),
            "connected IP with no resolved set must fail closed, got {result:?}"
        );
    }

    #[test]
    fn verify_connected_peer_message_is_redacted() -> Result<(), Box<dyn std::error::Error>> {
        // The error must NOT leak the connected or resolved addresses.
        let resolved = vec![IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10))];
        let connected = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let error = verify_connected_peer(Some(connected), &resolved)
            .err()
            .ok_or("expected PeerAddressMismatch for non-resolved connected IP")?;
        let message = format!("{error}");
        assert!(
            !message.contains("10.0.0.1"),
            "error must not leak connected IP: {message}"
        );
        assert!(
            !message.contains("203.0.113.10"),
            "error must not leak resolved IP: {message}"
        );
        Ok(())
    }

    // --- ADR-0018: HTTPS→HTTP redirect downgrade (Issue #383) ---

    #[test]
    fn insecure_downgrade_blocked_by_default() {
        let policy = FetchPolicy {
            allowed_schemes: vec![FetchScheme::Http, FetchScheme::Https],
            ..FetchPolicy::default()
        };
        let result = ensure_no_insecure_downgrade("https", "http", &policy);
        assert!(
            matches!(result, Err(FetchError::InsecureRedirectDowngrade)),
            "HTTPS→HTTP downgrade must be blocked by default, got {result:?}"
        );
    }

    #[test]
    fn insecure_downgrade_allowed_when_opted_in() {
        let policy = FetchPolicy {
            allowed_schemes: vec![FetchScheme::Http, FetchScheme::Https],
            allow_https_to_http_redirect: true,
            ..FetchPolicy::default()
        };
        let result = ensure_no_insecure_downgrade("https", "http", &policy);
        assert!(
            result.is_ok(),
            "explicit opt-in must allow downgrade: {result:?}"
        );
    }

    #[test]
    fn same_scheme_redirect_not_a_downgrade() {
        let policy = FetchPolicy::default();
        assert!(ensure_no_insecure_downgrade("https", "https", &policy).is_ok());
        assert!(ensure_no_insecure_downgrade("http", "http", &policy).is_ok());
    }

    #[test]
    fn http_to_https_is_an_upgrade_not_blocked() {
        let policy = FetchPolicy::default();
        let result = ensure_no_insecure_downgrade("http", "https", &policy);
        assert!(
            result.is_ok(),
            "HTTP→HTTPS upgrade must never be blocked: {result:?}"
        );
    }

    #[test]
    fn fetch_policy_defaults_block_https_to_http_downgrade() {
        let policy = FetchPolicy::default();
        assert!(
            !policy.allow_https_to_http_redirect,
            "default policy must block HTTPS→HTTP downgrade (fail-closed)"
        );
    }

    // -----------------------------------------------------------------
    // Cross-origin redirect policy (spec §11.2, §11.4)
    // -----------------------------------------------------------------

    #[test]
    fn fetch_policy_defaults_allow_cross_origin_redirects() {
        let policy = FetchPolicy::default();
        assert!(
            policy.allow_cross_origin_redirect,
            "default policy must allow cross-origin redirects (spec §11.4 default = true; \
             GitHub release → CDN is the common case)"
        );
    }

    #[test]
    fn fetch_policy_defaults_block_cross_origin_authorization_forwarding() {
        let policy = FetchPolicy::default();
        assert!(
            !policy.forward_authorization_cross_origin,
            "default policy must block cross-origin Authorization forwarding (spec §11.2; \
             fail-closed credential-leak defence)"
        );
    }

    #[test]
    fn cross_origin_redirect_blocked_when_disallowed() {
        let policy = FetchPolicy {
            allow_cross_origin_redirect: false,
            ..FetchPolicy::default()
        };
        let from = Url::parse("https://example.com/a").unwrap();
        let to = Url::parse("https://cdn.example.net/b").unwrap();
        let result = ensure_cross_origin_allowed(&from, &to, &policy);
        assert!(
            matches!(result, Err(FetchError::CrossOriginRedirect)),
            "cross-origin redirect must be blocked when policy disallows it: {result:?}"
        );
    }

    #[test]
    fn same_origin_redirect_allowed_when_cross_origin_disallowed() {
        let policy = FetchPolicy {
            allow_cross_origin_redirect: false,
            ..FetchPolicy::default()
        };
        let from = Url::parse("https://example.com/a").unwrap();
        let to = Url::parse("https://example.com/b").unwrap();
        let result = ensure_cross_origin_allowed(&from, &to, &policy);
        assert!(
            result.is_ok(),
            "same-origin redirect must always be allowed: {result:?}"
        );
    }

    #[test]
    fn cross_origin_redirect_allowed_when_policy_permits() {
        let policy = FetchPolicy {
            allow_cross_origin_redirect: true,
            ..FetchPolicy::default()
        };
        let from = Url::parse("https://example.com/a").unwrap();
        let to = Url::parse("https://cdn.example.net/b").unwrap();
        let result = ensure_cross_origin_allowed(&from, &to, &policy);
        assert!(
            result.is_ok(),
            "cross-origin redirect must be allowed when policy opts in: {result:?}"
        );
    }

    #[test]
    fn different_port_is_treated_as_cross_origin() {
        let policy = FetchPolicy {
            allow_cross_origin_redirect: false,
            ..FetchPolicy::default()
        };
        let from = Url::parse("https://example.com/a").unwrap();
        let to = Url::parse("https://example.com:8443/b").unwrap();
        let result = ensure_cross_origin_allowed(&from, &to, &policy);
        assert!(
            matches!(result, Err(FetchError::CrossOriginRedirect)),
            "explicit different port must be treated as cross-origin (conservative; \
             web-origin would normalize ports but a download gate cannot rely on \
             SameSite cookie semantics): {result:?}"
        );
    }

    #[test]
    fn different_scheme_is_treated_as_cross_origin() {
        let policy = FetchPolicy {
            allow_cross_origin_redirect: false,
            ..FetchPolicy::default()
        };
        let from = Url::parse("https://example.com/a").unwrap();
        let to = Url::parse("http://example.com/b").unwrap();
        let result = ensure_cross_origin_allowed(&from, &to, &policy);
        assert!(
            matches!(result, Err(FetchError::CrossOriginRedirect)),
            "scheme change is cross-origin: {result:?}"
        );
    }

    // -----------------------------------------------------------------
    // Credential stripping on cross-origin redirects (spec §11.2)
    // -----------------------------------------------------------------

    #[test]
    fn strip_credentials_removes_authorization_on_cross_origin() {
        let policy = FetchPolicy::default();
        let from = Url::parse("https://example.com/a").unwrap();
        let to = Url::parse("https://cdn.example.net/b").unwrap();
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert(
            reqwest::header::AUTHORIZATION,
            reqwest::header::HeaderValue::from_static("Bearer secret123"),
        );
        headers.insert(
            reqwest::header::COOKIE,
            reqwest::header::HeaderValue::from_static("session=abc"),
        );

        strip_credentials_on_cross_origin(&mut headers, &from, &to, &policy);

        assert!(
            headers.get(reqwest::header::AUTHORIZATION).is_none(),
            "Authorization MUST be stripped on cross-origin redirect"
        );
        assert!(
            headers.get(reqwest::header::COOKIE).is_none(),
            "Cookie MUST be stripped on cross-origin redirect"
        );
    }

    #[test]
    fn strip_credentials_preserves_headers_on_same_origin() {
        let policy = FetchPolicy::default();
        let from = Url::parse("https://example.com/a").unwrap();
        let to = Url::parse("https://example.com/b").unwrap();
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert(
            reqwest::header::AUTHORIZATION,
            reqwest::header::HeaderValue::from_static("Bearer secret123"),
        );

        strip_credentials_on_cross_origin(&mut headers, &from, &to, &policy);

        assert!(
            headers.get(reqwest::header::AUTHORIZATION).is_some(),
            "Authorization MUST be preserved on same-origin redirect"
        );
    }

    #[test]
    fn strip_credentials_preserves_headers_when_opted_in() {
        let policy = FetchPolicy {
            forward_authorization_cross_origin: true,
            ..FetchPolicy::default()
        };
        let from = Url::parse("https://example.com/a").unwrap();
        let to = Url::parse("https://cdn.example.net/b").unwrap();
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert(
            reqwest::header::AUTHORIZATION,
            reqwest::header::HeaderValue::from_static("Bearer secret123"),
        );

        strip_credentials_on_cross_origin(&mut headers, &from, &to, &policy);

        assert!(
            headers.get(reqwest::header::AUTHORIZATION).is_some(),
            "Authorization MUST be preserved when policy opts in to cross-origin forwarding"
        );
    }
}
