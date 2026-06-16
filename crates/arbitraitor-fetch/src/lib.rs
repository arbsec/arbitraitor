//! HTTP retrieval and transport policy.
//!
//! This crate owns artifact retrieval. It deliberately keeps `reqwest` behind
//! [`Fetcher`] so storage, scanning, and execution code cannot depend on a
//! concrete HTTP client or inherit unsafe transport defaults.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use std::collections::HashSet;
use std::fmt;
use std::net::IpAddr;
use std::path::PathBuf;
use std::time::Duration;

use arbitraitor_model::ids::{ArtifactId, Sha256Digest};
use async_trait::async_trait;
use reqwest::Url;
use reqwest::header::{ACCEPT_ENCODING, CONTENT_LENGTH, CONTENT_TYPE, HeaderValue};
use sha2::{Digest, Sha256};
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt};
use tracing::{debug, instrument, trace, warn};

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
}

impl FetchRequest {
    /// Builds a URL fetch request.
    #[must_use]
    pub fn url(url: FetchUrl, policy: FetchPolicy) -> Self {
        Self {
            source: FetchSource::Url(url),
            policy,
        }
    }

    /// Builds a local file fetch request.
    #[must_use]
    pub fn file(path: PathBuf, policy: FetchPolicy) -> Self {
        Self {
            source: FetchSource::File(path),
            policy,
        }
    }

    /// Builds a standard input fetch request.
    #[must_use]
    pub const fn stdin(policy: FetchPolicy) -> Self {
        Self {
            source: FetchSource::Stdin,
            policy,
        }
    }
}

/// Transport policy applied by fetchers.
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
    ///
    /// Reqwest currently exposes the peer certificate but not the negotiated
    /// rustls protocol version through its stable public response API, so this
    /// is `None` for the MVP HTTP fetcher.
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

        let future = self.fetch_inner(url, &request.policy, sink);
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
        sink: &mut dyn ArtifactSink,
    ) -> Result<FetchReceipt, FetchError> {
        ensure_scheme_allowed(
            FetchScheme::from_str(url.as_url().scheme()),
            url.as_url().scheme(),
            policy,
        )?;
        let client = build_http_client(policy)?;
        let mut current = url.into_url();
        let mut visited = HashSet::new();
        let mut redirect_chain = Vec::new();

        for redirect_count in 0..=policy.max_redirects {
            if !visited.insert(current.clone()) {
                return Err(FetchError::RedirectLoop);
            }
            let resolved_ips = resolve_url_ips(&current).await?;
            debug!(url = %redacted_url(&current), resolved_count = resolved_ips.len(), "resolved fetch host");
            let response = execute_request(&client, current.clone(), policy).await?;
            let status = response.status();

            if status.is_redirection() {
                if redirect_count == policy.max_redirects {
                    return Err(FetchError::RedirectLimitExceeded {
                        limit: policy.max_redirects,
                    });
                }
                let next = redirect_target(&current, response.headers())?;
                ensure_scheme_allowed(FetchScheme::from_str(next.scheme()), next.scheme(), policy)?;
                trace!(from = %redacted_url(&current), to = %redacted_url(&next), "following policy-approved redirect");
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
        let file = tokio::fs::File::open(path)
            .await
            .map_err(|source| FetchError::Io {
                stage: "open",
                source,
            })?;
        stream_reader(file, &request.policy, sink, FetchMetadata::default()).await
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
        stream_reader(
            tokio::io::stdin(),
            &request.policy,
            sink,
            FetchMetadata::default(),
        )
        .await
    }
}

fn build_http_client(policy: &FetchPolicy) -> Result<reqwest::Client, FetchError> {
    reqwest::Client::builder()
        .use_rustls_tls()
        .connect_timeout(policy.connect_timeout)
        .read_timeout(policy.read_timeout)
        .timeout(policy.total_timeout)
        .redirect(reqwest::redirect::Policy::none())
        .no_proxy()
        .no_gzip()
        .no_brotli()
        .no_deflate()
        .no_zstd()
        .tls_info(true)
        .user_agent(format!("{USER_AGENT_PREFIX}{}", env!("CARGO_PKG_VERSION")))
        .build()
        .map_err(|error| classify_reqwest_error("client build", &error))
}

async fn execute_request(
    client: &reqwest::Client,
    url: Url,
    _policy: &FetchPolicy,
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
        .map_err(|error| classify_reqwest_error("request", &error))
}

async fn stream_response(
    mut response: reqwest::Response,
    policy: &FetchPolicy,
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
        final_url: Some(final_url),
        redirect_chain,
    };

    let mut state = StreamState::default();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|error| classify_reqwest_error("read", &error))?
    {
        write_checked_chunk(&mut state, policy, sink, &chunk).await?;
    }
    Ok(state.finish(metadata))
}

async fn stream_reader<R: AsyncRead + Unpin>(
    mut reader: R,
    policy: &FetchPolicy,
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
            return Ok(state.finish(metadata));
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
    fn finish(self, metadata: FetchMetadata) -> FetchReceipt {
        let digest = Sha256Digest::new(self.hasher.finalize().into());
        FetchReceipt {
            artifact_id: ArtifactId(digest.clone()),
            sha256: digest,
            bytes_written: self.bytes_written,
            metadata,
        }
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

async fn resolve_url_ips(url: &Url) -> Result<Vec<IpAddr>, FetchError> {
    let Some(host) = url.host_str() else {
        return Ok(Vec::new());
    };
    let port = url.port_or_known_default().unwrap_or(443);
    let addrs = tokio::net::lookup_host((host, port))
        .await
        .map_err(|source| FetchError::Io {
            stage: "resolve",
            source,
        })?;
    let mut ips = Vec::new();
    for addr in addrs {
        let ip = addr.ip();
        if !ips.contains(&ip) {
            ips.push(ip);
        }
    }
    Ok(ips)
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

fn ensure_policy_allows(scheme: FetchScheme, policy: &FetchPolicy) -> Result<(), FetchError> {
    if policy.allows_scheme(scheme) {
        return Ok(());
    }
    Err(FetchError::InvalidScheme {
        scheme: scheme.as_str().to_owned(),
    })
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

fn classify_reqwest_error(stage: &'static str, error: &reqwest::Error) -> FetchError {
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
    let message = error.to_string();
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

fn redacted_url(url: &Url) -> String {
    let mut redacted = url.clone();
    redacted.set_query(None);
    let _ = redacted.set_username("");
    let _ = redacted.set_password(None);
    redacted.to_string()
}
