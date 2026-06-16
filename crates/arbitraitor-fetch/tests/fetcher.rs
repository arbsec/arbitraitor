//! Integration tests for fetch transports.

use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use arbitraitor_fetch::{
    FetchError, FetchPolicy, FetchRequest, FetchScheme, FetchUrl, Fetcher, FileFetcher,
    HttpFetcher, SizeLimitKind, VecSink,
};
use arbitraitor_model::ids::Sha256Digest;
use arbitraitor_testkit::mock_server::MockHttpServer;
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::task::JoinHandle;

fn http_policy() -> FetchPolicy {
    FetchPolicy {
        connect_timeout: Duration::from_secs(5),
        read_timeout: Duration::from_secs(5),
        total_timeout: Duration::from_secs(30),
        max_compressed_size: 1024 * 1024,
        max_uncompressed_size: 1024 * 1024,
        max_redirects: 0,
        allowed_schemes: vec![FetchScheme::Http],
    }
}

fn sha256(bytes: &[u8]) -> Sha256Digest {
    Sha256Digest::new(Sha256::digest(bytes).into())
}
#[tokio::test]
async fn http_fetch_streams_exact_response_bytes() -> Result<(), Box<dyn std::error::Error>> {
    let server = MockHttpServer::start().await;
    let bytes = b"\x00arbitraitor\xff";
    let url = server
        .binary_response(bytes, "application/octet-stream")
        .await;

    let mut sink = VecSink::new();
    let receipt = HttpFetcher::new()
        .fetch(
            FetchRequest::url(FetchUrl::parse(&url)?, http_policy()),
            &mut sink,
        )
        .await?;

    assert_eq!(sink.as_bytes(), bytes);
    assert_eq!(receipt.bytes_written, u64::try_from(bytes.len())?);
    assert_eq!(receipt.sha256, sha256(bytes));
    assert_eq!(receipt.artifact_id.0, receipt.sha256);
    assert_eq!(
        receipt.metadata.content_type.as_deref(),
        Some("application/octet-stream")
    );
    assert!(receipt.metadata.connected_ip.is_some());
    assert!(!receipt.metadata.resolved_ips.is_empty());
    Ok(())
}

#[tokio::test]
async fn http_fetch_sends_identity_and_does_not_decompress()
-> Result<(), Box<dyn std::error::Error>> {
    let encoded = vec![0x1f, 0x8b, 0x08, 0x00, b'a', b'b', b'c'];
    let (url, request_headers) = exact_byte_server(encoded.clone()).await?;

    let mut sink = VecSink::new();
    HttpFetcher::new()
        .fetch(
            FetchRequest::url(FetchUrl::parse(&url)?, http_policy()),
            &mut sink,
        )
        .await?;

    let headers = request_headers.await??;
    assert!(headers.contains("accept-encoding: identity"));
    assert_eq!(sink.into_bytes(), encoded);
    Ok(())
}
#[tokio::test]
async fn redirects_are_not_followed_by_default() -> Result<(), Box<dyn std::error::Error>> {
    let server = MockHttpServer::start().await;
    let url = server.redirect_chain(1).await;
    let mut sink = VecSink::new();

    let error = HttpFetcher::new()
        .fetch(
            FetchRequest::url(FetchUrl::parse(&url)?, http_policy()),
            &mut sink,
        )
        .await
        .err()
        .ok_or("redirect should fail with default policy")?;

    assert!(matches!(
        error,
        FetchError::RedirectLimitExceeded { limit: 0 }
    ));
    assert!(sink.as_bytes().is_empty());
    Ok(())
}

#[tokio::test]
async fn redirect_policy_records_chain_when_enabled() -> Result<(), Box<dyn std::error::Error>> {
    let server = MockHttpServer::start().await;
    let url = server.redirect_chain(2).await;
    let mut policy = http_policy();
    policy.max_redirects = 2;
    let mut sink = VecSink::new();

    let receipt = HttpFetcher::new()
        .fetch(FetchRequest::url(FetchUrl::parse(&url)?, policy), &mut sink)
        .await?;

    assert_eq!(sink.as_bytes(), b"redirect complete");
    assert_eq!(receipt.metadata.redirect_chain.len(), 2);
    assert!(receipt.metadata.final_url.is_some());
    Ok(())
}
#[tokio::test]
async fn size_limit_stops_streaming_before_sink_write() -> Result<(), Box<dyn std::error::Error>> {
    let server = MockHttpServer::start().await;
    let url = server.large_response(8).await;
    let mut policy = http_policy();
    policy.max_compressed_size = 4;
    let mut sink = VecSink::new();

    let error = HttpFetcher::new()
        .fetch(FetchRequest::url(FetchUrl::parse(&url)?, policy), &mut sink)
        .await
        .err()
        .ok_or("oversized response should fail")?;

    assert!(matches!(
        error,
        FetchError::SizeExceeded {
            kind: SizeLimitKind::Compressed,
            limit: 4,
            observed: 8
        }
    ));
    assert!(sink.as_bytes().is_empty());
    Ok(())
}

#[tokio::test]
async fn file_fetch_streams_local_bytes() -> Result<(), Box<dyn std::error::Error>> {
    let bytes = b"local artifact bytes";
    let path = temp_file_path()?;
    tokio::fs::write(&path, bytes).await?;
    let mut sink = VecSink::new();

    let receipt = FileFetcher::new()
        .fetch(
            FetchRequest::file(path.clone(), FetchPolicy::default()),
            &mut sink,
        )
        .await?;

    assert_eq!(sink.as_bytes(), bytes);
    assert_eq!(receipt.sha256, sha256(bytes));
    tokio::fs::remove_file(path).await?;
    Ok(())
}
async fn exact_byte_server(
    body: Vec<u8>,
) -> Result<(String, JoinHandle<Result<String, std::io::Error>>), std::io::Error> {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await?;
    let addr = listener.local_addr()?;
    let handle = tokio::spawn(async move {
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
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        );
        stream.write_all(response.as_bytes()).await?;
        stream.write_all(&body).await?;
        stream.shutdown().await?;
        Ok(String::from_utf8_lossy(&request).to_ascii_lowercase())
    });
    Ok((format!("http://{addr}/artifact"), handle))
}

fn temp_file_path() -> Result<PathBuf, std::time::SystemTimeError> {
    let nanos = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    Ok(std::env::temp_dir().join(format!("arbitraitor-fetch-test-{nanos}.bin")))
}
