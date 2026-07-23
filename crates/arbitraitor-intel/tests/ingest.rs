//! Integration tests for the feed ingestion pipeline.
//!
//! These tests drive [`arbitraitor_intel::ingest_feed`] with a mock
//! [`Fetcher`] so no real HTTP traffic is generated.

#![allow(clippy::module_name_repetitions)]

use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use arbitraitor_fetch::{
    ArtifactSink, FetchError, FetchMetadata, FetchPolicy, FetchReceipt, FetchRequest, Fetcher,
};
use arbitraitor_intel::{
    FeedSourceClass, Indicator, IndicatorType, IntelStore, UrlhausAdapter, ingest_feed,
    match_indicator,
};
use arbitraitor_model::ids::{ArtifactId, Sha256Digest};
use async_trait::async_trait;
use sha2::{Digest, Sha256};

const CSV_PAYLOAD: &str = "\
# generated: 2026-06-18
\"id\",\"dateadded\",\"url\",\"url_status\",\"threat\",\"tags\",\"urlhaus_link\"
\"1\",\"2026-06-18 08:00:00 UTC\",\"http://evil.example/payload\",\"online\",\"malware_download\",\"Loader\",\"https://urlhaus.abuse.ch/url/1/\"
\"2\",\"2026-06-18 09:00:00 UTC\",\"http://evil.example/dropper\",\"offline\",\"malware_download\",\"\",\"https://urlhaus.abuse.ch/url/2/\"
";

const JSON_PAYLOAD: &str = r#"{
  "query_status": "ok",
  "url_count": 1,
  "urls": [
    {
      "id": "77",
      "url": "http://evil.example/api-payload",
      "url_status": "online",
      "date_added": "2026-06-18 11:00:00 UTC",
      "threat": "malware_download",
      "tags": "Banker",
      "urlhaus_link": "https://urlhaus.abuse.ch/url/77/"
    }
  ]
}"#;

/// Test [`Fetcher`] that returns a fixed byte payload regardless of request.
struct CannedFetcher {
    bytes: Vec<u8>,
    requests: AtomicUsize,
}

impl CannedFetcher {
    fn new(bytes: &[u8]) -> Self {
        Self {
            bytes: bytes.to_vec(),
            requests: AtomicUsize::new(0),
        }
    }

    fn request_count(&self) -> usize {
        self.requests.load(Ordering::Relaxed)
    }
}

#[async_trait]
impl Fetcher for CannedFetcher {
    async fn fetch(
        &self,
        _request: FetchRequest,
        sink: &mut dyn ArtifactSink,
    ) -> Result<FetchReceipt, FetchError> {
        self.requests.fetch_add(1, Ordering::Relaxed);
        sink.write_chunk(&self.bytes)
            .await
            .map_err(FetchError::from)?;
        let digest = Sha256Digest::new(Sha256::digest(&self.bytes).into());
        Ok(FetchReceipt {
            artifact_id: ArtifactId(digest.clone()),
            sha256: digest,
            bytes_written: u64::try_from(self.bytes.len()).unwrap_or(0),
            metadata: FetchMetadata::default(),
            child_artifacts: Vec::new(),
        })
    }
}

#[tokio::test]
async fn ingest_feed_csv_populates_store_and_reports_counts()
-> Result<(), Box<dyn std::error::Error>> {
    let store_path = unique_store_path("ingest-csv");
    let mut store = IntelStore::open(&store_path)?;
    let fetcher = CannedFetcher::new(CSV_PAYLOAD.as_bytes());
    let adapter = UrlhausAdapter::with_url("https://urlhaus.test/downloads/csv/");

    let report = ingest_feed(&adapter, &fetcher, &mut store, &FetchPolicy::default()).await?;

    assert_eq!(report.source, "urlhaus");
    assert_eq!(report.entries_added, 2);
    assert_eq!(report.entries_updated, 0);
    assert_eq!(fetcher.request_count(), 1);
    assert_eq!(store.entries().len(), 2);
    let _ = std::fs::remove_file(store_path);
    Ok(())
}

#[tokio::test]
async fn ingest_feed_json_populates_store() -> Result<(), Box<dyn std::error::Error>> {
    let store_path = unique_store_path("ingest-json");
    let mut store = IntelStore::open(&store_path)?;
    let fetcher = CannedFetcher::new(JSON_PAYLOAD.as_bytes());
    let adapter = UrlhausAdapter::with_url("https://urlhaus-api.test/v1/urls/recent/");

    let report = ingest_feed(&adapter, &fetcher, &mut store, &FetchPolicy::default()).await?;

    assert_eq!(report.entries_added, 1);
    let entry = &store.entries()[0];
    assert_eq!(entry.id, "urlhaus:77");
    assert_eq!(entry.indicator.value, "http://evil.example/api-payload");
    let _ = std::fs::remove_file(store_path);
    Ok(())
}

#[tokio::test]
async fn ingest_feed_then_match_indicator_finds_url() -> Result<(), Box<dyn std::error::Error>> {
    let store_path = unique_store_path("ingest-match");
    let mut store = IntelStore::open(&store_path)?;
    let fetcher = CannedFetcher::new(CSV_PAYLOAD.as_bytes());
    let adapter = UrlhausAdapter::with_url("https://urlhaus.test/downloads/csv/");
    ingest_feed(&adapter, &fetcher, &mut store, &FetchPolicy::default()).await?;

    let matches = match_indicator(
        &store,
        &Indicator {
            indicator_type: IndicatorType::ExactUrl,
            value: "http://evil.example/payload".to_owned(),
        },
    );
    assert_eq!(matches.len(), 1);
    assert_eq!(
        matches[0].entry.source_class,
        FeedSourceClass::Authoritative
    );
    assert_eq!(
        matches[0].entry.indicator.value,
        "http://evil.example/payload"
    );
    let _ = std::fs::remove_file(store_path);
    Ok(())
}

#[tokio::test]
async fn ingest_feed_re_ingest_updates_existing_entries() -> Result<(), Box<dyn std::error::Error>>
{
    let store_path = unique_store_path("ingest-update");
    let mut store = IntelStore::open(&store_path)?;
    let fetcher = CannedFetcher::new(CSV_PAYLOAD.as_bytes());
    let adapter = UrlhausAdapter::with_url("https://urlhaus.test/downloads/csv/");

    let first = ingest_feed(&adapter, &fetcher, &mut store, &FetchPolicy::default()).await?;
    assert_eq!(first.entries_added, 2);

    let second = ingest_feed(&adapter, &fetcher, &mut store, &FetchPolicy::default()).await?;
    assert_eq!(second.entries_added, 0);
    assert_eq!(second.entries_updated, 2);
    assert_eq!(store.entries().len(), 2);
    let _ = std::fs::remove_file(store_path);
    Ok(())
}

#[tokio::test]
async fn ingest_feed_empty_payload_reports_zero_entries() -> Result<(), Box<dyn std::error::Error>>
{
    let store_path = unique_store_path("ingest-empty");
    let mut store = IntelStore::open(&store_path)?;
    let fetcher = CannedFetcher::new(b"");
    let adapter = UrlhausAdapter::with_url("https://urlhaus.test/downloads/csv/");

    let report = ingest_feed(&adapter, &fetcher, &mut store, &FetchPolicy::default()).await?;

    assert_eq!(report.entries_added, 0);
    assert!(store.entries().is_empty());
    let _ = std::fs::remove_file(store_path);
    Ok(())
}

#[tokio::test]
async fn ingest_feed_malformed_payload_returns_decode_error() {
    let store_path = unique_store_path("ingest-malformed");
    let Ok(mut store) = IntelStore::open(&store_path) else {
        return;
    };
    let fetcher = CannedFetcher::new(b"{ not valid json");
    let adapter = UrlhausAdapter::with_url("https://urlhaus-api.test/v1/");
    let result = ingest_feed(&adapter, &fetcher, &mut store, &FetchPolicy::default()).await;
    assert!(result.is_err());
    let _ = std::fs::remove_file(store_path);
}

#[tokio::test]
async fn ingest_feed_propagates_fetch_failure() {
    let store_path = unique_store_path("ingest-fetch-error");
    let Ok(mut store) = IntelStore::open(&store_path) else {
        return;
    };
    let fetcher = ErrorFetcher;
    let adapter = UrlhausAdapter::with_url("https://urlhaus.test/downloads/csv/");
    let result = ingest_feed(&adapter, &fetcher, &mut store, &FetchPolicy::default()).await;
    assert!(result.is_err());
    let _ = std::fs::remove_file(store_path);
}

/// [`Fetcher`] that always returns a [`FetchError`] without network access.
struct ErrorFetcher;

#[async_trait]
impl Fetcher for ErrorFetcher {
    async fn fetch(
        &self,
        _request: FetchRequest,
        _sink: &mut dyn ArtifactSink,
    ) -> Result<FetchReceipt, FetchError> {
        Err(FetchError::ConnectionRefused)
    }
}

fn unique_store_path(label: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    std::env::temp_dir().join(format!(
        "arbitraitor-intel-it-{label}-{}-{nanos}.json",
        std::process::id(),
    ))
}
