//! Feed adapter trait and ingestion pipeline.
//!
//! A [`FeedAdapter`] translates a vendor-specific feed payload into
//! [`FeedEntry`] records via a pure [`FeedAdapter::parse`] implementation.
//! Network retrieval is owned by the caller-supplied
//! [`arbitraitor_fetch::Fetcher`] so the same SSRF, TLS, and byte-limit policy
//! that governs artifact retrieval governs feed retrieval. No reqwest types
//! cross this boundary (ADR 0003).

#![allow(clippy::module_name_repetitions)]

use arbitraitor_fetch::{FetchPolicy, FetchRequest, FetchUrl, Fetcher, VecSink};
use tracing::{debug, instrument, warn};

use crate::{FeedEntry, FeedSourceClass, IntelError, IntelStore, Result};

/// Shared behavior for a threat-intelligence feed source.
///
/// Adapters expose a stable name, source trust class, and an offline indicator
/// retrieval surface. Network-backed adapters may additionally override
/// [`FeedAdapter::feed_url`] and [`FeedAdapter::parse`] so [`ingest_feed`] can
/// retrieve payloads through [`arbitraitor_fetch::Fetcher`].
pub trait FeedAdapter: Send + Sync {
    /// Stable lowercase source label written into entries and reports.
    fn name(&self) -> &str;

    /// Return indicators available from the adapter's configured offline source.
    ///
    /// # Errors
    ///
    /// Returns an adapter-specific [`IntelError`] when the offline source cannot
    /// be read or decoded.
    fn fetch_indicators(&self) -> Result<Vec<FeedEntry>>;

    /// Source trust class advertised on entries produced by this adapter.
    fn source_class(&self) -> FeedSourceClass;

    /// Canonical URL fetched by [`ingest_feed`].
    ///
    /// Offline-only adapters return an empty string and therefore cannot be
    /// passed to [`ingest_feed`].
    fn feed_url(&self) -> &str;

    /// Decode a fetched feed payload into [`FeedEntry`] records.
    ///
    /// Offline-only adapters use [`FeedAdapter::fetch_indicators`] by default.
    /// Network-backed adapters override this method to parse `bytes`.
    ///
    /// # Errors
    ///
    /// Returns an adapter-specific [`IntelError`] when indicators cannot be
    /// read or the payload cannot be decoded.
    fn parse(&self, _bytes: &[u8]) -> Result<Vec<FeedEntry>> {
        self.fetch_indicators()
    }
}

/// Statistics produced by merging a batch of feed entries into an [`IntelStore`].
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct IngestionReport {
    /// Source label copied from [`FeedAdapter::name`].
    pub source: String,
    /// Entries inserted into the store for the first time.
    pub entries_added: usize,
    /// Entries that replaced an existing record with the same identifier.
    pub entries_updated: usize,
    /// Entries removed from the store by expiry during this ingestion.
    pub entries_expired: usize,
    /// Safe diagnostic messages for rows that could not be stored.
    pub errors: Vec<String>,
}

impl IngestionReport {
    /// Creates an empty report anchored to `source`.
    #[must_use]
    pub fn for_source(source: impl Into<String>) -> Self {
        Self {
            source: source.into(),
            entries_added: 0,
            entries_updated: 0,
            entries_expired: 0,
            errors: Vec::new(),
        }
    }
}

/// Fetch a feed through `fetcher`, parse it via `adapter`, and merge the
/// resulting entries into `store`.
///
/// Network access is delegated to `fetcher` so the same SSRF, TLS, redirect,
/// and byte-limit policy that governs artifact retrieval governs feed
/// retrieval. The parsed entries are merged with a single store persist via
/// [`IntelStore::merge_entries`], then expired entries are purged.
///
/// # Errors
///
/// Returns [`IntelError::Fetch`] when retrieval fails,
/// [`IntelError::FeedDecode`] when the adapter cannot decode the payload, and
/// store I/O errors when the merge cannot be persisted.
#[instrument(skip(adapter, fetcher, store, policy), fields(source = adapter.name()))]
pub async fn ingest_feed(
    adapter: &dyn FeedAdapter,
    fetcher: &dyn Fetcher,
    store: &mut IntelStore,
    policy: &FetchPolicy,
) -> Result<IngestionReport> {
    let fetch_url =
        FetchUrl::parse(adapter.feed_url()).map_err(|error| IntelError::FeedDecode {
            reason: format!("invalid feed URL: {error}"),
        })?;
    let request = FetchRequest::url(fetch_url, policy.clone());
    let mut sink = VecSink::new();
    let receipt = fetcher
        .fetch(request, &mut sink)
        .await
        .map_err(IntelError::Fetch)?;
    let bytes = sink.into_bytes();
    debug!(
        source = adapter.name(),
        bytes = receipt.bytes_written,
        "fetched feed payload"
    );

    let entries = adapter.parse(&bytes)?;
    let mut report = ingest_entries(entries, store, adapter.name())?;
    match store.purge_expired() {
        Ok(expired) => {
            report.entries_expired = expired;
        }
        Err(error) => {
            warn!(
                source = report.source.as_str(),
                "failed to purge expired entries after ingestion: {error}"
            );
            report.errors.push(error.to_string());
        }
    }
    Ok(report)
}

/// Merge parsed entries into `store`, returning an [`IngestionReport`].
///
/// Unlike [`ingest_feed`], this performs no network I/O and is suitable for
/// tests, offline imports, and adapters that source bytes through a channel
/// other than [`arbitraitor_fetch::Fetcher`].
///
/// # Errors
///
/// Returns store I/O errors when [`IntelStore::merge_entries`] cannot persist.
pub fn ingest_entries(
    entries: Vec<FeedEntry>,
    store: &mut IntelStore,
    source: &str,
) -> Result<IngestionReport> {
    let (added, updated) = store.merge_entries(entries)?;
    Ok(IngestionReport {
        source: source.to_owned(),
        entries_added: added,
        entries_updated: updated,
        entries_expired: 0,
        errors: Vec::new(),
    })
}
