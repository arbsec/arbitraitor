//! TTL-based response cache for inspection results.
//!
//! [`InspectionCache`] stores [`InspectionResult`] values keyed by URL.
//! Entries expire after the configured time-to-live. Expired entries are
//! treated as misses by [`InspectionCache::get`]; call
//! [`InspectionCache::evict_expired`] periodically to reclaim memory.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use std::collections::HashMap;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use crate::api::InspectionResult;

/// A time-to-live cache for inspection results keyed by URL.
///
/// Lookups are synchronous because the critical section (a single `HashMap`
/// probe) is too short to justify an async lock. The cache is safe to share
/// across threads via `&self`.
pub struct InspectionCache {
    entries: Arc<Mutex<HashMap<String, CachedInspection>>>,
    ttl: Duration,
}

struct CachedInspection {
    result: InspectionResult,
    cached_at: Instant,
}

impl InspectionCache {
    /// Creates a new cache with the given time-to-live.
    #[must_use]
    pub fn new(ttl: Duration) -> Self {
        Self {
            entries: Arc::new(Mutex::new(HashMap::new())),
            ttl,
        }
    }

    /// Returns a cached inspection result if the URL was inspected within the
    /// TTL window; `None` otherwise (including when the entry has expired or
    /// was never stored).
    #[must_use]
    pub fn get(&self, url: &str) -> Option<InspectionResult> {
        let entries = self.entries.lock().unwrap_or_else(PoisonError::into_inner);
        let cached = entries.get(url)?;
        if cached.cached_at.elapsed() < self.ttl {
            Some(cached.result.clone())
        } else {
            None
        }
    }

    /// Stores an inspection result for the given URL, overwriting any
    /// previous entry.
    pub fn put(&self, url: &str, result: InspectionResult) {
        let mut entries = self.entries.lock().unwrap_or_else(PoisonError::into_inner);
        entries.insert(
            url.to_owned(),
            CachedInspection {
                result,
                cached_at: Instant::now(),
            },
        );
    }

    /// Removes all entries whose age exceeds the configured TTL.
    pub fn evict_expired(&self) {
        let mut entries = self.entries.lock().unwrap_or_else(PoisonError::into_inner);
        entries.retain(|_, cached| cached.cached_at.elapsed() < self.ttl);
    }
}
