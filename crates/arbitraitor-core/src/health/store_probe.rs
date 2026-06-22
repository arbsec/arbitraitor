//! Filesystem inspection helpers for store health checks.
//!
//! These functions probe the content-addressed store layout without going
//! through [`arbitraitor_store::ContentStore`] — they read directory entries
//! and file metadata only, and never authorize release or modify durable
//! state (the writability probe creates and immediately removes a temporary
//! directory).

use std::fs;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

/// Attempts a bounded write probe inside `root` and cleans up afterwards.
///
/// # Errors
///
/// Returns the underlying I/O error when the probe directory cannot be
/// created or removed. A `NotFound` error on removal is treated as success.
pub(crate) fn probe_writable(root: &Path) -> Result<(), std::io::Error> {
    let probe = root.join(format!(".arbitraitor-health-probe-{}", epoch_seconds()));
    fs::create_dir(&probe)?;
    match fs::remove_dir(&probe) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

/// Counts objects stored under `<root>/objects/<shard>/<digest>`.
pub(crate) fn count_objects(root: &Path) -> u64 {
    let objects = root.join("objects");
    let Ok(shards) = fs::read_dir(&objects) else {
        return 0;
    };
    let mut count = 0u64;
    for shard in shards.flatten() {
        if !shard.file_type().is_ok_and(|ft| ft.is_dir()) {
            continue;
        }
        let Ok(entries) = fs::read_dir(shard.path()) else {
            continue;
        };
        for entry in entries.flatten() {
            if entry.file_type().is_ok_and(|ft| ft.is_file()) {
                count += 1;
            }
        }
    }
    count
}

/// Sums the size of every regular file under `<root>/objects/`.
pub(crate) fn measure_store_bytes(root: &Path) -> u64 {
    let objects = root.join("objects");
    let Ok(shards) = fs::read_dir(&objects) else {
        return 0;
    };
    let mut total = 0u64;
    for shard in shards.flatten() {
        if !shard.file_type().is_ok_and(|ft| ft.is_dir()) {
            continue;
        }
        let Ok(entries) = fs::read_dir(shard.path()) else {
            continue;
        };
        for entry in entries.flatten() {
            if let Ok(meta) = entry.metadata()
                && meta.is_file()
            {
                total += meta.len();
            }
        }
    }
    total
}

/// Formats a byte count as a human-readable binary size string.
pub(crate) fn format_bytes(bytes: u64) -> String {
    const UNITS: &[&str] = &["B", "KiB", "MiB", "GiB", "TiB"];
    if bytes == 0 {
        return "0 B".to_owned();
    }
    // Display formatting tolerates f64 precision loss above 2^52.
    #[allow(clippy::cast_precision_loss)]
    let mut value = bytes as f64;
    let mut unit_index = 0;
    while value >= 1024.0 && unit_index < UNITS.len() - 1 {
        value /= 1024.0;
        unit_index += 1;
    }
    if unit_index == 0 {
        return format!("{bytes} {}", UNITS[0]);
    }
    format!("{value:.1} {}", UNITS[unit_index])
}

/// Returns the current time as Unix epoch seconds, or `0` if the clock is
/// before the epoch (which should never happen on a healthy system).
pub(crate) fn epoch_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;
    use std::fs;
    use std::time::SystemTime;

    fn unique_temp_dir(label: &str) -> std::path::PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0u128, |d| d.as_nanos());
        let path = std::env::temp_dir().join(format!(
            "arbitraitor-health-probe-{label}-{}-{nanos}",
            std::process::id(),
        ));
        let _ = fs::remove_dir_all(&path);
        fs::create_dir_all(&path).expect("temp dir should be creatable");
        path
    }

    #[test]
    fn probe_writable_succeeds_for_writable_dir() {
        let root = unique_temp_dir("writable");
        probe_writable(&root).expect("writable dir should probe successfully");
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn count_objects_returns_zero_for_empty_store() {
        let root = unique_temp_dir("empty-count");
        assert_eq!(count_objects(&root), 0);
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn count_objects_counts_files_in_shards() {
        let root = unique_temp_dir("sharded-count");
        let shard = root.join("objects").join("ab");
        fs::create_dir_all(&shard).unwrap();
        fs::write(shard.join("abcd"), b"x").unwrap();
        fs::write(shard.join("abef"), b"y").unwrap();
        assert_eq!(count_objects(&root), 2);
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn measure_store_bytes_sums_file_sizes() {
        let root = unique_temp_dir("bytes");
        let shard = root.join("objects").join("cd");
        fs::create_dir_all(&shard).unwrap();
        fs::write(shard.join("cdef"), [0u8; 1024]).unwrap();
        fs::write(shard.join("cd12"), [0u8; 512]).unwrap();
        assert_eq!(measure_store_bytes(&root), 1536);
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn format_bytes_handles_common_cases() {
        assert_eq!(format_bytes(0), "0 B");
        assert_eq!(format_bytes(512), "512 B");
        assert!(format_bytes(1024).starts_with("1.0 KiB"));
        assert!(format_bytes(88_281_472).contains("MiB"));
    }
}
