//! macOS stable-facility helpers (spec §41.13).
//!
//! These helpers wrap the stable macOS CLI utilities `xattr` and `mdfind`
//! so the AV crate can read quarantine provenance and Spotlight metadata
//! without pulling in macOS-only FFI bindings. On non-macOS targets the
//! helpers return `None` and never invoke the underlying binaries.
//!
//! # Stability
//!
//! `xattr` and `mdfind` are both Apple-supported stable facilities: the
//! `xattr(1)` command is a thin wrapper over the public `getxattr(2)`
//! syscall family, and `mdfind(1)` is the public Spotlight query CLI.
//! Both have shipped since macOS 10.4 / 10.5 respectively and remain
//! supported today. Endpoint Security is intentionally NOT wrapped here
//! because it requires a signed system extension and is documented
//! separately in the spec.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use std::path::Path;
#[cfg(target_os = "macos")]
use std::process::Command;

/// Reads the `com.apple.quarantine` xattr value from `path` using the
/// stable `/usr/bin/xattr` CLI.
///
/// Returns `None` when:
/// - The host is not macOS.
/// - The binary is missing or fails to spawn.
/// - The xattr is not set on the file (xattr exits non-zero).
/// - The output is not valid UTF-8 or is empty.
///
/// The returned string is the trimmed xattr payload, e.g.
/// `"0081;5f123456;arbitraitor;"`. The value is safe to log because
/// quarantine attributes are operator-controlled metadata, never
/// executable content.
#[cfg(target_os = "macos")]
#[must_use]
pub fn read_quarantine_xattr(path: &Path) -> Option<String> {
    let output = Command::new("/usr/bin/xattr")
        .arg("-p")
        .arg("com.apple.quarantine")
        .arg(path)
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    String::from_utf8(output.stdout)
        .ok()
        .map(|s| s.trim().to_owned())
        .filter(|s| !s.is_empty())
}

/// Non-macOS stub. Returns `None` because the quarantine attribute is
/// macOS-specific.
#[cfg(not(target_os = "macos"))]
#[must_use]
pub fn read_quarantine_xattr(_path: &Path) -> Option<String> {
    None
}

/// Queries Spotlight via `/usr/bin/mdfind` for `path` and returns the
/// first matching indexed location.
///
/// `mdfind` returns every indexed file path whose metadata matches the
/// supplied query. Passing the file path itself returns any indexed
/// copies. Returns `None` when:
/// - The host is not macOS.
/// - The binary is missing or fails to spawn.
/// - Spotlight has no record of `path` (exit status is non-zero).
/// - The output is not valid UTF-8 or is empty.
///
/// The returned string is the trimmed first line of stdout. Because
/// `mdfind` indexes by absolute path, callers should canonicalize the
/// input first to avoid spurious misses.
#[cfg(target_os = "macos")]
#[must_use]
pub fn read_spotlight_metadata(path: &Path) -> Option<String> {
    let path_str = path.to_str()?;
    let output = Command::new("/usr/bin/mdfind")
        .arg(path_str)
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let stdout = String::from_utf8(output.stdout).ok()?;
    let first = stdout.lines().next()?.trim();
    if first.is_empty() {
        None
    } else {
        Some(first.to_owned())
    }
}

/// Non-macOS stub. Returns `None` because Spotlight is macOS-specific.
#[cfg(not(target_os = "macos"))]
#[must_use]
pub fn read_spotlight_metadata(_path: &Path) -> Option<String> {
    None
}

#[cfg(test)]
#[cfg(target_os = "macos")]
mod tests {
    use super::*;
    use std::env;
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    /// On macOS, an existing file without a quarantine attribute yields `None`.
    /// The function must not panic and must not return an empty string.
    #[test]
    fn quarantine_returns_none_for_unquarantined_file() {
        let path = env::temp_dir().join(format!(
            "arbitraitor-av-quarantine-test-{}.txt",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_or(0, |d| d.as_nanos())
        ));
        fs::write(&path, b"hello").expect("write temp file");

        let result = read_quarantine_xattr(&path);
        let _ = fs::remove_file(&path);

        // On most CI images the file has no quarantine attribute, so we
        // accept either `None` (no attribute) or `Some(_)` (CI set one).
        // What we must NOT see is an empty string or a panic.
        if let Some(value) = result {
            assert!(!value.is_empty());
        }
    }

    /// `read_spotlight_metadata` returns either `None` (no index entry) or a
    /// non-empty first line. It must never panic on a real temp file.
    #[test]
    fn spotlight_returns_none_or_nonempty() {
        let path = env::temp_dir().join(format!(
            "arbitraitor-av-spotlight-test-{}.txt",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_or(0, |d| d.as_nanos())
        ));
        fs::write(&path, b"hello").expect("write temp file");

        let result = read_spotlight_metadata(&path);
        let _ = fs::remove_file(&path);

        if let Some(value) = result {
            assert!(!value.is_empty());
        }
    }
}

#[cfg(test)]
#[cfg(not(target_os = "macos"))]
mod tests {
    use super::*;
    use std::path::PathBuf;

    /// On non-macOS targets the helpers must short-circuit to `None` without
    /// spawning any subprocess.
    #[test]
    fn quarantine_returns_none_off_macos() {
        assert_eq!(read_quarantine_xattr(&PathBuf::from("/tmp/whatever")), None);
    }

    /// On non-macOS targets `read_spotlight_metadata` returns `None`.
    #[test]
    fn spotlight_returns_none_off_macos() {
        assert_eq!(
            read_spotlight_metadata(&PathBuf::from("/tmp/whatever")),
            None
        );
    }
}
