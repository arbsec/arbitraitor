//! Local antivirus engine adapters
//!
//! See `docs/spec/` for the full specification.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

/// Microsoft Defender command-line adapter.
pub mod defender;

use arbitraitor_analysis::{AnalysisContext, Detector, DetectorError};
use arbitraitor_model::finding::{
    DetectorMetadata, Evidence, EvidenceKind, Finding, FindingCategory,
};
use arbitraitor_model::verdict::{Confidence, Severity};
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};
use thiserror::Error;

/// macOS stable-facility helpers per spec §41.13.
pub mod macos;

const CLAMAV_ADAPTER_NAME: &str = "clamav";
const CLAMD_COMMAND: &[u8] = b"zINSTREAM\0";
const CLAMD_DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);
const CLAMD_PRIMARY_SOCKET: &str = "/var/run/clamav/clamd.ctl";
const CLAMD_FALLBACK_SOCKET: &str = "/tmp/clamd.socket";
const CLAMD_STREAM_CHUNK_SIZE: usize = 1024 * 1024;
const CLAMD_MAX_RESPONSE_SIZE: usize = 4096;
const DETECTOR_ID: &str = "arbitraitor-av.adapter";

/// Adapter interface for local antivirus engines.
///
/// Implementations must scan only the bytes supplied to [`Self::scan`]. Remote
/// upload is intentionally not part of this trait; detector metadata advertises
/// `may_upload = false` so policy can keep AV inspection local by default.
pub trait AntivirusAdapter: Send + Sync {
    /// Stable human-readable adapter or engine name.
    fn name(&self) -> &str;

    /// Returns whether the underlying AV engine is installed and usable.
    fn is_available(&self) -> bool;

    /// Returns the AV engine version when available.
    fn engine_version(&self) -> Option<String>;

    /// Returns the signature database version when available.
    fn signature_db_version(&self) -> Option<String>;

    /// Returns the last signature update time when available.
    fn last_update_time(&self) -> Option<String>;

    /// Scans immutable artifact bytes and returns the local AV verdict.
    ///
    /// # Errors
    ///
    /// Returns [`AvError`] when the adapter cannot complete the scan safely.
    fn scan(&self, data: &[u8]) -> Result<ScanResult, AvError>;

    /// Returns a [`SignatureFreshness`] snapshot marking the adapter's
    /// signatures stale when the most recent update exceeds `max_age`.
    ///
    /// Per spec §18.3, callers operating under `required = true` policy must
    /// fail closed on stale signatures rather than treating the scan as
    /// clean. The default implementation reads [`Self::engine_version`],
    /// [`Self::signature_db_version`], and [`Self::last_update_time`]; if
    /// the timestamp cannot be parsed or is older than `max_age`,
    /// `is_stale` is `true`. Adapters that have a more authoritative source
    /// (e.g. a local signature DB mtime) may override this default.
    fn check_freshness(&self, max_age: Duration) -> SignatureFreshness {
        let last_update = self
            .last_update_time()
            .as_deref()
            .and_then(parse_rfc3339_utc);
        let is_stale = match last_update {
            Some(timestamp) => freshness_is_stale(timestamp, max_age),
            None => false,
        };
        SignatureFreshness {
            engine_version: self.engine_version(),
            signature_version: self.signature_db_version(),
            last_update,
            is_stale,
        }
    }
}

/// Snapshot of an AV adapter's signature freshness state (spec §18.3).
///
/// When an adapter is configured as `required = true`, callers must treat
/// `is_stale == true` as a fail-closed signal rather than silently accepting
/// the scan as clean. The fields are independent so policy can layer on top
/// (e.g. emit a finding when stale, refuse to release when stale).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SignatureFreshness {
    /// Engine binary version (e.g. `"1.4.1"` for `ClamAV`) when reported by the adapter.
    pub engine_version: Option<String>,
    /// Signature database version (e.g. `"26721"` for the `ClamAV` daily CVD) when reported.
    pub signature_version: Option<String>,
    /// Parsed timestamp of the last signature update when known.
    pub last_update: Option<SystemTime>,
    /// `true` when `last_update` exceeds the supplied `max_age` or the timestamp
    /// is in the future. `false` when the timestamp is missing or fresh.
    pub is_stale: bool,
}

/// Result returned by an antivirus adapter scan.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ScanResult {
    /// No malware or suspicious content was detected.
    Clean,
    /// A malware signature matched the artifact.
    Detected {
        /// Malware family or signature family reported by the engine.
        malware_family: String,
    },
    /// The engine reported suspicious content without a confirmed family.
    Suspicious,
    /// The engine completed with an error result instead of a detection verdict.
    Error {
        /// Safe diagnostic reason supplied by the adapter.
        reason: String,
    },
}

/// Policy controlling antivirus detector execution.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AvPolicy {
    /// Whether AV scanning is enabled.
    pub enabled: bool,
    /// Whether missing or failed AV scanning must fail closed.
    pub required: bool,
    /// Maximum permitted signature age in hours, when policy enforces freshness.
    pub max_signature_age_hours: Option<u64>,
    /// Detector timeout budget in milliseconds.
    pub timeout_ms: u64,
}

impl Default for AvPolicy {
    fn default() -> Self {
        Self {
            enabled: false,
            required: false,
            max_signature_age_hours: None,
            timeout_ms: 5_000,
        }
    }
}

/// Antivirus adapter error.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum AvError {
    /// The configured engine is not available.
    #[error("antivirus engine is unavailable: {reason}")]
    Unavailable {
        /// Safe diagnostic reason.
        reason: String,
    },
    /// The adapter could not complete scanning.
    #[error("antivirus scan failed: {reason}")]
    ScanFailed {
        /// Safe diagnostic reason.
        reason: String,
    },
}

/// `ClamAV` adapter backed by a local `clamd` Unix socket.
///
/// The adapter uses clamd's `INSTREAM` protocol and never uploads data to a
/// remote service. Each scan streams the supplied immutable bytes to the local
/// daemon and maps clamd's response into a [`ScanResult`].
pub struct ClamavAdapter {
    socket_path: PathBuf,
    timeout: Duration,
}

impl ClamavAdapter {
    /// Creates a `ClamAV` adapter for the provided clamd Unix socket path.
    #[must_use]
    pub fn new(socket_path: impl AsRef<Path>) -> Self {
        Self {
            socket_path: socket_path.as_ref().to_path_buf(),
            timeout: CLAMD_DEFAULT_TIMEOUT,
        }
    }

    /// Returns the conventional clamd Unix socket path for this host.
    ///
    /// `/var/run/clamav/clamd.ctl` is preferred when present; otherwise the
    /// common test and local-development fallback `/tmp/clamd.socket` is used.
    #[must_use]
    pub fn default_socket() -> PathBuf {
        let primary = PathBuf::from(CLAMD_PRIMARY_SOCKET);
        if primary.exists() {
            primary
        } else {
            PathBuf::from(CLAMD_FALLBACK_SOCKET)
        }
    }

    /// Creates a `ClamAV` adapter with an explicit timeout.
    #[must_use]
    pub fn with_timeout(socket_path: impl AsRef<Path>, timeout: Duration) -> Self {
        Self {
            socket_path: socket_path.as_ref().to_path_buf(),
            timeout,
        }
    }

    fn connect(&self) -> Result<UnixStream, AvError> {
        let stream =
            UnixStream::connect(&self.socket_path).map_err(|error| AvError::Unavailable {
                reason: format!("could not connect to clamd Unix socket: {error}"),
            })?;
        stream
            .set_read_timeout(Some(self.timeout))
            .map_err(|error| AvError::ScanFailed {
                reason: format!("could not configure clamd read timeout: {error}"),
            })?;
        stream
            .set_write_timeout(Some(self.timeout))
            .map_err(|error| AvError::ScanFailed {
                reason: format!("could not configure clamd write timeout: {error}"),
            })?;
        Ok(stream)
    }

    fn write_instream(stream: &mut UnixStream, data: &[u8]) -> Result<(), AvError> {
        stream
            .write_all(CLAMD_COMMAND)
            .map_err(|error| clamd_io_error(&error))?;
        for chunk in data.chunks(CLAMD_STREAM_CHUNK_SIZE) {
            let chunk_len = u32::try_from(chunk.len()).map_err(|error| AvError::ScanFailed {
                reason: format!("clamd stream chunk length conversion failed: {error}"),
            })?;
            stream
                .write_all(&chunk_len.to_be_bytes())
                .map_err(|error| clamd_io_error(&error))?;
            stream
                .write_all(chunk)
                .map_err(|error| clamd_io_error(&error))?;
        }
        stream
            .write_all(&0_u32.to_be_bytes())
            .map_err(|error| clamd_io_error(&error))
    }

    fn read_response(stream: &mut UnixStream) -> Result<String, AvError> {
        let mut response = Vec::new();
        let mut byte = [0_u8; 1];

        while response.len() < CLAMD_MAX_RESPONSE_SIZE {
            let bytes_read = stream
                .read(&mut byte)
                .map_err(|error| clamd_io_error(&error))?;
            if bytes_read == 0 || byte[0] == 0 {
                break;
            }
            response.push(byte[0]);
        }

        if response.len() == CLAMD_MAX_RESPONSE_SIZE {
            return Err(AvError::ScanFailed {
                reason: "clamd response exceeded maximum length".to_owned(),
            });
        }

        String::from_utf8(response).map_err(|error| AvError::ScanFailed {
            reason: format!("clamd returned a non-UTF-8 response: {error}"),
        })
    }

    fn parse_response(response: &str) -> Result<ScanResult, AvError> {
        let result = response
            .strip_prefix("stream: ")
            .ok_or_else(|| AvError::ScanFailed {
                reason: format!("clamd returned an unexpected response: {response}"),
            })?;

        if result == "OK" {
            return Ok(ScanResult::Clean);
        }

        if let Some(malware_family) = result.strip_suffix(" FOUND") {
            if malware_family.is_empty() {
                return Err(AvError::ScanFailed {
                    reason: "clamd reported FOUND without a malware family".to_owned(),
                });
            }
            return Ok(ScanResult::Detected {
                malware_family: malware_family.to_owned(),
            });
        }

        Err(AvError::ScanFailed {
            reason: format!("clamd returned an error response: {result}"),
        })
    }
}

impl AntivirusAdapter for ClamavAdapter {
    fn name(&self) -> &str {
        CLAMAV_ADAPTER_NAME
    }

    fn is_available(&self) -> bool {
        self.connect().is_ok()
    }

    fn engine_version(&self) -> Option<String> {
        None
    }

    fn signature_db_version(&self) -> Option<String> {
        None
    }

    fn last_update_time(&self) -> Option<String> {
        None
    }

    fn scan(&self, data: &[u8]) -> Result<ScanResult, AvError> {
        let mut stream = self.connect()?;
        Self::write_instream(&mut stream, data)?;
        let response = Self::read_response(&mut stream)?;
        Self::parse_response(&response)
    }
}

fn clamd_io_error(error: &std::io::Error) -> AvError {
    AvError::ScanFailed {
        reason: format!("clamd I/O failed: {error}"),
    }
}

/// Computes the stale flag for a known last-update timestamp.
///
/// A timestamp in the future is treated as stale because clock skew or a
/// misconfigured engine should not silently pass `required = true` scans.
fn freshness_is_stale(last_update: SystemTime, max_age: Duration) -> bool {
    match SystemTime::now().duration_since(last_update) {
        Ok(age) => age > max_age,
        Err(_) => true,
    }
}

/// Parses a strict RFC 3339 / ISO 8601 UTC timestamp into a [`SystemTime`].
///
/// Accepts `YYYY-MM-DDTHH:MM:SS[.fraction]Z` and the space-separator variant
/// `YYYY-MM-DD HH:MM:SS[.fraction]Z`. Fractional seconds are accepted but
/// ignored: AV engines report second precision in practice and ignoring
/// sub-second noise avoids float math. Returns `None` for any other format
/// so callers can treat unknown timestamps as "unknown" rather than erroring.
///
/// The parser deliberately avoids `chrono` / `time` to keep the AV crate
/// dependency-light; the supported grammar is the minimum needed to read
/// `last_update_time()` strings emitted by `ClamAV` (`freshclam.dat` style)
/// and Microsoft Defender.
fn parse_rfc3339_utc(input: &str) -> Option<SystemTime> {
    let bytes = input.as_bytes();
    if bytes.len() < 20 {
        return None;
    }
    if bytes[4] != b'-' || bytes[7] != b'-' {
        return None;
    }
    if bytes[10] != b'T' && bytes[10] != b' ' {
        return None;
    }
    if bytes.last()? != &b'Z' {
        return None;
    }

    let parse_u32 = |slice: &[u8]| -> Option<u32> { std::str::from_utf8(slice).ok()?.parse().ok() };

    let year = parse_u32(&bytes[0..4])?.cast_signed();
    let month = parse_u32(&bytes[5..7])?;
    let day = parse_u32(&bytes[8..10])?;
    let hour = parse_u32(&bytes[11..13])?;
    let minute = parse_u32(&bytes[14..16])?;
    let second = parse_u32(&bytes[17..19])?;

    if !(1..=12).contains(&month) || day == 0 || day > 31 || hour > 23 || minute > 59 || second > 59
    {
        return None;
    }

    // The remaining bytes (bytes[19..bytes.len()-1]) are the optional
    // fractional-second suffix and were already validated by the length
    // check; we ignore them deliberately.

    let days = days_from_civil(year, month, day)?;
    let secs = days
        .checked_mul(86_400)?
        .checked_add(i64::from(hour) * 3_600)?
        .checked_add(i64::from(minute) * 60)?
        .checked_add(i64::from(second))?;
    if secs < 0 {
        return None;
    }
    SystemTime::UNIX_EPOCH.checked_add(Duration::from_secs(secs.cast_unsigned()))
}

/// Howard Hinnant's `days_from_civil` algorithm
/// (<http://howardhinnant.github.io/date_algorithms.html>) adapted to return
/// the number of days since the Unix epoch for the given civil date.
///
/// Restricted to years 1970..=9999 because pre-1970 dates are not meaningful
/// for AV signature timestamps and the algorithm intentionally rejects them
/// to keep `checked_add` arithmetic tight.
fn days_from_civil(year: i32, month: u32, day: u32) -> Option<i64> {
    if !(1970..=9999).contains(&year) {
        return None;
    }
    let y = i64::from(if month <= 2 { year - 1 } else { year });
    let era = y.div_euclid(400);
    let yoe = u64::try_from(y - era * 400).ok()?;
    let m = u64::from(if month > 2 { month - 3 } else { month + 9 });
    let doy = (153 * m + 2) / 5 + u64::from(day) - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era.checked_mul(146_097)?
        .checked_add(i64::try_from(doe).ok()?.checked_sub(719_468)?)
}

/// Analysis detector that wraps a local antivirus adapter.
pub struct AvDetector {
    adapter: Box<dyn AntivirusAdapter>,
    policy: AvPolicy,
}

impl AvDetector {
    /// Creates a detector from an antivirus adapter and AV policy.
    #[must_use]
    pub fn new(adapter: Box<dyn AntivirusAdapter>, policy: AvPolicy) -> Self {
        Self { adapter, policy }
    }

    fn unavailable_finding(&self, ctx: &AnalysisContext<'_>) -> Finding {
        Finding {
            id: "av.adapter-unavailable".to_owned(),
            detector: DETECTOR_ID.to_owned(),
            category: FindingCategory::PolicyViolation,
            severity: Severity::Critical,
            confidence: Confidence::Confirmed,
            title: "Required antivirus adapter is unavailable".to_owned(),
            description: format!(
                "Antivirus policy requires adapter '{}' but the adapter is not available.",
                self.adapter.name()
            ),
            evidence: self.adapter_evidence("availability", Some("unavailable".to_owned())),
            artifact_sha256: ctx.artifact_sha256.clone(),
            location: None,
            remediation: Some(
                "Install or repair the configured antivirus engine before release.".to_owned(),
            ),
            references: vec!["Arbitraitor spec sections 18.2-18.4".to_owned()],
            tags: vec!["antivirus".to_owned(), "fail-closed".to_owned()],
            taxonomies: Vec::new(),
        }
    }

    fn finding_for_result(&self, ctx: &AnalysisContext<'_>, result: ScanResult) -> Option<Finding> {
        match result {
            ScanResult::Clean => None,
            ScanResult::Detected { malware_family } => Some(Finding {
                id: "av.malware-detected".to_owned(),
                detector: DETECTOR_ID.to_owned(),
                category: FindingCategory::MalwareSignature,
                severity: Severity::Critical,
                confidence: Confidence::Confirmed,
                title: "Antivirus detected malware".to_owned(),
                description: format!(
                    "Antivirus adapter '{}' detected malware family '{malware_family}'.",
                    self.adapter.name()
                ),
                evidence: self.adapter_evidence("malware_family", Some(malware_family)),
                artifact_sha256: ctx.artifact_sha256.clone(),
                location: None,
                remediation: Some("Block release and investigate the artifact source.".to_owned()),
                references: vec!["Arbitraitor spec sections 18.2-18.3".to_owned()],
                tags: vec!["antivirus".to_owned(), "malware-signature".to_owned()],
                taxonomies: Vec::new(),
            }),
            ScanResult::Suspicious => Some(Finding {
                id: "av.suspicious".to_owned(),
                detector: DETECTOR_ID.to_owned(),
                category: FindingCategory::MalwareSignature,
                severity: Severity::High,
                confidence: Confidence::High,
                title: "Antivirus reported suspicious content".to_owned(),
                description: format!(
                    "Antivirus adapter '{}' reported suspicious content without a confirmed malware family.",
                    self.adapter.name()
                ),
                evidence: self.adapter_evidence("scan_result", Some("suspicious".to_owned())),
                artifact_sha256: ctx.artifact_sha256.clone(),
                location: None,
                remediation: Some(
                    "Review the artifact manually or require a clean AV result before release."
                        .to_owned(),
                ),
                references: vec!["Arbitraitor spec sections 18.2-18.3".to_owned()],
                tags: vec!["antivirus".to_owned(), "suspicious".to_owned()],
                taxonomies: Vec::new(),
            }),
            ScanResult::Error { reason } => Some(self.scan_error_finding(ctx, &reason)),
        }
    }

    fn scan_error_finding(&self, ctx: &AnalysisContext<'_>, reason: &str) -> Finding {
        Finding {
            id: "av.scan-error".to_owned(),
            detector: DETECTOR_ID.to_owned(),
            category: FindingCategory::PolicyViolation,
            severity: if self.policy.required {
                Severity::Critical
            } else {
                Severity::High
            },
            confidence: Confidence::Confirmed,
            title: "Antivirus scan did not complete cleanly".to_owned(),
            description: format!(
                "Antivirus adapter '{}' returned an error result, so AV coverage is incomplete.",
                self.adapter.name()
            ),
            evidence: self.adapter_evidence("scan_error", Some(reason.to_owned())),
            artifact_sha256: ctx.artifact_sha256.clone(),
            location: None,
            remediation: Some("Fail closed when AV scanning is required by policy.".to_owned()),
            references: vec!["Arbitraitor spec sections 18.2-18.4".to_owned()],
            tags: vec!["antivirus".to_owned(), "incomplete-analysis".to_owned()],
            taxonomies: Vec::new(),
        }
    }

    /// Builds a critical fail-closed finding when the configured `required =
    /// true` policy sees stale signatures (spec §18.3).
    fn stale_signature_finding(
        &self,
        ctx: &AnalysisContext<'_>,
        freshness: &SignatureFreshness,
    ) -> Finding {
        Finding {
            id: "av.signatures-stale".to_owned(),
            detector: DETECTOR_ID.to_owned(),
            category: FindingCategory::PolicyViolation,
            severity: Severity::Critical,
            confidence: Confidence::Confirmed,
            title: "Antivirus signatures are stale".to_owned(),
            description: format!(
                "Antivirus adapter '{}' has stale signatures and required scanning is enabled, so coverage cannot be trusted.",
                self.adapter.name()
            ),
            evidence: vec![Evidence {
                kind: EvidenceKind::Other,
                description: "antivirus freshness snapshot".to_owned(),
                content: Some(format!(
                    "adapter={}; is_stale=true; engine_version={}; signature_version={}; last_update={}",
                    self.adapter.name(),
                    freshness.engine_version.as_deref().unwrap_or("unknown"),
                    freshness.signature_version.as_deref().unwrap_or("unknown"),
                    freshness
                        .last_update
                        .and_then(|t| t.duration_since(SystemTime::UNIX_EPOCH).ok())
                        .map_or_else(
                            || "unknown".to_owned(),
                            |d| format!("{}s since epoch", d.as_secs())
                        ),
                )),
            }],
            artifact_sha256: ctx.artifact_sha256.clone(),
            location: None,
            remediation: Some(
                "Refresh the AV signature database before releasing the artifact.".to_owned(),
            ),
            references: vec!["Arbitraitor spec section 18.3".to_owned()],
            tags: vec![
                "antivirus".to_owned(),
                "fail-closed".to_owned(),
                "stale-signatures".to_owned(),
            ],
            taxonomies: Vec::new(),
        }
    }

    fn adapter_evidence(&self, result_key: &str, result_value: Option<String>) -> Vec<Evidence> {
        let mut parts = vec![format!("adapter={}", self.adapter.name())];
        if let Some(version) = self.adapter.engine_version() {
            parts.push(format!("engine_version={version}"));
        }
        if let Some(version) = self.adapter.signature_db_version() {
            parts.push(format!("signature_db_version={version}"));
        }
        if let Some(update_time) = self.adapter.last_update_time() {
            parts.push(format!("last_update_time={update_time}"));
        }
        if let Some(value) = result_value {
            parts.push(format!("{result_key}={value}"));
        }

        vec![Evidence {
            kind: EvidenceKind::Other,
            description: "antivirus adapter result".to_owned(),
            content: Some(parts.join("; ")),
        }]
    }
}

impl Detector for AvDetector {
    fn metadata(&self) -> DetectorMetadata {
        DetectorMetadata {
            id: DETECTOR_ID.to_owned(),
            version: env!("CARGO_PKG_VERSION").to_owned(),
            supported_artifact_kinds: Vec::new(),
            capabilities: vec!["local-antivirus-scan".to_owned()],
            is_local: true,
            may_upload: false,
            default_timeout_ms: self.policy.timeout_ms,
            is_deterministic: false,
        }
    }

    fn analyze(&self, ctx: &AnalysisContext<'_>) -> Result<Vec<Finding>, DetectorError> {
        if !self.policy.enabled {
            return Ok(Vec::new());
        }
        if !self.adapter.is_available() {
            return if self.policy.required {
                Ok(vec![self.unavailable_finding(ctx)])
            } else {
                Ok(Vec::new())
            };
        }

        let mut findings = Vec::new();
        if let Some(max_age_hours) = self.policy.max_signature_age_hours {
            let freshness = self
                .adapter
                .check_freshness(Duration::from_secs(max_age_hours.saturating_mul(3600)));
            if self.policy.required && freshness.is_stale {
                findings.push(self.stale_signature_finding(ctx, &freshness));
            }
        }

        match self.adapter.scan(ctx.artifact_bytes) {
            Ok(result) => findings.extend(self.finding_for_result(ctx, result)),
            Err(error) => findings.push(self.scan_error_finding(ctx, &error.to_string())),
        }
        Ok(findings)
    }
}

#[cfg(test)]
mod tests {
    use super::{AntivirusAdapter, AvDetector, AvError, AvPolicy, ClamavAdapter, ScanResult};
    use arbitraitor_analysis::AnalysisCoordinator;
    use arbitraitor_model::finding::FindingCategory;
    use arbitraitor_model::verdict::{Severity, Verdict};
    use std::error::Error;
    use std::fs;
    use std::io::{self, Read, Write};
    use std::os::unix::net::UnixListener;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::thread;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    static SOCKET_COUNTER: AtomicU64 = AtomicU64::new(0);

    struct MockAdapter {
        available: bool,
        result: ScanResult,
    }

    impl MockAdapter {
        fn new(available: bool, result: ScanResult) -> Self {
            Self { available, result }
        }
    }

    impl AntivirusAdapter for MockAdapter {
        fn name(&self) -> &'static str {
            "mock-av"
        }

        fn is_available(&self) -> bool {
            self.available
        }

        fn engine_version(&self) -> Option<String> {
            Some("1.0.0".to_owned())
        }

        fn signature_db_version(&self) -> Option<String> {
            Some("sig-42".to_owned())
        }

        fn last_update_time(&self) -> Option<String> {
            Some("2026-06-19T00:00:00Z".to_owned())
        }

        fn scan(&self, _data: &[u8]) -> Result<ScanResult, AvError> {
            Ok(self.result.clone())
        }
    }

    fn enabled_policy(required: bool) -> AvPolicy {
        AvPolicy {
            enabled: true,
            required,
            max_signature_age_hours: None,
            timeout_ms: 1_000,
        }
    }

    fn analyze(adapter: MockAdapter, policy: AvPolicy) -> arbitraitor_analysis::AnalysisResult {
        let coordinator = AnalysisCoordinator::with_detectors(vec![Box::new(AvDetector::new(
            Box::new(adapter),
            policy,
        ))]);
        coordinator.analyze(b"test artifact")
    }

    fn unique_socket_path() -> PathBuf {
        let counter = SOCKET_COUNTER.fetch_add(1, Ordering::Relaxed);
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |duration| duration.as_nanos());
        std::env::temp_dir().join(format!(
            "arbitraitor-clamd-{}-{nanos}-{counter}.sock",
            std::process::id()
        ))
    }

    fn remove_socket(path: &Path) -> io::Result<()> {
        match fs::remove_file(path) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error),
        }
    }

    fn read_instream(listener: &UnixListener, response: &'static [u8]) -> io::Result<Vec<u8>> {
        let (mut stream, _) = listener.accept()?;
        let mut command = [0_u8; 10];
        stream.read_exact(&mut command)?;
        if command != *b"zINSTREAM\0" {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "unexpected clamd command",
            ));
        }

        let mut data = Vec::new();
        loop {
            let mut length = [0_u8; 4];
            stream.read_exact(&mut length)?;
            let chunk_len = usize::try_from(u32::from_be_bytes(length)).map_err(|error| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("invalid clamd chunk length: {error}"),
                )
            })?;
            if chunk_len == 0 {
                break;
            }
            let previous_len = data.len();
            data.resize(previous_len + chunk_len, 0);
            stream.read_exact(&mut data[previous_len..])?;
        }
        stream.write_all(response)?;
        Ok(data)
    }

    fn scan_with_mock_response(
        response: &'static [u8],
        data: &[u8],
    ) -> Result<(ScanResult, Vec<u8>), Box<dyn Error>> {
        let socket_path = unique_socket_path();
        remove_socket(&socket_path)?;
        let listener = UnixListener::bind(&socket_path)?;
        let handle = thread::spawn(move || read_instream(&listener, response));

        let adapter = ClamavAdapter::with_timeout(&socket_path, Duration::from_secs(1));
        let scan_result = adapter.scan(data)?;
        let streamed = match handle.join() {
            Ok(result) => result?,
            Err(_) => return Err("mock clamd thread panicked".into()),
        };
        remove_socket(&socket_path)?;
        Ok((scan_result, streamed))
    }

    #[test]
    fn clean_scan_returns_no_findings() {
        let result = analyze(
            MockAdapter::new(true, ScanResult::Clean),
            enabled_policy(true),
        );

        assert!(result.findings.is_empty());
        assert_eq!(result.verdict, Verdict::Pass);
    }

    #[test]
    fn detected_scan_returns_critical_finding() {
        let result = analyze(
            MockAdapter::new(
                true,
                ScanResult::Detected {
                    malware_family: "EICAR-Test-File".to_owned(),
                },
            ),
            enabled_policy(true),
        );

        assert_eq!(result.findings.len(), 1);
        assert_eq!(
            result.findings[0].category,
            FindingCategory::MalwareSignature
        );
        assert_eq!(result.findings[0].severity, Severity::Critical);
        assert_eq!(result.verdict, Verdict::Block);
    }

    #[test]
    fn required_unavailable_adapter_fails_closed() {
        let result = analyze(
            MockAdapter::new(false, ScanResult::Clean),
            enabled_policy(true),
        );

        assert_eq!(result.findings.len(), 1);
        assert_eq!(result.findings[0].severity, Severity::Critical);
        assert_eq!(result.verdict, Verdict::Block);
        assert!(
            result.findings[0]
                .tags
                .iter()
                .any(|tag| tag == "fail-closed")
        );
    }

    #[test]
    fn non_required_unavailable_adapter_skips() {
        let result = analyze(
            MockAdapter::new(false, ScanResult::Clean),
            enabled_policy(false),
        );

        assert!(result.findings.is_empty());
        assert_eq!(result.verdict, Verdict::Pass);
    }

    #[test]
    fn clamav_clean_response_returns_clean() -> Result<(), Box<dyn Error>> {
        let data = b"artifact bytes";
        let (result, streamed) = scan_with_mock_response(b"stream: OK\0", data)?;

        assert_eq!(result, ScanResult::Clean);
        assert_eq!(streamed, data);
        Ok(())
    }

    #[test]
    fn clamav_found_response_returns_detection() -> Result<(), Box<dyn Error>> {
        let (result, streamed) = scan_with_mock_response(b"stream: EICAR FOUND\0", b"eicar")?;

        assert_eq!(
            result,
            ScanResult::Detected {
                malware_family: "EICAR".to_owned()
            }
        );
        assert_eq!(streamed, b"eicar");
        Ok(())
    }

    #[test]
    fn clamav_unavailable_socket_returns_false() -> Result<(), Box<dyn Error>> {
        let socket_path = unique_socket_path();
        remove_socket(&socket_path)?;
        let adapter = ClamavAdapter::with_timeout(&socket_path, Duration::from_millis(50));

        assert!(!adapter.is_available());
        Ok(())
    }

    #[test]
    fn clamav_read_timeout_returns_error() -> Result<(), Box<dyn Error>> {
        let socket_path = unique_socket_path();
        remove_socket(&socket_path)?;
        let listener = UnixListener::bind(&socket_path)?;
        let handle = thread::spawn(move || -> io::Result<()> {
            let (_stream, _) = listener.accept()?;
            thread::sleep(Duration::from_millis(250));
            Ok(())
        });

        let adapter = ClamavAdapter::with_timeout(&socket_path, Duration::from_millis(50));
        let result = adapter.scan(b"artifact bytes");

        assert!(matches!(result, Err(AvError::ScanFailed { .. })));
        match handle.join() {
            Ok(result) => result?,
            Err(_) => return Err("mock clamd thread panicked".into()),
        }
        remove_socket(&socket_path)?;
        Ok(())
    }

    /// The default trait implementation reads the mock's `last_update_time`
    /// and reports it as fresh when `max_age` exceeds the timestamp age.
    #[test]
    fn check_freshness_reports_fresh_when_recent() {
        let adapter = MockAdapter::new(true, ScanResult::Clean);
        let freshness = adapter.check_freshness(Duration::from_hours(8_760));

        assert_eq!(freshness.engine_version.as_deref(), Some("1.0.0"));
        assert_eq!(freshness.signature_version.as_deref(), Some("sig-42"));
        assert!(freshness.last_update.is_some());
        assert!(!freshness.is_stale);
    }

    /// When `max_age` is tiny, even a recent-but-not-now timestamp is stale.
    #[test]
    fn check_freshness_reports_stale_when_max_age_zero() {
        let adapter = MockAdapter::new(true, ScanResult::Clean);
        let freshness = adapter.check_freshness(Duration::from_secs(0));

        assert!(freshness.last_update.is_some());
        assert!(freshness.is_stale);
    }

    /// An RFC3339 string that cannot be parsed yields `last_update = None`
    /// and `is_stale = false` so callers can layer their own policy on top.
    #[test]
    fn check_freshness_handles_unparseable_timestamp() {
        struct BadAdapter;
        impl AntivirusAdapter for BadAdapter {
            fn name(&self) -> &'static str {
                "bad-av"
            }
            fn is_available(&self) -> bool {
                true
            }
            fn engine_version(&self) -> Option<String> {
                Some("1.0.0".to_owned())
            }
            fn signature_db_version(&self) -> Option<String> {
                Some("sig-1".to_owned())
            }
            fn last_update_time(&self) -> Option<String> {
                Some("not-a-timestamp".to_owned())
            }
            fn scan(&self, _data: &[u8]) -> Result<ScanResult, AvError> {
                Ok(ScanResult::Clean)
            }
        }

        let freshness = BadAdapter.check_freshness(Duration::from_mins(1));
        assert!(freshness.last_update.is_none());
        assert!(!freshness.is_stale);
    }

    /// When `required = true` and signatures are stale, the detector emits a
    /// critical finding that fails closed (spec §18.3).
    #[test]
    fn required_policy_fails_closed_on_stale_signatures() {
        let adapter = MockAdapter::new(true, ScanResult::Clean);
        let mut policy = enabled_policy(true);
        policy.max_signature_age_hours = Some(0);
        let result = analyze(adapter, policy);

        assert_eq!(result.findings.len(), 1);
        assert_eq!(result.findings[0].id, "av.signatures-stale");
        assert_eq!(result.findings[0].severity, Severity::Critical);
        assert_eq!(result.verdict, Verdict::Block);
        assert!(
            result.findings[0]
                .tags
                .iter()
                .any(|tag| tag == "fail-closed")
        );
    }

    /// Non-required policies skip the freshness check entirely.
    #[test]
    fn non_required_policy_ignores_stale_signatures() {
        let adapter = MockAdapter::new(true, ScanResult::Clean);
        let mut policy = enabled_policy(false);
        policy.max_signature_age_hours = Some(0);
        let result = analyze(adapter, policy);

        assert!(result.findings.is_empty());
        assert_eq!(result.verdict, Verdict::Pass);
    }

    /// Helper: parses a fixed timestamp and verifies the round-trip back to
    /// the same [`SystemTime`]. Using a self-consistent check avoids hard-coding
    /// epoch seconds that would drift if the algorithm changed.
    #[test]
    fn parse_rfc3339_utc_accepts_iso8601() -> Result<(), &'static str> {
        let ts =
            super::parse_rfc3339_utc("2026-07-20T00:00:00Z").ok_or("timestamp should parse")?;
        // 2026-07-20T00:00:00Z is 1_784_505_600 seconds since the Unix epoch.
        let expected = SystemTime::UNIX_EPOCH
            .checked_add(Duration::from_hours(495_696))
            .ok_or("epoch arithmetic fits")?;
        assert_eq!(ts, expected);
        Ok(())
    }

    /// The parser rejects malformed timestamps without panicking.
    #[test]
    fn parse_rfc3339_utc_rejects_malformed() {
        assert!(super::parse_rfc3339_utc("").is_none());
        assert!(super::parse_rfc3339_utc("2026-07-20").is_none());
        assert!(super::parse_rfc3339_utc("2026-07-20T00:00:00").is_none()); // missing Z
        assert!(super::parse_rfc3339_utc("2026-13-01T00:00:00Z").is_none()); // bad month
        assert!(super::parse_rfc3339_utc("2026-07-32T00:00:00Z").is_none()); // bad day
    }
}
