//! Archive inspection and decompression under resource limits
//!
//! See `.spec/` for the full specification.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use std::collections::{HashMap, HashSet};
use std::fs::{self, File};
use std::io::{self, Cursor, Read, Write};
use std::path::{Component, Path, PathBuf};
use std::time::{Duration, Instant};

use arbitraitor_artifact::ArtifactType;
use arbitraitor_model::finding::{Evidence, EvidenceKind, Finding, FindingCategory};
use arbitraitor_model::ids::Sha256Digest;
use arbitraitor_model::taxonomy::{TaxonomyName, TaxonomyRef};
use arbitraitor_model::verdict::{Confidence, Severity};
use bzip2::read::BzDecoder;
use flate2::read::GzDecoder;
use sha2::{Digest, Sha256};
use tar::Archive;
use thiserror::Error;
use xz2::read::XzDecoder;
use zip::ZipArchive;
use zip::result::ZipError;

mod companion;
mod payload;

pub use payload::{
    ArtifactNode, ArtifactOrigin, DEFAULT_MAX_PAYLOAD_DEPTH, NodeStatus, PayloadError,
    PayloadIssue, PayloadNode, discover_payloads, is_archive_type, walk_payloads,
};

pub use companion::{
    CompanionArtifact, ParsedCompanion, discover_companion_artifacts, parse_companion,
    vex_can_suppress_finding,
};

const DEFAULT_MAX_DEPTH: u32 = 5;
const DEFAULT_MAX_FILES: u32 = 10_000;
const DEFAULT_MAX_TOTAL_UNPACKED_BYTES: u64 = 1_073_741_824;
const DEFAULT_MAX_SINGLE_FILE_BYTES: u64 = 268_435_456;
const DEFAULT_MAX_COMPRESSION_RATIO: u32 = 200;
const DEFAULT_MAX_SYMLINKS: u32 = 0;
const DEFAULT_MAX_PROCESSING_TIME: Duration = Duration::from_mins(1);
const COPY_BUFFER_SIZE: usize = 16 * 1024;
const SINGLE_FILE_ENTRY_NAME: &str = "payload";
const TAR_MAGIC_OFFSET: usize = 257;
const TAR_MAGIC: &[u8] = b"ustar";
const DETECTOR_ID: &str = "arbitraitor-archive.hazards";
const ARCHIVE_HAZARD_REFERENCE: &str = "Arbitraitor spec section 19.3";
const PARSER_DIFFERENTIAL_REFERENCE: &str = "Arbitraitor spec section 19.1";
const CWE_436_URL: &str = "https://cwe.mitre.org/data/definitions/436.html";
const TAR_BLOCK_SIZE: usize = 512;
const TAR_NAME_RANGE: std::ops::Range<usize> = 0..100;
const TAR_SIZE_RANGE: std::ops::Range<usize> = 124..136;
const TAR_TYPEFLAG_OFFSET: usize = 156;
const TAR_PREFIX_RANGE: std::ops::Range<usize> = 345..500;
const SETUID_BIT: u32 = 0o4000;
const SETGID_BIT: u32 = 0o2000;
const UNIX_FILE_TYPE_MASK: u32 = 0o170_000;
const ARCHIVE_SUFFIXES: &[&str] = &[
    ".zip", ".jar", ".war", ".tar", ".tar.gz", ".tgz", ".tar.xz", ".txz", ".tar.bz2", ".tbz",
    ".tbz2", ".tar.zst", ".gz", ".xz", ".bz2", ".zst",
];

/// Format-neutral archive entry type metadata.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ArchiveEntryType {
    /// Regular file payload.
    File,
    /// Directory entry.
    Directory,
    /// Symbolic link entry.
    Symlink,
    /// Hard link entry.
    Hardlink,
    /// FIFO / named pipe entry.
    Fifo,
    /// Character device node entry.
    CharacterDevice,
    /// Block device node entry.
    BlockDevice,
    /// Entry type was not recognized or is not extractable to a regular file.
    Other,
}

/// Format-neutral archive entry metadata.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ArchiveEntry {
    /// Entry path as stored in the archive after validation.
    pub name: String,
    /// Uncompressed entry byte size.
    pub size: u64,
    /// Compressed entry byte size when the format exposes it.
    pub compressed_size: Option<u64>,
    /// Whether the entry is a directory.
    pub is_dir: bool,
    /// Whether the entry is a symbolic link.
    pub is_symlink: bool,
    /// Format-neutral entry type.
    pub entry_type: ArchiveEntryType,
    /// Symbolic or hard link target when present in archive metadata.
    pub link_target: Option<String>,
    /// Unix permissions when present in the archive metadata.
    pub permissions: Option<u32>,
    /// Whether ZIP metadata marks this member as encrypted.
    pub is_encrypted: bool,
}

/// Spec §19.3 archive hazard type.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ArchiveHazardType {
    /// Archive member paths or links escape the extraction root.
    PathTraversal,
    /// Archive metadata can exhaust bounded processing limits.
    ResourceExhaustion,
    /// Archive parser ambiguity can produce different member sets.
    ParserSmelting,
}

/// Resource limits applied while listing and extracting archives.
///
/// Defaults follow spec §19.2. Callers that need looser limits (e.g. an
/// enterprise-internal scan of a trusted release bundle that legitimately
/// contains many symlinks) must do so explicitly via
/// [`ArchiveLimits::default`] field overrides — never by ignoring the limit.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ArchiveLimits {
    /// Maximum path depth allowed for an entry. Default `5` per spec §19.2.
    pub max_depth: u32,
    /// Maximum number of entries allowed in one archive operation.
    /// Default `10_000` per spec §19.2.
    pub max_files: u32,
    /// Maximum total unpacked bytes allowed in one archive operation.
    /// Default `1 GiB` per spec §19.2.
    pub max_total_unpacked_bytes: u64,
    /// Maximum unpacked bytes allowed for a single file entry.
    /// Default `256 MiB` per spec §19.2.
    pub max_single_file_bytes: u64,
    /// Maximum allowed uncompressed-to-compressed size ratio.
    /// Default `200` per spec §19.2.
    pub max_compression_ratio: u32,
    /// Maximum number of symbolic-link entries permitted in one archive
    /// operation. Default `0` per spec §19.2 — any symlink triggers a
    /// `LimitExceeded { limit: "max_symlinks" }` error. This enforces
    /// spec invariant 15 (no archive path escape via symlinks) at the
    /// extraction gate; the per-entry `symlink_target_escapes` check
    /// remains as defense-in-depth.
    pub max_symlinks: u32,
    /// Maximum wall-clock processing time allowed in one archive operation.
    /// Default `60 s` per spec §19.2.
    pub max_processing_time: Duration,
}

impl Default for ArchiveLimits {
    fn default() -> Self {
        Self {
            max_depth: DEFAULT_MAX_DEPTH,
            max_files: DEFAULT_MAX_FILES,
            max_total_unpacked_bytes: DEFAULT_MAX_TOTAL_UNPACKED_BYTES,
            max_single_file_bytes: DEFAULT_MAX_SINGLE_FILE_BYTES,
            max_compression_ratio: DEFAULT_MAX_COMPRESSION_RATIO,
            max_symlinks: DEFAULT_MAX_SYMLINKS,
            max_processing_time: DEFAULT_MAX_PROCESSING_TIME,
        }
    }
}

/// Archive reader that lists metadata and extracts named entries to a caller-provided sink.
pub trait ArchiveReader {
    /// Lists archive entries without releasing file content.
    ///
    /// # Errors
    ///
    /// Returns an error when the archive is malformed, unsafe, or exceeds configured limits.
    fn entries(&mut self) -> Result<Vec<ArchiveEntry>, ArchiveError>;

    /// Extracts one named entry to `sink` while enforcing configured limits.
    ///
    /// # Errors
    ///
    /// Returns an error when the entry is absent, unsafe to extract, malformed, or exceeds limits.
    fn extract_entry(&mut self, name: &str, sink: &mut dyn Write) -> Result<(), ArchiveError>;
}

/// Archive inspection error.
#[derive(Debug, Error)]
pub enum ArchiveError {
    /// I/O failed while reading or writing archive content.
    #[error("archive I/O failed: {0}")]
    Io(#[from] io::Error),
    /// ZIP decoding failed.
    #[error("zip archive error: {0}")]
    Zip(#[from] ZipError),
    /// The supplied artifact type is not an archive type supported by this crate.
    #[error("unsupported archive artifact type: {artifact_type:?}")]
    UnsupportedArtifactType {
        /// Unsupported artifact type.
        artifact_type: ArtifactType,
    },
    /// The archive format is malformed.
    #[error("malformed archive: {0}")]
    MalformedArchive(String),
    /// The requested entry was not found.
    #[error("archive entry not found: {0}")]
    EntryNotFound(String),
    /// Entry path validation failed.
    #[error("unsafe archive entry path: {0}")]
    UnsafePath(String),
    /// The requested entry cannot be extracted to a byte sink.
    #[error("unsupported archive entry: {0}")]
    UnsupportedEntry(String),
    /// Archive processing exceeded a configured limit.
    #[error("archive limit exceeded: {limit}")]
    LimitExceeded {
        /// Limit that was exceeded.
        limit: &'static str,
    },
}

/// Opens archive bytes using default resource limits.
///
/// # Errors
///
/// Returns an error when `artifact_type` is unsupported.
pub fn open_archive(
    data: &[u8],
    artifact_type: ArtifactType,
) -> Result<Box<dyn ArchiveReader>, ArchiveError> {
    open_archive_with_limits(data, artifact_type, ArchiveLimits::default())
}

/// Opens archive bytes using caller-provided resource limits.
///
/// # Errors
///
/// Returns an error when `artifact_type` is unsupported.
pub fn open_archive_with_limits(
    data: &[u8],
    artifact_type: ArtifactType,
    limits: ArchiveLimits,
) -> Result<Box<dyn ArchiveReader>, ArchiveError> {
    let data = data.to_vec();
    match artifact_type {
        ArtifactType::ZipArchive => Ok(Box::new(ZipReader { data, limits })),
        ArtifactType::TarArchive => Ok(Box::new(TarReader { data, limits })),
        ArtifactType::GzipCompressed => Ok(Box::new(CompressedReader::gzip(data, limits))),
        ArtifactType::XzCompressed => Ok(Box::new(CompressedReader::xz(data, limits))),
        ArtifactType::Bzip2Compressed => Ok(Box::new(CompressedReader::bzip2(data, limits))),
        ArtifactType::ZstdCompressed => Ok(Box::new(CompressedReader::zstd(data, limits))),
        _ => Err(ArchiveError::UnsupportedArtifactType { artifact_type }),
    }
}

/// Metadata for a regular file extracted under archive resource limits.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExtractedFile {
    /// Filesystem path of the extracted file.
    pub path: PathBuf,
    /// Entry name as stored in the archive after path validation.
    pub original_name: String,
    /// Number of bytes written to `path`.
    pub size: u64,
    /// SHA-256 digest of the extracted bytes.
    pub sha256: Sha256Digest,
}

/// Extracts regular archive files into a restricted analysis directory.
///
/// The directory is created with owner-only permissions on Unix platforms. The caller owns the
/// directory after a successful extraction and must remove it after analysis. If extraction fails,
/// this function removes the partially populated inspection directory before returning the error.
///
/// # Errors
///
/// Returns an error if the archive contains unsupported entries, unsafe paths, I/O failures, or if
/// any configured resource limit is exceeded while extracting.
pub fn extract_to_inspection_dir(
    reader: &mut dyn ArchiveReader,
    limits: &ArchiveLimits,
    inspection_dir: &Path,
) -> Result<Vec<ExtractedFile>, ArchiveError> {
    let result = extract_to_directory(reader, limits, inspection_dir, DirectoryMode::Private);
    if result.is_err() {
        let _ = fs::remove_dir_all(inspection_dir);
    }
    result
}

/// Extracts regular archive files into a caller-selected destination directory.
///
/// This is intended for explicit release/unpack flows, not analysis-time scratch extraction. The
/// original archive bytes remain the authoritative artifact identity; extracted files are derived
/// outputs and must not replace the original release payload.
///
/// # Errors
///
/// Returns an error if the archive contains unsupported entries, unsafe paths, I/O failures, or if
/// any configured resource limit is exceeded while extracting.
pub fn extract_to_output_dir(
    reader: &mut dyn ArchiveReader,
    limits: &ArchiveLimits,
    output_dir: &Path,
) -> Result<Vec<ExtractedFile>, ArchiveError> {
    extract_to_directory(reader, limits, output_dir, DirectoryMode::Normal)
}

#[derive(Clone, Copy, Debug)]
enum DirectoryMode {
    Private,
    Normal,
}

fn extract_to_directory(
    reader: &mut dyn ArchiveReader,
    limits: &ArchiveLimits,
    destination: &Path,
    directory_mode: DirectoryMode,
) -> Result<Vec<ExtractedFile>, ArchiveError> {
    create_destination_dir(destination, directory_mode)?;
    let entries = reader.entries()?;
    let mut metadata_tracker = LimitTracker::new(limits);
    for entry in &entries {
        metadata_tracker.record_entry(&entry.name, entry.size, entry.compressed_size)?;
        if entry.is_symlink {
            metadata_tracker.record_symlink()?;
        }
        validate_extractable_entry(entry)?;
    }

    let mut extraction_tracker = LimitTracker::new(limits);
    let mut extracted = Vec::new();
    for entry in entries.iter().filter(|entry| !entry.is_dir) {
        extraction_tracker.record_file_metadata(&entry.name)?;
        let output_path = safe_output_path(destination, &entry.name)?;
        if let Some(parent) = output_path.parent() {
            fs::create_dir_all(parent)?;
        }

        let partial_path = partial_output_path(&output_path);
        let mut writer = HashingLimitWriter::new(
            File::create(&partial_path)?,
            &mut extraction_tracker,
            entry.compressed_size,
        );
        let extraction_result = reader.extract_entry(&entry.name, &mut writer);
        let extracted_file = match extraction_result {
            Ok(()) => writer.finish(output_path.clone(), entry.name.clone()),
            Err(error) => {
                let _ = fs::remove_file(&partial_path);
                return Err(error);
            }
        };
        fs::rename(&partial_path, &output_path)?;
        extracted.push(extracted_file);
    }

    Ok(extracted)
}

fn create_destination_dir(path: &Path, mode: DirectoryMode) -> Result<(), ArchiveError> {
    fs::create_dir_all(path)?;
    if matches!(mode, DirectoryMode::Private) {
        set_private_directory_permissions(path)?;
    }
    Ok(())
}

#[cfg(unix)]
fn set_private_directory_permissions(path: &Path) -> Result<(), ArchiveError> {
    use std::os::unix::fs::PermissionsExt;

    fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    Ok(())
}

#[cfg(not(unix))]
fn set_private_directory_permissions(_path: &Path) -> Result<(), ArchiveError> {
    Ok(())
}

fn validate_extractable_entry(entry: &ArchiveEntry) -> Result<(), ArchiveError> {
    if entry.is_dir {
        return Ok(());
    }
    if entry.entry_type != ArchiveEntryType::File || entry.is_symlink || entry.is_encrypted {
        return Err(ArchiveError::UnsupportedEntry(entry.name.clone()));
    }
    Ok(())
}

fn safe_output_path(root: &Path, name: &str) -> Result<PathBuf, ArchiveError> {
    let safe_name = safe_entry_name(name)?;
    let mut path = root.to_path_buf();
    for component in safe_name.split('/') {
        path.push(component);
    }
    Ok(path)
}

fn partial_output_path(path: &Path) -> PathBuf {
    let mut partial = path.to_path_buf();
    let extension = path.extension().map_or_else(
        || "arbitraitor-partial".into(),
        |extension| {
            let mut value = extension.to_os_string();
            value.push(".arbitraitor-partial");
            value
        },
    );
    partial.set_extension(extension);
    partial
}

struct HashingLimitWriter<'limits, 'tracker> {
    file: File,
    tracker: &'tracker mut LimitTracker<'limits>,
    hasher: Sha256,
    size: u64,
    compressed_size: Option<u64>,
}

impl<'limits, 'tracker> HashingLimitWriter<'limits, 'tracker> {
    fn new(
        file: File,
        tracker: &'tracker mut LimitTracker<'limits>,
        compressed_size: Option<u64>,
    ) -> Self {
        Self {
            file,
            tracker,
            hasher: Sha256::new(),
            size: 0,
            compressed_size,
        }
    }

    fn finish(self, path: PathBuf, original_name: String) -> ExtractedFile {
        ExtractedFile {
            path,
            original_name,
            size: self.size,
            sha256: Sha256Digest::new(self.hasher.finalize().into()),
        }
    }
}

impl Write for HashingLimitWriter<'_, '_> {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        self.tracker.check_time().map_err(io::Error::other)?;
        let bytes = u64::try_from(buffer.len()).map_err(io::Error::other)?;
        let next_size = self.size.checked_add(bytes).ok_or_else(|| {
            io::Error::other(ArchiveError::LimitExceeded {
                limit: "max_single_file_bytes",
            })
        })?;
        self.tracker
            .check_single_file(next_size)
            .map_err(io::Error::other)?;
        self.tracker
            .add_unpacked_bytes(bytes)
            .map_err(io::Error::other)?;
        self.tracker
            .check_ratio(next_size, self.compressed_size)
            .map_err(io::Error::other)?;

        self.file.write_all(buffer)?;
        self.hasher.update(buffer);
        self.size = next_size;
        Ok(buffer.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.file.flush()
    }
}

#[derive(Clone)]
struct ZipReader {
    data: Vec<u8>,
    limits: ArchiveLimits,
}

impl ArchiveReader for ZipReader {
    fn entries(&mut self) -> Result<Vec<ArchiveEntry>, ArchiveError> {
        let mut tracker = LimitTracker::new(&self.limits);
        let mut archive = ZipArchive::new(Cursor::new(self.data.as_slice()))?;
        let mut entries = Vec::new();

        for index in 0..archive.len() {
            tracker.check_time()?;
            let file = archive.by_index(index)?;
            let name = safe_entry_name(file.name())?;
            let size = file.size();
            let compressed_size = file.compressed_size();
            let is_dir = file.is_dir();
            let permissions = file.unix_mode();
            let is_symlink = permissions.is_some_and(is_unix_symlink_mode);
            let entry_type = if is_dir {
                ArchiveEntryType::Directory
            } else if is_symlink {
                ArchiveEntryType::Symlink
            } else {
                ArchiveEntryType::File
            };

            tracker.record_entry(&name, size, Some(compressed_size))?;
            if is_symlink {
                tracker.record_symlink()?;
            }
            entries.push(ArchiveEntry {
                name,
                size,
                compressed_size: Some(compressed_size),
                is_dir,
                is_symlink,
                entry_type,
                link_target: None,
                permissions,
                is_encrypted: file.encrypted(),
            });
        }

        Ok(entries)
    }

    fn extract_entry(&mut self, name: &str, sink: &mut dyn Write) -> Result<(), ArchiveError> {
        let mut tracker = LimitTracker::new(&self.limits);
        let safe_name = safe_entry_name(name)?;
        let mut archive = ZipArchive::new(Cursor::new(self.data.as_slice()))?;
        let mut file = archive.by_name(&safe_name).map_err(|error| match error {
            ZipError::FileNotFound => ArchiveError::EntryNotFound(safe_name.clone()),
            other => ArchiveError::Zip(other),
        })?;

        if file.is_dir() {
            return Err(ArchiveError::UnsupportedEntry(safe_name));
        }
        if file.unix_mode().is_some_and(is_unix_symlink_mode) {
            return Err(ArchiveError::UnsupportedEntry(safe_name));
        }

        let compressed_size = file.compressed_size();
        tracker.record_file_metadata(&safe_name)?;
        copy_with_limits(&mut file, sink, &mut tracker, Some(compressed_size))?;
        Ok(())
    }
}

#[derive(Clone)]
struct TarReader {
    data: Vec<u8>,
    limits: ArchiveLimits,
}

impl ArchiveReader for TarReader {
    fn entries(&mut self) -> Result<Vec<ArchiveEntry>, ArchiveError> {
        let mut tracker = LimitTracker::new(&self.limits);
        list_tar_entries(self.data.as_slice(), &mut tracker)
    }

    fn extract_entry(&mut self, name: &str, sink: &mut dyn Write) -> Result<(), ArchiveError> {
        let safe_name = safe_entry_name(name)?;
        let mut tracker = LimitTracker::new(&self.limits);
        extract_tar_entry(self.data.as_slice(), &safe_name, sink, &mut tracker)
    }
}

#[derive(Clone, Copy, Debug)]
enum CompressionKind {
    Gzip,
    Xz,
    Bzip2,
    Zstd,
}

#[derive(Clone)]
struct CompressedReader {
    data: Vec<u8>,
    limits: ArchiveLimits,
    kind: CompressionKind,
}

impl CompressedReader {
    fn gzip(data: Vec<u8>, limits: ArchiveLimits) -> Self {
        Self {
            data,
            limits,
            kind: CompressionKind::Gzip,
        }
    }

    fn xz(data: Vec<u8>, limits: ArchiveLimits) -> Self {
        Self {
            data,
            limits,
            kind: CompressionKind::Xz,
        }
    }

    fn bzip2(data: Vec<u8>, limits: ArchiveLimits) -> Self {
        Self {
            data,
            limits,
            kind: CompressionKind::Bzip2,
        }
    }

    fn zstd(data: Vec<u8>, limits: ArchiveLimits) -> Self {
        Self {
            data,
            limits,
            kind: CompressionKind::Zstd,
        }
    }

    fn decoder(&self) -> Result<Box<dyn Read + '_>, ArchiveError> {
        let cursor = Cursor::new(self.data.as_slice());
        match self.kind {
            CompressionKind::Gzip => Ok(Box::new(GzDecoder::new(cursor))),
            CompressionKind::Xz => Ok(Box::new(XzDecoder::new(cursor))),
            CompressionKind::Bzip2 => Ok(Box::new(BzDecoder::new(cursor))),
            CompressionKind::Zstd => Ok(Box::new(zstd::stream::read::Decoder::new(cursor)?)),
        }
    }
}

impl ArchiveReader for CompressedReader {
    fn entries(&mut self) -> Result<Vec<ArchiveEntry>, ArchiveError> {
        let mut tracker = LimitTracker::new(&self.limits);
        let decoded = decompress_to_vec(self.decoder()?, &mut tracker, self.data.len() as u64)?;

        if is_tar(&decoded) {
            return list_tar_entries(decoded.as_slice(), &mut LimitTracker::new(&self.limits));
        }

        let size = decoded.len() as u64;
        tracker.record_file_metadata(SINGLE_FILE_ENTRY_NAME)?;
        Ok(vec![ArchiveEntry {
            name: SINGLE_FILE_ENTRY_NAME.to_owned(),
            size,
            compressed_size: Some(self.data.len() as u64),
            is_dir: false,
            is_symlink: false,
            entry_type: ArchiveEntryType::File,
            link_target: None,
            permissions: None,
            is_encrypted: false,
        }])
    }

    fn extract_entry(&mut self, name: &str, sink: &mut dyn Write) -> Result<(), ArchiveError> {
        let safe_name = safe_entry_name(name)?;
        let mut tracker = LimitTracker::new(&self.limits);

        if safe_name == SINGLE_FILE_ENTRY_NAME {
            tracker.record_file_metadata(SINGLE_FILE_ENTRY_NAME)?;
            copy_with_limits(
                &mut self.decoder()?,
                sink,
                &mut tracker,
                Some(self.data.len() as u64),
            )?;
            return Ok(());
        }

        let decoded = decompress_to_vec(self.decoder()?, &mut tracker, self.data.len() as u64)?;
        if !is_tar(&decoded) {
            return Err(ArchiveError::EntryNotFound(safe_name));
        }
        extract_tar_entry(
            decoded.as_slice(),
            &safe_name,
            sink,
            &mut LimitTracker::new(&self.limits),
        )
    }
}

fn list_tar_entries(
    data: &[u8],
    tracker: &mut LimitTracker<'_>,
) -> Result<Vec<ArchiveEntry>, ArchiveError> {
    let mut archive = Archive::new(Cursor::new(data));
    let mut entries = Vec::new();

    for entry_result in archive.entries()? {
        tracker.check_time()?;
        let entry = entry_result?;
        let path = entry.path()?;
        let name = safe_entry_name(path.to_string_lossy().as_ref())?;
        let header = entry.header();
        let size = header.size()?;
        let entry_type = header.entry_type();
        let is_dir = entry_type.is_dir();
        let is_symlink = entry_type.is_symlink();
        let permissions = header.mode().ok();
        let link_target = header
            .link_name()
            .ok()
            .flatten()
            .map(|target| target.to_string_lossy().into_owned());

        tracker.record_entry(&name, size, None)?;
        if is_symlink {
            tracker.record_symlink()?;
        }
        entries.push(ArchiveEntry {
            name,
            size,
            compressed_size: None,
            is_dir,
            is_symlink,
            entry_type: tar_entry_type(entry_type),
            link_target,
            permissions,
            is_encrypted: false,
        });
    }

    Ok(entries)
}

fn extract_tar_entry(
    data: &[u8],
    name: &str,
    sink: &mut dyn Write,
    tracker: &mut LimitTracker<'_>,
) -> Result<(), ArchiveError> {
    let mut archive = Archive::new(Cursor::new(data));

    for entry_result in archive.entries()? {
        tracker.check_time()?;
        let mut entry = entry_result?;
        let path = entry.path()?;
        let entry_name = safe_entry_name(path.to_string_lossy().as_ref())?;
        tracker.record_file_metadata(&entry_name)?;

        if entry_name != name {
            continue;
        }
        if entry.header().entry_type().is_dir() || entry.header().entry_type().is_symlink() {
            return Err(ArchiveError::UnsupportedEntry(name.to_owned()));
        }

        copy_with_limits(&mut entry, sink, tracker, None)?;
        return Ok(());
    }

    Err(ArchiveError::EntryNotFound(name.to_owned()))
}

/// Scans archive metadata for extraction and archive-processing hazards.
#[must_use]
pub fn detect_archive_hazards(entries: &[ArchiveEntry], limits: &ArchiveLimits) -> Vec<Finding> {
    let mut findings = Vec::new();
    let mut exact_names = HashSet::new();
    let mut normalized_names = HashMap::<String, String>::new();
    let mut total_unpacked_bytes = 0_u64;

    if entries.len() > limits.max_files as usize {
        findings.push(hazard_finding(
            "archive.hazard.excessive-file-count",
            Severity::High,
            "Archive contains too many entries",
            format!(
                "Archive contains {} entries, exceeding the configured limit of {}.",
                entries.len(),
                limits.max_files
            ),
            "max_files",
            Some(format!(
                "entries={}; limit={}",
                entries.len(),
                limits.max_files
            )),
        ));
    }

    for (index, entry) in entries.iter().enumerate() {
        detect_path_hazards(entry, index, &mut findings);
        detect_metadata_hazards(entry, index, limits, &mut findings);
        detect_entry_type_hazards(entry, index, &mut findings);

        if !exact_names.insert(entry.name.clone()) {
            findings.push(entry_hazard_finding(
                index,
                "overwriting-entry",
                Severity::High,
                "Archive contains duplicate entry names",
                "Multiple entries share the same archive path and may overwrite each other during extraction.",
                entry,
            ));
        }

        let normalized_name = normalized_collision_key(&entry.name);
        if let Some(previous) = normalized_names.insert(normalized_name, entry.name.clone())
            && previous != entry.name
        {
            findings.push(entry_hazard_finding(
                index,
                "case-unicode-collision",
                Severity::High,
                "Archive paths collide after case or Unicode normalization",
                "This entry can collide with another entry on case-insensitive or Unicode-normalizing filesystems.",
                entry,
            ));
        }

        total_unpacked_bytes = if let Some(total) = total_unpacked_bytes.checked_add(entry.size) {
            total
        } else {
            findings.push(entry_hazard_finding(
                index,
                "malformed-size-overflow",
                Severity::High,
                "Archive entry sizes overflow metadata accounting",
                "The advertised uncompressed sizes overflow total size accounting.",
                entry,
            ));
            total_unpacked_bytes
        };
    }

    if total_unpacked_bytes > limits.max_total_unpacked_bytes {
        findings.push(hazard_finding(
            "archive.hazard.excessive-total-size",
            Severity::High,
            "Archive expands beyond total unpacked byte limit",
            format!(
                "Archive advertises {total_unpacked_bytes} unpacked bytes, exceeding the configured limit of {}.",
                limits.max_total_unpacked_bytes
            ),
            "max_total_unpacked_bytes",
            Some(format!(
                "unpacked_bytes={total_unpacked_bytes}; limit={}",
                limits.max_total_unpacked_bytes
            )),
        ));
    }

    findings
}

/// Scans tar parser consensus hazards that can make member lists parser-dependent.
#[must_use]
pub fn detect_tar_parser_differentials(
    data: &[u8],
    primary_entries: &[ArchiveEntry],
    limits: &ArchiveLimits,
) -> Vec<Finding> {
    match consensus_tar_members(data, limits) {
        Ok(report) => {
            parser_differential_findings(primary_entries, &report.members, report.hazards)
        }
        Err(error) => vec![parser_differential_finding(
            "consensus-parser-error",
            "Tar consensus parser could not complete",
            format!(
                "The bounded tar consensus parser failed while checking parser agreement: {error}."
            ),
            Some(format!("error={error}")),
        )],
    }
}

/// Emits parser-differential findings for disagreeing primary and consensus member lists.
#[must_use]
pub fn parser_differential_findings(
    primary_entries: &[ArchiveEntry],
    consensus_members: &[String],
    mut hazards: Vec<ParserDifferentialHazard>,
) -> Vec<Finding> {
    let primary_members: Vec<String> = primary_entries
        .iter()
        .filter(|entry| !entry.is_dir)
        .map(|entry| entry.name.clone())
        .collect();

    if primary_members != consensus_members {
        hazards.push(ParserDifferentialHazard::MemberListMismatch {
            primary_members,
            consensus_members: consensus_members.to_vec(),
        });
    }

    hazards
        .into_iter()
        .enumerate()
        .map(|(index, hazard)| hazard.into_finding(index))
        .collect()
}

/// Bounded tar consensus parser hazard.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ParserDifferentialHazard {
    /// A PAX `size=` record appears before an intermediary extension header.
    PaxSizeAppliesAcrossExtensionHeader {
        /// Extension header block index with PAX size state pending.
        block_index: u64,
        /// Intermediary tar typeflag (`L`, `K`, `x`, or `g`).
        typeflag: u8,
    },
    /// Primary tar-rs member list differs from the consensus scanner.
    MemberListMismatch {
        /// Member list returned by the primary parser.
        primary_members: Vec<String>,
        /// Member list returned by the consensus scanner.
        consensus_members: Vec<String>,
    },
}

impl ParserDifferentialHazard {
    fn into_finding(self, index: usize) -> Finding {
        match self {
            Self::PaxSizeAppliesAcrossExtensionHeader {
                block_index,
                typeflag,
            } => parser_differential_finding(
                &format!("archive.parser-differential.pax-size-extension-header.{index}"),
                "Tar PAX size metadata crosses an extension header",
                "A PAX extended header contains `size=` while an intermediary GNU/PAX extension header appears before the file entry. POSIX applies PAX records to the file entry, not to extension headers; vulnerable parsers can desynchronize the member stream.".to_owned(),
                Some(format!(
                    "block_index={block_index}; typeflag={}",
                    char::from(typeflag)
                )),
            ),
            Self::MemberListMismatch {
                primary_members,
                consensus_members,
            } => parser_differential_finding(
                &format!("archive.parser-differential.member-list.{index}"),
                "Tar parsers disagree about member list",
                "The primary archive parser and bounded consensus scanner produced different member lists for the same tar bytes.".to_owned(),
                Some(format!(
                    "primary_members={primary_members:?}; consensus_members={consensus_members:?}"
                )),
            ),
        }
    }
}

#[derive(Debug)]
struct ConsensusTarReport {
    members: Vec<String>,
    hazards: Vec<ParserDifferentialHazard>,
}

fn consensus_tar_members(
    data: &[u8],
    limits: &ArchiveLimits,
) -> Result<ConsensusTarReport, ArchiveError> {
    let mut tracker = LimitTracker::new(limits);
    let mut members = Vec::new();
    let mut hazards = Vec::new();
    let mut offset = 0_usize;
    let mut block_index = 0_u64;
    let mut pax_size_pending = false;

    while let Some(header) = data.get(offset..offset.saturating_add(TAR_BLOCK_SIZE)) {
        if header.len() < TAR_BLOCK_SIZE {
            return Err(ArchiveError::MalformedArchive(
                "truncated tar header".to_owned(),
            ));
        }
        if header.iter().all(|byte| *byte == 0) {
            break;
        }

        tracker.check_time()?;
        let typeflag = header[TAR_TYPEFLAG_OFFSET];
        let size = parse_tar_octal(&header[TAR_SIZE_RANGE])?;
        let content_offset =
            offset
                .checked_add(TAR_BLOCK_SIZE)
                .ok_or(ArchiveError::LimitExceeded {
                    limit: "max_total_unpacked_bytes",
                })?;

        if is_pax_header_typeflag(typeflag) {
            let pax_content = tar_content(data, content_offset, size)?;
            if pax_content_has_size_record(pax_content) {
                pax_size_pending = true;
            }
        } else if is_tar_extension_header(typeflag) {
            if pax_size_pending {
                hazards.push(
                    ParserDifferentialHazard::PaxSizeAppliesAcrossExtensionHeader {
                        block_index,
                        typeflag,
                    },
                );
            }
        } else {
            pax_size_pending = false;
            let name = tar_header_name(header)?;
            tracker.record_entry(&name, size, None)?;
            if !is_directory_typeflag(typeflag) {
                members.push(name);
            }
        }

        let padded_size = padded_tar_size(size)?;
        offset = content_offset
            .checked_add(padded_size)
            .ok_or(ArchiveError::LimitExceeded {
                limit: "max_total_unpacked_bytes",
            })?;
        block_index = block_index
            .checked_add(1)
            .ok_or(ArchiveError::LimitExceeded { limit: "max_files" })?;
    }

    Ok(ConsensusTarReport { members, hazards })
}

fn tar_content(data: &[u8], offset: usize, size: u64) -> Result<&[u8], ArchiveError> {
    let size = usize::try_from(size).map_err(|_| ArchiveError::LimitExceeded {
        limit: "max_single_file_bytes",
    })?;
    data.get(offset..offset.saturating_add(size))
        .ok_or_else(|| ArchiveError::MalformedArchive("truncated tar content".to_owned()))
}

fn tar_header_name(header: &[u8]) -> Result<String, ArchiveError> {
    let name = tar_string(&header[TAR_NAME_RANGE]);
    let prefix = tar_string(&header[TAR_PREFIX_RANGE]);
    let raw_name = if prefix.is_empty() {
        name
    } else {
        format!("{prefix}/{name}")
    };
    safe_entry_name(&raw_name)
}

fn tar_string(bytes: &[u8]) -> String {
    let end = bytes
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..end]).into_owned()
}

fn parse_tar_octal(bytes: &[u8]) -> Result<u64, ArchiveError> {
    let value = bytes
        .iter()
        .copied()
        .take_while(|byte| *byte != 0)
        .filter(|byte| !byte.is_ascii_whitespace())
        .try_fold(0_u64, |acc, byte| {
            if !(b'0'..=b'7').contains(&byte) {
                return Err(ArchiveError::MalformedArchive(
                    "tar size field is not octal".to_owned(),
                ));
            }
            acc.checked_mul(8)
                .and_then(|value| value.checked_add(u64::from(byte - b'0')))
                .ok_or(ArchiveError::LimitExceeded {
                    limit: "max_single_file_bytes",
                })
        })?;
    Ok(value)
}

fn padded_tar_size(size: u64) -> Result<usize, ArchiveError> {
    let padding = (TAR_BLOCK_SIZE as u64 - size % TAR_BLOCK_SIZE as u64) % TAR_BLOCK_SIZE as u64;
    usize::try_from(
        size.checked_add(padding)
            .ok_or(ArchiveError::LimitExceeded {
                limit: "max_single_file_bytes",
            })?,
    )
    .map_err(|_| ArchiveError::LimitExceeded {
        limit: "max_single_file_bytes",
    })
}

fn pax_content_has_size_record(content: &[u8]) -> bool {
    String::from_utf8_lossy(content).lines().any(|line| {
        line.split_once(' ')
            .is_some_and(|(_, record)| record.starts_with("size="))
    })
}

fn is_pax_header_typeflag(typeflag: u8) -> bool {
    matches!(typeflag, b'x' | b'g')
}

fn is_tar_extension_header(typeflag: u8) -> bool {
    matches!(typeflag, b'L' | b'K' | b'x' | b'g')
}

fn is_directory_typeflag(typeflag: u8) -> bool {
    typeflag == b'5'
}

fn parser_differential_finding(
    id: &str,
    title: &str,
    description: String,
    evidence_content: Option<String>,
) -> Finding {
    Finding {
        id: id.to_owned(),
        detector: DETECTOR_ID.to_owned(),
        category: FindingCategory::ParserDifferential,
        severity: Severity::Medium,
        confidence: Confidence::Confirmed,
        title: title.to_owned(),
        description,
        evidence: vec![Evidence {
            kind: EvidenceKind::Other,
            description: "tar parser consensus".to_owned(),
            content: evidence_content,
        }],
        artifact_sha256: Sha256Digest::new([0_u8; 32]),
        location: None,
        remediation: Some("Refuse release until the tar stream is rebuilt without parser-dependent extension-header state and all parsers agree on the member set.".to_owned()),
        references: vec![PARSER_DIFFERENTIAL_REFERENCE.to_owned()],
        tags: vec!["archive-hazard".to_owned(), "parser-smelting".to_owned()],
        taxonomies: vec![TaxonomyRef {
            name: TaxonomyName::Cwe,
            id: "CWE-436".to_owned(),
            confidence: Confidence::High,
            url: Some(CWE_436_URL.to_owned()),
        }],
    }
}

fn detect_path_hazards(entry: &ArchiveEntry, index: usize, findings: &mut Vec<Finding>) {
    if entry.name.starts_with('/') {
        findings.push(entry_hazard_finding(
            index,
            "absolute-path",
            Severity::Critical,
            "Archive entry uses an absolute path",
            "Absolute paths can write outside the intended extraction root.",
            entry,
        ));
    }
    if entry.name.contains("..") {
        findings.push(entry_hazard_finding(
            index,
            "parent-traversal",
            Severity::Critical,
            "Archive entry contains parent-directory traversal",
            "Parent-directory components can write outside the intended extraction root.",
            entry,
        ));
    }
    if is_windows_absolute_path(&entry.name) {
        findings.push(entry_hazard_finding(
            index,
            "windows-absolute-path",
            Severity::Critical,
            "Archive entry uses a Windows absolute path",
            "Windows drive or UNC paths can write outside the intended extraction root.",
            entry,
        ));
    }
    if is_reserved_windows_name(&entry.name) {
        findings.push(entry_hazard_finding(
            index,
            "reserved-device-name",
            Severity::High,
            "Archive entry uses a reserved Windows device name",
            "Reserved device names can target special devices instead of normal files on Windows.",
            entry,
        ));
    }
    if executable_hidden_by_extension(&entry.name) {
        findings.push(entry_hazard_finding(
            index,
            "hidden-executable-extension",
            Severity::High,
            "Archive entry hides an executable behind a benign extension",
            "Double extensions can disguise executable content as a document or media file.",
            entry,
        ));
    }
    if is_nested_archive_name(&entry.name) {
        findings.push(entry_hazard_finding(
            index,
            "nested-archive",
            Severity::Medium,
            "Archive entry is itself an archive",
            "Nested archives require bounded recursive inspection before release.",
            entry,
        ));
    }
    if entry.is_symlink && symlink_target_escapes(entry) {
        findings.push(entry_hazard_finding(
            index,
            "symlink-escape",
            Severity::Critical,
            "Archive symlink target escapes the extraction root",
            "A symlink can redirect extraction or later access outside the archive root.",
            entry,
        ));
    }
}

fn detect_metadata_hazards(
    entry: &ArchiveEntry,
    index: usize,
    limits: &ArchiveLimits,
    findings: &mut Vec<Finding>,
) {
    if entry.name.is_empty() {
        findings.push(entry_hazard_finding(
            index,
            "malformed-empty-name",
            Severity::High,
            "Archive entry has an empty name",
            "Empty entry names are malformed and cannot be mapped safely to an extraction path.",
            entry,
        ));
    }
    if entry.size > limits.max_single_file_bytes {
        findings.push(entry_hazard_finding(
            index,
            "excessive-entry-size",
            Severity::High,
            "Archive entry exceeds single-file byte limit",
            "The advertised uncompressed size exceeds the configured per-file limit.",
            entry,
        ));
    }
    if compression_ratio_exceeded(entry, limits) {
        findings.push(entry_hazard_finding(
            index,
            "excessive-compression-ratio",
            Severity::Critical,
            "Archive entry has an excessive compression ratio",
            "The advertised compressed and uncompressed sizes match zip-bomb characteristics.",
            entry,
        ));
    }
    if entry.size > 0 && entry.compressed_size == Some(0) {
        findings.push(entry_hazard_finding(
            index,
            "malformed-zero-compressed-size",
            Severity::High,
            "Archive entry has suspicious size metadata",
            "A non-empty entry advertises a zero compressed size.",
            entry,
        ));
    }
    if entry.is_encrypted {
        findings.push(entry_hazard_finding(
            index,
            "encrypted-member",
            Severity::High,
            "Archive entry is encrypted",
            "Encrypted members prevent content inspection and must fail closed.",
            entry,
        ));
    }
    if entry
        .permissions
        .is_some_and(|mode| mode & (SETUID_BIT | SETGID_BIT) != 0)
    {
        findings.push(entry_hazard_finding(
            index,
            "setuid-setgid-bits",
            Severity::High,
            "Archive entry sets setuid or setgid permission bits",
            "setuid and setgid bits can alter privilege boundaries after extraction.",
            entry,
        ));
    }
}

fn detect_entry_type_hazards(entry: &ArchiveEntry, index: usize, findings: &mut Vec<Finding>) {
    if matches!(
        entry.entry_type,
        ArchiveEntryType::Fifo | ArchiveEntryType::CharacterDevice | ArchiveEntryType::BlockDevice
    ) || entry.permissions.is_some_and(is_unix_special_file_mode)
    {
        findings.push(entry_hazard_finding(
            index,
            "device-or-fifo",
            Severity::Critical,
            "Archive entry is a device node or FIFO",
            "Device nodes and FIFOs are not safe regular filesystem payloads.",
            entry,
        ));
    } else if matches!(
        entry.entry_type,
        ArchiveEntryType::Hardlink | ArchiveEntryType::Other
    ) {
        findings.push(entry_hazard_finding(
            index,
            "unsupported-entry-type",
            Severity::High,
            "Archive entry uses a non-regular file type",
            "Non-regular entries require explicit policy handling before extraction.",
            entry,
        ));
    }
}

fn hazard_finding(
    id: &str,
    severity: Severity,
    title: &str,
    description: String,
    tag: &str,
    evidence_content: Option<String>,
) -> Finding {
    Finding {
        id: id.to_owned(),
        detector: DETECTOR_ID.to_owned(),
        category: FindingCategory::ArchiveHazard,
        severity,
        confidence: Confidence::Confirmed,
        title: title.to_owned(),
        description,
        evidence: vec![Evidence {
            kind: EvidenceKind::Other,
            description: "archive metadata".to_owned(),
            content: evidence_content,
        }],
        artifact_sha256: Sha256Digest::new([0_u8; 32]),
        location: None,
        remediation: Some("Do not extract or release this archive until the hazardous entries are removed or policy explicitly handles them under containment.".to_owned()),
        references: vec![ARCHIVE_HAZARD_REFERENCE.to_owned()],
        tags: vec!["archive-hazard".to_owned(), tag.to_owned()],
        taxonomies: Vec::new(),
    }
}

fn entry_hazard_finding(
    index: usize,
    tag: &str,
    severity: Severity,
    title: &str,
    description: &str,
    entry: &ArchiveEntry,
) -> Finding {
    hazard_finding(
        &format!("archive.hazard.{tag}.{index}"),
        severity,
        title,
        description.to_owned(),
        tag,
        Some(entry_evidence(entry)),
    )
}

fn entry_evidence(entry: &ArchiveEntry) -> String {
    format!(
        "name={:?}; size={}; compressed_size={:?}; entry_type={:?}; link_target={:?}; permissions={:?}; encrypted={}",
        entry.name,
        entry.size,
        entry.compressed_size,
        entry.entry_type,
        entry.link_target,
        entry.permissions,
        entry.is_encrypted
    )
}

fn compression_ratio_exceeded(entry: &ArchiveEntry, limits: &ArchiveLimits) -> bool {
    let Some(compressed_size) = entry.compressed_size else {
        return false;
    };
    if compressed_size == 0 {
        return entry.size > 0;
    }
    entry.size / compressed_size > u64::from(limits.max_compression_ratio)
}

fn is_windows_absolute_path(name: &str) -> bool {
    let bytes = name.as_bytes();
    bytes.len() >= 3
        && bytes[0].is_ascii_alphabetic()
        && bytes[1] == b':'
        && matches!(bytes[2], b'/' | b'\\')
        || name.starts_with("\\\\")
        || name.starts_with("//")
}

fn is_reserved_windows_name(name: &str) -> bool {
    let Some(file_name) = name.rsplit(['/', '\\']).next() else {
        return false;
    };
    let stem = file_name
        .trim_end_matches([' ', '.'])
        .split('.')
        .next()
        .unwrap_or_default()
        .to_ascii_uppercase();
    matches!(stem.as_str(), "CON" | "PRN" | "AUX" | "NUL")
        || numbered_reserved_name(&stem, "COM")
        || numbered_reserved_name(&stem, "LPT")
}

fn numbered_reserved_name(value: &str, prefix: &str) -> bool {
    let Some(suffix) = value.strip_prefix(prefix) else {
        return false;
    };
    matches!(suffix, "1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9")
}

fn executable_hidden_by_extension(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    let parts: Vec<&str> = lower
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or_default()
        .split('.')
        .collect();
    if parts.len() < 3 {
        return false;
    }
    let executable = parts.last().copied().unwrap_or_default();
    let disguised = parts.get(parts.len() - 2).copied().unwrap_or_default();
    matches!(
        executable,
        "exe" | "scr" | "com" | "bat" | "cmd" | "ps1" | "vbs" | "js" | "msi"
    ) && matches!(
        disguised,
        "txt"
            | "pdf"
            | "doc"
            | "docx"
            | "xls"
            | "xlsx"
            | "png"
            | "jpg"
            | "jpeg"
            | "gif"
            | "csv"
            | "rtf"
    )
}

fn is_nested_archive_name(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    ARCHIVE_SUFFIXES
        .iter()
        .any(|suffix| lower.as_bytes().ends_with(suffix.as_bytes()))
}

fn symlink_target_escapes(entry: &ArchiveEntry) -> bool {
    let Some(target) = entry.link_target.as_deref() else {
        return false;
    };
    if target.starts_with('/') || is_windows_absolute_path(target) {
        return true;
    }

    let mut depth = entry.name.split(['/', '\\']).count().saturating_sub(1);
    for component in target
        .split(['/', '\\'])
        .filter(|component| !component.is_empty())
    {
        match component {
            "." => {}
            ".." if depth == 0 => return true,
            ".." => depth -= 1,
            _ => depth += 1,
        }
    }
    false
}

fn normalized_collision_key(name: &str) -> String {
    name.chars()
        .filter(|character| !matches!(*character, '\u{0300}'..='\u{036f}'))
        .flat_map(normalized_collision_chars)
        .collect()
}

fn normalized_collision_chars(character: char) -> Vec<char> {
    let folded = match character {
        'À'..='Å' | 'à'..='å' | 'Ā' | 'ā' | 'Ă' | 'ă' | 'Ą' | 'ą' => "a",
        'Ç' | 'ç' | 'Ć' | 'ć' | 'Ĉ' | 'ĉ' | 'Ċ' | 'ċ' | 'Č' | 'č' => "c",
        'È'..='Ë' | 'è'..='ë' | 'Ē' | 'ē' | 'Ĕ' | 'ĕ' | 'Ė' | 'ė' | 'Ę' | 'ę' | 'Ě' | 'ě' => {
            "e"
        }
        'Ì'..='Ï' | 'ì'..='ï' | 'Ĩ' | 'ĩ' | 'Ī' | 'ī' | 'Ĭ' | 'ĭ' | 'Į' | 'į' | 'İ' => {
            "i"
        }
        'Ñ' | 'ñ' | 'Ń' | 'ń' | 'Ņ' | 'ņ' | 'Ň' | 'ň' => "n",
        'Ò'..='Ö' | 'Ø' | 'ò'..='ö' | 'ø' | 'Ō' | 'ō' | 'Ŏ' | 'ŏ' | 'Ő' | 'ő' => "o",
        'Ù'..='Ü'
        | 'ù'..='ü'
        | 'Ũ'
        | 'ũ'
        | 'Ū'
        | 'ū'
        | 'Ŭ'
        | 'ŭ'
        | 'Ů'
        | 'ů'
        | 'Ű'
        | 'ű'
        | 'Ų'
        | 'ų' => "u",
        'Ý' | 'ý' | 'ÿ' | 'Ŷ' | 'ŷ' => "y",
        'ß' => "ss",
        _ => return character.to_lowercase().collect(),
    };
    folded.chars().collect()
}

fn is_unix_special_file_mode(mode: u32) -> bool {
    matches!(
        mode & UNIX_FILE_TYPE_MASK,
        0o010_000 | 0o020_000 | 0o060_000
    )
}

fn tar_entry_type(entry_type: tar::EntryType) -> ArchiveEntryType {
    if entry_type.is_file() {
        ArchiveEntryType::File
    } else if entry_type.is_dir() {
        ArchiveEntryType::Directory
    } else if entry_type.is_symlink() {
        ArchiveEntryType::Symlink
    } else if entry_type.is_hard_link() {
        ArchiveEntryType::Hardlink
    } else if entry_type.is_fifo() {
        ArchiveEntryType::Fifo
    } else if entry_type.is_character_special() {
        ArchiveEntryType::CharacterDevice
    } else if entry_type.is_block_special() {
        ArchiveEntryType::BlockDevice
    } else {
        ArchiveEntryType::Other
    }
}

struct LimitTracker<'a> {
    limits: &'a ArchiveLimits,
    started_at: Instant,
    files: u32,
    total_unpacked_bytes: u64,
    symlinks: u32,
}

impl<'a> LimitTracker<'a> {
    fn new(limits: &'a ArchiveLimits) -> Self {
        Self {
            limits,
            started_at: Instant::now(),
            files: 0,
            total_unpacked_bytes: 0,
            symlinks: 0,
        }
    }

    fn check_time(&self) -> Result<(), ArchiveError> {
        if self.started_at.elapsed() > self.limits.max_processing_time {
            return Err(ArchiveError::LimitExceeded {
                limit: "max_processing_time",
            });
        }
        Ok(())
    }

    fn record_entry(
        &mut self,
        name: &str,
        size: u64,
        compressed_size: Option<u64>,
    ) -> Result<(), ArchiveError> {
        self.record_file_metadata(name)?;
        self.check_single_file(size)?;
        self.add_unpacked_bytes(size)?;
        self.check_ratio(size, compressed_size)
    }

    /// Counts a symlink entry against `max_symlinks`. Must be called for
    /// every archive entry whose `is_symlink` flag is true, in addition to
    /// [`record_entry`](Self::record_entry). The spec default of
    /// `max_symlinks = 0` means any symlink entry triggers
    /// `ArchiveError::LimitExceeded` with `limit = "max_symlinks"`.
    fn record_symlink(&mut self) -> Result<(), ArchiveError> {
        self.check_time()?;
        self.symlinks = self
            .symlinks
            .checked_add(1)
            .ok_or(ArchiveError::LimitExceeded {
                limit: "max_symlinks",
            })?;
        if self.symlinks > self.limits.max_symlinks {
            return Err(ArchiveError::LimitExceeded {
                limit: "max_symlinks",
            });
        }
        Ok(())
    }

    fn record_file_metadata(&mut self, name: &str) -> Result<(), ArchiveError> {
        self.check_time()?;
        check_depth(name, self.limits.max_depth)?;
        self.files = self
            .files
            .checked_add(1)
            .ok_or(ArchiveError::LimitExceeded { limit: "max_files" })?;
        if self.files > self.limits.max_files {
            return Err(ArchiveError::LimitExceeded { limit: "max_files" });
        }
        Ok(())
    }

    fn check_single_file(&self, size: u64) -> Result<(), ArchiveError> {
        if size > self.limits.max_single_file_bytes {
            return Err(ArchiveError::LimitExceeded {
                limit: "max_single_file_bytes",
            });
        }
        Ok(())
    }

    fn add_unpacked_bytes(&mut self, bytes: u64) -> Result<(), ArchiveError> {
        self.total_unpacked_bytes =
            self.total_unpacked_bytes
                .checked_add(bytes)
                .ok_or(ArchiveError::LimitExceeded {
                    limit: "max_total_unpacked_bytes",
                })?;
        if self.total_unpacked_bytes > self.limits.max_total_unpacked_bytes {
            return Err(ArchiveError::LimitExceeded {
                limit: "max_total_unpacked_bytes",
            });
        }
        Ok(())
    }

    fn check_ratio(
        &self,
        unpacked_size: u64,
        compressed_size: Option<u64>,
    ) -> Result<(), ArchiveError> {
        let Some(compressed_size) = compressed_size else {
            return Ok(());
        };
        if compressed_size == 0 {
            if unpacked_size > 0 {
                return Err(ArchiveError::LimitExceeded {
                    limit: "max_compression_ratio",
                });
            }
            return Ok(());
        }
        if unpacked_size / compressed_size > u64::from(self.limits.max_compression_ratio) {
            return Err(ArchiveError::LimitExceeded {
                limit: "max_compression_ratio",
            });
        }
        Ok(())
    }
}

fn copy_with_limits(
    reader: &mut dyn Read,
    sink: &mut dyn Write,
    tracker: &mut LimitTracker<'_>,
    compressed_size: Option<u64>,
) -> Result<u64, ArchiveError> {
    let mut buffer = [0_u8; COPY_BUFFER_SIZE];
    let initial_total = tracker.total_unpacked_bytes;
    let mut copied = 0_u64;

    loop {
        tracker.check_time()?;
        let read = reader.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        let read_u64 = read as u64;
        copied = copied
            .checked_add(read_u64)
            .ok_or(ArchiveError::LimitExceeded {
                limit: "max_single_file_bytes",
            })?;
        tracker.check_single_file(copied)?;

        let total_after_chunk =
            initial_total
                .checked_add(copied)
                .ok_or(ArchiveError::LimitExceeded {
                    limit: "max_total_unpacked_bytes",
                })?;
        if total_after_chunk > tracker.limits.max_total_unpacked_bytes {
            return Err(ArchiveError::LimitExceeded {
                limit: "max_total_unpacked_bytes",
            });
        }
        tracker.total_unpacked_bytes = tracker.total_unpacked_bytes.checked_add(read_u64).ok_or(
            ArchiveError::LimitExceeded {
                limit: "max_total_unpacked_bytes",
            },
        )?;
        if tracker.total_unpacked_bytes > tracker.limits.max_total_unpacked_bytes {
            return Err(ArchiveError::LimitExceeded {
                limit: "max_total_unpacked_bytes",
            });
        }
        tracker.check_ratio(copied, compressed_size)?;
        write_all_archive(sink, &buffer[..read])?;
    }

    Ok(copied)
}

fn write_all_archive(sink: &mut dyn Write, buffer: &[u8]) -> Result<(), ArchiveError> {
    sink.write_all(buffer).map_err(archive_error_from_io)
}

fn archive_error_from_io(error: io::Error) -> ArchiveError {
    if let Some(ArchiveError::LimitExceeded { limit }) = error
        .get_ref()
        .and_then(|inner| inner.downcast_ref::<ArchiveError>())
    {
        return ArchiveError::LimitExceeded { limit };
    }
    ArchiveError::Io(error)
}

fn decompress_to_vec(
    mut reader: Box<dyn Read + '_>,
    tracker: &mut LimitTracker<'_>,
    compressed_size: u64,
) -> Result<Vec<u8>, ArchiveError> {
    let mut decoded = Vec::new();
    copy_with_limits(&mut reader, &mut decoded, tracker, Some(compressed_size))?;
    Ok(decoded)
}

fn safe_entry_name(name: &str) -> Result<String, ArchiveError> {
    let path = Path::new(name);
    if name.is_empty() || path.is_absolute() {
        return Err(ArchiveError::UnsafePath(name.to_owned()));
    }

    let mut normal = Vec::new();
    for component in path.components() {
        match component {
            Component::Normal(part) => normal.push(part.to_string_lossy().into_owned()),
            Component::CurDir => {}
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                return Err(ArchiveError::UnsafePath(name.to_owned()));
            }
        }
    }

    if normal.is_empty() {
        return Err(ArchiveError::UnsafePath(name.to_owned()));
    }
    Ok(normal.join("/"))
}

fn check_depth(name: &str, max_depth: u32) -> Result<(), ArchiveError> {
    let depth = u32::try_from(
        name.split('/')
            .filter(|component| !component.is_empty())
            .count(),
    )
    .map_err(|_| ArchiveError::LimitExceeded { limit: "max_depth" })?;
    if depth > max_depth {
        return Err(ArchiveError::LimitExceeded { limit: "max_depth" });
    }
    Ok(())
}

fn is_unix_symlink_mode(mode: u32) -> bool {
    mode & 0o170_000 == 0o120_000
}

fn is_tar(data: &[u8]) -> bool {
    data.get(TAR_MAGIC_OFFSET..TAR_MAGIC_OFFSET + TAR_MAGIC.len()) == Some(TAR_MAGIC)
}

#[cfg(test)]
#[path = "tests.rs"]
mod tests;
