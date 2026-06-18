//! Archive inspection and decompression under resource limits
//!
//! See `.spec/` for the full specification.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use std::io::{self, Cursor, Read, Write};
use std::path::{Component, Path};
use std::time::{Duration, Instant};

use arbitraitor_artifact::ArtifactType;
use bzip2::read::BzDecoder;
use flate2::read::GzDecoder;
use tar::Archive;
use thiserror::Error;
use xz2::read::XzDecoder;
use zip::ZipArchive;
use zip::result::ZipError;

const DEFAULT_MAX_DEPTH: u32 = 32;
const DEFAULT_MAX_FILES: u32 = 10_000;
const DEFAULT_MAX_TOTAL_UNPACKED_BYTES: u64 = 1_073_741_824;
const DEFAULT_MAX_SINGLE_FILE_BYTES: u64 = 536_870_912;
const DEFAULT_MAX_COMPRESSION_RATIO: u32 = 100;
const DEFAULT_MAX_PROCESSING_TIME: Duration = Duration::from_secs(30);
const COPY_BUFFER_SIZE: usize = 16 * 1024;
const SINGLE_FILE_ENTRY_NAME: &str = "payload";
const TAR_MAGIC_OFFSET: usize = 257;
const TAR_MAGIC: &[u8] = b"ustar";

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
    /// Unix permissions when present in the archive metadata.
    pub permissions: Option<u32>,
}

/// Resource limits applied while listing and extracting archives.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ArchiveLimits {
    /// Maximum path depth allowed for an entry.
    pub max_depth: u32,
    /// Maximum number of entries allowed in one archive operation.
    pub max_files: u32,
    /// Maximum total unpacked bytes allowed in one archive operation.
    pub max_total_unpacked_bytes: u64,
    /// Maximum unpacked bytes allowed for a single file entry.
    pub max_single_file_bytes: u64,
    /// Maximum allowed uncompressed-to-compressed size ratio.
    pub max_compression_ratio: u32,
    /// Maximum wall-clock processing time allowed in one archive operation.
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

            tracker.record_entry(&name, size, Some(compressed_size))?;
            entries.push(ArchiveEntry {
                name,
                size,
                compressed_size: Some(compressed_size),
                is_dir,
                is_symlink,
                permissions,
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
            permissions: None,
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

        tracker.record_entry(&name, size, None)?;
        entries.push(ArchiveEntry {
            name,
            size,
            compressed_size: None,
            is_dir,
            is_symlink,
            permissions,
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

struct LimitTracker<'a> {
    limits: &'a ArchiveLimits,
    started_at: Instant,
    files: u32,
    total_unpacked_bytes: u64,
}

impl<'a> LimitTracker<'a> {
    fn new(limits: &'a ArchiveLimits) -> Self {
        Self {
            limits,
            started_at: Instant::now(),
            files: 0,
            total_unpacked_bytes: 0,
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
        sink.write_all(&buffer[..read])?;
    }

    Ok(copied)
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
mod tests {
    use super::{ArchiveError, ArchiveLimits, open_archive, open_archive_with_limits};
    use arbitraitor_artifact::ArtifactType;
    use flate2::Compression;
    use flate2::write::GzEncoder;
    use std::error::Error;
    use std::io::{Cursor, Write};
    use std::time::Duration;
    use tar::{Builder, EntryType, Header};
    use zip::ZipWriter;
    use zip::write::SimpleFileOptions;

    #[test]
    fn zip_lists_and_extracts_multiple_entries() -> Result<(), Box<dyn Error>> {
        let data = zip_bytes(&[("first.txt", b"alpha"), ("nested/second.txt", b"beta")])?;
        let mut reader = open_archive(&data, ArtifactType::ZipArchive)?;

        let entries = reader.entries()?;
        assert_eq!(entries.len(), 2);
        assert!(entries.iter().any(|entry| entry.name == "first.txt"));
        assert!(
            entries
                .iter()
                .any(|entry| entry.name == "nested/second.txt")
        );

        let mut extracted = Vec::new();
        reader.extract_entry("nested/second.txt", &mut extracted)?;
        assert_eq!(extracted, b"beta");
        Ok(())
    }

    #[test]
    fn tar_lists_files_directories_and_extracts_file() -> Result<(), Box<dyn Error>> {
        let data = tar_bytes()?;
        let mut reader = open_archive(&data, ArtifactType::TarArchive)?;

        let entries = reader.entries()?;
        assert!(
            entries
                .iter()
                .any(|entry| entry.name == "dir" && entry.is_dir)
        );
        assert!(entries.iter().any(|entry| entry.name == "dir/file.txt"));

        let mut extracted = Vec::new();
        reader.extract_entry("dir/file.txt", &mut extracted)?;
        assert_eq!(extracted, b"tar content");
        Ok(())
    }

    #[test]
    fn gzip_single_file_decompresses_payload() -> Result<(), Box<dyn Error>> {
        let data = gzip_bytes(b"compressed content")?;
        let mut reader = open_archive(&data, ArtifactType::GzipCompressed)?;

        let entries = reader.entries()?;
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "payload");
        assert_eq!(entries[0].size, 18);

        let mut extracted = Vec::new();
        reader.extract_entry("payload", &mut extracted)?;
        assert_eq!(extracted, b"compressed content");
        Ok(())
    }

    #[test]
    fn compound_tar_gzip_lists_and_extracts_tar_entries() -> Result<(), Box<dyn Error>> {
        let data = gzip_bytes(&tar_bytes()?)?;
        let mut reader = open_archive(&data, ArtifactType::GzipCompressed)?;

        let entries = reader.entries()?;
        assert!(entries.iter().any(|entry| entry.name == "dir/file.txt"));

        let mut extracted = Vec::new();
        reader.extract_entry("dir/file.txt", &mut extracted)?;
        assert_eq!(extracted, b"tar content");
        Ok(())
    }

    #[test]
    fn resource_limits_enforce_file_count_and_size() -> Result<(), Box<dyn Error>> {
        let data = zip_bytes(&[("one.txt", b"1"), ("two.txt", b"2")])?;
        let mut reader =
            open_archive_with_limits(&data, ArtifactType::ZipArchive, limits_with_file_count(1))?;
        assert!(matches!(
            reader.entries(),
            Err(ArchiveError::LimitExceeded { limit: "max_files" })
        ));

        let data = gzip_bytes(b"too large")?;
        let mut reader = open_archive_with_limits(
            &data,
            ArtifactType::GzipCompressed,
            limits_with_single_file_bytes(3),
        )?;
        assert!(matches!(
            reader.entries(),
            Err(ArchiveError::LimitExceeded {
                limit: "max_single_file_bytes"
            })
        ));
        Ok(())
    }

    #[test]
    fn empty_zip_archive_lists_no_entries() -> Result<(), Box<dyn Error>> {
        let cursor = Cursor::new(Vec::new());
        let writer = ZipWriter::new(cursor);
        let data = writer.finish()?.into_inner();
        let mut reader = open_archive(&data, ArtifactType::ZipArchive)?;

        assert!(reader.entries()?.is_empty());
        Ok(())
    }

    #[test]
    fn malformed_archive_returns_error() -> Result<(), Box<dyn Error>> {
        let mut reader = open_archive(b"not a zip archive", ArtifactType::ZipArchive)?;
        assert!(reader.entries().is_err());
        Ok(())
    }

    #[test]
    fn unsafe_paths_are_rejected() -> Result<(), Box<dyn Error>> {
        let data = zip_bytes(&[("../escape.txt", b"no")])?;
        let mut reader = open_archive(&data, ArtifactType::ZipArchive)?;
        assert!(matches!(reader.entries(), Err(ArchiveError::UnsafePath(_))));
        Ok(())
    }

    fn zip_bytes(entries: &[(&str, &[u8])]) -> Result<Vec<u8>, Box<dyn Error>> {
        let cursor = Cursor::new(Vec::new());
        let mut writer = ZipWriter::new(cursor);
        for (name, data) in entries {
            writer.start_file(*name, SimpleFileOptions::default())?;
            writer.write_all(data)?;
        }
        Ok(writer.finish()?.into_inner())
    }

    fn tar_bytes() -> Result<Vec<u8>, Box<dyn Error>> {
        let mut builder = Builder::new(Vec::new());

        let mut dir_header = Header::new_gnu();
        dir_header.set_entry_type(EntryType::Directory);
        dir_header.set_mode(0o755);
        dir_header.set_size(0);
        dir_header.set_cksum();
        builder.append_data(&mut dir_header, "dir", Cursor::new(Vec::new()))?;

        let content = b"tar content";
        let mut file_header = Header::new_gnu();
        file_header.set_entry_type(EntryType::Regular);
        file_header.set_mode(0o644);
        file_header.set_size(content.len() as u64);
        file_header.set_cksum();
        builder.append_data(
            &mut file_header,
            "dir/file.txt",
            Cursor::new(content.as_slice()),
        )?;

        Ok(builder.into_inner()?)
    }

    fn gzip_bytes(data: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(data)?;
        Ok(encoder.finish()?)
    }

    fn limits_with_file_count(max_files: u32) -> ArchiveLimits {
        ArchiveLimits {
            max_files,
            ..test_limits()
        }
    }

    fn limits_with_single_file_bytes(max_single_file_bytes: u64) -> ArchiveLimits {
        ArchiveLimits {
            max_single_file_bytes,
            ..test_limits()
        }
    }

    fn test_limits() -> ArchiveLimits {
        ArchiveLimits {
            max_depth: 32,
            max_files: 100,
            max_total_unpacked_bytes: 1_048_576,
            max_single_file_bytes: 1_048_576,
            max_compression_ratio: 1_000,
            max_processing_time: Duration::from_secs(5),
        }
    }
}
