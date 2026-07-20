use super::{
    ArchiveEntry, ArchiveEntryType, ArchiveError, ArchiveLimits, detect_archive_hazards,
    detect_tar_parser_differentials, extract_to_inspection_dir, open_archive,
    open_archive_with_limits, parser_differential_findings,
};
use arbitraitor_artifact::ArtifactType;
use arbitraitor_model::finding::FindingCategory;
use arbitraitor_model::verdict::Severity;
use flate2::Compression;
use flate2::write::GzEncoder;
use proptest::prelude::*;
use std::error::Error;
use std::fs;
use std::io::{Cursor, Write};
use std::path::PathBuf;
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

/// Locks `ArchiveLimits::default()` to spec §19.2 values. Adding a new
/// field or changing a default requires extending this test alongside
/// the spec change so accidental drift is caught at compile-test time.
#[test]
fn archive_limits_defaults_match_spec_section_19_2() {
    let defaults = ArchiveLimits::default();
    assert_eq!(defaults.max_depth, 5, "spec §19.2 max_depth = 5");
    assert_eq!(defaults.max_files, 10_000, "spec §19.2 max_files = 10_000");
    assert_eq!(
        defaults.max_total_unpacked_bytes, 1_073_741_824,
        "spec §19.2 max_total_unpacked_bytes = 1 GiB"
    );
    assert_eq!(
        defaults.max_single_file_bytes, 268_435_456,
        "spec §19.2 max_single_file_bytes = 256 MiB"
    );
    assert_eq!(
        defaults.max_compression_ratio, 200,
        "spec §19.2 max_compression_ratio = 200"
    );
    assert_eq!(
        defaults.max_symlinks, 0,
        "spec §19.2 max_symlinks = 0 (any symlink trips the limit)"
    );
    assert_eq!(
        defaults.max_processing_time,
        Duration::from_mins(1),
        "spec §19.2 max_processing_time = 60 s"
    );
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
fn extraction_enforces_total_bytes_limit() -> Result<(), Box<dyn Error>> {
    let data = zip_bytes(&[("one.txt", b"1234"), ("two.txt", b"5678")])?;
    let limits = ArchiveLimits {
        max_total_unpacked_bytes: 7,
        ..test_limits()
    };
    let mut reader = open_archive_with_limits(&data, ArtifactType::ZipArchive, limits.clone())?;

    let result = extract_to_inspection_dir(&mut *reader, &limits, &unique_temp_path("total"));

    assert!(matches!(
        result,
        Err(ArchiveError::LimitExceeded {
            limit: "max_total_unpacked_bytes"
        })
    ));
    Ok(())
}

#[test]
fn extraction_enforces_file_count_limit() -> Result<(), Box<dyn Error>> {
    let data = zip_bytes(&[("one.txt", b"1"), ("two.txt", b"2")])?;
    let limits = ArchiveLimits {
        max_files: 1,
        ..test_limits()
    };
    let mut reader = open_archive_with_limits(&data, ArtifactType::ZipArchive, limits.clone())?;

    let result = extract_to_inspection_dir(&mut *reader, &limits, &unique_temp_path("files"));

    assert!(matches!(
        result,
        Err(ArchiveError::LimitExceeded { limit: "max_files" })
    ));
    Ok(())
}

#[test]
fn extraction_enforces_time_limit() -> Result<(), Box<dyn Error>> {
    let data = zip_bytes(&[("one.txt", b"1")])?;
    let limits = ArchiveLimits {
        max_processing_time: Duration::ZERO,
        ..test_limits()
    };
    let mut reader = open_archive_with_limits(&data, ArtifactType::ZipArchive, limits.clone())?;

    let result = extract_to_inspection_dir(&mut *reader, &limits, &unique_temp_path("time"));

    assert!(matches!(
        result,
        Err(ArchiveError::LimitExceeded {
            limit: "max_processing_time"
        })
    ));
    Ok(())
}

#[test]
fn inspection_directory_is_private_and_cleaned_after_failure() -> Result<(), Box<dyn Error>> {
    let data = zip_bytes(&[("../escape.txt", b"no")])?;
    let limits = test_limits();
    let inspection_dir = unique_temp_path("cleanup");
    let mut reader = open_archive_with_limits(&data, ArtifactType::ZipArchive, limits.clone())?;

    assert!(extract_to_inspection_dir(&mut *reader, &limits, &inspection_dir).is_err());
    assert!(!inspection_dir.exists());

    let private_dir = unique_temp_path("private");
    let data = zip_bytes(&[("safe.txt", b"yes")])?;
    let mut reader = open_archive_with_limits(&data, ArtifactType::ZipArchive, limits.clone())?;
    let extracted = extract_to_inspection_dir(&mut *reader, &limits, &private_dir)?;

    assert_eq!(extracted.len(), 1);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            fs::metadata(&private_dir)?.permissions().mode() & 0o777,
            0o700
        );
    }
    fs::remove_dir_all(private_dir)?;
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

#[test]
fn hazard_detection_flags_path_traversal_entry() {
    let findings = detect_archive_hazards(&[entry("../escape.txt")], &test_limits());

    assert_hazard(&findings, "parent-traversal", Severity::Critical);
}

#[test]
fn hazard_detection_flags_symlink_escape() {
    let mut entry = entry("links/outside");
    entry.is_symlink = true;
    entry.entry_type = ArchiveEntryType::Symlink;
    entry.link_target = Some("../../etc/passwd".to_owned());

    let findings = detect_archive_hazards(&[entry], &test_limits());

    assert_hazard(&findings, "symlink-escape", Severity::Critical);
}

#[test]
fn hazard_detection_flags_zip_bomb_ratio() {
    let mut entry = entry("payload.bin");
    entry.size = 10_000;
    entry.compressed_size = Some(10);
    let limits = ArchiveLimits {
        max_compression_ratio: 10,
        ..test_limits()
    };

    let findings = detect_archive_hazards(&[entry], &limits);

    assert_hazard(&findings, "excessive-compression-ratio", Severity::Critical);
}

#[test]
fn hazard_detection_flags_setuid_bit() {
    let mut entry = entry("bin/helper");
    entry.permissions = Some(0o4755);

    let findings = detect_archive_hazards(&[entry], &test_limits());

    assert_hazard(&findings, "setuid-setgid-bits", Severity::High);
}

#[test]
fn hazard_detection_flags_encrypted_zip_entry() {
    let mut entry = entry("secret.txt");
    entry.is_encrypted = true;

    let findings = detect_archive_hazards(&[entry], &test_limits());

    assert_hazard(&findings, "encrypted-member", Severity::High);
}

#[test]
fn hazard_detection_allows_clean_archive_metadata() {
    let mut first = entry("docs/readme.txt");
    first.size = 12;
    first.compressed_size = Some(10);
    first.permissions = Some(0o644);
    let mut second = entry("bin/tool");
    second.size = 20;
    second.compressed_size = Some(20);
    second.permissions = Some(0o755);

    let findings = detect_archive_hazards(&[first, second], &test_limits());

    assert!(findings.is_empty());
}

#[test]
fn tar_consensus_flags_pax_size_desync_pattern() -> Result<(), Box<dyn Error>> {
    let data = pax_size_desync_tar()?;
    let mut reader = open_archive(&data, ArtifactType::TarArchive)?;
    let primary_entries = reader.entries().unwrap_or_default();

    let findings = detect_tar_parser_differentials(&data, &primary_entries, &test_limits());

    assert_parser_differential(&findings);
    assert!(
        findings
            .iter()
            .any(|finding| finding.tags.iter().any(|tag| tag == "parser-smelting"))
    );
    Ok(())
}

#[test]
fn tar_consensus_allows_clean_tar_members() -> Result<(), Box<dyn Error>> {
    let data = tar_bytes()?;
    let mut reader = open_archive(&data, ArtifactType::TarArchive)?;
    let primary_entries = reader.entries()?;

    let findings = detect_tar_parser_differentials(&data, &primary_entries, &test_limits());

    assert!(findings.is_empty());
    Ok(())
}

proptest! {
    #[test]
    fn parser_disagreement_produces_finding(
        primary_name in "[a-z]{1,8}",
        consensus_name in "[i-z]{1,8}"
    ) {
        prop_assume!(primary_name != consensus_name);
        let findings = parser_differential_findings(
            &[entry(&primary_name)],
            &[consensus_name],
            Vec::new(),
        );
        let has_parser_differential = findings.iter().any(|finding| {
            finding.category == FindingCategory::ParserDifferential
                && finding.severity == Severity::Medium
        });

        prop_assert!(has_parser_differential);
    }
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

fn pax_size_desync_tar() -> Result<Vec<u8>, Box<dyn Error>> {
    let mut data = Vec::new();
    append_raw_tar_entry(&mut data, EntryType::XHeader, "pax", b"13 size=2048\n")?;
    append_raw_tar_entry(
        &mut data,
        EntryType::GNULongName,
        "././@LongLink",
        b"longname.txt\0",
    )?;
    append_raw_tar_entry(&mut data, EntryType::Regular, "file_b", &vec![b'A'; 2048])?;
    data.extend_from_slice(&[0_u8; 1024]);
    Ok(data)
}

fn append_raw_tar_entry(
    data: &mut Vec<u8>,
    entry_type: EntryType,
    path: &str,
    content: &[u8],
) -> Result<(), Box<dyn Error>> {
    let mut header = Header::new_gnu();
    header.set_entry_type(entry_type);
    header.set_mode(0o644);
    header.set_size(content.len() as u64);
    header.set_path(path)?;
    header.set_cksum();
    data.extend_from_slice(header.as_bytes());
    data.extend_from_slice(content);
    let padding = (512 - content.len() % 512) % 512;
    data.extend(std::iter::repeat_n(0_u8, padding));
    Ok(())
}

fn gzip_bytes(data: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(data)?;
    Ok(encoder.finish()?)
}

fn unique_temp_path(label: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
        "arbitraitor-archive-{label}-{}-{}",
        std::process::id(),
        timestamp_nanos()
    ))
}

fn timestamp_nanos() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |duration| duration.as_nanos())
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
        max_symlinks: u32::MAX,
        max_processing_time: Duration::from_secs(5),
    }
}

fn entry(name: &str) -> ArchiveEntry {
    ArchiveEntry {
        name: name.to_owned(),
        size: 1,
        compressed_size: Some(1),
        is_dir: false,
        is_symlink: false,
        entry_type: ArchiveEntryType::File,
        link_target: None,
        permissions: Some(0o644),
        is_encrypted: false,
    }
}

fn assert_hazard(findings: &[arbitraitor_model::finding::Finding], tag: &str, severity: Severity) {
    assert!(findings.iter().any(|finding| {
        finding.category == FindingCategory::ArchiveHazard
            && finding.severity == severity
            && finding.tags.iter().any(|finding_tag| finding_tag == tag)
    }));
}

fn assert_parser_differential(findings: &[arbitraitor_model::finding::Finding]) {
    assert!(findings.iter().any(|finding| {
        finding.category == FindingCategory::ParserDifferential
            && finding.severity == Severity::Medium
            && finding
                .taxonomies
                .iter()
                .any(|taxonomy| taxonomy.id == "CWE-436")
    }));
}
