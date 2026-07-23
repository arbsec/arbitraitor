//! Integration tests for decoded child artifact discovery (spec §41.4.2).

use std::io::Cursor;
use std::io::Write;

use arbitraitor_fetch::{discover_child_artifacts, discover_child_artifacts_with_bytes};
use flate2::Compression;
use flate2::write::GzEncoder;
use sha2::{Digest, Sha256};
use zip::ZipWriter;
use zip::write::SimpleFileOptions;

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn sha256(bytes: &[u8]) -> arbitraitor_model::ids::Sha256Digest {
    arbitraitor_model::ids::Sha256Digest::new(Sha256::digest(bytes).into())
}

fn zip_bytes(entries: &[(&str, &[u8])]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let cursor = Cursor::new(Vec::new());
    let mut writer = ZipWriter::new(cursor);
    for (name, data) in entries {
        writer.start_file(*name, SimpleFileOptions::default())?;
        writer.write_all(data)?;
    }
    Ok(writer.finish()?.into_inner())
}

fn gzip_bytes(data: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(data)?;
    Ok(encoder.finish()?)
}

#[test]
fn zip_archive_children_match_member_digests() -> TestResult {
    let member_a = b"hello world";
    let member_b = b"\x00\x01\x02\x03\x04\x05\x06\x07";
    let archive = zip_bytes(&[("hello.txt", member_a), ("data.bin", member_b)])?;

    let children = discover_child_artifacts(&archive);

    assert_eq!(children.len(), 2, "zip with two files yields two children");

    assert_eq!(children[0].name, "hello.txt");
    assert_eq!(children[0].digest, sha256(member_a));
    assert_eq!(children[0].decoded_size, member_a.len() as u64);
    assert_eq!(children[0].parent_offset, 0);

    assert_eq!(children[1].name, "data.bin");
    assert_eq!(children[1].digest, sha256(member_b));
    assert_eq!(children[1].decoded_size, member_b.len() as u64);
    assert_eq!(children[1].parent_offset, 1);
    Ok(())
}

#[test]
fn gzip_child_matches_decompressed_digest() -> TestResult {
    let payload = b"this is the decompressed content";
    let compressed = gzip_bytes(payload)?;

    let children = discover_child_artifacts(&compressed);

    assert_eq!(children.len(), 1, "gzip yields one decoded child");
    assert_eq!(children[0].digest, sha256(payload));
    assert_eq!(children[0].decoded_size, payload.len() as u64);
    Ok(())
}

#[test]
fn non_archive_bytes_yield_no_children() {
    let plain = b"#!/bin/bash\necho hello\n";
    let children = discover_child_artifacts(plain);
    assert!(children.is_empty(), "shell script is not an archive");
}

#[test]
fn empty_bytes_yield_no_children() {
    let children = discover_child_artifacts(&[]);
    assert!(children.is_empty(), "empty input is not an archive");
}

#[test]
fn with_bytes_returns_correct_decoded_content() -> TestResult {
    let member = b"exact byte content for cas storage";
    let archive = zip_bytes(&[("payload.txt", member)])?;

    let children_with_bytes = discover_child_artifacts_with_bytes(&archive);

    assert_eq!(children_with_bytes.len(), 1);
    let (artifact, bytes) = &children_with_bytes[0];
    assert_eq!(artifact.digest, sha256(member));
    assert_eq!(bytes, member, "decoded bytes must match original member");
    Ok(())
}

#[test]
fn child_artifact_struct_fields_are_consistent() -> TestResult {
    let members: &[(&str, &[u8])] = &[("a.txt", b"aaa"), ("b.txt", b"bbbb")];
    let archive = zip_bytes(members)?;

    let children = discover_child_artifacts(&archive);

    for (index, (artifact, (_, member_bytes))) in children.iter().zip(members.iter()).enumerate() {
        assert_eq!(
            artifact.digest,
            sha256(member_bytes),
            "child {index} digest must match member bytes"
        );
        assert_eq!(
            artifact.decoded_size,
            member_bytes.len() as u64,
            "child {index} size must match member length"
        );
        assert_eq!(
            artifact.parent_offset, index as u64,
            "child {index} offset must be ordinal position"
        );
    }
    Ok(())
}

#[test]
fn receipt_with_child_artifacts_preserves_children() -> TestResult {
    let member = b"receipt test payload";
    let archive = zip_bytes(&[("entry.bin", member)])?;
    let children = discover_child_artifacts(&archive);

    let receipt = arbitraitor_fetch::FetchReceipt {
        artifact_id: arbitraitor_model::ids::ArtifactId(sha256(&archive)),
        sha256: sha256(&archive),
        bytes_written: archive.len() as u64,
        metadata: arbitraitor_fetch::FetchMetadata::default(),
        child_artifacts: Vec::new(),
    };

    let receipt = receipt.with_child_artifacts(children.clone());
    assert_eq!(receipt.child_artifacts, children);
    assert_eq!(receipt.child_artifacts.len(), 1);
    assert_eq!(receipt.child_artifacts[0].digest, sha256(member));
    Ok(())
}
