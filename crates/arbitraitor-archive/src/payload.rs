//! Recursive payload graph discovery for nested archives.
//!
//! When an artifact is an archive, Arbitraitor must inspect every contained
//! payload through the same bounded pipeline. This module builds a
//! content-addressed tree ([`ArtifactNode`]) describing each regular payload
//! reachable through nested archives, enforcing [`ArchiveLimits`] at every
//! level, detecting containment cycles, and bounding recursion depth.
//!
//! Extraction happens into process memory only (never the final destination);
//! every level is bounded by [`ArchiveLimits`]. See `.spec/` §20.1 for the full
//! specification.

use arbitraitor_artifact::{ArtifactType, ClassificationResult, classify};
use arbitraitor_model::ids::Sha256Digest;
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::{ArchiveEntryType, ArchiveError, ArchiveLimits, open_archive_with_limits};

/// Default maximum archive-nesting depth for payload discovery.
///
/// This bounds how many archive layers are peeled recursively. It is
/// intentionally small because each layer multiplies inspection cost and most
/// legitimate artifacts nest at most a few levels deep.
pub const DEFAULT_MAX_PAYLOAD_DEPTH: u32 = 4;

/// Origin of an artifact node within a recursive payload graph.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ArtifactOrigin {
    /// The artifact supplied directly by the caller (the analysis root).
    Root,
    /// A payload extracted from a containing archive entry.
    ArchiveEntry {
        /// SHA-256 of the archive that contained this payload.
        parent_sha256: Sha256Digest,
        /// Validated entry name this payload was stored under.
        entry_name: String,
    },
}

/// A node in the recursive payload graph.
#[derive(Clone, Debug)]
pub struct ArtifactNode {
    /// SHA-256 digest of this node's payload bytes.
    pub sha256: Sha256Digest,
    /// Classified artifact type of this node's bytes.
    pub kind: ArtifactType,
    /// Payload byte size.
    pub size: u64,
    /// How this node was reached from the root.
    pub origin: ArtifactOrigin,
    /// Payloads contained within this node when it is an archive, otherwise empty.
    pub contained: Vec<ArtifactNode>,
}

/// Recursive payload discovery error used by the strict [`discover_payloads`] API.
#[derive(Debug, Error)]
pub enum PayloadError {
    /// An archive could not be opened, listed, or extracted under the configured limits.
    #[error("archive error during payload discovery: {0}")]
    Archive(#[from] ArchiveError),
    /// A payload containment cycle was detected (an archive transitively contains itself).
    #[error(
        "payload cycle detected: artifact {sha256} is contained within its own containment chain"
    )]
    Cycle {
        /// Digest of the payload that completed the cycle.
        sha256: Sha256Digest,
    },
}

/// Issue observed while discovering payloads leniently.
///
/// Unlike [`PayloadError`], issues never abort discovery; affected branches
/// become leaves and callers (such as recursive analysis) can convert the issues
/// into findings.
#[derive(Debug)]
pub enum PayloadIssue {
    /// A containment cycle was detected at the given origin.
    Cycle {
        /// Digest of the cyclic payload.
        sha256: Sha256Digest,
        /// Origin where the cycle was observed.
        origin: ArtifactOrigin,
    },
    /// An archive could not be opened or an entry could not be extracted.
    ArchiveError {
        /// Underlying archive error.
        error: ArchiveError,
        /// Digest of the archive associated with the failed operation.
        sha256: Sha256Digest,
        /// Origin associated with the failed operation.
        origin: ArtifactOrigin,
    },
    /// An archive was not expanded because the maximum recursion depth was reached.
    DepthTruncated {
        /// Digest of the archive that was not expanded.
        sha256: Sha256Digest,
        /// Origin of the truncated archive.
        origin: ArtifactOrigin,
        /// Configured maximum depth.
        max_depth: u32,
    },
}

/// Expansion status of a discovered node, reported to payload visitors.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NodeStatus {
    /// Leaf payload that is not an archive.
    Leaf,
    /// Archive that was expanded into contained nodes.
    Expanded,
    /// Archive that was not expanded because the depth limit was reached.
    Truncated,
}

/// Read-only view of a discovered node passed to payload visitors.
#[derive(Clone, Copy, Debug)]
pub struct PayloadNode<'a> {
    /// SHA-256 digest of the node's payload bytes.
    pub sha256: &'a Sha256Digest,
    /// Classified artifact type.
    pub kind: ArtifactType,
    /// Payload byte size.
    pub size: u64,
    /// How this node was reached from the root.
    pub origin: &'a ArtifactOrigin,
    /// Expansion status of this node.
    pub status: NodeStatus,
    /// Nesting depth (root is 0).
    pub depth: u32,
}

/// Returns whether an artifact type is an archive supported by recursive discovery.
///
/// This mirrors the archive types accepted by [`open_archive_with_limits`] and is
/// the canonical predicate for "should this payload be expanded recursively?".
///
/// [`open_archive_with_limits`]: crate::open_archive_with_limits
#[must_use]
pub fn is_archive_type(kind: ArtifactType) -> bool {
    matches!(
        kind,
        ArtifactType::ZipArchive
            | ArtifactType::TarArchive
            | ArtifactType::GzipCompressed
            | ArtifactType::XzCompressed
            | ArtifactType::Bzip2Compressed
            | ArtifactType::ZstdCompressed
    )
}

/// Discovers the recursive payload graph for `bytes` strictly.
///
/// Classifies each contained payload, bounds extraction with `limits` at every
/// level, detects containment cycles, and stops descending at `max_depth`.
/// Reaching `max_depth` only truncates the tree (the affected archive appears as
/// a leaf); a containment cycle or an archive/extraction error aborts discovery.
///
/// # Errors
///
/// Returns [`PayloadError::Cycle`] when an archive transitively contains itself,
/// and [`PayloadError::Archive`] when an archive cannot be opened or extracted
/// under the configured limits.
pub fn discover_payloads(
    bytes: &[u8],
    classification: &ClassificationResult,
    limits: &ArchiveLimits,
    max_depth: u32,
) -> Result<ArtifactNode, PayloadError> {
    let kind = classification.artifact_type;
    let sha256 = digest(bytes);
    let mut ancestors = Vec::new();
    let mut issues = Vec::new();
    let mut env = WalkEnv {
        limits,
        max_depth,
        ancestors: &mut ancestors,
        issues: &mut issues,
        visitor: &mut noop_visitor,
    };
    let node = walk(
        bytes,
        kind,
        ArtifactOrigin::Root,
        sha256,
        bytes.len() as u64,
        0,
        &mut env,
    );
    for issue in issues {
        match issue {
            PayloadIssue::Cycle { sha256, .. } => return Err(PayloadError::Cycle { sha256 }),
            PayloadIssue::ArchiveError { error, .. } => return Err(PayloadError::Archive(error)),
            PayloadIssue::DepthTruncated { .. } => {}
        }
    }
    Ok(node)
}

/// Lenient payload graph discovery with a visitor.
///
/// Walks every reachable payload, calls `visitor` for each node with the node's
/// bytes and a [`PayloadNode`] view, and returns the resulting graph alongside
/// any [`PayloadIssue`]s observed. Unlike [`discover_payloads`], this never
/// aborts: cycles and archive errors become issues and affected branches become
/// leaves, so callers can keep analyzing the rest of the graph.
///
/// This is the foundation for recursive analysis: a visitor runs the analysis
/// coordinator on each node's bytes while the walker handles cycle detection,
/// depth bounding, and per-level [`ArchiveLimits`] enforcement.
#[must_use]
pub fn walk_payloads(
    bytes: &[u8],
    kind: ArtifactType,
    limits: &ArchiveLimits,
    max_depth: u32,
    visitor: &mut dyn FnMut(&PayloadNode<'_>, &[u8]),
) -> (ArtifactNode, Vec<PayloadIssue>) {
    let sha256 = digest(bytes);
    let mut ancestors = Vec::new();
    let mut issues = Vec::new();
    let mut env = WalkEnv {
        limits,
        max_depth,
        ancestors: &mut ancestors,
        issues: &mut issues,
        visitor,
    };
    let node = walk(
        bytes,
        kind,
        ArtifactOrigin::Root,
        sha256,
        bytes.len() as u64,
        0,
        &mut env,
    );
    (node, issues)
}

/// Mutable context threaded through the recursive walk.
struct WalkEnv<'a> {
    limits: &'a ArchiveLimits,
    max_depth: u32,
    ancestors: &'a mut Vec<Sha256Digest>,
    issues: &'a mut Vec<PayloadIssue>,
    visitor: &'a mut dyn FnMut(&PayloadNode<'_>, &[u8]),
}

fn noop_visitor(_node: &PayloadNode<'_>, _bytes: &[u8]) {}

fn walk(
    bytes: &[u8],
    kind: ArtifactType,
    origin: ArtifactOrigin,
    sha256: Sha256Digest,
    size: u64,
    depth: u32,
    env: &mut WalkEnv<'_>,
) -> ArtifactNode {
    // Cycle check: if this node's digest already appears in the ancestor chain,
    // the archive transitively contains itself. Record the issue and stop.
    if env.ancestors.iter().any(|ancestor| ancestor == &sha256) {
        env.issues.push(PayloadIssue::Cycle {
            sha256: sha256.clone(),
            origin: origin.clone(),
        });
        let view = PayloadNode {
            sha256: &sha256,
            kind,
            size,
            origin: &origin,
            status: NodeStatus::Leaf,
            depth,
        };
        (env.visitor)(&view, bytes);
        return ArtifactNode {
            sha256,
            kind,
            size,
            origin,
            contained: Vec::new(),
        };
    }

    let archive = is_archive_type(kind);
    let can_expand = archive && depth < env.max_depth;
    let status = if !archive {
        NodeStatus::Leaf
    } else if can_expand {
        NodeStatus::Expanded
    } else {
        NodeStatus::Truncated
    };

    if archive && !can_expand {
        env.issues.push(PayloadIssue::DepthTruncated {
            sha256: sha256.clone(),
            origin: origin.clone(),
            max_depth: env.max_depth,
        });
    }

    let view = PayloadNode {
        sha256: &sha256,
        kind,
        size,
        origin: &origin,
        status,
        depth,
    };
    (env.visitor)(&view, bytes);

    let mut contained = Vec::new();
    if can_expand {
        env.ancestors.push(sha256.clone());
        contained = expand(bytes, kind, &sha256, &origin, depth, env);
        env.ancestors.pop();
    }

    ArtifactNode {
        sha256,
        kind,
        size,
        origin,
        contained,
    }
}

fn expand(
    parent_bytes: &[u8],
    parent_kind: ArtifactType,
    parent_sha: &Sha256Digest,
    parent_origin: &ArtifactOrigin,
    parent_depth: u32,
    env: &mut WalkEnv<'_>,
) -> Vec<ArtifactNode> {
    let mut reader = match open_archive_with_limits(parent_bytes, parent_kind, env.limits.clone()) {
        Ok(reader) => reader,
        Err(error) => {
            env.issues.push(PayloadIssue::ArchiveError {
                error,
                sha256: parent_sha.clone(),
                origin: parent_origin.clone(),
            });
            return Vec::new();
        }
    };

    let entries = match reader.entries() {
        Ok(entries) => entries,
        Err(error) => {
            env.issues.push(PayloadIssue::ArchiveError {
                error,
                sha256: parent_sha.clone(),
                origin: parent_origin.clone(),
            });
            return Vec::new();
        }
    };

    let mut contained = Vec::new();
    let mut total_extracted_bytes = 0_u64;
    for entry in entries {
        // Only regular unencrypted files yield inspectable payloads. Skipping
        // other entry types here does not relax hazard detection: the archive
        // hazard detector still runs on the parent archive's bytes via the
        // visitor and reports symlinks, devices, encryption, etc.
        if entry.is_dir
            || entry.entry_type != ArchiveEntryType::File
            || entry.is_symlink
            || entry.is_encrypted
        {
            continue;
        }

        let mut sink = Vec::new();
        if let Err(error) = reader.extract_entry(&entry.name, &mut sink) {
            env.issues.push(PayloadIssue::ArchiveError {
                error,
                sha256: parent_sha.clone(),
                origin: ArtifactOrigin::ArchiveEntry {
                    parent_sha256: parent_sha.clone(),
                    entry_name: entry.name.clone(),
                },
            });
            continue;
        }

        // Enforce a cumulative unpacked-byte budget across this archive's
        // extracted entries, complementing the per-entry limits enforced inside
        // `extract_entry`. This bounds total memory regardless of how the
        // underlying reader accounts bytes.
        let extracted_len = sink.len() as u64;
        let Some(updated) = total_extracted_bytes.checked_add(extracted_len) else {
            env.issues.push(PayloadIssue::ArchiveError {
                error: ArchiveError::LimitExceeded {
                    limit: "max_total_unpacked_bytes",
                },
                sha256: parent_sha.clone(),
                origin: ArtifactOrigin::ArchiveEntry {
                    parent_sha256: parent_sha.clone(),
                    entry_name: entry.name.clone(),
                },
            });
            break;
        };
        total_extracted_bytes = updated;
        if total_extracted_bytes > env.limits.max_total_unpacked_bytes {
            env.issues.push(PayloadIssue::ArchiveError {
                error: ArchiveError::LimitExceeded {
                    limit: "max_total_unpacked_bytes",
                },
                sha256: parent_sha.clone(),
                origin: ArtifactOrigin::ArchiveEntry {
                    parent_sha256: parent_sha.clone(),
                    entry_name: entry.name.clone(),
                },
            });
            break;
        }

        let child_sha = digest(&sink);
        let child_kind = classify(&sink).artifact_type;
        let child_origin = ArtifactOrigin::ArchiveEntry {
            parent_sha256: parent_sha.clone(),
            entry_name: entry.name.clone(),
        };
        let child = walk(
            &sink,
            child_kind,
            child_origin,
            child_sha,
            extracted_len,
            parent_depth + 1,
            env,
        );
        contained.push(child);
    }

    contained
}

fn digest(bytes: &[u8]) -> Sha256Digest {
    Sha256Digest::new(Sha256::digest(bytes).into())
}

#[cfg(test)]
mod tests {
    use super::{
        ArtifactOrigin, ArtifactType, NodeStatus, PayloadError, PayloadIssue, WalkEnv, digest,
        discover_payloads, is_archive_type, walk, walk_payloads,
    };
    use crate::ArchiveLimits;
    use arbitraitor_artifact::classify;
    use flate2::Compression;
    use flate2::write::GzEncoder;
    use std::error::Error;
    use std::io::{Cursor, Write};
    use std::time::Duration;
    use zip::ZipWriter;
    use zip::write::SimpleFileOptions;

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

    fn zip_bytes(entries: &[(&str, &[u8])]) -> Result<Vec<u8>, Box<dyn Error>> {
        let cursor = Cursor::new(Vec::new());
        let mut writer = ZipWriter::new(cursor);
        for (name, data) in entries {
            writer.start_file(*name, SimpleFileOptions::default())?;
            writer.write_all(data)?;
        }
        Ok(writer.finish()?.into_inner())
    }

    fn gzip_bytes(data: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(data)?;
        Ok(encoder.finish()?)
    }

    fn noop(_: &super::PayloadNode<'_>, _: &[u8]) {}

    fn entry_name(origin: &ArtifactOrigin) -> Option<&str> {
        match origin {
            ArtifactOrigin::ArchiveEntry { entry_name, .. } => Some(entry_name.as_str()),
            ArtifactOrigin::Root => None,
        }
    }

    #[test]
    fn is_archive_type_covers_supported_archive_kinds() {
        assert!(is_archive_type(ArtifactType::ZipArchive));
        assert!(is_archive_type(ArtifactType::TarArchive));
        assert!(is_archive_type(ArtifactType::GzipCompressed));
        assert!(is_archive_type(ArtifactType::XzCompressed));
        assert!(is_archive_type(ArtifactType::Bzip2Compressed));
        assert!(is_archive_type(ArtifactType::ZstdCompressed));

        assert!(!is_archive_type(ArtifactType::GenericText));
        assert!(!is_archive_type(ArtifactType::ElfExecutable));
        assert!(!is_archive_type(ArtifactType::Unknown));
    }

    #[test]
    fn non_archive_payload_is_a_single_leaf() -> Result<(), Box<dyn Error>> {
        let bytes = b"#!/bin/sh\necho hi\n";
        let classification = classify(bytes);
        let limits = test_limits();
        let node = discover_payloads(bytes, &classification, &limits, 4)?;

        assert_eq!(node.kind, classification.artifact_type);
        assert_eq!(node.origin, ArtifactOrigin::Root);
        assert_eq!(node.size, bytes.len() as u64);
        assert_eq!(node.sha256, digest(bytes));
        assert!(node.contained.is_empty());
        Ok(())
    }

    #[test]
    fn simple_zip_builds_payload_graph_with_entries() -> Result<(), Box<dyn Error>> {
        let bytes = zip_bytes(&[("alpha.txt", b"alpha"), ("beta.txt", b"beta-bytes")])?;
        let classification = classify(&bytes);
        let limits = test_limits();
        let node = discover_payloads(&bytes, &classification, &limits, 4)?;

        assert_eq!(node.kind, ArtifactType::ZipArchive);
        assert_eq!(node.contained.len(), 2);

        let alpha = node
            .contained
            .iter()
            .find(|child| entry_name(&child.origin) == Some("alpha.txt"))
            .ok_or("alpha.txt entry missing")?;
        assert_eq!(alpha.sha256, digest(b"alpha"));
        assert_eq!(alpha.size, 5);
        assert_eq!(alpha.kind, ArtifactType::GenericText);
        assert!(alpha.contained.is_empty());
        Ok(())
    }

    #[test]
    fn nested_archive_is_recursively_expanded() -> Result<(), Box<dyn Error>> {
        let inner = zip_bytes(&[("leaf.txt", b"leaf-payload")])?;
        let outer = zip_bytes(&[("inner.zip", &inner)])?;
        let classification = classify(&outer);
        let limits = test_limits();
        let node = discover_payloads(&outer, &classification, &limits, 4)?;

        assert_eq!(node.kind, ArtifactType::ZipArchive);
        assert_eq!(node.contained.len(), 1, "outer contains one entry");

        let inner_node = &node.contained[0];
        assert_eq!(inner_node.kind, ArtifactType::ZipArchive);
        assert_eq!(inner_node.sha256, digest(&inner));
        assert_eq!(
            inner_node.contained.len(),
            1,
            "inner archive is itself expanded"
        );

        let leaf = &inner_node.contained[0];
        assert_eq!(leaf.kind, ArtifactType::GenericText);
        assert_eq!(leaf.sha256, digest(b"leaf-payload"));
        assert_eq!(entry_name(&leaf.origin), Some("leaf.txt"));
        Ok(())
    }

    #[test]
    fn gzip_wrapping_single_payload_is_expanded() -> Result<(), Box<dyn Error>> {
        let outer = gzip_bytes(b"gzip-payload")?;
        let classification = classify(&outer);
        let limits = test_limits();
        let node = discover_payloads(&outer, &classification, &limits, 4)?;

        assert_eq!(node.kind, ArtifactType::GzipCompressed);
        assert_eq!(node.contained.len(), 1);
        assert_eq!(node.contained[0].sha256, digest(b"gzip-payload"));
        Ok(())
    }

    #[test]
    fn max_depth_zero_leaves_root_unexpanded() -> Result<(), Box<dyn Error>> {
        let bytes = zip_bytes(&[("alpha.txt", b"alpha")])?;
        let classification = classify(&bytes);
        let limits = test_limits();
        let node = discover_payloads(&bytes, &classification, &limits, 0)?;

        assert_eq!(node.kind, ArtifactType::ZipArchive);
        assert!(
            node.contained.is_empty(),
            "root must not be expanded when max_depth is 0"
        );
        Ok(())
    }

    #[test]
    fn depth_limit_truncates_deeper_archives_without_error() -> Result<(), Box<dyn Error>> {
        let inner = zip_bytes(&[("leaf.txt", b"leaf")])?;
        let outer = zip_bytes(&[("inner.zip", &inner)])?;
        let classification = classify(&outer);
        let limits = test_limits();

        let node = discover_payloads(&outer, &classification, &limits, 1)?;

        assert_eq!(node.contained.len(), 1);
        let inner_node = &node.contained[0];
        assert_eq!(inner_node.kind, ArtifactType::ZipArchive);
        assert!(
            inner_node.contained.is_empty(),
            "inner archive must be truncated at max_depth=1"
        );
        Ok(())
    }

    #[test]
    fn depth_truncation_is_surfaced_as_an_issue_by_walk_payloads() -> Result<(), Box<dyn Error>> {
        let inner = zip_bytes(&[("leaf.txt", b"leaf")])?;
        let outer = zip_bytes(&[("inner.zip", &inner)])?;
        let limits = test_limits();

        let (_, issues) = walk_payloads(&outer, ArtifactType::ZipArchive, &limits, 1, &mut noop);

        assert!(
            issues
                .iter()
                .any(|issue| matches!(issue, PayloadIssue::DepthTruncated { max_depth: 1, .. })),
            "expected a depth-truncation issue, got {issues:?}"
        );
        Ok(())
    }

    #[test]
    fn cycle_is_detected_via_ancestor_chain() -> Result<(), Box<dyn Error>> {
        // A real containment cycle cannot be constructed with standard archivers
        // (archive bytes depend on their entries' content), so drive the walker
        // with a seeded ancestor chain that simulates `inner` re-appearing inside
        // itself. This is the exact condition the cycle check must reject.
        let inner = zip_bytes(&[("leaf.txt", b"leaf")])?;
        let inner_sha = digest(&inner);
        let outer = zip_bytes(&[("inner.zip", &inner)])?;
        let outer_sha = digest(&outer);

        let mut ancestors = vec![outer_sha, inner_sha.clone()];
        let mut issues = Vec::new();
        let limits = test_limits();
        let mut env = WalkEnv {
            limits: &limits,
            max_depth: 8,
            ancestors: &mut ancestors,
            issues: &mut issues,
            visitor: &mut noop,
        };
        let node = walk(
            &inner,
            ArtifactType::ZipArchive,
            ArtifactOrigin::Root,
            inner_sha.clone(),
            inner.len() as u64,
            2,
            &mut env,
        );

        assert!(
            node.contained.is_empty(),
            "cyclic node must not be expanded"
        );
        assert!(issues.iter().any(|issue| matches!(
            issue,
            PayloadIssue::Cycle { sha256, .. } if sha256 == &inner_sha
        )));
        Ok(())
    }

    #[test]
    fn normal_nested_archive_does_not_trigger_cycle_detection() -> Result<(), Box<dyn Error>> {
        let inner = zip_bytes(&[("leaf.txt", b"leaf")])?;
        let outer = zip_bytes(&[("inner.zip", &inner)])?;
        let limits = test_limits();

        let (_, issues) = walk_payloads(&outer, ArtifactType::ZipArchive, &limits, 8, &mut noop);

        assert!(
            issues
                .iter()
                .all(|issue| !matches!(issue, PayloadIssue::Cycle { .. })),
            "a non-cyclic nested archive must not raise a cycle issue: {issues:?}"
        );
        Ok(())
    }

    #[test]
    fn corrupt_nested_archive_makes_discover_payloads_fail_closed() -> Result<(), Box<dyn Error>> {
        // The entry has ZIP magic so it classifies as a zip, but the bytes are
        // malformed. Opening it to expand must fail and surface an archive error.
        let corrupt_inner = b"PK\x03\x04corrupt-but-magic-correct-payload";
        let outer = zip_bytes(&[("inner.zip", corrupt_inner)])?;
        let classification = classify(&outer);
        let limits = test_limits();

        let result = discover_payloads(&outer, &classification, &limits, 4);
        assert!(
            matches!(result, Err(PayloadError::Archive(_))),
            "corrupt nested archive must fail closed, got {result:?}"
        );
        Ok(())
    }

    #[test]
    fn cumulative_byte_budget_bounds_extraction() -> Result<(), Box<dyn Error>> {
        // Two entries each under the per-entry limit but together over the total.
        let bytes = zip_bytes(&[("a.txt", b"abcd"), ("b.txt", b"efgh")])?;
        let limits = ArchiveLimits {
            max_total_unpacked_bytes: 5,
            ..test_limits()
        };

        let (_, issues) = walk_payloads(&bytes, ArtifactType::ZipArchive, &limits, 4, &mut noop);

        assert!(
            issues.iter().any(|issue| matches!(
                issue,
                PayloadIssue::ArchiveError {
                    error: crate::ArchiveError::LimitExceeded {
                        limit: "max_total_unpacked_bytes"
                    },
                    ..
                }
            )),
            "expected total-bytes limit to trip, got {issues:?}"
        );
        Ok(())
    }

    #[test]
    fn walk_payloads_reports_node_status_for_each_kind() -> Result<(), Box<dyn Error>> {
        let inner = zip_bytes(&[("leaf.txt", b"leaf")])?;
        let outer = zip_bytes(&[("inner.zip", &inner), ("plain.txt", b"plain")])?;
        let limits = test_limits();

        let mut statuses: Vec<(ArtifactType, NodeStatus)> = Vec::new();
        let _ = walk_payloads(
            &outer,
            ArtifactType::ZipArchive,
            &limits,
            1,
            &mut |node, _| {
                statuses.push((node.kind, node.status));
            },
        );

        // With max_depth=1: the root archive is Expanded, the nested inner.zip is
        // Truncated (not expanded), and plain.txt is a Leaf. inner.zip's contained
        // leaf is NOT visited because inner.zip is truncated.
        let expanded_root = statuses.iter().any(|(kind, status)| {
            *kind == ArtifactType::ZipArchive && *status == NodeStatus::Expanded
        });
        let truncated_inner = statuses.iter().any(|(kind, status)| {
            *kind == ArtifactType::ZipArchive && *status == NodeStatus::Truncated
        });
        let leaf = statuses.iter().any(|(kind, status)| {
            *kind == ArtifactType::GenericText && *status == NodeStatus::Leaf
        });
        assert!(
            expanded_root,
            "root archive must be reported as expanded: {statuses:?}"
        );
        assert!(
            truncated_inner,
            "inner archive must be reported as truncated: {statuses:?}"
        );
        assert!(
            leaf,
            "plain text entry must be reported as a leaf: {statuses:?}"
        );
        assert_eq!(
            statuses
                .iter()
                .filter(|(kind, _)| *kind == ArtifactType::GenericText)
                .count(),
            1,
            "only the top-level plain.txt leaf should be visited: {statuses:?}"
        );
        Ok(())
    }
}
