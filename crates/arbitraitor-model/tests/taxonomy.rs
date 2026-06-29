//! Tests for the `TaxonomyRef` and `TaxonomyName` types (spec §15.2).

use arbitraitor_model::finding::{Evidence, EvidenceKind, Finding, FindingCategory};
use arbitraitor_model::ids::Sha256Digest;
use arbitraitor_model::taxonomy::{TaxonomyName, TaxonomyRef};
use arbitraitor_model::verdict::{Confidence, Severity};

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn sample_finding() -> Finding {
    Finding {
        id: "test-001".to_owned(),
        detector: "test".to_owned(),
        category: FindingCategory::MalwareSignature,
        severity: Severity::Critical,
        confidence: Confidence::Confirmed,
        title: "test".to_owned(),
        description: "test".to_owned(),
        evidence: vec![Evidence {
            kind: EvidenceKind::Other,
            description: "test".to_owned(),
            content: None,
        }],
        artifact_sha256: Sha256Digest::new([0; 32]),
        location: None,
        remediation: None,
        references: Vec::new(),
        tags: Vec::new(),
        taxonomies: Vec::new(),
    }
}

#[test]
fn taxonomy_ref_serializes_with_cwe() -> TestResult {
    let ref_ = TaxonomyRef {
        name: TaxonomyName::Cwe,
        id: "CWE-78".to_owned(),
        confidence: Confidence::High,
        url: Some("https://cwe.mitre.org/data/definitions/78.html".to_owned()),
    };
    let json = serde_json::to_string(&ref_)?;
    assert!(json.contains(r#""name":"cwe""#));
    assert!(json.contains("CWE-78"));
    Ok(())
}

#[test]
fn taxonomy_ref_serializes_custom() -> TestResult {
    let ref_ = TaxonomyRef {
        name: TaxonomyName::Custom("internal".to_owned()),
        id: "INT-042".to_owned(),
        confidence: Confidence::Medium,
        url: None,
    };
    let json = serde_json::to_string(&ref_)?;
    assert!(json.contains(r#""custom":"internal""#));
    assert!(!json.contains("url"));
    Ok(())
}

#[test]
fn finding_with_taxonomy_attaches_refs() {
    let finding = sample_finding()
        .with_taxonomy(TaxonomyRef {
            name: TaxonomyName::Cwe,
            id: "CWE-78".to_owned(),
            confidence: Confidence::High,
            url: None,
        })
        .with_taxonomy(TaxonomyRef {
            name: TaxonomyName::Capec,
            id: "CAPEC-88".to_owned(),
            confidence: Confidence::Medium,
            url: None,
        });
    assert_eq!(finding.taxonomies.len(), 2);
    assert_eq!(finding.taxonomies[0].id, "CWE-78");
    assert_eq!(finding.taxonomies[1].id, "CAPEC-88");
}

#[test]
fn finding_without_taxonomy_has_empty_vec() {
    let finding = sample_finding();
    assert!(finding.taxonomies.is_empty());
}

#[test]
fn finding_with_taxonomy_roundtrips_serde() -> TestResult {
    let finding = sample_finding().with_taxonomy(TaxonomyRef {
        name: TaxonomyName::Cwe,
        id: "CWE-22".to_owned(),
        confidence: Confidence::Confirmed,
        url: None,
    });
    let json = serde_json::to_string(&finding)?;
    let back: Finding = serde_json::from_str(&json)?;
    assert_eq!(back.taxonomies.len(), 1);
    assert_eq!(back.taxonomies[0].id, "CWE-22");
    Ok(())
}
