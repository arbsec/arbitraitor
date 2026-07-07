use super::*;
use crate::lifecycle::LifecycleScript;
use crate::npm::{NpmPackage, PackageLock};
use arbitraitor_model::ids::Sha256Digest;

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn digest() -> Sha256Digest {
    Sha256Digest::new([0x11; 32])
}

fn pkg(name: &str, version: &str, resolved: Option<&str>, scripts: bool) -> NpmPackage {
    NpmPackage {
        name: name.to_owned(),
        version: version.to_owned(),
        resolved: resolved.map(str::to_owned),
        integrity: None,
        has_scripts: scripts,
    }
}

#[test]
fn clean_lockfile_yields_pass_verdict() {
    let lock = PackageLock {
        lockfile_version: 3,
        packages: vec![pkg(
            "express",
            "4.18.2",
            Some("https://registry.npmjs.org/express/-/express-4.18.2.tgz"),
            false,
        )],
    };
    let outcome = analyze(&lock, &[], "10.8.0", digest());
    assert_eq!(outcome.verdict, AdvisoryVerdict::Pass);
    assert!(outcome.findings.is_empty());
    assert_eq!(outcome.receipt.packages_inspected, 1);
    assert_eq!(outcome.receipt.packages_blocked, 0);
    assert_eq!(outcome.receipt.packages_incomplete, 0);
    assert_eq!(
        outcome.receipt.lifecycle_scripts,
        LifecycleScriptStatus::NotApplicable
    );
    assert_eq!(outcome.receipt.proxy_mode, ProxyMode::LockfilePrescan);
}

#[test]
fn dependency_with_scripts_warns_and_marks_incomplete() {
    let lock = PackageLock {
        lockfile_version: 3,
        packages: vec![pkg("evil", "1.0.0", None, true)],
    };
    let outcome = analyze(&lock, &[], "10.8.0", digest());
    assert_eq!(outcome.verdict, AdvisoryVerdict::Warn);
    assert_eq!(outcome.findings.len(), 1);
    assert_eq!(outcome.findings[0].id, "npm.lifecycle.dependency");
    assert_eq!(outcome.findings[0].package, "evil");
    assert_eq!(outcome.receipt.packages_incomplete, 1);
    assert_eq!(
        outcome.receipt.lifecycle_scripts,
        LifecycleScriptStatus::IncompleteCoverage
    );
}

#[test]
fn root_postinstall_script_is_reported() {
    let lock = PackageLock {
        lockfile_version: 3,
        packages: vec![],
    };
    let scripts = vec![LifecycleScript {
        phase: "postinstall".to_owned(),
        command: "node evil.js".to_owned(),
    }];
    let outcome = analyze(&lock, &scripts, "10.8.0", digest());
    assert_eq!(outcome.verdict, AdvisoryVerdict::Warn);
    assert_eq!(outcome.findings.len(), 1);
    assert_eq!(outcome.findings[0].id, "npm.lifecycle.postinstall.root");
    assert_eq!(outcome.findings[0].package, "(root)");
    assert_eq!(outcome.findings[0].detail.as_deref(), Some("node evil.js"));
    assert_eq!(outcome.receipt.packages_incomplete, 1);
}

#[test]
fn non_registry_resolved_url_blocks() -> TestResult {
    let lock = PackageLock {
        lockfile_version: 3,
        packages: vec![pkg(
            "backdoor",
            "1.0.0",
            Some("git+https://evil.test/repo.git"),
            false,
        )],
    };
    let outcome = analyze(&lock, &[], "10.8.0", digest());
    assert_eq!(outcome.verdict, AdvisoryVerdict::Block);
    assert!(!outcome.verdict.allows_execution());
    assert_eq!(outcome.receipt.packages_blocked, 1);
    let block = outcome
        .findings
        .iter()
        .find(|f| f.severity == FindingSeverity::Block)
        .ok_or("a block finding was expected")?;
    assert_eq!(block.id, "npm.provenance.non_registry");
    assert_eq!(
        block.detail.as_deref(),
        Some("git+https://evil.test/repo.git")
    );
    Ok(())
}

#[test]
fn registry_url_is_not_flagged() {
    let lock = PackageLock {
        lockfile_version: 3,
        packages: vec![pkg(
            "lodash",
            "4.17.21",
            Some("https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz"),
            false,
        )],
    };
    let outcome = analyze(&lock, &[], "10.8.0", digest());
    assert_eq!(outcome.verdict, AdvisoryVerdict::Pass);
    assert!(outcome.findings.is_empty());
}

#[test]
fn block_and_warn_coexist_with_block_verdict() {
    let lock = PackageLock {
        lockfile_version: 3,
        packages: vec![
            pkg("scripted", "1.0.0", None, true),
            pkg("malicious", "2.0.0", Some("file:./local.tgz"), false),
        ],
    };
    let outcome = analyze(&lock, &[], "10.8.0", digest());
    assert_eq!(outcome.verdict, AdvisoryVerdict::Block);
    assert_eq!(outcome.findings.len(), 2);
    assert_eq!(outcome.receipt.packages_blocked, 1);
    assert_eq!(outcome.receipt.packages_incomplete, 1);
}

#[test]
fn empty_lockfile_and_no_scripts_is_pass() {
    let lock = PackageLock {
        lockfile_version: 3,
        packages: vec![],
    };
    let outcome = analyze(&lock, &[], "10.8.0", digest());
    assert_eq!(outcome.verdict, AdvisoryVerdict::Pass);
    assert_eq!(outcome.receipt.packages_inspected, 0);
}

#[test]
fn capabilities_recorded_in_receipt() {
    let lock = PackageLock {
        lockfile_version: 3,
        packages: vec![],
    };
    let outcome = analyze(&lock, &[], "10.8.0", digest());
    let names: Vec<&str> = outcome
        .receipt
        .capabilities
        .iter()
        .map(|c| c.name.as_str())
        .collect();
    assert!(names.contains(&"read_lockfile"));
    assert!(names.contains(&"parse_argv"));
    assert!(outcome.receipt.capabilities.iter().all(|c| c.granted));
}

#[test]
fn tool_version_recorded() {
    let lock = PackageLock {
        lockfile_version: 3,
        packages: vec![],
    };
    let outcome = analyze(&lock, &[], "10.8.2", digest());
    assert_eq!(outcome.receipt.tool, "npm");
    assert_eq!(outcome.receipt.tool_version, "10.8.2");
}
