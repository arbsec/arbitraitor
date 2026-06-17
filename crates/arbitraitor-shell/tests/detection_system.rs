//! Integration tests for shell system threat detection.

use arbitraitor_model::finding::FindingCategory;
use arbitraitor_model::verdict::{Confidence, Severity};
use arbitraitor_shell::{ShellParser, detect_system_threats, normalize};

fn findings_for(
    source: &str,
) -> Result<Vec<arbitraitor_model::finding::Finding>, Box<dyn std::error::Error>> {
    let mut parser = ShellParser::new()?;
    let parsed = parser.parse_str(source);
    let normalized = normalize(&parsed.ast, source)?;
    Ok(detect_system_threats(&normalized, source))
}

#[test]
fn detects_privilege_escalation_tool() -> Result<(), Box<dyn std::error::Error>> {
    let findings = findings_for("pkexec sh -c 'id > /tmp/out'\n")?;
    assert!(findings.iter().any(|finding| {
        finding.category == FindingCategory::PrivilegeEscalation
            && finding.severity == Severity::Medium
            && finding.confidence == Confidence::High
    }));
    Ok(())
}

#[test]
fn detects_shell_startup_modification() -> Result<(), Box<dyn std::error::Error>> {
    let findings = findings_for("echo 'curl https://x' >> ~/.bashrc\n")?;
    assert!(findings.iter().any(|finding| {
        finding.category == FindingCategory::Persistence && finding.severity == Severity::High
    }));
    Ok(())
}

#[test]
fn detects_scheduler_or_service_persistence() -> Result<(), Box<dyn std::error::Error>> {
    let findings = findings_for("crontab -e\n")?;
    assert!(findings.iter().any(|finding| {
        finding.category == FindingCategory::Persistence && finding.severity == Severity::High
    }));
    Ok(())
}

#[test]
fn detects_protected_system_path_write() -> Result<(), Box<dyn std::error::Error>> {
    let findings = findings_for("echo 'bad' > /etc/sudoers.d/backdoor\n")?;
    assert!(findings.iter().any(|finding| {
        finding.category == FindingCategory::Persistence
            && finding.severity == Severity::Critical
            && finding.confidence == Confidence::Confirmed
    }));
    Ok(())
}

#[test]
fn detects_package_repository_modification() -> Result<(), Box<dyn std::error::Error>> {
    let findings = findings_for("echo 'deb https://evil stable main' >> /etc/apt/sources.list\n")?;
    assert!(findings.iter().any(|finding| {
        finding.category == FindingCategory::Persistence && finding.severity == Severity::High
    }));
    Ok(())
}

#[test]
fn detects_history_deletion() -> Result<(), Box<dyn std::error::Error>> {
    let findings = findings_for("history -c\n")?;
    assert!(findings.iter().any(|finding| {
        finding.category == FindingCategory::SuspiciousScriptBehavior
            && finding.severity == Severity::Medium
    }));
    Ok(())
}

#[test]
fn detects_security_control_disabling() -> Result<(), Box<dyn std::error::Error>> {
    let findings = findings_for("systemctl stop clamav\n")?;
    assert!(findings.iter().any(|finding| {
        finding.category == FindingCategory::SuspiciousScriptBehavior
            && finding.severity == Severity::High
    }));
    Ok(())
}

#[test]
fn detects_shell_failure_obscuring_options() -> Result<(), Box<dyn std::error::Error>> {
    let findings = findings_for("set +o pipefail\n")?;
    assert!(findings.iter().any(|finding| {
        finding.category == FindingCategory::SuspiciousScriptBehavior
            && finding.severity == Severity::Low
            && finding.confidence == Confidence::Medium
    }));
    Ok(())
}

#[test]
fn detects_insecure_tls_flags() -> Result<(), Box<dyn std::error::Error>> {
    let findings = findings_for("curl --insecure https://example.invalid/install.sh\n")?;
    assert!(findings.iter().any(|finding| {
        finding.category == FindingCategory::Transport
            && finding.severity == Severity::Medium
            && finding.confidence == Confidence::High
    }));
    Ok(())
}

#[test]
fn does_not_flag_legitimate_sudo_install_script() -> Result<(), Box<dyn std::error::Error>> {
    let findings = findings_for("sudo apt-get install -y curl\n")?;
    assert!(findings.is_empty());
    Ok(())
}

#[test]
fn does_not_flag_writing_to_user_config() -> Result<(), Box<dyn std::error::Error>> {
    let findings =
        findings_for("mkdir -p ~/.config/tool && echo theme=dark > ~/.config/tool/config\n")?;
    assert!(findings.is_empty());
    Ok(())
}

#[test]
fn does_not_flag_set_errexit() -> Result<(), Box<dyn std::error::Error>> {
    let findings = findings_for("set -e\n")?;
    assert!(findings.is_empty());
    Ok(())
}

#[test]
fn does_not_flag_tls_verification_defaults() -> Result<(), Box<dyn std::error::Error>> {
    let findings = findings_for("curl https://example.invalid/install.sh\n")?;
    assert!(findings.is_empty());
    Ok(())
}

#[test]
fn does_not_flag_home_conf_file_edit() -> Result<(), Box<dyn std::error::Error>> {
    let findings = findings_for("echo option=true >> ~/project/app.conf\n")?;
    assert!(findings.is_empty());
    Ok(())
}
