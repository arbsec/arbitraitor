use super::{
    Cli, Command, HealthChecker, WrappersCommand, WrappersSubcommand, commands,
    emit_wrapper_output, parse_cli_from_args, wrapper_output_destination, wrapper_url_argument,
    write_status_text,
};
use clap::Parser;
use std::fs;
use std::io::{Cursor, Write};
use std::path::PathBuf;
use zip::ZipWriter;
use zip::write::SimpleFileOptions;

#[test]
fn inspect_accepts_sha256_flag() -> Result<(), Box<dyn std::error::Error>> {
    let digest = "ab".repeat(32);
    let cli = Cli::try_parse_from([
        "arbitraitor",
        "inspect",
        "https://example.test/artifact",
        "--sha256",
        &digest,
    ])?;

    match cli.command {
        Command::Inspect(command) => {
            assert_eq!(
                command.sha256.ok_or("missing parsed digest")?.to_string(),
                digest
            );
        }
        Command::Daemon(_)
        | Command::Fetch(_)
        | Command::Unpack(_)
        | Command::Intel(_)
        | Command::Run(_)
        | Command::Status(_)
        | Command::Wrappers(_)
        | Command::Mcp
        | Command::Scan(_)
        | Command::Explain(_)
        | Command::Store(_)
        | Command::Policy(_)
        | Command::Doctor(_)
        | Command::Rules(_)
        | Command::Update(_)
        | Command::Plugin(_)
        | Command::Hook(_)
        | Command::Shim(_)
        | Command::Version => {
            return Err("parsed wrong command".into());
        }
    }
    Ok(())
}

#[test]
fn inspect_rejects_invalid_sha256_flag() {
    let result = Cli::try_parse_from([
        "arbitraitor",
        "inspect",
        "https://example.test/artifact",
        "--sha256",
        "not-a-digest",
    ]);

    assert!(result.is_err());
}

#[test]
fn accepts_global_config_flag() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::try_parse_from([
        "arbitraitor",
        "--config",
        "arbitraitor.toml",
        "inspect",
        "https://example.test/artifact",
    ])?;

    assert_eq!(cli.config, Some(PathBuf::from("arbitraitor.toml")));
    Ok(())
}

#[test]
fn inspect_accepts_rules_directory_flag() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::try_parse_from([
        "arbitraitor",
        "inspect",
        "https://example.test/artifact",
        "--rules",
        "/tmp/rules",
    ])?;

    match cli.command {
        Command::Inspect(command) => {
            assert_eq!(
                command.rules.ok_or("missing rules path")?,
                std::path::PathBuf::from("/tmp/rules")
            );
        }
        Command::Daemon(_)
        | Command::Fetch(_)
        | Command::Unpack(_)
        | Command::Intel(_)
        | Command::Run(_)
        | Command::Status(_)
        | Command::Wrappers(_)
        | Command::Mcp
        | Command::Scan(_)
        | Command::Explain(_)
        | Command::Store(_)
        | Command::Policy(_)
        | Command::Doctor(_)
        | Command::Rules(_)
        | Command::Update(_)
        | Command::Plugin(_)
        | Command::Hook(_)
        | Command::Shim(_)
        | Command::Version => {
            return Err("parsed wrong command".into());
        }
    }
    Ok(())
}

#[test]
fn inspect_accepts_signature_flags() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::try_parse_from([
        "arbitraitor",
        "inspect",
        "https://example.test/artifact",
        "--minisign-sig",
        "artifact.minisig",
        "--minisign-key",
        "RWQexamplekeymaterial",
        "--cosign-bundle",
        "artifact.bundle",
        "--cosign-identity",
        "builder@example.test",
        "--cosign-issuer",
        "https://issuer.example.test",
    ])?;

    match cli.command {
        Command::Inspect(command) => {
            assert_eq!(command.minisign_sig.len(), 1);
            assert_eq!(command.minisign_key, ["RWQexamplekeymaterial"]);
            assert_eq!(command.cosign_bundle.len(), 1);
            assert_eq!(command.cosign_identity, ["builder@example.test"]);
            assert_eq!(command.cosign_issuer, ["https://issuer.example.test"]);
        }
        Command::Daemon(_)
        | Command::Fetch(_)
        | Command::Unpack(_)
        | Command::Intel(_)
        | Command::Run(_)
        | Command::Status(_)
        | Command::Wrappers(_)
        | Command::Mcp
        | Command::Scan(_)
        | Command::Explain(_)
        | Command::Store(_)
        | Command::Policy(_)
        | Command::Doctor(_)
        | Command::Rules(_)
        | Command::Update(_)
        | Command::Plugin(_)
        | Command::Hook(_)
        | Command::Shim(_)
        | Command::Version => {
            return Err("parsed wrong command".into());
        }
    }
    Ok(())
}

#[test]
fn inspect_accepts_explain_flag() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::try_parse_from([
        "arbitraitor",
        "inspect",
        "https://example.test/artifact",
        "--explain",
    ])?;

    match cli.command {
        Command::Inspect(command) => {
            assert!(command.explain);
            assert!(command.format.is_none());
        }
        _ => return Err("parsed wrong command".into()),
    }
    Ok(())
}

#[test]
fn inspect_accepts_format_shellcheck_flag() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::try_parse_from([
        "arbitraitor",
        "inspect",
        "https://example.test/artifact",
        "--explain",
        "--format",
        "shellcheck",
    ])?;

    match cli.command {
        Command::Inspect(command) => {
            assert!(command.explain);
            assert_eq!(command.format, Some(super::ExplainFormat::Shellcheck));
        }
        _ => return Err("parsed wrong command".into()),
    }
    Ok(())
}

#[test]
fn inspect_accepts_format_text_flag() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::try_parse_from([
        "arbitraitor",
        "inspect",
        "https://example.test/artifact",
        "--format",
        "text",
    ])?;

    match cli.command {
        Command::Inspect(command) => {
            assert_eq!(command.format, Some(super::ExplainFormat::Text));
        }
        _ => return Err("parsed wrong command".into()),
    }
    Ok(())
}

#[test]
fn unpack_accepts_archive_and_output_flags() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::try_parse_from(["arbitraitor", "unpack", "archive.zip", "--output", "out"])?;

    match cli.command {
        Command::Unpack(command) => {
            assert_eq!(command.archive, PathBuf::from("archive.zip"));
            assert_eq!(command.output, PathBuf::from("out"));
        }
        Command::Inspect(_)
        | Command::Daemon(_)
        | Command::Fetch(_)
        | Command::Intel(_)
        | Command::Run(_)
        | Command::Status(_)
        | Command::Wrappers(_)
        | Command::Mcp
        | Command::Scan(_)
        | Command::Explain(_)
        | Command::Store(_)
        | Command::Policy(_)
        | Command::Doctor(_)
        | Command::Rules(_)
        | Command::Update(_)
        | Command::Plugin(_)
        | Command::Hook(_)
        | Command::Shim(_)
        | Command::Version => {
            return Err("parsed wrong command".into());
        }
    }
    Ok(())
}

#[test]
fn daemon_accepts_start_stop_status() -> Result<(), Box<dyn std::error::Error>> {
    for subcommand in ["start", "stop", "status"] {
        let cli = Cli::try_parse_from([
            "arbitraitor",
            "daemon",
            "--socket",
            "/tmp/arbitraitor.sock",
            subcommand,
        ])?;

        match cli.command {
            Command::Daemon(command) => {
                assert_eq!(command.socket, Some(PathBuf::from("/tmp/arbitraitor.sock")));
            }
            _ => return Err("parsed wrong command".into()),
        }
    }
    Ok(())
}

#[test]
fn unpack_command_extracts_safe_archive() -> Result<(), Box<dyn std::error::Error>> {
    let root = unique_temp_path("cli-unpack");
    fs::create_dir_all(&root)?;
    let archive_path = root.join("archive.zip");
    let output_dir = root.join("out");
    fs::write(&archive_path, zip_bytes(&[("nested/file.txt", b"safe")])?)?;

    super::unpack(&archive_path, &output_dir)?;

    assert_eq!(fs::read(output_dir.join("nested/file.txt"))?, b"safe");
    fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn rejects_unpaired_signature_flags() {
    let signatures = super::signature_inputs(
        vec!["artifact.minisig".into()],
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
    );

    assert!(signatures.is_err());
}

#[test]
fn intel_update_parses_urlhaus_flag() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::try_parse_from([
        "arbitraitor",
        "intel",
        "update",
        "--urlhaus",
        "--intel-store",
        "/tmp/intel.json",
    ])?;

    match cli.command {
        Command::Intel(super::IntelCommand {
            subcommand: super::IntelSubcommand::Update(update),
        }) => {
            assert!(update.urlhaus);
            assert_eq!(update.intel_store, Some(PathBuf::from("/tmp/intel.json")));
            assert!(update.urlhaus_url.is_none());
        }
        _ => return Err("parsed wrong command".into()),
    }
    Ok(())
}

#[test]
fn intel_update_parses_custom_urlhaus_url() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::try_parse_from([
        "arbitraitor",
        "intel",
        "update",
        "--urlhaus",
        "--urlhaus-url",
        "https://mirror.example/urlhaus.csv",
    ])?;

    match cli.command {
        Command::Intel(super::IntelCommand {
            subcommand: super::IntelSubcommand::Update(update),
        }) => {
            assert_eq!(
                update.urlhaus_url.as_deref(),
                Some("https://mirror.example/urlhaus.csv")
            );
        }
        _ => return Err("parsed wrong command".into()),
    }
    Ok(())
}

fn zip_bytes(entries: &[(&str, &[u8])]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let cursor = Cursor::new(Vec::new());
    let mut writer = ZipWriter::new(cursor);
    for (name, data) in entries {
        writer.start_file(*name, SimpleFileOptions::default())?;
        writer.write_all(data)?;
    }
    Ok(writer.finish()?.into_inner())
}

fn unique_temp_path(label: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
        "arbitraitor-cli-{label}-{}-{}",
        std::process::id(),
        timestamp_nanos()
    ))
}

fn timestamp_nanos() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |duration| duration.as_nanos())
}

#[test]
fn status_command_parses_text_mode() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::try_parse_from(["arbitraitor", "status"])?;

    match cli.command {
        Command::Status(command) => {
            assert!(!command.json);
            assert!(command.cas_dir.is_none());
            assert!(command.rules.is_none());
        }
        _ => return Err("parsed wrong command".into()),
    }
    Ok(())
}

#[test]
fn status_command_parses_json_flag() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::try_parse_from(["arbitraitor", "status", "--json"])?;

    match cli.command {
        Command::Status(command) => assert!(command.json),
        _ => return Err("parsed wrong command".into()),
    }
    Ok(())
}

#[test]
fn status_command_outputs_text() -> Result<(), Box<dyn std::error::Error>> {
    let root = unique_temp_path("status-text");
    fs::create_dir_all(root.join("objects").join("ab"))?;
    fs::write(root.join("objects").join("ab").join("object"), b"data")?;

    let report = HealthChecker::new()
        .with_store(root.clone())
        .with_rule_pack("v2024.6".to_owned())
        .check();
    let mut buffer = Vec::new();
    write_status_text(&mut buffer, &report)?;
    let output = String::from_utf8(buffer)?;

    assert!(output.contains("Arbitraitor v"));
    assert!(output.contains("Store"));
    assert!(output.contains("Detector"));
    assert!(output.contains("Version"));
    assert!(output.contains("Healthy"));
    fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn status_command_outputs_json() -> Result<(), Box<dyn std::error::Error>> {
    let report = HealthChecker::new()
        .with_rule_pack("v2024.6".to_owned())
        .check();
    let json = serde_json::to_value(&report)?;
    let parsed: arbitraitor_core::health::HealthReport = serde_json::from_value(json.clone())?;

    assert_eq!(parsed.version, report.version);
    assert!(json.get("checks").is_some());
    assert!(json["checks"].get("store").is_some());
    assert!(json["checks"].get("detectors").is_some());
    assert!(json["checks"].get("version").is_some());
    Ok(())
}

#[test]
fn wrappers_install_parses_all_targets() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::try_parse_from(["arbitraitor", "wrappers", "install"])?;

    match cli.command {
        Command::Wrappers(cmd) => match cmd.subcommand {
            WrappersSubcommand::Install(install) => {
                assert!(install.targets.is_empty());
                assert!(!cmd.use_scripts);
            }
            _ => return Err("parsed wrong subcommand".into()),
        },
        _ => return Err("parsed wrong command".into()),
    }
    Ok(())
}

#[test]
fn wrappers_install_parses_specific_target() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::try_parse_from(["arbitraitor", "wrappers", "install", "curl"])?;

    match cli.command {
        Command::Wrappers(WrappersCommand {
            subcommand: WrappersSubcommand::Install(install),
            ..
        }) => {
            assert_eq!(install.targets, ["curl"]);
        }
        _ => return Err("parsed wrong command".into()),
    }
    Ok(())
}

#[test]
fn wrappers_accepts_shim_dir_and_scripts_flags() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::try_parse_from([
        "arbitraitor",
        "wrappers",
        "--shim-dir",
        "/tmp/shims",
        "--use-scripts",
        "install",
    ])?;

    match cli.command {
        Command::Wrappers(cmd) => {
            assert_eq!(
                cmd.shim_dir.as_deref(),
                Some(std::path::Path::new("/tmp/shims"))
            );
            assert!(cmd.use_scripts);
        }
        _ => return Err("parsed wrong command".into()),
    }
    Ok(())
}

#[test]
fn wrappers_uninstall_status_init_script_parse() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::try_parse_from(["arbitraitor", "wrappers", "uninstall"])?;
    assert!(matches!(
        cli.command,
        Command::Wrappers(WrappersCommand {
            subcommand: WrappersSubcommand::Uninstall(_),
            ..
        })
    ));

    let cli = Cli::try_parse_from(["arbitraitor", "wrappers", "status"])?;
    assert!(matches!(
        cli.command,
        Command::Wrappers(WrappersCommand {
            subcommand: WrappersSubcommand::Status(_),
            ..
        })
    ));

    let cli = Cli::try_parse_from(["arbitraitor", "wrappers", "init-script"])?;
    assert!(matches!(
        cli.command,
        Command::Wrappers(WrappersCommand {
            subcommand: WrappersSubcommand::InitScript(_),
            ..
        })
    ));
    Ok(())
}

#[test]
fn wrappers_init_parses_shell_arg() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::try_parse_from(["arbitraitor", "wrappers", "init", "zsh"])?;
    match cli.command {
        Command::Wrappers(WrappersCommand {
            subcommand: WrappersSubcommand::Init(cmd),
            ..
        }) => {
            assert_eq!(cmd.shell.as_deref(), Some("zsh"));
            assert!(!cmd.install);
            assert!(!cmd.uninstall);
            assert!(!cmd.detect_shell);
        }
        _ => return Err("parsed wrong command".into()),
    }
    Ok(())
}

#[test]
fn wrappers_init_parses_flags() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::try_parse_from(["arbitraitor", "wrappers", "init", "bash", "--install"])?;
    match cli.command {
        Command::Wrappers(WrappersCommand {
            subcommand: WrappersSubcommand::Init(cmd),
            ..
        }) => {
            assert_eq!(cmd.shell.as_deref(), Some("bash"));
            assert!(cmd.install);
        }
        _ => return Err("parsed wrong command".into()),
    }

    let cli = Cli::try_parse_from(["arbitraitor", "wrappers", "init", "--uninstall"])?;
    match cli.command {
        Command::Wrappers(WrappersCommand {
            subcommand: WrappersSubcommand::Init(cmd),
            ..
        }) => {
            assert!(cmd.shell.is_none());
            assert!(cmd.uninstall);
        }
        _ => return Err("parsed wrong command".into()),
    }

    let cli = Cli::try_parse_from(["arbitraitor", "wrappers", "init", "--detect-shell"])?;
    match cli.command {
        Command::Wrappers(WrappersCommand {
            subcommand: WrappersSubcommand::Init(cmd),
            ..
        }) => assert!(cmd.detect_shell),
        _ => return Err("parsed wrong command".into()),
    }
    Ok(())
}

#[test]
fn rules_list_parses() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::try_parse_from(["arbitraitor", "rules", "list"])?;
    match cli.command {
        Command::Rules(cmd) => {
            assert!(cmd.rules_dir.is_none());
            assert!(matches!(cmd.subcommand, commands::RulesSubcommand::List));
        }
        _ => return Err("parsed wrong command".into()),
    }
    Ok(())
}

#[test]
fn rules_list_with_dir_parses() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::try_parse_from([
        "arbitraitor",
        "rules",
        "--rules-dir",
        "/path/to/rules",
        "list",
    ])?;
    match cli.command {
        Command::Rules(cmd) => {
            assert_eq!(
                cmd.rules_dir.as_deref(),
                Some(std::path::Path::new("/path/to/rules"))
            );
            assert!(matches!(cmd.subcommand, commands::RulesSubcommand::List));
        }
        _ => return Err("parsed wrong command".into()),
    }
    Ok(())
}

#[test]
fn rules_validate_parses() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::try_parse_from(["arbitraitor", "rules", "validate", "/path/to/rules.yar"])?;
    match cli.command {
        Command::Rules(cmd) => match cmd.subcommand {
            commands::RulesSubcommand::Validate { file } => {
                assert_eq!(file, PathBuf::from("/path/to/rules.yar"));
            }
            commands::RulesSubcommand::List => return Err("wrong subcommand".into()),
        },
        _ => return Err("parsed wrong command".into()),
    }
    Ok(())
}

#[test]
fn update_verify_parses() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::try_parse_from([
        "arbitraitor",
        "update",
        "verify",
        "manifest.json",
        "--key",
        "pubkey.pub",
    ])?;
    match cli.command {
        Command::Update(cmd) => match cmd.subcommand {
            commands::UpdateSubcommand::Verify {
                manifest_file,
                key,
                signature,
            } => {
                assert_eq!(manifest_file, PathBuf::from("manifest.json"));
                assert_eq!(key, PathBuf::from("pubkey.pub"));
                assert!(signature.is_none());
            }
        },
        _ => return Err("parsed wrong command".into()),
    }
    Ok(())
}

#[test]
fn update_verify_with_explicit_sig_parses() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::try_parse_from([
        "arbitraitor",
        "update",
        "verify",
        "manifest.json",
        "--key",
        "pubkey.pub",
        "--signature",
        "custom.sig",
    ])?;
    match cli.command {
        Command::Update(cmd) => match cmd.subcommand {
            commands::UpdateSubcommand::Verify { signature, .. } => {
                assert_eq!(
                    signature.as_deref(),
                    Some(std::path::Path::new("custom.sig"))
                );
            }
        },
        _ => return Err("parsed wrong command".into()),
    }
    Ok(())
}

#[test]
fn symlink_invocation_parses_as_fetch_wrapper() -> Result<(), Box<dyn std::error::Error>> {
    let cli = parse_cli_from_args([
        "/tmp/shims/curl",
        "-fsSL",
        "https://example.test/install.sh",
    ]);

    match cli.command {
        Command::Fetch(fetch) => {
            assert_eq!(fetch.tool.as_deref(), Some("curl"));
            assert_eq!(fetch.args, ["-fsSL", "https://example.test/install.sh"]);
        }
        _ => return Err("parsed wrong command".into()),
    }
    Ok(())
}

#[test]
fn symlink_invocation_treats_help_as_curl_arg() -> Result<(), Box<dyn std::error::Error>> {
    let cli = parse_cli_from_args([
        "/tmp/shims/curl",
        "--help",
        "https://example.test/install.sh",
    ]);

    match cli.command {
        Command::Fetch(fetch) => {
            assert_eq!(fetch.tool.as_deref(), Some("curl"));
            assert_eq!(fetch.args, ["--help", "https://example.test/install.sh"]);
        }
        _ => return Err("parsed wrong command".into()),
    }
    Ok(())
}

#[test]
fn symlink_invocation_treats_config_as_curl_arg() -> Result<(), Box<dyn std::error::Error>> {
    let cli = parse_cli_from_args([
        "/tmp/shims/curl",
        "--config",
        "curlrc",
        "https://example.test/install.sh",
    ]);

    assert!(cli.config.is_none());
    match cli.command {
        Command::Fetch(fetch) => {
            assert_eq!(fetch.tool.as_deref(), Some("curl"));
            assert_eq!(
                fetch.args,
                ["--config", "curlrc", "https://example.test/install.sh"]
            );
        }
        _ => return Err("parsed wrong command".into()),
    }
    Ok(())
}

#[test]
fn wrapper_url_argument_ignores_options() -> Result<(), Box<dyn std::error::Error>> {
    let args = [
        "-o".to_owned(),
        "install.sh".to_owned(),
        "https://example.test/install.sh".to_owned(),
    ];

    let url = wrapper_url_argument(Some("curl"), &args).ok_or("missing wrapper URL")?;

    assert_eq!(url, "https://example.test/install.sh");
    Ok(())
}

#[test]
fn wrapper_url_argument_uses_curl_parser_for_url_valued_options()
-> Result<(), Box<dyn std::error::Error>> {
    let args = [
        "--proxy".to_owned(),
        "https://example.test/proxy".to_owned(),
        "https://www.rust-lang.org/".to_owned(),
    ];

    let url = wrapper_url_argument(Some("curl"), &args).ok_or("missing wrapper URL")?;

    assert_eq!(url, "https://www.rust-lang.org/");
    Ok(())
}

#[test]
fn wrapper_url_argument_consumes_unsupported_curl_option_values()
-> Result<(), Box<dyn std::error::Error>> {
    let args = [
        "--config".to_owned(),
        "curlrc".to_owned(),
        "https://example.test/install.sh".to_owned(),
    ];

    let url = wrapper_url_argument(Some("curl"), &args).ok_or("missing wrapper URL")?;

    assert_eq!(url, "https://example.test/install.sh");
    Ok(())
}
#[test]
fn wrapper_output_destination_curl_stdout() {
    let args: Vec<String> = ["curl", "-fsSL", "https://example.test/install.sh"]
        .iter()
        .map(std::string::ToString::to_string)
        .collect();
    let (output, remote_name) = wrapper_output_destination(Some("curl"), &args);
    assert!(output.is_none(), "no -o flag should yield None");
    assert!(!remote_name, "no -O flag should yield false");
}

#[test]
fn wrapper_output_destination_curl_dash_o() {
    let args: Vec<String> = [
        "curl",
        "-o",
        "/tmp/file.tar.gz",
        "https://example.test/file.tar.gz",
    ]
    .iter()
    .map(std::string::ToString::to_string)
    .collect();
    let (output, remote_name) = wrapper_output_destination(Some("curl"), &args);
    assert_eq!(output.as_deref(), Some("/tmp/file.tar.gz"));
    assert!(!remote_name);
}

#[test]
fn wrapper_output_destination_curl_remote_name() {
    let args: Vec<String> = ["curl", "-O", "https://example.test/file.tar.gz"]
        .iter()
        .map(std::string::ToString::to_string)
        .collect();
    let (output, remote_name) = wrapper_output_destination(Some("curl"), &args);
    assert!(output.is_none());
    assert!(remote_name, "-O should set remote_name");
}

#[test]
fn wrapper_output_destination_wget_output_document() {
    let args: Vec<String> = [
        "wget",
        "-O",
        "/tmp/file.tar.gz",
        "https://example.test/file.tar.gz",
    ]
    .iter()
    .map(std::string::ToString::to_string)
    .collect();
    let (output, remote_name) = wrapper_output_destination(Some("wget"), &args);
    assert_eq!(output.as_deref(), Some("/tmp/file.tar.gz"));
    assert!(!remote_name);
}

#[test]
fn emit_output_writes_bytes_to_file() -> std::io::Result<()> {
    let dir = std::env::temp_dir().join("arb_test_emit_file");
    std::fs::create_dir_all(&dir)?;
    let path = dir.join("output.bin");
    let path_str = path.to_string_lossy().into_owned();
    let bytes = b"hello world";
    emit_wrapper_output(
        bytes,
        Some(path_str.as_str()),
        false,
        "https://example.com/file.bin",
    )
    .map_err(|e| std::io::Error::other(e.to_string()))?;
    let read_back = std::fs::read(&path)?;
    assert_eq!(read_back, bytes);
    std::fs::remove_file(path)?;
    std::fs::remove_dir(dir)?;
    Ok(())
}

#[test]
fn emit_output_remote_name_derives_filename() -> std::io::Result<()> {
    let dir = std::env::temp_dir().join("arb_test_emit_remote");
    std::fs::create_dir_all(&dir)?;
    let prev = std::env::current_dir()?;
    std::env::set_current_dir(&dir)?;
    let bytes = b"remote content";
    emit_wrapper_output(bytes, None, true, "https://example.com/path/to/tool.tar.gz")
        .map_err(|e| std::io::Error::other(e.to_string()))?;
    let read_back = std::fs::read("tool.tar.gz")?;
    assert_eq!(read_back, bytes);
    std::fs::remove_file("tool.tar.gz")?;
    std::env::set_current_dir(prev)?;
    std::fs::remove_dir(dir)?;
    Ok(())
}

#[test]
fn emit_output_remote_name_strips_query_and_fragment() -> std::io::Result<()> {
    let dir = std::env::temp_dir().join("arb_test_emit_query");
    std::fs::create_dir_all(&dir)?;
    let prev = std::env::current_dir()?;
    std::env::set_current_dir(&dir)?;
    let bytes = b"data";
    emit_wrapper_output(
        bytes,
        None,
        true,
        "https://example.com/file.bin?token=secret#frag",
    )
    .map_err(|e| std::io::Error::other(e.to_string()))?;
    let read_back = std::fs::read("file.bin")?;
    assert_eq!(read_back, bytes);
    std::fs::remove_file("file.bin")?;
    std::env::set_current_dir(prev)?;
    std::fs::remove_dir(dir)?;
    Ok(())
}

#[test]
fn emit_output_remote_name_rejects_url_without_filename() {
    let result = emit_wrapper_output(b"x", None, true, "https://example.com/");
    assert!(
        result.is_err(),
        "URL with no filename component should fail"
    );
}

#[test]
fn wrappers_rejects_unknown_target_name() {
    let result = Cli::try_parse_from(["arbitraitor", "wrappers", "install", "unknown-tool"]);
    assert!(
        result.is_ok(),
        "unknown target is a runtime error, not parse"
    );
}
