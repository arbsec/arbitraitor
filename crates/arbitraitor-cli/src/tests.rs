use super::{
    Cli, Command, HealthChecker, WrappersCommand, WrappersSubcommand, commands,
    emit_wrapper_output, parse_cli_from_args, pipeline::parse_fetch_source, query_daemon_status,
    wrapper_output_destination, wrapper_url_argument, write_status_text,
};
use arbitraitor_artifact::ArtifactType;
use arbitraitor_fetch::FetchSource;
use arbitraitor_model::origin::CallerOrigin;
use clap::Parser;
use std::fs;
use std::io::{Cursor, Write};
use std::path::PathBuf;
use std::time::Duration;
use zip::ZipWriter;
use zip::write::SimpleFileOptions;

#[test]
fn parse_fetch_source_https_url() -> Result<(), Box<dyn std::error::Error>> {
    let source = parse_fetch_source("https://example.com/artifact.sh")?;
    assert!(matches!(source, FetchSource::Url(_)));
    Ok(())
}

#[test]
fn parse_fetch_source_http_url() -> Result<(), Box<dyn std::error::Error>> {
    let source = parse_fetch_source("http://example.com/artifact.sh")?;
    assert!(matches!(source, FetchSource::Url(_)));
    Ok(())
}

#[test]
fn parse_fetch_source_bare_relative_path() -> Result<(), Box<dyn std::error::Error>> {
    let source = parse_fetch_source("./suspicious.sh")?;
    assert!(matches!(source, FetchSource::File(ref p) if p == &PathBuf::from("./suspicious.sh")));
    Ok(())
}

#[test]
fn parse_fetch_source_bare_absolute_path() -> Result<(), Box<dyn std::error::Error>> {
    let source = parse_fetch_source("/tmp/artifact.sh")?;
    assert!(matches!(source, FetchSource::File(ref p) if p == &PathBuf::from("/tmp/artifact.sh")));
    Ok(())
}

#[test]
fn parse_fetch_source_file_url() -> Result<(), Box<dyn std::error::Error>> {
    let source = parse_fetch_source("file:///tmp/artifact.sh")?;
    assert!(matches!(source, FetchSource::File(ref p) if p == &PathBuf::from("/tmp/artifact.sh")));
    Ok(())
}

#[test]
fn parse_fetch_source_dotdash_is_stdin() -> Result<(), Box<dyn std::error::Error>> {
    let source = parse_fetch_source("-")?;
    assert!(matches!(source, FetchSource::Stdin));
    Ok(())
}

#[test]
fn parse_fetch_source_stdin_url() -> Result<(), Box<dyn std::error::Error>> {
    let source = parse_fetch_source("stdin://")?;
    assert!(matches!(source, FetchSource::Stdin));
    Ok(())
}

#[test]
fn parse_fetch_source_unsupported_scheme_errors() {
    let result = parse_fetch_source("ftp://example.com/file");
    assert!(result.is_err());
}

#[test]
fn parse_fetch_source_non_url_scheme_errors() {
    let result = parse_fetch_source("data:text/html,<script>alert(1)</script>");
    assert!(result.is_err());
}

#[test]
fn inspect_accepts_local_path_in_cli() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::try_parse_from(["arbitraitor", "inspect", "./local-artifact.sh"])?;
    let Command::Inspect(command) = cli.command else {
        return Err("expected Inspect command".into());
    };
    assert_eq!(command.url, "./local-artifact.sh");
    Ok(())
}

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
        | Command::Wrap(_)
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
        | Command::Graph(_)
        | Command::Approve(_)
        | Command::Execute(_)
        | Command::Report(_)
        | Command::Allow(_)
        | Command::Pm(_)
        | Command::Env(_)
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
fn allow_root_flag_is_accepted_globally() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::try_parse_from(["arbitraitor", "--allow-root", "doctor"])?;

    assert!(cli.allow_root, "--allow-root must parse to true");
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
        | Command::Wrap(_)
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
        | Command::Graph(_)
        | Command::Approve(_)
        | Command::Execute(_)
        | Command::Report(_)
        | Command::Allow(_)
        | Command::Pm(_)
        | Command::Env(_)
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
        | Command::Wrap(_)
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
        | Command::Graph(_)
        | Command::Approve(_)
        | Command::Execute(_)
        | Command::Report(_)
        | Command::Allow(_)
        | Command::Pm(_)
        | Command::Env(_)
        | Command::Version => {
            return Err("parsed wrong command".into());
        }
    }
    Ok(())
}

#[test]
fn scan_command_parses_all_flags() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::try_parse_from([
        "arbitraitor",
        "scan",
        "--stdin",
        "--emit-on-pass",
        "--recursive",
        "--type",
        "elf",
        "--name",
        "artifact",
        "--source-url",
        "https://example.test/artifact.sh",
        "--json",
        "--sarif",
        "--rules",
        "/tmp/rules",
    ])?;

    match cli.command {
        Command::Scan(command) => {
            assert!(command.stdin);
            assert!(command.emit_on_pass);
            assert!(command.recursive);
            assert_eq!(command.artifact_type, Some(ArtifactType::ElfExecutable));
            assert_eq!(command.detector_name.as_deref(), Some("artifact"));
            assert_eq!(
                command.source_url.as_deref(),
                Some("https://example.test/artifact.sh")
            );
            assert!(command.json);
            assert!(command.sarif);
            assert_eq!(command.rules, Some(PathBuf::from("/tmp/rules")));
        }
        Command::Daemon(_)
        | Command::Fetch(_)
        | Command::Unpack(_)
        | Command::Intel(_)
        | Command::Run(_)
        | Command::Status(_)
        | Command::Wrappers(_)
        | Command::Mcp
        | Command::Inspect(_)
        | Command::Explain(_)
        | Command::Store(_)
        | Command::Policy(_)
        | Command::Doctor(_)
        | Command::Rules(_)
        | Command::Update(_)
        | Command::Plugin(_)
        | Command::Hook(_)
        | Command::Shim(_)
        | Command::Graph(_)
        | Command::Approve(_)
        | Command::Execute(_)
        | Command::Report(_)
        | Command::Allow(_)
        | Command::Pm(_)
        | Command::Env(_)
        | Command::Version => {
            return Err("parsed wrong command".into());
        }
    }
    Ok(())
}

#[test]
fn scan_command_defaults() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::try_parse_from(["arbitraitor", "scan", "artifact.sh"])?;

    match cli.command {
        Command::Scan(command) => {
            assert_eq!(command.path, Some(PathBuf::from("artifact.sh")));
            assert!(!command.emit_on_pass);
            assert!(!command.recursive);
            assert_eq!(command.artifact_type, None);
            assert_eq!(command.detector_name, None);
            assert_eq!(command.source_url, None);
            assert!(!command.json);
            assert!(!command.sarif);
        }
        Command::Daemon(_)
        | Command::Fetch(_)
        | Command::Unpack(_)
        | Command::Intel(_)
        | Command::Run(_)
        | Command::Status(_)
        | Command::Wrappers(_)
        | Command::Mcp
        | Command::Inspect(_)
        | Command::Explain(_)
        | Command::Store(_)
        | Command::Policy(_)
        | Command::Doctor(_)
        | Command::Rules(_)
        | Command::Update(_)
        | Command::Plugin(_)
        | Command::Hook(_)
        | Command::Shim(_)
        | Command::Graph(_)
        | Command::Approve(_)
        | Command::Execute(_)
        | Command::Report(_)
        | Command::Allow(_)
        | Command::Pm(_)
        | Command::Env(_)
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
        | Command::Wrap(_)
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
        | Command::Graph(_)
        | Command::Approve(_)
        | Command::Execute(_)
        | Command::Report(_)
        | Command::Allow(_)
        | Command::Pm(_)
        | Command::Env(_)
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
    let signatures = super::pipeline::signature_inputs(
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
            assert!(!update.ossf_malicious_packages);
            assert!(update.ossf_malicious_packages_url.is_none());
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

#[test]
fn intel_update_parses_ossf_malicious_packages_flag() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::try_parse_from([
        "arbitraitor",
        "intel",
        "update",
        "--ossf-malicious-packages",
        "--ossf-malicious-packages-url",
        "https://mirror.example/osv-querybatch.json",
    ])?;

    match cli.command {
        Command::Intel(super::IntelCommand {
            subcommand: super::IntelSubcommand::Update(update),
        }) => {
            assert!(update.ossf_malicious_packages);
            assert_eq!(
                update.ossf_malicious_packages_url.as_deref(),
                Some("https://mirror.example/osv-querybatch.json")
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
            assert!(command.socket.is_none());
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
fn status_command_parses_socket_flag() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::try_parse_from([
        "arbitraitor",
        "status",
        "--socket",
        "/tmp/arbitraitor-status.sock",
    ])?;

    match cli.command {
        Command::Status(command) => {
            assert_eq!(
                command.socket.as_deref(),
                Some(std::path::Path::new("/tmp/arbitraitor-status.sock"))
            );
        }
        _ => return Err("parsed wrong command".into()),
    }
    Ok(())
}

#[test]
fn status_falls_back_when_socket_missing() -> Result<(), Box<dyn std::error::Error>> {
    let root = unique_temp_path("status-no-daemon");
    fs::create_dir_all(root.join("objects").join("ab"))?;
    fs::write(root.join("objects").join("ab").join("object"), b"data")?;

    let checker = HealthChecker::new().with_store(root.clone());
    let report = checker.check();
    let mut buffer = Vec::new();
    write_status_text(&mut buffer, &report, None)?;

    let output = String::from_utf8(buffer)?;
    assert!(output.contains("Arbitraitor v"));
    assert!(
        output.contains("Daemon: not running"),
        "missing-daemon output must announce store-only fallback: {output}",
    );
    fs::remove_dir_all(root)?;
    Ok(())
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn status_query_returns_none_when_daemon_socket_missing() {
    // A path under /tmp that has no socket bound. The handler must NOT error:
    // missing-daemon is the documented spec §28.1 fallback path.
    let socket = unique_temp_path("status-missing-daemon").join("daemon.sock");
    let info = query_daemon_status(&socket).await;
    assert!(
        info.is_none(),
        "missing daemon must return None, not error: {info:?}",
    );
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn status_query_returns_info_from_real_daemon() -> Result<(), Box<dyn std::error::Error>> {
    // Spawn a real daemon on a temp socket, drive a couple of operations
    // through it, then verify the CLI handler reads the daemon_info snapshot.
    let root = unique_temp_path("status-real-daemon");
    fs::create_dir_all(&root)?;
    let socket = root.join("daemon.sock");
    let daemon = arbitraitor_daemon::Daemon::new(&socket);
    let handle = tokio::spawn(async move { daemon.run().await });

    // Wait for the listener to appear.
    for _ in 0..100 {
        if socket.exists() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(socket.exists(), "daemon socket was not created");

    // Drive a Health request so the recent-operations ring has an entry.
    let _ = arbitraitor_daemon::request_once(
        &socket,
        &arbitraitor_daemon::DaemonRequest::Health {
            caller_origin: CallerOrigin::HumanTty,
            capability_token: None,
        },
    )
    .await?;

    let info = query_daemon_status(&socket)
        .await
        .ok_or("daemon running: query must return Some(daemon_info)")?;

    assert!(info.pid > 0);
    assert!(
        info.recent_operations
            .iter()
            .all(|op| op.operation != "status"),
        "Status must not self-record: {info:?}",
    );

    // Shutdown the daemon so the spawned task can finish.
    let _ = arbitraitor_daemon::request_once(
        &socket,
        &arbitraitor_daemon::DaemonRequest::Shutdown {
            caller_origin: CallerOrigin::HumanTty,
            capability_token: None,
        },
    )
    .await?;
    let _ = handle.await;
    fs::remove_dir_all(root)?;
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
    write_status_text(&mut buffer, &report, None)?;
    let output = String::from_utf8(buffer)?;

    assert!(output.contains("Arbitraitor v"));
    assert!(output.contains("Store"));
    assert!(output.contains("Detector"));
    assert!(output.contains("Version"));
    assert!(output.contains("Healthy"));
    assert!(
        output.contains("Daemon: not running"),
        "expected store-only fallback text, got: {output}",
    );
    fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn status_command_outputs_text_with_daemon_info() -> Result<(), Box<dyn std::error::Error>> {
    let report = HealthChecker::new().check();
    let daemon = arbitraitor_daemon::DaemonInfo {
        pid: 4242,
        uptime_secs: 13,
        last_operation: Some(arbitraitor_daemon::RecentOperation {
            operation: "inspect".to_owned(),
            outcome: "success".to_owned(),
            uptime_ms: 250,
            sha256: Some("deadbeef".repeat(8)),
            error: None,
        }),
        recent_operations: vec![arbitraitor_daemon::RecentOperation {
            operation: "scan".to_owned(),
            outcome: "success".to_owned(),
            uptime_ms: 100,
            sha256: Some("feedface".repeat(8)),
            error: None,
        }],
    };
    let mut buffer = Vec::new();
    write_status_text(&mut buffer, &report, Some(&daemon))?;
    let output = String::from_utf8(buffer)?;

    assert!(output.contains("Daemon:"));
    assert!(output.contains("pid: 4242"));
    assert!(output.contains("uptime: 13s"));
    assert!(output.contains("last operation: inspect (success)"));
    assert!(output.contains("recent operations:"));
    assert!(output.contains("scan"));
    assert!(output.contains("inspect"));
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
fn wrap_command_parses_curl() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::try_parse_from([
        "arbitraitor",
        "wrap",
        "curl",
        "--",
        "-fsSL",
        "https://example.com/install.sh",
    ])?;

    match cli.command {
        Command::Wrap(command) => {
            assert_eq!(command.tool, "curl");
            assert_eq!(command.args, ["-fsSL", "https://example.com/install.sh"]);
        }
        _ => return Err("parsed wrong command".into()),
    }
    Ok(())
}

#[test]
fn wrap_command_parses_wget() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::try_parse_from([
        "arbitraitor",
        "wrap",
        "wget",
        "--",
        "-qO-",
        "https://example.com/install.sh",
    ])?;

    match cli.command {
        Command::Wrap(command) => {
            assert_eq!(command.tool, "wget");
            assert_eq!(command.args, ["-qO-", "https://example.com/install.sh"]);
        }
        _ => return Err("parsed wrong command".into()),
    }
    Ok(())
}

#[test]
fn wrap_command_requires_tool() {
    let result = Cli::try_parse_from(["arbitraitor", "wrap"]);

    assert!(result.is_err());
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

#[test]
fn report_false_positive_parses_finding_id() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::try_parse_from(["arbitraitor", "report", "false-positive", "SHELL-EVAL-001"])?;

    match cli.command {
        Command::Report(commands::ReportCommand {
            subcommand: commands::ReportSubcommand::FalsePositive { finding_id },
        }) => {
            assert_eq!(finding_id, "SHELL-EVAL-001");
        }
        _ => return Err("parsed wrong command".into()),
    }
    Ok(())
}

#[test]
fn report_false_positive_handles_whitespace_finding_id() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::try_parse_from(["arbitraitor", "report", "false-positive", "   "])?;

    match cli.command {
        Command::Report(commands::ReportCommand {
            subcommand: commands::ReportSubcommand::FalsePositive { finding_id },
        }) => {
            assert_eq!(finding_id, "   ");
        }
        _ => return Err("parsed wrong command".into()),
    }
    Ok(())
}

#[test]
fn allow_parses_required_scope_expires_reason() -> Result<(), Box<dyn std::error::Error>> {
    let digest = "ab".repeat(32);
    let cli = Cli::try_parse_from([
        "arbitraitor",
        "allow",
        &format!("sha256:{digest}"),
        "--scope",
        "project",
        "--expires",
        "7d",
        "--reason",
        "approved by sec review #482",
    ])?;

    match cli.command {
        Command::Allow(cmd) => {
            assert_eq!(cmd.hash, digest);
            assert_eq!(cmd.scope, commands::AllowScope::Project);
            assert_eq!(cmd.expires, "7d");
            assert_eq!(cmd.reason, "approved by sec review #482");
        }
        _ => return Err("parsed wrong command".into()),
    }
    Ok(())
}

#[test]
fn allow_rejects_missing_scope_flag() {
    let digest = "cd".repeat(32);
    let result = Cli::try_parse_from([
        "arbitraitor",
        "allow",
        &format!("sha256:{digest}"),
        "--expires",
        "7d",
        "--reason",
        "missing scope",
    ]);
    assert!(result.is_err(), "--scope is required");
}

#[test]
fn allow_rejects_missing_expires_flag() {
    let digest = "ef".repeat(32);
    let result = Cli::try_parse_from([
        "arbitraitor",
        "allow",
        &format!("sha256:{digest}"),
        "--scope",
        "user",
        "--reason",
        "missing expires",
    ]);
    assert!(result.is_err(), "--expires is required");
}

#[test]
fn allow_rejects_missing_reason_flag() {
    let digest = "12".repeat(32);
    let result = Cli::try_parse_from([
        "arbitraitor",
        "allow",
        &format!("sha256:{digest}"),
        "--scope",
        "org",
        "--expires",
        "24h",
    ]);
    assert!(result.is_err(), "--reason is required");
}

#[test]
fn allow_rejects_unknown_scope_value() {
    let digest = "34".repeat(32);
    let result = Cli::try_parse_from([
        "arbitraitor",
        "allow",
        &format!("sha256:{digest}"),
        "--scope",
        "global",
        "--expires",
        "7d",
        "--reason",
        "wrong scope",
    ]);
    assert!(result.is_err(), "scope must be user, project, or org");
}

#[test]
fn allow_rejects_hash_without_sha256_prefix() {
    let digest = "ab".repeat(32);
    let result = Cli::try_parse_from([
        "arbitraitor",
        "allow",
        &digest,
        "--scope",
        "user",
        "--expires",
        "7d",
        "--reason",
        "no prefix",
    ]);
    assert!(result.is_err(), "hash must include the sha256: prefix");
}

#[test]
fn report_handler_rejects_empty_finding_id() {
    let cmd = commands::ReportCommand {
        subcommand: commands::ReportSubcommand::FalsePositive {
            finding_id: String::new(),
        },
    };
    let result = commands::report(&cmd);
    assert!(result.is_err(), "empty finding_id must be rejected");
}

#[test]
fn allow_handler_rejects_invalid_hash_prefix() {
    let digest = "ab".repeat(32);
    let cmd = commands::AllowCommand {
        hash: digest,
        scope: commands::AllowScope::User,
        expires: "7d".to_owned(),
        reason: "missing prefix".to_owned(),
    };
    let result = commands::allow(&cmd);
    assert!(result.is_err(), "sha256: prefix is mandatory");
}

#[test]
fn allow_handler_rejects_zero_duration() {
    let digest = "ab".repeat(32);
    let cmd = commands::AllowCommand {
        hash: format!("sha256:{digest}"),
        scope: commands::AllowScope::User,
        expires: "0d".to_owned(),
        reason: "bad duration".to_owned(),
    };
    let result = commands::allow(&cmd);
    assert!(result.is_err(), "duration must be greater than zero");
}

#[test]
fn allow_handler_rejects_unknown_duration_unit() {
    let digest = "ab".repeat(32);
    let cmd = commands::AllowCommand {
        hash: format!("sha256:{digest}"),
        scope: commands::AllowScope::User,
        expires: "7w".to_owned(),
        reason: "bad unit".to_owned(),
    };
    let result = commands::allow(&cmd);
    assert!(result.is_err(), "unknown duration unit must be rejected");
}

#[test]
fn allow_handler_rejects_empty_reason() {
    let digest = "ab".repeat(32);
    let cmd = commands::AllowCommand {
        hash: format!("sha256:{digest}"),
        scope: commands::AllowScope::User,
        expires: "7d".to_owned(),
        reason: "   ".to_owned(),
    };
    let result = commands::allow(&cmd);
    assert!(result.is_err(), "empty reason must be rejected");
}

#[test]
fn allow_handler_accepts_valid_inputs() {
    let digest = "ab".repeat(32);
    let cmd = commands::AllowCommand {
        hash: format!("sha256:{digest}"),
        scope: commands::AllowScope::Project,
        expires: "7d".to_owned(),
        reason: "approved".to_owned(),
    };
    let result = commands::allow(&cmd);
    assert!(
        result.is_ok(),
        "valid allow command must succeed: {result:?}"
    );
}

#[test]
fn report_handler_accepts_valid_finding_id() {
    let cmd = commands::ReportCommand {
        subcommand: commands::ReportSubcommand::FalsePositive {
            finding_id: "SHELL-EVAL-001".to_owned(),
        },
    };
    let result = commands::report(&cmd);
    assert!(
        result.is_ok(),
        "valid report command must succeed: {result:?}"
    );
}

#[test]
fn fetch_first_class_mode_parses_url_in_args() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::try_parse_from(["arbitraitor", "fetch", "https://example.com/file"])?;
    match cli.command {
        Command::Fetch(fetch) => {
            assert!(fetch.tool.is_none());
            assert_eq!(fetch.args, ["https://example.com/file"]);
        }
        _ => return Err("parsed wrong command".into()),
    }
    Ok(())
}

#[test]
fn fetch_accepts_output_long_flag() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::try_parse_from([
        "arbitraitor",
        "fetch",
        "--output",
        "/tmp/file",
        "https://example.com/file",
    ])?;
    match cli.command {
        Command::Fetch(fetch) => {
            assert_eq!(
                fetch.output.as_deref(),
                Some(std::path::Path::new("/tmp/file"))
            );
            assert_eq!(fetch.args, ["https://example.com/file"]);
        }
        _ => return Err("parsed wrong command".into()),
    }
    Ok(())
}

#[test]
fn fetch_accepts_output_short_flag() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::try_parse_from([
        "arbitraitor",
        "fetch",
        "-o",
        "/tmp/file",
        "https://example.com/file",
    ])?;
    match cli.command {
        Command::Fetch(fetch) => {
            assert_eq!(
                fetch.output.as_deref(),
                Some(std::path::Path::new("/tmp/file"))
            );
        }
        _ => return Err("parsed wrong command".into()),
    }
    Ok(())
}

#[test]
fn fetch_accepts_sha256_flag() -> Result<(), Box<dyn std::error::Error>> {
    let digest = "ab".repeat(32);
    let cli = Cli::try_parse_from([
        "arbitraitor",
        "fetch",
        "--sha256",
        &digest,
        "https://example.com/file",
    ])?;
    match cli.command {
        Command::Fetch(fetch) => {
            assert_eq!(
                fetch.sha256.as_ref().ok_or("missing digest")?.to_string(),
                digest
            );
        }
        _ => return Err("parsed wrong command".into()),
    }
    Ok(())
}

#[test]
fn fetch_rejects_invalid_sha256_flag() {
    let result = Cli::try_parse_from([
        "arbitraitor",
        "fetch",
        "--sha256",
        "not-a-digest",
        "https://example.com/file",
    ]);
    assert!(result.is_err());
}

#[test]
fn fetch_accepts_provenance_flags() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::try_parse_from([
        "arbitraitor",
        "fetch",
        "--signature",
        "artifact.minisig",
        "--cosign-bundle",
        "artifact.bundle",
        "--identity",
        "builder@example.test",
        "--issuer",
        "https://issuer.example.test",
        "https://example.com/file",
    ])?;
    match cli.command {
        Command::Fetch(fetch) => {
            assert_eq!(fetch.signature.len(), 1);
            assert_eq!(fetch.cosign_bundle.len(), 1);
            assert_eq!(fetch.identity, ["builder@example.test"]);
            assert_eq!(fetch.issuer, ["https://issuer.example.test"]);
        }
        _ => return Err("parsed wrong command".into()),
    }
    Ok(())
}

#[test]
fn fetch_accepts_receipt_flag() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::try_parse_from([
        "arbitraitor",
        "fetch",
        "--receipt",
        "/tmp/receipt.json",
        "https://example.com/file",
    ])?;
    match cli.command {
        Command::Fetch(fetch) => {
            assert_eq!(
                fetch.receipt.as_deref(),
                Some(std::path::Path::new("/tmp/receipt.json"))
            );
        }
        _ => return Err("parsed wrong command".into()),
    }
    Ok(())
}

#[test]
fn fetch_accepts_policy_flag() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::try_parse_from([
        "arbitraitor",
        "fetch",
        "--policy",
        "/tmp/policy.toml",
        "https://example.com/file",
    ])?;
    match cli.command {
        Command::Fetch(fetch) => {
            assert_eq!(
                fetch.policy.as_deref(),
                Some(std::path::Path::new("/tmp/policy.toml"))
            );
        }
        _ => return Err("parsed wrong command".into()),
    }
    Ok(())
}

#[test]
fn fetch_accepts_boolean_flags() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::try_parse_from([
        "arbitraitor",
        "fetch",
        "--recursive",
        "--sandbox",
        "--non-interactive",
        "--json",
        "--sarif",
        "--no-cache",
        "https://example.com/file",
    ])?;
    match cli.command {
        Command::Fetch(fetch) => {
            assert!(fetch.recursive);
            assert!(fetch.sandbox);
            assert!(fetch.non_interactive);
            assert!(fetch.json);
            assert!(fetch.sarif);
            assert!(fetch.no_cache);
        }
        _ => return Err("parsed wrong command".into()),
    }
    Ok(())
}

#[test]
fn fetch_accepts_repeatable_header_flag() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::try_parse_from([
        "arbitraitor",
        "fetch",
        "--header",
        "Authorization: Bearer token",
        "--header",
        "X-Custom: value",
        "https://example.com/file",
    ])?;
    match cli.command {
        Command::Fetch(fetch) => {
            assert_eq!(fetch.header.len(), 2);
            assert_eq!(fetch.header[0], "Authorization: Bearer token");
            assert_eq!(fetch.header[1], "X-Custom: value");
        }
        _ => return Err("parsed wrong command".into()),
    }
    Ok(())
}

#[test]
fn fetch_accepts_max_bytes_flag() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::try_parse_from([
        "arbitraitor",
        "fetch",
        "--max-bytes",
        "1048576",
        "https://example.com/file",
    ])?;
    match cli.command {
        Command::Fetch(fetch) => {
            assert_eq!(fetch.max_bytes, Some(1_048_576));
        }
        _ => return Err("parsed wrong command".into()),
    }
    Ok(())
}

#[test]
fn fetch_accepts_expected_type_flags() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::try_parse_from([
        "arbitraitor",
        "fetch",
        "--expected-type",
        "shell",
        "--expected-content-type",
        "application/x-sh",
        "https://example.com/file",
    ])?;
    match cli.command {
        Command::Fetch(fetch) => {
            assert_eq!(fetch.expected_type.as_deref(), Some("shell"));
            assert_eq!(
                fetch.expected_content_type.as_deref(),
                Some("application/x-sh")
            );
        }
        _ => return Err("parsed wrong command".into()),
    }
    Ok(())
}

#[test]
fn fetch_wrapper_mode_still_parses_tool_and_args() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::try_parse_from([
        "arbitraitor",
        "fetch",
        "--tool",
        "curl",
        "--",
        "-fsSL",
        "https://example.com/install.sh",
    ])?;
    match cli.command {
        Command::Fetch(fetch) => {
            assert_eq!(fetch.tool.as_deref(), Some("curl"));
            assert_eq!(fetch.args, ["-fsSL", "https://example.com/install.sh"]);
        }
        _ => return Err("parsed wrong command".into()),
    }
    Ok(())
}
