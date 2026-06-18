//! Arbitraitor CLI entry point.

#![forbid(unsafe_code)]

use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use arbitraitor_analysis::{
    AnalysisCoordinator, ArtifactDetector, RetrievalInfo as AnalysisRetrievalInfo, ShellDetector,
};
use arbitraitor_fetch::{FetchPolicy, FetchRequest, FetchUrl, Fetcher, HttpFetcher, VecSink};
use arbitraitor_model::finding::FindingCategory;
use arbitraitor_model::ids::Sha256Digest;
use arbitraitor_model::verdict::{Confidence, Severity};
use arbitraitor_provenance::{
    SignatureSystem, SignatureVerification, parse_minisign_public_key, verify_cosign,
    verify_minisign,
};
use arbitraitor_receipt::{
    DetectorVersion, FindingSummary, ReceiptBuilder, ReceiptTimestamps,
    RetrievalInfo as ReceiptRetrievalInfo, VerdictInfo,
};
use arbitraitor_store::ContentStore;
use arbitraitor_yarax::{RulePackManager, RuleSource, YaraDetector};
use clap::{Parser, Subcommand};
use miette::{IntoDiagnostic, Result};
use sha2::{Digest, Sha256};

/// Arbitraitor: Secure Download and Execution Gate
#[derive(Parser)]
#[command(name = "arbitraitor", version, about, long_about = None)]
struct Cli {
    /// Enable verbose output
    #[arg(short, long, action = clap::ArgAction::Count)]
    verbose: u8,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    Inspect {
        url: String,
        #[arg(long)]
        receipt: Option<PathBuf>,
        #[arg(long)]
        cas_dir: Option<PathBuf>,
        #[arg(long, value_name = "HEX")]
        sha256: Option<Sha256Digest>,
<<<<<<< HEAD
        #[arg(long, value_name = "DIR")]
        rules: Option<PathBuf>,
||||||| parent of 6818d20 (feat(provenance): minisign and cosign signature verification)
=======
        #[arg(long, value_name = "PATH")]
        minisign_sig: Vec<PathBuf>,
        #[arg(long, value_name = "KEY")]
        minisign_key: Vec<String>,
        #[arg(long, value_name = "PATH")]
        cosign_bundle: Vec<PathBuf>,
        #[arg(long, value_name = "IDENTITY")]
        cosign_identity: Vec<String>,
        #[arg(long, value_name = "ISSUER")]
        cosign_issuer: Vec<String>,
>>>>>>> 6818d20 (feat(provenance): minisign and cosign signature verification)
    },
}

#[derive(Debug, Default)]
struct SignatureInputs {
    minisign: Vec<MinisignInput>,
    cosign: Vec<CosignInput>,
}

#[derive(Debug)]
struct MinisignInput {
    signature_path: PathBuf,
    public_key: String,
}

#[derive(Debug)]
struct CosignInput {
    bundle_path: PathBuf,
    identity: String,
    issuer: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    let level = match cli.verbose {
        0 => "warn",
        1 => "info",
        2 => "debug",
        _ => "trace",
    };

    tracing_subscriber::fmt().with_env_filter(level).init();

    tracing::info!("arbitraitor initialized");

    match cli.command {
        Command::Inspect {
            url,
            receipt,
            cas_dir,
            sha256,
<<<<<<< HEAD
            rules,
        } => {
            inspect(
                &url,
                receipt.as_deref(),
                cas_dir.as_deref(),
                sha256,
                rules.as_deref(),
||||||| parent of 6818d20 (feat(provenance): minisign and cosign signature verification)
        } => inspect(&url, receipt.as_deref(), cas_dir.as_deref(), sha256).await?,
=======
            minisign_sig,
            minisign_key,
            cosign_bundle,
            cosign_identity,
            cosign_issuer,
        } => {
            let signatures = signature_inputs(
                minisign_sig,
                minisign_key,
                cosign_bundle,
                cosign_identity,
                cosign_issuer,
            )?;
            inspect(
                &url,
                receipt.as_deref(),
                cas_dir.as_deref(),
                sha256,
                signatures,
>>>>>>> 6818d20 (feat(provenance): minisign and cosign signature verification)
            )
            .await?;
        }
    }

    Ok(())
}

async fn inspect(
    url: &str,
    receipt_path: Option<&Path>,
    cas_dir: Option<&Path>,
    expected_sha256: Option<Sha256Digest>,
<<<<<<< HEAD
    rules_dir: Option<&Path>,
||||||| parent of 6818d20 (feat(provenance): minisign and cosign signature verification)
=======
    signatures: SignatureInputs,
>>>>>>> 6818d20 (feat(provenance): minisign and cosign signature verification)
) -> Result<()> {
    let fetch_url = FetchUrl::parse(url).into_diagnostic()?;
    let mut request = FetchRequest::url(fetch_url, FetchPolicy::default());
    if let Some(digest) = expected_sha256 {
        request = request.with_expected_sha256(digest);
    }
    let mut fetch_sink = VecSink::new();
    let fetch_receipt = HttpFetcher::new()
        .fetch(request, &mut fetch_sink)
        .await
        .into_diagnostic()?;
    let bytes = fetch_sink.into_bytes();
    let artifact_sha256 = Sha256Digest::new(Sha256::digest(&bytes).into());
    if artifact_sha256 != fetch_receipt.sha256 {
        miette::bail!(
            "fetch digest mismatch: receipt={}, bytes={}",
            fetch_receipt.sha256,
            artifact_sha256
        );
    }

    let cas_root = cas_dir.map_or_else(default_cas_dir, Path::to_path_buf);
    let store = ContentStore::open(&cas_root).into_diagnostic()?;
    let mut store_sink = store.sink(Some(&artifact_sha256)).into_diagnostic()?;
    store_sink.write_chunk(&bytes).await.into_diagnostic()?;
    let stored_digest = store_sink.finish().await.into_diagnostic()?;
    if stored_digest != artifact_sha256 {
        miette::bail!(
            "CAS digest mismatch: stored={}, expected={}",
            stored_digest,
            artifact_sha256
        );
    }

    let signature_verifications = verify_signatures(&bytes, &signatures)?;

    let analysis_retrieval = analysis_retrieval_info(url, &fetch_receipt);
    let (coordinator, rule_pack_versions) = analysis_coordinator(rules_dir)?;
    let result = coordinator.analyze_with_retrieval(&bytes, Some(analysis_retrieval));
    write_report(
        &mut std::io::stderr().lock(),
        &result,
        &artifact_sha256,
        &cas_root,
        &signature_verifications,
    )?;

    if let Some(path) = receipt_path {
        let receipt = build_receipt(
            url,
            &fetch_receipt,
            &result,
            &artifact_sha256,
            bytes.len(),
<<<<<<< HEAD
            &rule_pack_versions,
||||||| parent of 6818d20 (feat(provenance): minisign and cosign signature verification)
        let receipt = build_receipt(url, &fetch_receipt, &result, &artifact_sha256, bytes.len())?;
=======
            &signature_verifications,
>>>>>>> 6818d20 (feat(provenance): minisign and cosign signature verification)
        )?;
        let json = serde_json::to_vec_pretty(&receipt).into_diagnostic()?;
        std::fs::write(path, json).into_diagnostic()?;
    }

    Ok(())
}

fn analysis_coordinator(
    rules_dir: Option<&Path>,
) -> Result<(AnalysisCoordinator, Vec<DetectorVersion>)> {
    let Some(rules_dir) = rules_dir else {
        return Ok((AnalysisCoordinator::new(), Vec::new()));
    };

    let mut manager = RulePackManager::with_built_in().into_diagnostic()?;
    manager
        .load_directory(rules_dir, RuleSource::FileSystem(rules_dir.to_path_buf()))
        .into_diagnostic()?;
    let rule_pack_versions = manager.pack_versions();
    let scanner = manager.compile_all().into_diagnostic()?;
    let detector = YaraDetector::from_scanner(&scanner).into_diagnostic()?;
    Ok((
        AnalysisCoordinator::with_detectors(vec![
            Box::new(ArtifactDetector),
            Box::new(ShellDetector),
            Box::new(detector),
        ]),
        rule_pack_versions,
    ))
}

fn default_cas_dir() -> PathBuf {
    PathBuf::from(".arbitraitor").join("cas")
}

fn analysis_retrieval_info(
    requested_url: &str,
    fetch_receipt: &arbitraitor_fetch::FetchReceipt,
) -> AnalysisRetrievalInfo {
    AnalysisRetrievalInfo {
        requested_location: Some(arbitraitor_fetch::redact_url(requested_url)),
        final_location: fetch_receipt
            .metadata
            .final_url
            .as_ref()
            .map(ToString::to_string)
            .map(|url| arbitraitor_fetch::redact_url(&url)),
        content_type: fetch_receipt.metadata.content_type.clone(),
        byte_count: Some(fetch_receipt.bytes_written),
    }
}

fn write_report(
    writer: &mut impl std::io::Write,
    result: &arbitraitor_analysis::AnalysisResult,
    digest: &Sha256Digest,
    cas_root: &Path,
    signature_verifications: &[SignatureVerification],
) -> Result<()> {
    writeln!(writer, "artifact_sha256: {digest}").into_diagnostic()?;
    writeln!(writer, "cas_dir: {}", cas_root.display()).into_diagnostic()?;
    writeln!(
        writer,
        "artifact_type: {:?}",
        result.classification.artifact_type
    )
    .into_diagnostic()?;
    writeln!(writer, "verdict: {:?}", result.verdict).into_diagnostic()?;
    writeln!(
        writer,
        "signatures_verified: {}",
        signature_verifications.len()
    )
    .into_diagnostic()?;
    for verification in signature_verifications {
        writeln!(
            writer,
            "- signature: {} identity={}",
            verification.system.as_str(),
            verification.identity.as_deref().unwrap_or("<none>")
        )
        .into_diagnostic()?;
    }
    writeln!(writer, "findings: {}", result.findings.len()).into_diagnostic()?;
    for finding in &result.findings {
        writeln!(
            writer,
            "- [{} {:?}/{:?}] {}",
            finding.id, finding.severity, finding.confidence, finding.title
        )
        .into_diagnostic()?;
    }
    Ok(())
}

fn build_receipt(
    requested_url: &str,
    fetch_receipt: &arbitraitor_fetch::FetchReceipt,
    result: &arbitraitor_analysis::AnalysisResult,
    artifact_sha256: &Sha256Digest,
    artifact_size: usize,
<<<<<<< HEAD
    rule_pack_versions: &[DetectorVersion],
||||||| parent of 6818d20 (feat(provenance): minisign and cosign signature verification)
=======
    signature_verifications: &[SignatureVerification],
>>>>>>> 6818d20 (feat(provenance): minisign and cosign signature verification)
) -> Result<arbitraitor_receipt::Receipt> {
    let artifact_size = u64::try_from(artifact_size).into_diagnostic()?;
    let now = timestamp();
    let mut builder = ReceiptBuilder::new(
        env!("CARGO_PKG_VERSION"),
        artifact_sha256.to_string(),
        artifact_size,
        VerdictInfo {
            verdict: result.verdict,
            deciding_rule: None,
            policy_trace: vec!["arbitraitor-analysis built-in verdict derivation".to_owned()],
        },
        ReceiptTimestamps {
            created: now.clone(),
            modified: now,
        },
    )
    .artifact_type(format!("{:?}", result.classification.artifact_type))
    .retrieval(receipt_retrieval_info(requested_url, fetch_receipt))
    .findings(result.findings.iter().map(FindingSummary::from))
    .findings(
        signature_verifications
            .iter()
            .enumerate()
            .map(|(index, verification)| signature_finding(index, verification)),
    );

    for detector_result in &result.detector_results {
        builder = builder.detector_version(DetectorVersion {
            id: detector_result.metadata.id.clone(),
            version: detector_result.metadata.version.clone(),
        });
    }
    for rule_pack_version in rule_pack_versions {
        builder = builder.detector_version(rule_pack_version.clone());
    }

    Ok(builder.build())
}

fn signature_inputs(
    minisign_sig: Vec<PathBuf>,
    minisign_key: Vec<String>,
    cosign_bundle: Vec<PathBuf>,
    cosign_identity: Vec<String>,
    cosign_issuer: Vec<String>,
) -> Result<SignatureInputs> {
    if minisign_sig.len() != minisign_key.len() {
        miette::bail!("each --minisign-sig requires exactly one --minisign-key");
    }
    if cosign_bundle.len() != cosign_identity.len() || cosign_bundle.len() != cosign_issuer.len() {
        miette::bail!(
            "each --cosign-bundle requires exactly one --cosign-identity and --cosign-issuer"
        );
    }

    Ok(SignatureInputs {
        minisign: minisign_sig
            .into_iter()
            .zip(minisign_key)
            .map(|(signature_path, public_key)| MinisignInput {
                signature_path,
                public_key,
            })
            .collect(),
        cosign: cosign_bundle
            .into_iter()
            .zip(cosign_identity)
            .zip(cosign_issuer)
            .map(|((bundle_path, identity), issuer)| CosignInput {
                bundle_path,
                identity,
                issuer,
            })
            .collect(),
    })
}

fn verify_signatures(
    artifact_bytes: &[u8],
    signatures: &SignatureInputs,
) -> Result<Vec<SignatureVerification>> {
    let mut verifications = Vec::with_capacity(signatures.minisign.len() + signatures.cosign.len());
    for minisign_input in &signatures.minisign {
        let signature = std::fs::read(&minisign_input.signature_path).into_diagnostic()?;
        let public_key = parse_minisign_public_key(&minisign_input.public_key).into_diagnostic()?;
        verifications
            .push(verify_minisign(artifact_bytes, &signature, &public_key).into_diagnostic()?);
    }
    for cosign_input in &signatures.cosign {
        verifications.push(
            verify_cosign(
                artifact_bytes,
                &cosign_input.bundle_path,
                &cosign_input.identity,
                &cosign_input.issuer,
            )
            .into_diagnostic()?,
        );
    }
    Ok(verifications)
}

fn signature_finding(index: usize, verification: &SignatureVerification) -> FindingSummary {
    FindingSummary {
        id: format!(
            "provenance.signature.{}.{}",
            verification.system.as_str(),
            index + 1
        ),
        category: FindingCategory::Provenance,
        severity: Severity::Informational,
        confidence: Confidence::Confirmed,
        title: signature_title(verification),
        location: None,
    }
}

fn signature_title(verification: &SignatureVerification) -> String {
    let system = match verification.system {
        SignatureSystem::Minisign => "minisign",
        SignatureSystem::Cosign => "cosign",
    };
    match verification.identity.as_deref() {
        Some(identity) => format!("{system} signature verified for {identity}"),
        None => format!("{system} signature verified"),
    }
}

fn receipt_retrieval_info(
    requested_url: &str,
    fetch_receipt: &arbitraitor_fetch::FetchReceipt,
) -> ReceiptRetrievalInfo {
    let mut retrieval = ReceiptRetrievalInfo::new(requested_url)
        .with_redirect_chain(
            fetch_receipt
                .metadata
                .redirect_chain
                .iter()
                .map(ToString::to_string),
        )
        .with_byte_count(fetch_receipt.bytes_written);
    if let Some(final_url) = &fetch_receipt.metadata.final_url {
        retrieval = retrieval.with_final_url(final_url.to_string());
    }
    if let Some(content_type) = &fetch_receipt.metadata.content_type {
        retrieval = retrieval.with_content_type(content_type.clone());
    }
    if let Some(tls_version) = &fetch_receipt.metadata.tls_version {
        retrieval = retrieval.with_tls_version(tls_version.clone());
    }
    if let Some(fingerprint) = &fetch_receipt.metadata.peer_certificate_fingerprint {
        retrieval = retrieval.with_peer_cert_fingerprint(format!("sha256:{fingerprint}"));
    }
    retrieval
}

fn timestamp() -> String {
    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(duration) => format!(
            "unix:{}.{:09}Z",
            duration.as_secs(),
            duration.subsec_nanos()
        ),
        Err(error) => format!(
            "unix:-{}.{:09}Z",
            error.duration().as_secs(),
            error.duration().subsec_nanos()
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::{Cli, Command};
    use clap::Parser;

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

        let Command::Inspect { sha256, .. } = cli.command;
        assert_eq!(sha256.ok_or("missing parsed digest")?.to_string(), digest);
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
<<<<<<< HEAD
    fn inspect_accepts_rules_directory_flag() -> Result<(), Box<dyn std::error::Error>> {
        let cli = Cli::try_parse_from([
            "arbitraitor",
            "inspect",
            "https://example.test/artifact",
            "--rules",
            "/tmp/rules",
        ])?;

        let Command::Inspect { rules, .. } = cli.command;
        assert_eq!(
            rules.ok_or("missing rules path")?,
            std::path::PathBuf::from("/tmp/rules")
        );
        Ok(())
||||||| parent of 6818d20 (feat(provenance): minisign and cosign signature verification)
=======
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

        let Command::Inspect {
            minisign_sig,
            minisign_key,
            cosign_bundle,
            cosign_identity,
            cosign_issuer,
            ..
        } = cli.command;
        assert_eq!(minisign_sig.len(), 1);
        assert_eq!(minisign_key, ["RWQexamplekeymaterial"]);
        assert_eq!(cosign_bundle.len(), 1);
        assert_eq!(cosign_identity, ["builder@example.test"]);
        assert_eq!(cosign_issuer, ["https://issuer.example.test"]);
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
>>>>>>> 6818d20 (feat(provenance): minisign and cosign signature verification)
    }
}
