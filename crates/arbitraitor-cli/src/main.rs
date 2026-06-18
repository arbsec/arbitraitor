//! Arbitraitor CLI entry point.

#![forbid(unsafe_code)]

use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use arbitraitor_analysis::{AnalysisCoordinator, RetrievalInfo as AnalysisRetrievalInfo};
use arbitraitor_fetch::{FetchPolicy, FetchRequest, FetchUrl, Fetcher, HttpFetcher, VecSink};
use arbitraitor_model::ids::Sha256Digest;
use arbitraitor_receipt::{
    DetectorVersion, FindingSummary, ReceiptBuilder, ReceiptTimestamps,
    RetrievalInfo as ReceiptRetrievalInfo, VerdictInfo,
};
use arbitraitor_store::ContentStore;
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
    },
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
        } => inspect(&url, receipt.as_deref(), cas_dir.as_deref(), sha256).await?,
    }

    Ok(())
}

async fn inspect(
    url: &str,
    receipt_path: Option<&Path>,
    cas_dir: Option<&Path>,
    expected_sha256: Option<Sha256Digest>,
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

    let analysis_retrieval = analysis_retrieval_info(url, &fetch_receipt);
    let result =
        AnalysisCoordinator::new().analyze_with_retrieval(&bytes, Some(analysis_retrieval));
    write_report(
        &mut std::io::stderr().lock(),
        &result,
        &artifact_sha256,
        &cas_root,
    )?;

    if let Some(path) = receipt_path {
        let receipt = build_receipt(url, &fetch_receipt, &result, &artifact_sha256, bytes.len())?;
        let json = serde_json::to_vec_pretty(&receipt).into_diagnostic()?;
        std::fs::write(path, json).into_diagnostic()?;
    }

    Ok(())
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
    .findings(result.findings.iter().map(FindingSummary::from));

    for detector_result in &result.detector_results {
        builder = builder.detector_version(DetectorVersion {
            id: detector_result.metadata.id.clone(),
            version: detector_result.metadata.version.clone(),
        });
    }

    Ok(builder.build())
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
}
