//! Inspect pipeline orchestration for the CLI crate.
//!
//! This module keeps fetch, analysis, provenance verification, CAS storage, and
//! receipt assembly out of `main.rs` so the entry point can stay focused on
//! argument parsing, dispatch, and output formatting.

use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use arbitraitor_analysis::{
    AnalysisCoordinator, ArtifactDetector, RetrievalInfo as AnalysisRetrievalInfo, ShellDetector,
};
use arbitraitor_core::config::Config;
use arbitraitor_fetch::{
    FetchPolicy, FetchRequest, FetchSource, FetchUrl, Fetcher, FileFetcher, HttpFetcher, VecSink,
};
use arbitraitor_model::finding::FindingCategory;
use arbitraitor_model::ids::Sha256Digest;
use arbitraitor_model::verdict::{Confidence, Severity, Verdict};
use arbitraitor_provenance::{
    SignatureVerification, parse_minisign_public_key, verify_cosign, verify_minisign,
};
use arbitraitor_receipt::{
    DetectorVersion, FindingSummary, ReceiptBuilder, ReceiptTimestamps,
    RetrievalInfo as ReceiptRetrievalInfo, VerdictInfo,
};
use arbitraitor_store::ContentStore;
use arbitraitor_yarax::{RulePackManager, RuleSource, YaraDetector};
use miette::{IntoDiagnostic, Result};
use sha2::{Digest, Sha256};

/// Signature verification inputs collected from CLI arguments.
#[derive(Debug, Default)]
pub(crate) struct SignatureInputs {
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

/// Result data the CLI needs after inspect orchestration completes.
#[allow(clippy::too_many_arguments)]
pub(crate) struct InspectOutcome {
    /// Final policy verdict derived from analysis findings.
    pub(crate) verdict: Verdict,
    /// Exact bytes fetched, stored, and analyzed.
    pub(crate) bytes: Vec<u8>,
    /// SHA-256 digest for the fetched artifact bytes.
    pub(crate) sha256: Sha256Digest,
}

/// Fetch, store, analyze, verify provenance, and optionally emit a receipt.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn inspect(
    url: &str,
    receipt_path: Option<&Path>,
    cas_dir: Option<&Path>,
    expected_sha256: Option<Sha256Digest>,
    rules_dir: Option<&Path>,
    signatures: SignatureInputs,
    config: &Config,
    explain_format: Option<crate::ExplainFormat>,
) -> Result<InspectOutcome> {
    let fetch_policy = FetchPolicy {
        total_timeout: Duration::from_secs(config.fetch.total_timeout_secs),
        max_compressed_size: config.fetch.max_bytes,
        max_uncompressed_size: config.fetch.max_bytes,
        max_redirects: usize::try_from(config.fetch.max_redirects).into_diagnostic()?,
        require_digest: config.integrity.require_digest,
        allow_cross_origin_redirect: config.fetch.allow_cross_origin,
        forward_authorization_cross_origin: config.fetch.forward_authorization_cross_origin,
        ..FetchPolicy::default()
    };
    let source = parse_fetch_source(url)?;
    let request = FetchRequest {
        source,
        policy: fetch_policy,
        expected_sha256,
        cancellation: arbitraitor_fetch::FetchCancellation::new(),
        credentials: arbitraitor_fetch::RequestCredentials::default(),
    };
    let mut fetch_sink = VecSink::new();
    let fetch_receipt = match &request.source {
        FetchSource::File(_) => FileFetcher::new().fetch(request, &mut fetch_sink).await,
        FetchSource::Url(_) => HttpFetcher::new().fetch(request, &mut fetch_sink).await,
        FetchSource::Stdin => {
            miette::bail!(
                "stdin source is not supported by inspect; use 'arbitraitor scan --stdin'"
            );
        }
    }
    .into_diagnostic()?;
    let bytes = fetch_sink.into_bytes();
    let artifact_len = u64::try_from(bytes.len()).into_diagnostic()?;
    if artifact_len > config.store.max_bytes {
        miette::bail!(
            "artifact exceeds configured store limit: bytes={}, limit={}",
            artifact_len,
            config.store.max_bytes
        );
    }
    let artifact_sha256 = Sha256Digest::new(Sha256::digest(&bytes).into());
    if artifact_sha256 != fetch_receipt.sha256 {
        miette::bail!(
            "fetch digest mismatch: receipt={}, bytes={}",
            fetch_receipt.sha256,
            artifact_sha256
        );
    }

    let cas_root = cas_dir
        .map(Path::to_path_buf)
        .or_else(|| config.store.cas_dir.clone())
        .unwrap_or_else(default_cas_dir);
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
    crate::write_report(
        &mut std::io::stderr().lock(),
        &result,
        &artifact_sha256,
        &cas_root,
        &signature_verifications,
    )?;

    if let Some(format) = explain_format {
        crate::write_explainability(&result.findings, url, format)?;
    }

    if let Some(path) = receipt_path {
        let receipt = build_receipt(
            url,
            &fetch_receipt,
            &result,
            &artifact_sha256,
            bytes.len(),
            &rule_pack_versions,
            &signature_verifications,
        )?;
        let json = serde_json::to_vec_pretty(&receipt).into_diagnostic()?;
        std::fs::write(path, json).into_diagnostic()?;
    }

    Ok(InspectOutcome {
        verdict: result.verdict,
        bytes,
        sha256: artifact_sha256,
    })
}

/// Parse a CLI inspect source into a fetch source.
pub(crate) fn parse_fetch_source(input: &str) -> Result<FetchSource> {
    if input == "-" || input == "stdin://" {
        return Ok(FetchSource::Stdin);
    }
    if input.starts_with("http://") || input.starts_with("https://") {
        return Ok(FetchSource::Url(
            FetchUrl::parse(input).map_err(|e| miette::miette!("invalid URL: {e}"))?,
        ));
    }
    if input.starts_with("file://") {
        let parsed =
            FetchUrl::parse(input).map_err(|e| miette::miette!("invalid file:// URL: {e}"))?;
        let path = parsed
            .as_url()
            .to_file_path()
            .map_err(|()| miette::miette!("file:// URL does not resolve to a local path"))?;
        return Ok(FetchSource::File(path));
    }
    if let Some(colon) = input.find(':') {
        let scheme = &input[..colon];
        if !scheme.is_empty()
            && scheme
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '-' || c == '.')
        {
            miette::bail!(
                "unsupported URI scheme '{scheme}'; only http, https, and file are accepted"
            );
        }
    }
    Ok(FetchSource::File(PathBuf::from(input)))
}

/// Build the artifact analysis coordinator, including optional YARA rules.
pub(crate) fn analysis_coordinator(
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

/// Return the default content-addressed store directory.
pub(crate) fn default_cas_dir() -> PathBuf {
    PathBuf::from(".arbitraitor").join("cas")
}

/// Convert fetch receipt metadata to analysis retrieval metadata.
pub(crate) fn analysis_retrieval_info(
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

/// Build a receipt from fetch, analysis, detector, and signature data.
pub(crate) fn build_receipt(
    requested_url: &str,
    fetch_receipt: &arbitraitor_fetch::FetchReceipt,
    result: &arbitraitor_analysis::AnalysisResult,
    artifact_sha256: &Sha256Digest,
    artifact_size: usize,
    rule_pack_versions: &[DetectorVersion],
    signature_verifications: &[SignatureVerification],
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

/// Convert CLI signature argument vectors into typed signature inputs.
pub(crate) fn signature_inputs(
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

/// Verify all requested minisign and cosign signatures for artifact bytes.
pub(crate) fn verify_signatures(
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

/// Convert a signature verification into a receipt finding summary.
pub(crate) fn signature_finding(
    index: usize,
    verification: &SignatureVerification,
) -> FindingSummary {
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
        evidence: None,
        remediation: None,
        references: Vec::new(),
        taxonomies: Vec::new(),
    }
}

/// Generate a human-readable receipt title for a signature verification.
pub(crate) fn signature_title(verification: &SignatureVerification) -> String {
    let system = verification.system.as_str();
    match verification.identity.as_deref() {
        Some(identity) => format!("{system} signature verified for {identity}"),
        None => format!("{system} signature verified"),
    }
}

/// Convert fetch receipt metadata to receipt retrieval metadata.
pub(crate) fn receipt_retrieval_info(
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
        .with_byte_count(fetch_receipt.bytes_written)
        .with_redirect_credential_secrecy(fetch_receipt.metadata.redirect_credential_secrecy);
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

/// Return the current timestamp in the existing receipt timestamp format.
pub(crate) fn timestamp() -> String {
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
