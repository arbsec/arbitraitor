//! Thin inspection adapter over the pipeline engine (ADR-0038 decision 4).
//!
//! This module builds an [`arbitraitor_engine::ArbitraitorBuilder`] from CLI
//! arguments and the layered configuration, calls
//! [`arbitraitor_engine::ArbitraitorApi::inspect_pinned`], and formats the
//! result through the CLI's presentation helpers. No pipeline stage is
//! composed here: fetch, CAS storage, analysis, provenance verification,
//! policy evaluation, and receipt assembly all run inside the engine.
//!
//! The `scan` subcommand's local analysis wiring (`analysis_coordinator`)
//! remains CLI-side: it is not one of the three compositions ADR-0038
//! consolidated, and its stdin/recursive/filter semantics have no engine
//! equivalent yet.

use std::path::{Path, PathBuf};
use std::str::FromStr;

use arbitraitor_analysis::AnalysisCoordinator;
use arbitraitor_core::config::Config;
use arbitraitor_engine::{Arbitraitor, SignatureInputs};
use arbitraitor_fetch::FetchPolicy;
use arbitraitor_model::ids::Sha256Digest;
use arbitraitor_model::verdict::Verdict;
use arbitraitor_receipt::DetectorVersion;
use arbitraitor_yarax::{RulePackManager, RuleSource, YaraDetector};
use miette::{IntoDiagnostic, Result};

pub(crate) use arbitraitor_engine::{
    default_cas_dir, parse_fetch_source, receipt_timestamp as timestamp,
};

/// Result data the CLI needs after inspect orchestration completes.
pub(crate) struct InspectOutcome {
    /// Final policy verdict derived from analysis findings.
    pub(crate) verdict: Verdict,
    /// Exact bytes fetched, stored, and analyzed (read back from CAS).
    pub(crate) bytes: Vec<u8>,
    /// SHA-256 digest for the fetched artifact bytes.
    pub(crate) sha256: Sha256Digest,
}

/// Fetch, store, analyze, verify provenance, evaluate policy, and emit a
/// receipt through the pipeline engine.
///
/// `emit_human_report` controls the human-readable interception report on
/// stderr. Wrapper invocations (shim mode) pass `false` whenever stderr is
/// captured — piped agents merge stdout and stderr, so reports must not
/// interleave with released artifact streams.
#[allow(
    clippy::too_many_arguments,
    reason = "pipeline inputs mirror the CLI flag surface; grouping would hide the contract"
)]
pub(crate) async fn inspect(
    url: &str,
    receipt_path: Option<&Path>,
    cas_dir: Option<&Path>,
    expected_sha256: Option<Sha256Digest>,
    rules_dir: Option<&Path>,
    signatures: SignatureInputs,
    config: &Config,
    explain_format: Option<crate::ExplainFormat>,
    emit_human_report: bool,
) -> Result<InspectOutcome> {
    // Validate the source before opening the store so malformed URLs fail
    // fast with the parse error, exactly as the pre-engine pipeline did.
    if let Ok(arbitraitor_fetch::FetchSource::Stdin) = parse_fetch_source(url) {
        miette::bail!("stdin source is not supported by inspect; use 'arbitraitor scan --stdin'");
    }
    parse_fetch_source(url).into_diagnostic()?;
    let cas_root = cas_dir
        .map(Path::to_path_buf)
        .or_else(|| config.store.cas_dir.clone())
        .unwrap_or_else(default_cas_dir);
    let fetch_policy = FetchPolicy {
        total_timeout: std::time::Duration::from_secs(config.fetch.total_timeout_secs),
        max_compressed_size: config.fetch.max_bytes,
        max_uncompressed_size: config.fetch.max_bytes,
        max_redirects: usize::try_from(config.fetch.max_redirects).into_diagnostic()?,
        require_digest: config.integrity.require_digest,
        allow_cross_origin_redirect: config.fetch.allow_cross_origin,
        forward_authorization_cross_origin: config.fetch.forward_authorization_cross_origin,
        ..FetchPolicy::default()
    };
    // ADR-0038: the CLI now honors configured policy (closing the coverage
    // hole where `inspect` skipped policy evaluation entirely). With no
    // policy file and no inline rules, the engine's built-in verdict
    // derivation applies, preserving the CLI's default pass-through
    // behavior for clean artifacts.
    let policy_configured = config.policy.policy_file.is_some() || !config.policy.rules.is_empty();
    let mut builder = Arbitraitor::builder().config(arbitraitor_engine::Config {
        store_path: cas_root.clone(),
        receipts_path: receipts_sibling(&cas_root),
        fetch_policy,
        store_max_bytes: config.store.max_bytes,
        ..arbitraitor_engine::Config::default()
    });
    if policy_configured {
        builder = builder.policy(config.build_policy_engine().into_diagnostic()?);
    }
    if let Some(rules_dir) = rules_dir {
        builder = builder.yara_rules(rules_dir);
    }
    let api = builder.signatures(signatures).build().into_diagnostic()?;

    let result = api
        .inspect_pinned(url, expected_sha256)
        .await
        .into_diagnostic()?;

    if emit_human_report {
        crate::write_report(
            &mut std::io::stderr().lock(),
            &result.sha256,
            &cas_root,
            &result.artifact_type,
            result.verdict,
            &result.signature_verifications,
            &result.findings,
        )?;
    }

    if let Some(format) = explain_format {
        crate::write_explainability(&result.findings, url, format)?;
    }

    if let Some(path) = receipt_path {
        let json = result.receipt.to_vec_pretty().into_diagnostic()?;
        std::fs::write(path, json).into_diagnostic()?;
    }

    // Bytes stay CAS-addressed in the engine; the wrapper release path reads
    // them back and re-verifies the digest before any emission (invariant 2).
    let bytes = api.read_artifact(&result.sha256).into_diagnostic()?;
    let sha256 = Sha256Digest::from_str(&result.sha256).into_diagnostic()?;
    Ok(InspectOutcome {
        verdict: result.verdict,
        bytes,
        sha256,
    })
}

/// Returns the receipts directory sibling to a CAS root.
fn receipts_sibling(cas_root: &Path) -> PathBuf {
    cas_root.parent().map_or_else(
        || cas_root.join("receipts"),
        |parent| parent.join("receipts"),
    )
}

/// Build the artifact analysis coordinator, including optional YARA rules.
///
/// Used by the `scan` subcommand's local analysis wiring.
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
    // Preserve the 5 built-in MVP detectors alongside YARA.
    // The previous construction replaced built-ins with `[Artifact, Shell,
    // Yara]`, dropping ArchiveHazard, PythonJs, and UrlDiscovery — and
    // UrlDiscovery is mandatory for HTML/JSON per
    // MandatoryDetectorRegistry::mandatory_detectors, so configuring any
    // YARA rule pack silently blocked every HTML/JSON fetch with a
    // mandatory-coverage Critical finding.
    let mut detectors = AnalysisCoordinator::default_detectors();
    detectors.push(Box::new(detector));
    Ok((
        AnalysisCoordinator::with_detectors(detectors),
        rule_pack_versions,
    ))
}

/// Convert CLI signature argument vectors into typed engine signature inputs.
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
            .map(
                |(signature_path, public_key)| arbitraitor_engine::MinisignSignatureInput {
                    signature_path,
                    public_key,
                },
            )
            .collect(),
        cosign: cosign_bundle
            .into_iter()
            .zip(cosign_identity)
            .zip(cosign_issuer)
            .map(
                |((bundle_path, identity), issuer)| arbitraitor_engine::CosignBundleInput {
                    bundle_path,
                    identity,
                    issuer,
                },
            )
            .collect(),
    })
}
