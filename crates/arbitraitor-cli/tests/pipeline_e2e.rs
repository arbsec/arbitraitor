//! Pipeline end-to-end tests — Tier 3 per spec §43.8.
//!
//! Full pipeline tests using wiremock HTTP backends and the in-process
//! analysis coordinator. Verifies the complete flow: fetch → analyze →
//! evaluate → receipt, without requiring Docker.
//!
//! Uses `arbitraitor-testkit::mock_server` for disposable HTTP origins
//! that serve synthetic shell script fixtures from the corpus.

use arbitraitor_analysis::AnalysisCoordinator;
use arbitraitor_model::verdict::Verdict;
use arbitraitor_testkit::fixtures;
use arbitraitor_testkit::mock_server::MockHttpServer;
use reqwest::Client;
use sha2::Digest;

type TestResult = Result<(), Box<dyn std::error::Error>>;

async fn fetch_url(url: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let client = Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()?;
    let response = client.get(url).send().await?;
    if !response.status().is_success() {
        return Err(format!("HTTP {}: {}", response.status(), url).into());
    }
    Ok(response.bytes().await?.to_vec())
}

#[tokio::test]
async fn pipeline_clean_script_passes() -> TestResult {
    let server = MockHttpServer::start().await;
    let url = server
        .binary_response(&fixtures::benign_shell_script(), "text/x-shellscript")
        .await;

    let bytes = fetch_url(&url).await?;
    let result = AnalysisCoordinator::new().analyze(&bytes);

    assert_eq!(result.verdict, Verdict::Pass);
    assert!(
        result.findings.is_empty(),
        "clean script should have no findings"
    );
    Ok(())
}

#[tokio::test]
async fn pipeline_malicious_script_blocks() -> TestResult {
    let server = MockHttpServer::start().await;
    let url = server
        .binary_response(&fixtures::malicious_shell_script(), "text/x-shellscript")
        .await;

    let bytes = fetch_url(&url).await?;
    let result = AnalysisCoordinator::new().analyze(&bytes);

    assert_eq!(result.verdict, Verdict::Block);
    assert!(
        !result.findings.is_empty(),
        "malicious script should produce findings"
    );
    Ok(())
}

#[tokio::test]
async fn pipeline_sha256_is_deterministic() -> TestResult {
    let server = MockHttpServer::start().await;
    let url = server
        .binary_response(&fixtures::benign_shell_script(), "text/x-shellscript")
        .await;

    let bytes1 = fetch_url(&url).await?;
    let bytes2 = fetch_url(&url).await?;

    let result1 = AnalysisCoordinator::new().analyze(&bytes1);
    let result2 = AnalysisCoordinator::new().analyze(&bytes2);

    assert_eq!(
        result1.verdict, result2.verdict,
        "same content should produce same verdict"
    );
    assert_eq!(
        result1.findings.len(),
        result2.findings.len(),
        "same content should produce same finding count"
    );

    let sha1 = sha2::Sha256::digest(&bytes1);
    let sha2_hash = sha2::Sha256::digest(&bytes2);
    assert_eq!(sha1, sha2_hash, "content hash should match");
    Ok(())
}

#[tokio::test]
async fn pipeline_empty_response_handled() -> TestResult {
    let server = MockHttpServer::start().await;
    let url = server
        .binary_response(b"", "application/octet-stream")
        .await;

    let bytes = fetch_url(&url).await?;
    let result = AnalysisCoordinator::new().analyze(&bytes);

    assert_ne!(
        result.verdict,
        Verdict::Block,
        "empty file should not block"
    );
    Ok(())
}

#[tokio::test]
async fn pipeline_binary_file_classification() -> TestResult {
    let server = MockHttpServer::start().await;
    let elf = fixtures::elf_binary();
    let url = server
        .binary_response(&elf, "application/octet-stream")
        .await;

    let bytes = fetch_url(&url).await?;
    let result = AnalysisCoordinator::new().analyze(&bytes);

    assert!(
        format!("{:?}", result.classification.artifact_type).contains("Elf"),
        "ELF binary should be classified as ELF, got {:?}",
        result.classification.artifact_type
    );
    Ok(())
}
