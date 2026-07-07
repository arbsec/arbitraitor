//! Lifecycle script extraction from `package.json` (spec §39.14.3).
//!
//! Pure parser — no I/O, no subprocess. The advisory scanner feeds it raw
//! `package.json` bytes (root or registry-fetched) and receives the ordered
//! list of install-time lifecycle script entries.

#![forbid(unsafe_code)]

use std::collections::BTreeMap;

use serde::Deserialize;

/// Install-time lifecycle phases defined by npm. Only these execute during
/// `npm install`; `test`, `start`, `build`, etc. are user-invoked and are
/// NOT lifecycle scripts. Order matches npm's execution order.
///
/// Spec §39.14.3: `preinstall` → `install` → `postinstall` run on each
/// package during install; `prepare` runs after install on the root and on
/// packed packages; `prepublish` is deprecated but still executes in some
/// npm versions for backwards compatibility.
pub const LIFECYCLE_PHASES: &[&str] = &[
    "preinstall",
    "install",
    "postinstall",
    "prepare",
    "prepublish",
];

/// A single lifecycle script entry extracted from `package.json`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LifecycleScript {
    /// Phase name (one of [`LIFECYCLE_PHASES`]).
    pub phase: String,
    /// The shell command string npm would execute.
    pub command: String,
}

/// Errors produced while parsing lifecycle scripts.
#[derive(Debug, thiserror::Error)]
pub enum LifecycleParseError {
    /// The bytes were not valid JSON.
    #[error("failed to parse package.json: {0}")]
    Parse(#[from] serde_json::Error),
}

#[derive(Deserialize)]
struct RawPackageJson {
    #[serde(default)]
    scripts: BTreeMap<String, String>,
}

/// Parses lifecycle scripts from raw `package.json` bytes.
///
/// Returns scripts in canonical execution order (`preinstall`, `install`,
/// `postinstall`, `prepare`, `prepublish`). Non-lifecycle scripts (`test`,
/// `start`, `build`, ...) are ignored. Empty commands are skipped.
///
/// # Errors
///
/// Returns [`LifecycleParseError::Parse`] if `package_json` is not valid JSON.
pub fn parse_lifecycle_scripts(
    package_json: &[u8],
) -> Result<Vec<LifecycleScript>, LifecycleParseError> {
    let parsed: RawPackageJson = serde_json::from_slice(package_json)?;
    let mut result = Vec::new();
    for &phase in LIFECYCLE_PHASES {
        if let Some(command) = parsed.scripts.get(phase)
            && !command.is_empty()
        {
            result.push(LifecycleScript {
                phase: phase.to_owned(),
                command: command.clone(),
            });
        }
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    #[test]
    fn extracts_postinstall_and_preinstall_in_order() -> TestResult {
        let json = br#"{
            "name": "evil-pkg",
            "scripts": {
                "postinstall": "node postinstall.js",
                "preinstall": "echo hi",
                "test": "mocha"
            }
        }"#;
        let scripts = parse_lifecycle_scripts(json)?;
        assert_eq!(
            scripts,
            vec![
                LifecycleScript {
                    phase: "preinstall".to_owned(),
                    command: "echo hi".to_owned(),
                },
                LifecycleScript {
                    phase: "postinstall".to_owned(),
                    command: "node postinstall.js".to_owned(),
                },
            ]
        );
        Ok(())
    }

    #[test]
    fn ignores_non_lifecycle_scripts() -> TestResult {
        let json = br#"{
            "scripts": {
                "build": "tsc",
                "test": "mocha",
                "start": "node index.js",
                "dev": "nodemon"
            }
        }"#;
        let scripts = parse_lifecycle_scripts(json)?;
        assert!(scripts.is_empty(), "non-lifecycle scripts must be ignored");
        Ok(())
    }

    #[test]
    fn handles_package_without_scripts_field() -> TestResult {
        let json = br#"{"name": "bare", "version": "1.0.0"}"#;
        let scripts = parse_lifecycle_scripts(json)?;
        assert!(scripts.is_empty());
        Ok(())
    }

    #[test]
    fn skips_empty_lifecycle_commands() -> TestResult {
        let json = br#"{"scripts": {"postinstall": ""}}"#;
        let scripts = parse_lifecycle_scripts(json)?;
        assert!(scripts.is_empty(), "empty commands must be skipped");
        Ok(())
    }

    #[test]
    fn invalid_json_returns_parse_error() {
        let result = parse_lifecycle_scripts(b"not json {");
        assert!(matches!(result, Err(LifecycleParseError::Parse(_))));
    }

    #[test]
    fn includes_prepare_and_prepublish() -> TestResult {
        let json = br#"{
            "scripts": {
                "prepare": "husky install",
                "prepublish": "npm run build"
            }
        }"#;
        let scripts = parse_lifecycle_scripts(json)?;
        assert_eq!(scripts.len(), 2);
        assert_eq!(scripts[0].phase, "prepare");
        assert_eq!(scripts[1].phase, "prepublish");
        Ok(())
    }
}
