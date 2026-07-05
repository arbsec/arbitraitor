//! Regression tests for spec §8.2 threat-model adversaries added in v0.5.
//!
//! This file covers testable aspects of adversaries 17, 18, 20, and 21.
//! Adversaries 19 (mandatory scanning coverage) and 22 (privilege-helper
//! scope creep) lack the API surface to test and are tracked in #271.
//!
//! **Does NOT resolve #271** — this is partial coverage.

use arbitraitor_core::config::Config;
use arbitraitor_core::secret::SecretResolver;
use arbitraitor_exec::release::{ReleasePolicy, release_artifact};
use arbitraitor_fetch::redact_url;
use arbitraitor_model::ids::Sha256Digest;
use arbitraitor_store::ContentStore;

type TestResult = Result<(), Box<dyn std::error::Error>>;

/// Creates a test temp directory using the same pattern as the existing
/// release tests in `arbitraitor-exec/src/release.rs` to avoid macOS
/// `/var/folders/...` symlink resolution issues with `TempDir::new()`.
fn temp_dir() -> Result<std::path::PathBuf, Box<dyn std::error::Error>> {
    let dir = std::env::temp_dir().join(format!("arb-adversary-test-{}", std::process::id()));
    std::fs::remove_dir_all(&dir).ok();
    std::fs::create_dir_all(&dir)?;
    // Canonicalize to resolve symlinks (e.g. macOS /var -> /private/var)
    // so that release_artifact's O_NOFOLLOW path traversal succeeds.
    Ok(std::fs::canonicalize(dir)?)
}

async fn stored_digest(
    store: &ContentStore,
    bytes: &[u8],
) -> Result<Sha256Digest, Box<dyn std::error::Error>> {
    let mut sink = store.sink(None)?;
    for chunk in bytes.chunks(3) {
        sink.write_chunk(chunk).await?;
    }
    Ok(sink.finish().await?)
}

mod adversary_17_project_config {
    use arbitraitor_core::config::ConfigError;

    use super::*;

    fn write_project_config(
        project_dir: &std::path::Path,
        body: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let dir = project_dir.join(".arbitraitor");
        std::fs::create_dir_all(&dir)?;
        std::fs::write(dir.join("config.toml"), body)?;
        Ok(())
    }

    #[test]
    fn project_config_tightening_limit_accepted() -> TestResult {
        let root = temp_dir()?;
        let system = root.join("system.toml");
        std::fs::write(&system, "[fetch]\nmax_bytes = 1048576\n")?;

        let project = root.join("project");
        write_project_config(&project, "[fetch]\nmax_bytes = 524288\n")?;

        let config = Config::load_from_layers(Some(&system), None, &project)?;
        assert_eq!(config.fetch.max_bytes, 524_288);
        std::fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn project_config_enabling_integrity_accepted() -> TestResult {
        let root = temp_dir()?;
        let project = root.join("project");
        write_project_config(&project, "[integrity]\nrequire_digest = true\n")?;

        let config = Config::load_from_layers(None, None, &project)?;
        assert!(config.integrity.require_digest);
        std::fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn missing_project_config_preserves_system() -> TestResult {
        let root = temp_dir()?;
        let system = root.join("system.toml");
        std::fs::write(&system, "[fetch]\nmax_bytes = 5242880\n")?;
        let config = Config::load_from_layers(Some(&system), None, &root)?;
        assert_eq!(config.fetch.max_bytes, 5_242_880);
        std::fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn missing_project_config_uses_defaults() -> TestResult {
        let root = temp_dir()?;
        let config = Config::load_from_layers(None, None, &root)?;
        assert_eq!(config, Config::default());
        std::fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn project_config_raising_limit_rejected() -> TestResult {
        let root = temp_dir()?;
        let system = root.join("system.toml");
        std::fs::write(&system, "[fetch]\nmax_bytes = 524288\n")?;

        let project = root.join("project");
        write_project_config(&project, "[fetch]\nmax_bytes = 1048576\n")?;

        let result = Config::load_from_layers(Some(&system), None, &project);
        assert!(
            matches!(result, Err(ConfigError::PolicyWeakening { .. })),
            "project config must not raise fetch.max_bytes (ADR-0017)"
        );
        std::fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn project_config_enabling_execution_rejected() -> TestResult {
        let root = temp_dir()?;
        let project = root.join("project");
        write_project_config(&project, "[execution]\nenabled = true\n")?;

        let result = Config::load_from_layers(None, None, &project);
        assert!(
            matches!(result, Err(ConfigError::PolicyWeakening { .. })),
            "project config must not enable execution (ADR-0017)"
        );
        std::fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn project_config_disabling_detector_rejected() -> TestResult {
        let root = temp_dir()?;
        let project = root.join("project");
        write_project_config(&project, "[detectors]\nshell_analysis = false\n")?;

        let result = Config::load_from_layers(None, None, &project);
        assert!(
            matches!(result, Err(ConfigError::PolicyWeakening { .. })),
            "project config must not disable detectors (ADR-0017)"
        );
        std::fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn project_config_weakening_integrity_rejected() -> TestResult {
        let root = temp_dir()?;
        let system = root.join("system.toml");
        std::fs::write(&system, "[integrity]\nrequire_provenance = true\n")?;

        let project = root.join("project");
        write_project_config(&project, "[integrity]\nrequire_provenance = false\n")?;

        let result = Config::load_from_layers(Some(&system), None, &project);
        assert!(
            matches!(result, Err(ConfigError::PolicyWeakening { .. })),
            "project config must not relax integrity requirements (ADR-0017)"
        );
        std::fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn project_config_weakening_default_action_rejected() -> TestResult {
        let root = temp_dir()?;
        let system = root.join("system.toml");
        std::fs::write(&system, "[policy]\ndefault_action = \"block\"\n")?;

        let project = root.join("project");
        write_project_config(&project, "[policy]\ndefault_action = \"pass\"\n")?;

        let result = Config::load_from_layers(Some(&system), None, &project);
        assert!(
            matches!(result, Err(ConfigError::PolicyWeakening { .. })),
            "project config must not weaken default_action (ADR-0017)"
        );
        std::fs::remove_dir_all(root)?;
        Ok(())
    }
}

mod adversary_18_confused_deputy {
    use super::*;

    #[test]
    fn redact_url_strips_credentials() {
        let redacted = redact_url("https://user:secret@api.example.com/path");
        assert!(
            !redacted.contains("secret"),
            "URL credentials must not appear in redacted form (invariant 9)"
        );
    }

    #[test]
    fn redact_url_strips_query_params() {
        let redacted = redact_url("https://api.example.com/path?token=hidden&sig=abc");
        assert!(
            !redacted.contains("hidden") && !redacted.contains("abc"),
            "query parameters must not appear in redacted form (invariant 9)"
        );
    }

    #[test]
    fn redact_url_preserves_host_and_path() {
        let redacted = redact_url("https://api.example.com/releases/tool.tar.gz");
        assert!(
            redacted.contains("api.example.com") && redacted.contains("tool.tar.gz"),
            "host and path must be preserved after redaction"
        );
    }
}

mod adversary_20_release_destination {
    use super::*;

    #[tokio::test]
    async fn symlink_destination_is_rejected() -> TestResult {
        let root = temp_dir()?;
        let store = ContentStore::open(&root.join("store"))?;
        let digest = stored_digest(&store, b"safe content").await?;

        let dest = root.join("link.txt");
        std::os::unix::fs::symlink("/etc/passwd", &dest)?;
        let result = release_artifact(&store, &digest, &dest, &ReleasePolicy::default());
        assert!(
            result.is_err(),
            "release to symlink destination must be rejected (invariant 18)"
        );
        std::fs::remove_dir_all(root)?;
        Ok(())
    }

    #[tokio::test]
    async fn existing_destination_rejected_without_overwrite_policy() -> TestResult {
        let root = temp_dir()?;
        let store = ContentStore::open(&root.join("store"))?;
        let digest = stored_digest(&store, b"new content").await?;

        let dest = root.join("existing.txt");
        std::fs::write(&dest, b"old content")?;
        let result = release_artifact(&store, &digest, &dest, &ReleasePolicy::default());
        assert!(
            result.is_err(),
            "overwrite without policy approval must be rejected (invariant 18)"
        );
        assert_eq!(
            std::fs::read(&dest)?,
            b"old content",
            "existing file must be preserved"
        );
        std::fs::remove_dir_all(root)?;
        Ok(())
    }

    #[tokio::test]
    async fn overwrite_with_policy_releases_exact_bytes() -> TestResult {
        let root = temp_dir()?;
        let store = ContentStore::open(&root.join("store"))?;
        let bytes = b"replacement version";
        let digest = stored_digest(&store, bytes).await?;

        let dest = root.join("existing.txt");
        std::fs::write(&dest, b"old content")?;
        release_artifact(
            &store,
            &digest,
            &dest,
            &ReleasePolicy {
                allow_overwrite: true,
                ..Default::default()
            },
        )?;
        assert_eq!(
            std::fs::read(&dest)?,
            bytes,
            "released bytes must match scanned bytes (invariant 2)"
        );
        std::fs::remove_dir_all(root)?;
        Ok(())
    }

    #[tokio::test]
    async fn release_to_nonexistent_directory_fails() -> TestResult {
        let root = temp_dir()?;
        let store = ContentStore::open(&root.join("store"))?;
        let digest = stored_digest(&store, b"content").await?;

        let dest = root.join("nonexistent/dir/output.txt");
        let result = release_artifact(&store, &digest, &dest, &ReleasePolicy::default());
        assert!(
            result.is_err(),
            "release to nonexistent parent dir must fail"
        );
        std::fs::remove_dir_all(root)?;
        Ok(())
    }
}

mod adversary_21_secret_leakage {
    use super::*;

    #[test]
    fn secret_resolver_rejects_path_traversal() -> TestResult {
        let root = temp_dir()?;
        let secret_root = root.join("secrets");
        std::fs::create_dir_all(&secret_root)?;
        std::fs::write(secret_root.join("api_key"), "hidden-value")?;
        let resolver = SecretResolver::new().with_files(true, Some(secret_root));
        assert!(
            resolver
                .resolve("secret://file/../../../etc/passwd")
                .is_err()
        );
        std::fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn secret_resolver_rejects_absolute_paths() -> TestResult {
        let root = temp_dir()?;
        let secret_root = root.join("secrets");
        std::fs::create_dir_all(&secret_root)?;
        std::fs::write(secret_root.join("key"), "val")?;
        let resolver = SecretResolver::new().with_files(true, Some(secret_root));
        assert!(resolver.resolve("secret://file//etc/passwd").is_err());
        std::fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn secret_resolver_rejects_symlink_targets() -> TestResult {
        let root = temp_dir()?;
        let secret_root = root.join("secrets");
        std::fs::create_dir_all(&secret_root)?;
        let target = root.join("outside.txt");
        std::fs::write(&target, "sensitive")?;
        std::os::unix::fs::symlink(&target, secret_root.join("link"))?;
        let resolver = SecretResolver::new().with_files(true, Some(secret_root));
        assert!(resolver.resolve("secret://file/link").is_err());
        std::fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn secret_resolver_resolves_valid_file_reference() -> TestResult {
        let root = temp_dir()?;
        let secret_root = root.join("secrets");
        std::fs::create_dir_all(&secret_root)?;
        std::fs::write(secret_root.join("api_key"), "test-value")?;
        let resolver = SecretResolver::new().with_files(true, Some(secret_root));
        let result = resolver.resolve("secret://file/api_key")?;
        assert_eq!(result, "test-value");
        std::fs::remove_dir_all(root)?;
        Ok(())
    }
}
