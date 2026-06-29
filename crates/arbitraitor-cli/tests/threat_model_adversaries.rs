//! Regression tests for spec §8.2 threat-model adversaries added in v0.5.
//!
//! This file covers testable aspects of adversaries 17, 18, 20, and 21.
//! Adversaries 19 (mandatory scanning coverage) and 22 (privilege-helper
//! scope creep) lack the API surface to test and are tracked in #271.
//!
//! **Does NOT resolve #271** — this is partial coverage.

use arbitraitor_core::config::Config;
use arbitraitor_core::secret::SecretResolver;
use arbitraitor_exec::release::{ReleaseError, ReleasePolicy, release_artifact};
use arbitraitor_fetch::redact_url;
use arbitraitor_model::ids::Sha256Digest;
use arbitraitor_store::ContentStore;
use tempfile::TempDir;

type TestResult = Result<(), Box<dyn std::error::Error>>;

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
    use super::*;

    #[test]
    fn system_then_project_config_layers_correctly() -> TestResult {
        let tmp = TempDir::new()?;
        let system = tmp.path().join("system.toml");
        std::fs::write(&system, "[fetch]\nmax_bytes = 1048576\n")?;

        let project = tmp.path().join("project");
        std::fs::create_dir_all(project.join(".arbitraitor"))?;
        std::fs::write(
            project.join(".arbitraitor/config.toml"),
            "[fetch]\nmax_bytes = 524288\n",
        )?;

        let config = Config::load_from_layers(Some(&system), None, &project)?;
        assert_eq!(config.fetch.max_bytes, 524_288);
        Ok(())
    }

    #[test]
    fn missing_project_config_preserves_system() -> TestResult {
        let tmp = TempDir::new()?;
        let system = tmp.path().join("system.toml");
        std::fs::write(&system, "[fetch]\nmax_bytes = 5242880\n")?;
        let config = Config::load_from_layers(Some(&system), None, tmp.path())?;
        assert_eq!(config.fetch.max_bytes, 5_242_880);
        Ok(())
    }

    #[test]
    fn missing_project_config_uses_defaults() -> TestResult {
        let tmp = TempDir::new()?;
        let config = Config::load_from_layers(None, None, tmp.path())?;
        assert_eq!(config, Config::default());
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
        let tmp = TempDir::new()?;
        let store = ContentStore::open(&tmp.path().join("store"))?;
        let digest = stored_digest(&store, b"safe content").await?;

        let dest = tmp.path().join("link.txt");
        std::os::unix::fs::symlink("/etc/passwd", &dest)?;
        let result = release_artifact(&store, &digest, &dest, &ReleasePolicy::default());
        assert!(matches!(
            result,
            Err(ReleaseError::ForbiddenIndirection { .. })
        ));
        Ok(())
    }

    #[tokio::test]
    async fn existing_destination_rejected_without_overwrite_policy() -> TestResult {
        let tmp = TempDir::new()?;
        let store = ContentStore::open(&tmp.path().join("store"))?;
        let digest = stored_digest(&store, b"new content").await?;

        let dest = tmp.path().join("existing.txt");
        std::fs::write(&dest, b"old content")?;
        let result = release_artifact(&store, &digest, &dest, &ReleasePolicy::default());
        assert!(matches!(
            result,
            Err(ReleaseError::DestinationExists { .. })
        ));
        assert_eq!(std::fs::read(&dest)?, b"old content");
        Ok(())
    }

    #[tokio::test]
    async fn overwrite_with_policy_releases_exact_bytes() -> TestResult {
        let tmp = TempDir::new()?;
        let store = ContentStore::open(&tmp.path().join("store"))?;
        let bytes = b"replacement version";
        let digest = stored_digest(&store, bytes).await?;

        let dest = tmp.path().join("existing.txt");
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
        Ok(())
    }

    #[tokio::test]
    async fn release_to_nonexistent_directory_fails() -> TestResult {
        let tmp = TempDir::new()?;
        let store = ContentStore::open(&tmp.path().join("store"))?;
        let digest = stored_digest(&store, b"content").await?;

        let dest = tmp.path().join("nonexistent/dir/output.txt");
        let result = release_artifact(&store, &digest, &dest, &ReleasePolicy::default());
        assert!(
            result.is_err(),
            "release to nonexistent parent dir must fail"
        );
        Ok(())
    }
}

mod adversary_21_secret_leakage {
    use super::*;

    #[test]
    fn secret_resolver_rejects_path_traversal() -> TestResult {
        let tmp = TempDir::new()?;
        let root = tmp.path().join("secrets");
        std::fs::create_dir_all(&root)?;
        std::fs::write(root.join("api_key"), "hidden-value")?;
        let resolver = SecretResolver::new().with_files(true, Some(root));
        assert!(
            resolver
                .resolve("secret://file/../../../etc/passwd")
                .is_err()
        );
        Ok(())
    }

    #[test]
    fn secret_resolver_rejects_absolute_paths() -> TestResult {
        let tmp = TempDir::new()?;
        let root = tmp.path().join("secrets");
        std::fs::create_dir_all(&root)?;
        std::fs::write(root.join("key"), "val")?;
        let resolver = SecretResolver::new().with_files(true, Some(root));
        assert!(resolver.resolve("secret://file//etc/passwd").is_err());
        Ok(())
    }

    #[test]
    fn secret_resolver_rejects_symlink_targets() -> TestResult {
        let tmp = TempDir::new()?;
        let root = tmp.path().join("secrets");
        std::fs::create_dir_all(&root)?;
        let target = tmp.path().join("outside.txt");
        std::fs::write(&target, "sensitive")?;
        std::os::unix::fs::symlink(&target, root.join("link"))?;
        let resolver = SecretResolver::new().with_files(true, Some(root));
        assert!(resolver.resolve("secret://file/link").is_err());
        Ok(())
    }

    #[test]
    fn secret_resolver_resolves_valid_file_reference() -> TestResult {
        let tmp = TempDir::new()?;
        let root = tmp.path().join("secrets");
        std::fs::create_dir_all(&root)?;
        std::fs::write(root.join("api_key"), "test-value")?;
        let resolver = SecretResolver::new().with_files(true, Some(root));
        let result = resolver.resolve("secret://file/api_key")?;
        assert_eq!(result, "test-value");
        Ok(())
    }
}
