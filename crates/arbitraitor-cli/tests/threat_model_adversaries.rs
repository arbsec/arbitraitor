//! Tests for the six new §8.2 threat-model adversaries added in spec v0.5.
//!
//! Adversary 17: untrusted project config (.arbitraitor.toml)
//! Adversary 20: release-destination attacks (symlink/hardlink/reparse)
//! Adversary 21: privacy leakage via secret file path traversal

use arbitraitor_core::config::Config;
use arbitraitor_core::secret::SecretResolver;
use arbitraitor_exec::release::{ReleaseError, ReleasePolicy, release_artifact};
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

mod adversary_17_untrusted_project_config {
    use super::*;

    #[test]
    fn system_and_project_config_layer_correctly() -> TestResult {
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
        assert_eq!(
            config.fetch.max_bytes, 524_288,
            "project config overrides system"
        );
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
            "released bytes must match (invariant 2)"
        );
        Ok(())
    }
}

mod adversary_21_privacy_leakage {
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
