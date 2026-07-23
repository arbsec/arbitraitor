use std::collections::HashMap;
use std::io::Cursor;
use std::path::Path;
use std::process::Command;

use arbitraitor_model::ids::Sha256Digest;

use super::{
    ProvenanceError, SIGSTORE_BUNDLE_MEDIA_TYPES, SignatureSystem, SigstoreVerificationMode,
    TofuChange, TofuPin, TofuStore, TofuVerification, TufKey, TufRole, TufRoot, TufSignature,
    TufTargets, TufVersionStore, VerificationMaterialForm, determine_material_form,
    parse_bundle_metadata, parse_cosign_version, verify_cosign, verify_minisign,
};

#[test]
fn minisign_verifies_artifact_bytes() -> std::result::Result<(), Box<dyn std::error::Error>> {
    let key = minisign::KeyPair::generate_unencrypted_keypair()?;
    let artifact = b"trusted release artifact";
    let signature = minisign::sign(
        Some(&key.pk),
        &key.sk,
        Cursor::new(artifact),
        Some("arbitraitor artifact"),
        Some("signature from artifact producer"),
    )?;

    let verification = verify_minisign(artifact, &signature.to_bytes(), &key.pk)?;

    assert_eq!(verification.system, SignatureSystem::Minisign);
    assert!(verification.verified);
    assert_eq!(verification.identity, verification.trusted_identity);
    Ok(())
}

#[test]
fn minisign_rejects_wrong_key() -> std::result::Result<(), Box<dyn std::error::Error>> {
    let signing_key = minisign::KeyPair::generate_unencrypted_keypair()?;
    let wrong_key = minisign::KeyPair::generate_unencrypted_keypair()?;
    let artifact = b"trusted release artifact";
    let signature = minisign::sign(
        Some(&signing_key.pk),
        &signing_key.sk,
        Cursor::new(artifact),
        Some("arbitraitor artifact"),
        Some("signature from artifact producer"),
    )?;

    assert!(matches!(
        verify_minisign(artifact, &signature.to_bytes(), &wrong_key.pk),
        Err(ProvenanceError::MinisignVerification { .. })
    ));
    Ok(())
}

#[test]
fn parses_minisign_base64_public_key() -> std::result::Result<(), Box<dyn std::error::Error>> {
    let key = minisign::KeyPair::generate_unencrypted_keypair()?;
    let parsed = super::parse_minisign_public_key(&key.pk.to_base64())?;

    assert_eq!(parsed, key.pk);
    Ok(())
}

#[test]
fn verifies_all_required_minisign_signatures() -> std::result::Result<(), Box<dyn std::error::Error>>
{
    let first_key = minisign::KeyPair::generate_unencrypted_keypair()?;
    let second_key = minisign::KeyPair::generate_unencrypted_keypair()?;
    let artifact = b"artifact with multiple required signatures";
    let signatures = [
        minisign::sign(
            Some(&first_key.pk),
            &first_key.sk,
            Cursor::new(artifact),
            Some("first"),
            Some("first signer"),
        )?,
        minisign::sign(
            Some(&second_key.pk),
            &second_key.sk,
            Cursor::new(artifact),
            Some("second"),
            Some("second signer"),
        )?,
    ];
    let keys = [&first_key.pk, &second_key.pk];

    let results: Result<Vec<_>, _> = signatures
        .iter()
        .zip(keys)
        .map(|(signature, key)| verify_minisign(artifact, &signature.to_bytes(), key))
        .collect();

    assert_eq!(results?.len(), 2);
    Ok(())
}

#[test]
fn cosign_test_is_conditional_on_installed_binary() {
    if Command::new("cosign").arg("version").output().is_err() {
        return;
    }

    let result = verify_cosign(
        b"artifact bytes",
        Path::new("/definitely/missing/cosign.bundle"),
        "issuer@example.test",
        "https://issuer.example.test",
    );
    assert!(matches!(
        result,
        Err(ProvenanceError::CosignVerification { .. } | ProvenanceError::Io { .. })
    ));
}

#[test]
fn parse_cosign_version_extracts_v2_gitversion() {
    let output = "N/A\nGitVersion: v2.6.2\nGitCommit: abc\n";
    assert_eq!(parse_cosign_version(output), Some("2.6.2".to_owned()));
}

#[test]
fn parse_cosign_version_extracts_v3_bare() {
    let output = "v3.0.5\n";
    assert_eq!(parse_cosign_version(output), Some("3.0.5".to_owned()));
}

#[test]
fn parse_cosign_version_returns_none_for_garbage() {
    assert_eq!(parse_cosign_version("not a version"), None);
    assert_eq!(parse_cosign_version(""), None);
}

#[test]
fn tofu_first_use_pins_artifact_identity() -> std::result::Result<(), Box<dyn std::error::Error>> {
    let (_temp_dir, path) = temp_store_path("first-use")?;
    let mut store = TofuStore::open(&path)?;
    let url = "https://example.test/artifact";
    let pin = tofu_pin(url, 0x11, Some("signer@example.test"), Some(123));

    assert_eq!(
        store.verify_against_pin(url, &pin)?,
        TofuVerification::FirstUse
    );
    store.pin(url, pin.clone())?;
    let reopened = TofuStore::open(&path)?;

    assert_eq!(reopened.check(url), Some(&pin));
    Ok(())
}

#[test]
fn tofu_subsequent_match_passes() -> std::result::Result<(), Box<dyn std::error::Error>> {
    let (_temp_dir, path) = temp_store_path("match")?;
    let url = "https://example.test/tool";
    let pin = tofu_pin(url, 0x22, Some("release@example.test"), Some(42));
    let mut store = TofuStore::open(&path)?;
    store.pin(url, pin.clone())?;

    assert_eq!(
        store.verify_against_pin(url, &pin)?,
        TofuVerification::Matches
    );
    Ok(())
}

#[test]
fn tofu_change_produces_field_diff() -> std::result::Result<(), Box<dyn std::error::Error>> {
    let (_temp_dir, path) = temp_store_path("changed")?;
    let url = "https://example.test/tool";
    let pinned = tofu_pin(url, 0x33, Some("old@example.test"), Some(100));
    let actual = tofu_pin(url, 0x44, Some("new@example.test"), Some(101));
    let mut store = TofuStore::open(&path)?;
    store.pin(url, pinned)?;

    assert_eq!(
        store.verify_against_pin(url, &actual)?,
        TofuVerification::Changed {
            changes: vec![
                TofuChange::DigestChanged {
                    old: digest(0x33).to_string(),
                    new: digest(0x44).to_string(),
                },
                TofuChange::SignerChanged {
                    old: "old@example.test".to_owned(),
                    new: "new@example.test".to_owned(),
                },
                TofuChange::SizeChanged { old: 100, new: 101 },
            ],
        }
    );
    Ok(())
}

#[test]
fn tofu_redirect_destination_change_produces_field_diff()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    // Given
    let (_temp_dir, path) = temp_store_path("redirect-changed")?;
    let url = "https://example.test/tool";
    let mut pinned = tofu_pin(url, 0x33, Some("signer@example.test"), Some(100));
    pinned.redirect_destination = Some("https://old.example.test/tool".to_owned());
    let mut actual = pinned.clone();
    actual.redirect_destination = Some("https://new.example.test/tool".to_owned());
    let mut store = TofuStore::open(&path)?;
    store.pin(url, pinned)?;

    // When
    let verification = store.verify_against_pin(url, &actual)?;

    // Then
    assert_eq!(
        verification,
        TofuVerification::Changed {
            changes: vec![TofuChange::RedirectDestinationChanged {
                old: "https://old.example.test/tool".to_owned(),
                new: "https://new.example.test/tool".to_owned(),
            }],
        }
    );
    Ok(())
}

#[test]
fn tofu_certificate_identity_change_produces_field_diff()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    // Given
    let (_temp_dir, path) = temp_store_path("certificate-changed")?;
    let url = "https://example.test/tool";
    let mut pinned = tofu_pin(url, 0x33, Some("signer@example.test"), Some(100));
    pinned.certificate_identity = Some("old@example.test".to_owned());
    let mut actual = pinned.clone();
    actual.certificate_identity = Some("new@example.test".to_owned());
    let mut store = TofuStore::open(&path)?;
    store.pin(url, pinned)?;

    // When
    let verification = store.verify_against_pin(url, &actual)?;

    // Then
    assert_eq!(
        verification,
        TofuVerification::Changed {
            changes: vec![TofuChange::CertificateIdentityChanged {
                old: "old@example.test".to_owned(),
                new: "new@example.test".to_owned(),
            }],
        }
    );
    Ok(())
}

#[test]
fn tuf_version_validation_rejects_rollback() -> std::result::Result<(), Box<dyn std::error::Error>>
{
    let mut versions = TufVersionStore::new();
    versions.record_version("snapshot", 3)?;

    assert!(matches!(
        versions.validate_version("snapshot", 2),
        Err(ProvenanceError::TufRollback { .. })
    ));
    versions.validate_version("snapshot", 3)?;
    versions.validate_version("snapshot", 4)?;
    Ok(())
}

#[test]
fn tuf_expiration_rejects_expired_metadata() -> std::result::Result<(), Box<dyn std::error::Error>>
{
    let targets = TufTargets {
        version: 1,
        expires: "2026-01-01T00:00:00Z".to_owned(),
        targets: HashMap::new(),
    };

    assert!(matches!(
        targets.ensure_not_expired("2026-06-18T00:00:00Z"),
        Err(ProvenanceError::TufExpired { .. })
    ));
    targets.ensure_not_expired("2025-06-18T00:00:00Z")?;
    Ok(())
}

#[test]
fn tuf_threshold_requires_unique_authorized_signatures()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let root = TufRoot {
        version: 1,
        expires: "9999-01-01T00:00:00Z".to_owned(),
        keys: vec![tuf_key("root-a"), tuf_key("root-b"), tuf_key("unrelated")],
        roles: HashMap::from([(
            "root".to_owned(),
            TufRole {
                key_ids: vec!["root-a".to_owned(), "root-b".to_owned()],
                threshold: 2,
            },
        )]),
        consistent_snapshot: true,
    };

    assert!(matches!(
        root.verify_role_threshold(
            "root",
            &[
                TufSignature {
                    key_id: "root-a".to_owned(),
                },
                TufSignature {
                    key_id: "root-a".to_owned(),
                },
                TufSignature {
                    key_id: "unrelated".to_owned(),
                },
            ],
        ),
        Err(ProvenanceError::TufThreshold { .. })
    ));

    root.verify_role_threshold(
        "root",
        &[
            TufSignature {
                key_id: "root-a".to_owned(),
            },
            TufSignature {
                key_id: "root-b".to_owned(),
            },
        ],
    )?;
    Ok(())
}

#[test]
fn drain_to_bound_caps_output_and_marks_truncated() -> std::io::Result<()> {
    use std::io::Cursor;
    let payload = vec![b'a'; super::COSIGN_MAX_OUTPUT_BYTES * 2];
    let mut cursor = Cursor::new(payload);
    let output = super::drain_to_bound(&mut cursor)?;
    assert!(output.truncated);
    assert_eq!(output.bytes.len(), super::COSIGN_MAX_OUTPUT_BYTES);
    Ok(())
}

#[test]
fn drain_to_bound_marks_not_truncated_under_cap() -> std::io::Result<()> {
    use std::io::Cursor;
    let payload = b"short output".to_vec();
    let mut cursor = Cursor::new(payload);
    let output = super::drain_to_bound(&mut cursor)?;
    assert!(!output.truncated);
    assert_eq!(output.bytes, b"short output");
    Ok(())
}

#[test]
fn bounded_command_output_strips_terminal_control_bytes() {
    let result = super::bounded_command_output(b"ok\x1b\x07done", b"");
    assert_eq!(result, "okdone");
}

#[test]
fn bounded_command_output_marks_truncated_output() {
    let long = vec![b'x'; 1024];
    let result = super::bounded_command_output(&long, b"");
    assert!(result.ends_with('…'), "got: {result}");
    assert!(result.len() < long.len());
}

#[test]
fn bounded_command_output_falls_back_when_only_whitespace() {
    assert_eq!(
        super::bounded_command_output(b"   \n\t\x07\x07", b""),
        "cosign exited with a non-zero status"
    );
}

#[test]
fn bounded_command_output_prefers_stderr_when_present() {
    assert_eq!(
        super::bounded_command_output(b"from stderr", b"from stdout"),
        "from stderr"
    );
}

fn tofu_pin(url: &str, byte: u8, signer_identity: Option<&str>, size: Option<u64>) -> TofuPin {
    TofuPin {
        url: url.to_owned(),
        sha256: digest(byte),
        signer_identity: signer_identity.map(str::to_owned),
        certificate_identity: None,
        redirect_destination: None,
        content_type: Some("application/octet-stream".to_owned()),
        size,
        first_seen: "2026-06-18T00:00:00Z".to_owned(),
    }
}

fn digest(byte: u8) -> Sha256Digest {
    Sha256Digest::new([byte; 32])
}

fn tuf_key(key_id: &str) -> TufKey {
    TufKey {
        key_id: key_id.to_owned(),
        key_type: "ed25519".to_owned(),
        scheme: "minisign".to_owned(),
        value: "public-key".to_owned(),
    }
}

fn temp_store_path(name: &str) -> std::io::Result<(tempfile::TempDir, std::path::PathBuf)> {
    let dir = tempfile::TempDir::new()?;
    let path = dir.path().join(format!("{name}.json"));
    Ok((dir, path))
}

#[test]
fn parse_bundle_metadata_extracts_v03_fields() -> std::io::Result<()> {
    let dir = tempfile::TempDir::new()?;
    let bundle_path = dir.path().join("bundle.json");
    let bundle_json = serde_json::json!({
        "mediaType": "application/vnd.dev.sigstore.bundle+json;version=0.3",
        "verificationMaterial": {
            "content": {
                "x509Certificate": {
                    "rawBytes": "MIIB..."
                }
            },
            "tlogEntries": [
                {"log_index": 1},
                {"log_index": 2}
            ],
            "timestampVerificationData": {
                "rfc3161Timestamps": [
                    {"signed_theta": "MIAGCSqGSIb3DQEHA"}
                ]
            }
        },
        "message_signature": {
            "message_digest": {
                "algorithm": "SHA2_256",
                "digest": "abCd"
            }
        }
    });
    std::fs::write(&bundle_path, serde_json::to_vec_pretty(&bundle_json)?)?;

    let metadata = parse_bundle_metadata(&bundle_path, "test-identity", "test-issuer");

    assert!(metadata.is_some());
    let m = metadata.ok_or_else(|| std::io::Error::other("metadata should be parsed"))?;
    assert_eq!(
        m.media_type,
        "application/vnd.dev.sigstore.bundle+json;version=0.3"
    );
    assert_eq!(
        m.verification_material_form,
        VerificationMaterialForm::X509Certificate
    );
    assert_eq!(m.tlog_entries, 2);
    assert_eq!(m.rfc3161_timestamps, 1);
    assert_eq!(m.verification_mode, SigstoreVerificationMode::Offline);

    Ok(())
}

#[test]
fn parse_bundle_metadata_handles_missing_fields() -> std::io::Result<()> {
    let dir = tempfile::TempDir::new()?;
    let bundle_path = dir.path().join("minimal.json");
    std::fs::write(
        &bundle_path,
        r#"{"mediaType": "application/vnd.dev.sigstore.bundle+json;version=0.1"}"#,
    )?;

    let metadata = parse_bundle_metadata(&bundle_path, "id", "iss");

    assert!(metadata.is_some());
    let m = metadata.ok_or_else(|| std::io::Error::other("metadata should be parsed"))?;
    assert_eq!(
        m.media_type,
        "application/vnd.dev.sigstore.bundle+json;version=0.1"
    );
    assert_eq!(m.tlog_entries, 0);
    assert_eq!(m.rfc3161_timestamps, 0);

    Ok(())
}

#[test]
fn parse_bundle_metadata_returns_none_for_invalid_json() -> std::io::Result<()> {
    let dir = tempfile::TempDir::new()?;
    let bundle_path = dir.path().join("bad.json");
    std::fs::write(&bundle_path, b"not json at all")?;

    let metadata = parse_bundle_metadata(&bundle_path, "id", "iss");
    assert!(metadata.is_none());

    Ok(())
}

#[test]
fn sigstore_bundle_media_types_includes_v03() {
    assert!(
        SIGSTORE_BUNDLE_MEDIA_TYPES
            .contains(&"application/vnd.dev.sigstore.bundle+json;version=0.3")
    );
    assert!(
        SIGSTORE_BUNDLE_MEDIA_TYPES
            .contains(&"application/vnd.dev.sigstore.bundle+json;version=0.2")
    );
    assert!(
        SIGSTORE_BUNDLE_MEDIA_TYPES
            .contains(&"application/vnd.dev.sigstore.bundle+json;version=0.1")
    );
}

#[test]
fn determine_material_form_detects_public_key() {
    let bundle = serde_json::json!({
        "verificationMaterial": {
            "content": {
                "publicKey": {"rawBytes": "key"}
            }
        }
    });
    assert_eq!(
        determine_material_form(&bundle),
        VerificationMaterialForm::PublicKey
    );
}

#[test]
fn determine_material_form_defaults_to_chain() {
    let bundle = serde_json::json!({});
    assert_eq!(
        determine_material_form(&bundle),
        VerificationMaterialForm::X509CertificateChain
    );
}

#[test]
fn signature_system_as_str_returns_stable_labels() {
    assert_eq!(SignatureSystem::Minisign.as_str(), "minisign");
    assert_eq!(SignatureSystem::Cosign.as_str(), "cosign");
    assert_eq!(SignatureSystem::OpenPGP.as_str(), "openpgp");
    assert_eq!(SignatureSystem::Authenticode.as_str(), "authenticode");
    assert_eq!(SignatureSystem::AppleCodeSign.as_str(), "apple_code_sign");
    assert_eq!(SignatureSystem::LinuxPackage.as_str(), "linux_package");
}

#[test]
fn signature_system_as_str_is_distinct_per_variant() {
    let labels = [
        SignatureSystem::Minisign.as_str(),
        SignatureSystem::Cosign.as_str(),
        SignatureSystem::OpenPGP.as_str(),
        SignatureSystem::Authenticode.as_str(),
        SignatureSystem::AppleCodeSign.as_str(),
        SignatureSystem::LinuxPackage.as_str(),
    ];
    let mut unique = labels.to_vec();
    unique.sort_unstable();
    unique.dedup();
    assert_eq!(unique.len(), labels.len(), "as_str labels must be unique");
}
