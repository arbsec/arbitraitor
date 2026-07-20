use std::error::Error;

use super::*;

fn sample_indicator(indicator_type: IndicatorType, value: &str) -> Indicator {
    Indicator {
        indicator_type,
        value: value.to_owned(),
    }
}

fn sample_entry(indicator: Indicator) -> FeedEntry {
    FeedEntry {
        schema_version: CURRENT_SCHEMA_VERSION,
        id: format!(
            "entry:{}:{}",
            indicator.indicator_type as u8, indicator.value
        ),
        indicator,
        classification: Classification::Malicious,
        severity: Severity::High,
        confidence: Confidence::Confirmed,
        disposition: Disposition::Block,
        source_class: FeedSourceClass::ArbitraitorReviewed,
        first_seen: "2026-06-01T00:00:00Z".to_owned(),
        last_seen: "2026-06-17T00:00:00Z".to_owned(),
        source_update_time: None,
        expires_at: None,
        sources: vec![FeedSource {
            source_type: "analyst".to_owned(),
            reference: "case-111".to_owned(),
        }],
        evidence: FeedEvidence {
            malware_family: Some("ExampleRat".to_owned()),
            notes: Some("confirmed in sandbox".to_owned()),
        },
        review: ReviewStatus {
            status: ReviewState::Reviewed,
            reviewers: vec!["analyst@example.com".to_owned()],
        },
    }
}

fn temp_store_path(name: &str) -> PathBuf {
    let unique = format!(
        "arbitraitor-intel-{name}-{}-{}.json",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |duration| duration.as_nanos())
    );
    std::env::temp_dir().join(unique)
}

#[test]
fn feed_entry_round_trips_through_json() -> std::result::Result<(), Box<dyn Error>> {
    let entry = sample_entry(sample_indicator(IndicatorType::Sha256, &"ab".repeat(32)));
    let json = serde_json::to_string(&entry)?;
    let decoded: FeedEntry = serde_json::from_str(&json)?;
    assert_eq!(decoded, entry);
    Ok(())
}

#[test]
fn queries_by_sha256_indicator() -> std::result::Result<(), Box<dyn Error>> {
    let path = temp_store_path("sha256");
    let indicator = sample_indicator(IndicatorType::Sha256, &"cd".repeat(32));
    let mut store = IntelStore::open(&path)?;
    store.add_entry(sample_entry(indicator.clone()))?;

    let matches = store.query(&indicator);
    assert_eq!(matches.len(), 1);
    assert_eq!(matches[0].indicator, indicator);
    let _ = fs::remove_file(path);
    Ok(())
}

#[test]
fn queries_by_url_indicator() -> std::result::Result<(), Box<dyn Error>> {
    let path = temp_store_path("url");
    let indicator = sample_indicator(IndicatorType::ExactUrl, "https://example.invalid/a.sh");
    let mut store = IntelStore::open(&path)?;
    store.add_entry(sample_entry(indicator.clone()))?;

    assert_eq!(store.query(&indicator).len(), 1);
    assert!(
        store
            .query(&sample_indicator(
                IndicatorType::ExactUrl,
                "https://example.invalid/other.sh"
            ))
            .is_empty()
    );
    let _ = fs::remove_file(path);
    Ok(())
}

#[test]
fn purges_expired_entries() -> std::result::Result<(), Box<dyn Error>> {
    let path = temp_store_path("expiry");
    let mut expired = sample_entry(sample_indicator(IndicatorType::Hostname, "bad.example"));
    expired.expires_at = Some("1970-01-01T00:00:00Z".to_owned());
    let live = sample_entry(sample_indicator(IndicatorType::Hostname, "live.example"));
    let mut store = IntelStore::open(&path)?;
    store.add_entry(expired)?;
    store.add_entry(live.clone())?;

    assert_eq!(store.purge_expired()?, 1);
    assert_eq!(store.entries(), &[live]);
    let _ = fs::remove_file(path);
    Ok(())
}

#[test]
fn deny_unknown_fields_rejects_extra_feed_entry_fields() {
    let json = r#"{"schema_version":1,"id":"entry-1","indicator":{"indicator_type":"sha256","value":"abababababababababababababababababababababababababababababababab"},"classification":"malicious","severity":"high","confidence":"confirmed","disposition":"block","source_class":"arbitraitor-reviewed","first_seen":"2026-06-01T00:00:00Z","last_seen":"2026-06-17T00:00:00Z","expires_at":null,"sources":[],"evidence":{"malware_family":null,"notes":null},"review":{"status":"reviewed","reviewers":[]},"extra":true}"#;
    assert!(serde_json::from_str::<FeedEntry>(json).is_err());
}

#[test]
fn match_indicator_orders_exact_hash_before_hostname() -> std::result::Result<(), Box<dyn Error>> {
    let path = temp_store_path("specificity");
    let mut store = IntelStore::open(&path)?;
    let hash = sample_indicator(IndicatorType::Sha256, &"ef".repeat(32));
    store.add_entry(sample_entry(sample_indicator(
        IndicatorType::Hostname,
        "example.invalid",
    )))?;
    store.add_entry(sample_entry(hash.clone()))?;

    let matches = match_indicator(&store, &hash);
    assert_eq!(matches.len(), 1);
    assert_eq!(matches[0].specificity, MatchSpecificity::Exact);
    assert_eq!(matches[0].entry.indicator, hash);
    let _ = fs::remove_file(path);
    Ok(())
}

#[test]
fn match_indicator_matches_url_prefix_hostname_and_domain()
-> std::result::Result<(), Box<dyn Error>> {
    let path = temp_store_path("url-broad");
    let mut store = IntelStore::open(&path)?;
    store.add_entry(sample_entry(sample_indicator(
        IndicatorType::UrlPrefix,
        "https://example.invalid/releases/",
    )))?;
    store.add_entry(sample_entry(sample_indicator(
        IndicatorType::Hostname,
        "example.invalid",
    )))?;
    store.add_entry(sample_entry(sample_indicator(
        IndicatorType::RegistrableDomain,
        "invalid",
    )))?;

    let matches = match_indicator(
        &store,
        &sample_indicator(
            IndicatorType::ExactUrl,
            "https://example.invalid/releases/a.sh",
        ),
    );
    let specificities: Vec<MatchSpecificity> =
        matches.iter().map(|matched| matched.specificity).collect();
    assert_eq!(
        specificities,
        vec![
            MatchSpecificity::Moderate,
            MatchSpecificity::Broad,
            MatchSpecificity::Broad
        ]
    );
    let _ = fs::remove_file(path);
    Ok(())
}

#[test]
fn evaluate_matches_enforces_source_class_table() {
    let mut enterprise = sample_entry(sample_indicator(IndicatorType::Sha256, &"12".repeat(32)));
    enterprise.source_class = FeedSourceClass::EnterpriseDeny;
    let mut community = sample_entry(sample_indicator(
        IndicatorType::ExactUrl,
        "https://example.invalid/a",
    ));
    community.source_class = FeedSourceClass::CorroboratedCommunity;

    let result = evaluate_matches(&[
        MatchResult {
            entry: community,
            specificity: MatchSpecificity::Precise,
        },
        MatchResult {
            entry: enterprise,
            specificity: MatchSpecificity::Exact,
        },
    ]);

    assert_eq!(
        result,
        Some(EnforcementResult {
            disposition: Disposition::Block,
            severity: Severity::Critical,
            confidence: Confidence::Confirmed,
            deciding_source_class: FeedSourceClass::EnterpriseDeny,
        })
    );
}

#[test]
fn expired_entries_are_ignored_by_match_indicator() -> std::result::Result<(), Box<dyn Error>> {
    let path = temp_store_path("match-expiry");
    let indicator = sample_indicator(IndicatorType::Sha256, &"34".repeat(32));
    let mut expired = sample_entry(indicator.clone());
    expired.expires_at = Some("1970-01-01T00:00:00Z".to_owned());
    let mut store = IntelStore::open(&path)?;
    store.add_entry(expired)?;

    assert!(match_indicator(&store, &indicator).is_empty());
    let _ = fs::remove_file(path);
    Ok(())
}

#[test]
fn is_expired_is_false_when_no_expiration_set() {
    let entry = sample_entry(sample_indicator(IndicatorType::Sha256, &"aa".repeat(32)));
    assert!(entry.expires_at.is_none());
    assert!(!entry.is_expired("2026-07-20T00:00:00Z"));
    assert!(!entry.is_expired("1970-01-01T00:00:00Z"));
}

#[test]
fn is_expired_is_false_when_expiration_is_in_the_future() {
    let mut entry = sample_entry(sample_indicator(IndicatorType::Sha256, &"bb".repeat(32)));
    entry.expires_at = Some("2099-01-01T00:00:00Z".to_owned());

    assert!(!entry.is_expired("2026-07-20T00:00:00Z"));
    assert!(!entry.is_expired("2098-12-31T23:59:59Z"));
}

#[test]
fn is_expired_is_true_when_expiration_is_in_the_past() {
    let mut entry = sample_entry(sample_indicator(IndicatorType::Sha256, &"cc".repeat(32)));
    entry.expires_at = Some("1970-01-01T00:00:00Z".to_owned());

    assert!(entry.is_expired("2026-07-20T00:00:00Z"));
    assert!(entry.is_expired("1970-01-02T00:00:00Z"));
}

#[test]
fn is_expired_uses_strict_inequality_at_boundary() {
    // Spec §21.6: an entry is expired once `now` is strictly past `expires_at`.
    // At the exact expiration timestamp the entry is still considered fresh.
    let mut entry = sample_entry(sample_indicator(IndicatorType::Sha256, &"dd".repeat(32)));
    entry.expires_at = Some("2026-07-20T00:00:00Z".to_owned());

    assert!(!entry.is_expired("2026-07-20T00:00:00Z"));
    assert!(entry.is_expired("2026-07-20T00:00:01Z"));
}

#[test]
fn formats_unix_epoch_as_rfc3339_utc() {
    assert_eq!(format_unix_timestamp(0), "1970-01-01T00:00:00Z");
    assert_eq!(format_unix_timestamp(86_400), "1970-01-02T00:00:00Z");
}

#[test]
fn redact_url_strips_userinfo_and_keeps_host_and_path() {
    let redacted = redact_url("https://user:secret@api.example.com/v1/tool?token=abc");
    assert!(
        !redacted.contains("user"),
        "username must not survive redaction: {redacted}"
    );
    assert!(
        !redacted.contains("secret"),
        "password must not survive redaction: {redacted}"
    );
    assert!(
        redacted.contains("api.example.com"),
        "host must be preserved: {redacted}"
    );
    assert!(
        redacted.contains("/v1/tool"),
        "path must be preserved: {redacted}"
    );
    assert!(
        redacted.contains("token=[REDACTED]"),
        "sensitive query value must be replaced: {redacted}"
    );
    assert!(
        !redacted.contains("token=abc"),
        "sensitive query value must not survive: {redacted}"
    );
}

#[test]
fn redact_url_strips_username_only_when_no_password() {
    let redacted = redact_url("https://alice@example.com/path?page=1");
    assert!(
        !redacted.contains("alice"),
        "username must not survive redaction: {redacted}"
    );
    assert!(
        redacted.contains("example.com/path"),
        "host and path must be preserved: {redacted}"
    );
    assert!(
        redacted.contains("page=1"),
        "non-sensitive query param must be preserved: {redacted}"
    );
}

#[test]
fn redact_url_handles_multiple_sensitive_query_params() {
    let redacted = redact_url("https://example.com/path?token=t1&page=2&api_key=k1&signature=sig1");
    assert!(
        redacted.contains("token=[REDACTED]"),
        "token must be redacted: {redacted}"
    );
    assert!(
        redacted.contains("api_key=[REDACTED]"),
        "api_key must be redacted: {redacted}"
    );
    assert!(
        redacted.contains("signature=[REDACTED]"),
        "signature must be redacted: {redacted}"
    );
    assert!(
        redacted.contains("page=2"),
        "non-sensitive param must be preserved: {redacted}"
    );
    assert!(!redacted.contains("t1"), "t1 must not survive: {redacted}");
    assert!(!redacted.contains("k1"), "k1 must not survive: {redacted}");
    assert!(
        !redacted.contains("sig1"),
        "sig1 must not survive: {redacted}"
    );
}

#[test]
fn redact_url_matches_sensitive_query_keys_case_insensitively() {
    let redacted =
        redact_url("https://example.com/p?TOKEN=upper&Key=mixed&PASSWORD=lower&Sig=short");
    assert!(redacted.contains("TOKEN=[REDACTED]"), "got: {redacted}");
    assert!(redacted.contains("Key=[REDACTED]"), "got: {redacted}");
    assert!(redacted.contains("PASSWORD=[REDACTED]"), "got: {redacted}");
    assert!(redacted.contains("Sig=[REDACTED]"), "got: {redacted}");
}

#[test]
fn redact_url_leaves_non_sensitive_query_alone() {
    let redacted = redact_url("https://example.com/search?q=hello&page=3");
    assert_eq!(redacted, "https://example.com/search?q=hello&page=3");
}

#[test]
fn redact_url_returns_unparseable_input_unchanged() {
    let input = "not a url at all";
    assert_eq!(redact_url(input), input);
}

#[test]
fn redact_url_handles_empty_query_and_credentials() {
    assert_eq!(
        redact_url("https://example.com/path"),
        "https://example.com/path"
    );
    assert_eq!(
        redact_url("https://example.com/path?"),
        "https://example.com/path?"
    );
}

#[test]
fn redact_path_collapses_home_directory_prefix() {
    let redacted = redact_path_with_home("/home/alice/projects/x", Some(Path::new("/home/alice")));
    assert_eq!(redacted, "~/projects/x");
}

#[test]
fn redact_path_collapses_home_directory_prefix_to_root() {
    let redacted = redact_path_with_home("/home/alice/", Some(Path::new("/home/alice")));
    assert_eq!(redacted, "~/");
}

#[test]
fn redact_path_collapses_home_user_prefix_when_home_unset() {
    let redacted = redact_path_with_home("/home/bob/projects/x", None);
    assert_eq!(redacted, "~/projects/x");
}

#[test]
fn redact_path_leaves_relative_paths_alone() {
    let redacted = redact_path_with_home("./relative/file.txt", None);
    assert_eq!(redacted, "./relative/file.txt");
    let redacted = redact_path_with_home("just/a/path", None);
    assert_eq!(redacted, "just/a/path");
}

#[test]
fn redact_path_leaves_already_tilde_paths_alone() {
    let redacted = redact_path_with_home("~/already/redacted", None);
    assert_eq!(redacted, "~/already/redacted");
}

#[test]
fn redact_path_handles_missing_trailing_slash() {
    // "/home/alice" with no sub-path is ambiguous; we leave it alone rather
    // than guess at the user's home boundary.
    let redacted = redact_path_with_home("/home/alice", None);
    assert_eq!(redacted, "/home/alice");
}

#[test]
fn redact_env_var_returns_none_for_sensitive_suffixes() {
    assert_eq!(redact_env_var("API_KEY", "abc"), None);
    assert_eq!(redact_env_var("AUTH_TOKEN", "abc"), None);
    assert_eq!(redact_env_var("DB_SECRET", "abc"), None);
    assert_eq!(redact_env_var("ROOT_PASSWORD", "abc"), None);
}

#[test]
fn redact_env_var_matches_sensitive_suffixes_case_insensitively() {
    assert_eq!(redact_env_var("api_key", "abc"), None);
    assert_eq!(redact_env_var("Auth_Token", "abc"), None);
    assert_eq!(redact_env_var("Db_Password", "abc"), None);
    assert_eq!(redact_env_var("foo_secret", "abc"), None);
}

#[test]
fn redact_env_var_returns_value_for_safe_names() {
    assert_eq!(
        redact_env_var("HOME", "/home/alice"),
        Some("/home/alice".to_owned())
    );
    assert_eq!(
        redact_env_var("PATH", "/usr/bin:/bin"),
        Some("/usr/bin:/bin".to_owned())
    );
    assert_eq!(redact_env_var("USER", "alice"), Some("alice".to_owned()));
}

#[test]
fn redact_env_var_does_not_match_without_underscore_prefix() {
    // "TOKEN" alone does not end in "_TOKEN", so it must not be treated as a
    // sensitive name — only the documented *_SUFFIX pattern counts.
    assert_eq!(
        redact_env_var("TOKEN", "public-value"),
        Some("public-value".to_owned())
    );
}

#[test]
fn project_posture_records_available_advisory_signals() {
    let posture = ProjectPosture {
        scorecard_score: Some(8),
        deps_dev_deprecated: Some(false),
        package_analysis_malicious: Some(true),
        available: true,
    };

    assert_eq!(posture.scorecard_score, Some(8));
    assert_eq!(posture.deps_dev_deprecated, Some(false));
    assert_eq!(posture.package_analysis_malicious, Some(true));
    assert!(posture.available);
}

#[tokio::test]
async fn no_op_posture_provider_returns_unavailable() -> std::result::Result<(), Box<dyn Error>> {
    let posture = NoOpPostureProvider
        .fetch_posture("https://github.com/arbsec/arbitraitor")
        .await?;

    assert_eq!(
        posture,
        ProjectPosture {
            scorecard_score: None,
            deps_dev_deprecated: None,
            package_analysis_malicious: None,
            available: false,
        }
    );
    Ok(())
}
