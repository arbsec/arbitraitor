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
fn formats_unix_epoch_as_rfc3339_utc() {
    assert_eq!(format_unix_timestamp(0), "1970-01-01T00:00:00Z");
    assert_eq!(format_unix_timestamp(86_400), "1970-01-02T00:00:00Z");
}
