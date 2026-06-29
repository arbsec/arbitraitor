//! Tests for the `CallerOrigin` type (spec §23.1.1).

use arbitraitor_model::origin::CallerOrigin;

type TestResult = Result<(), Box<dyn std::error::Error>>;

#[test]
fn default_is_unknown() {
    assert_eq!(CallerOrigin::default(), CallerOrigin::Unknown);
}

#[test]
fn as_str_returns_snake_case() {
    assert_eq!(CallerOrigin::HumanTty.as_str(), "human_tty");
    assert_eq!(CallerOrigin::HumanIpc.as_str(), "human_ipc");
    assert_eq!(CallerOrigin::Ci.as_str(), "ci");
    assert_eq!(CallerOrigin::McpServer.as_str(), "mcp_server");
    assert_eq!(CallerOrigin::AgentSession.as_str(), "agent_session");
    assert_eq!(CallerOrigin::DaemonLocal.as_str(), "daemon_local");
    assert_eq!(CallerOrigin::Unknown.as_str(), "unknown");
}

#[test]
fn all_names_are_distinct() {
    let origins = [
        CallerOrigin::HumanTty,
        CallerOrigin::HumanIpc,
        CallerOrigin::Ci,
        CallerOrigin::McpServer,
        CallerOrigin::AgentSession,
        CallerOrigin::DaemonLocal,
        CallerOrigin::Unknown,
    ];
    let names: Vec<&str> = origins.iter().map(CallerOrigin::as_str).collect();
    let unique: std::collections::HashSet<&str> = names.iter().copied().collect();
    assert_eq!(names.len(), unique.len(), "origin names must be distinct");
}

#[test]
fn is_self_reported_for_non_human_origins() {
    assert!(!CallerOrigin::HumanTty.is_self_reported());
    assert!(!CallerOrigin::HumanIpc.is_self_reported());
    assert!(CallerOrigin::Ci.is_self_reported());
    assert!(CallerOrigin::McpServer.is_self_reported());
    assert!(CallerOrigin::AgentSession.is_self_reported());
    assert!(CallerOrigin::DaemonLocal.is_self_reported());
    assert!(CallerOrigin::Unknown.is_self_reported());
}

#[test]
fn serde_roundtrip_preserves_variant() -> TestResult {
    for origin in [
        CallerOrigin::HumanTty,
        CallerOrigin::HumanIpc,
        CallerOrigin::Ci,
        CallerOrigin::McpServer,
        CallerOrigin::AgentSession,
        CallerOrigin::DaemonLocal,
        CallerOrigin::Unknown,
    ] {
        let json = serde_json::to_string(&origin)?;
        let back: CallerOrigin = serde_json::from_str(&json)?;
        assert_eq!(origin, back, "serde roundtrip must preserve variant");
    }
    Ok(())
}

#[test]
fn serde_uses_snake_case() -> TestResult {
    assert_eq!(
        serde_json::to_string(&CallerOrigin::HumanTty)?,
        r#""human_tty""#
    );
    assert_eq!(
        serde_json::to_string(&CallerOrigin::McpServer)?,
        r#""mcp_server""#
    );
    Ok(())
}
