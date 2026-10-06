//! Caller-origin classification for the policy engine.
//!
//! Every operation request carries a caller-origin class. Policy may branch
//! on this class to express rules such as "an MCP request from server X
//! requires human approval, but the same operation requested directly by a
//! human does not".

use serde::{Deserialize, Serialize};

/// The origin class of an operation request.
///
/// Spoofing rules: all non-`HumanTty` classes are spoofable by a malicious
/// local process unless the transport authenticates them. `HumanTty` and
/// `HumanIpc` are authenticated by the OS; `CiRelay` authenticates only the
/// relay channel itself, at request time, while its envelope metadata fields
/// remain self-reported per the §23.1.1 spoofing rules. Policy must not
/// treat any self-reported field as authoritative unless the corresponding
/// transport-level authentication is verified for the request.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CallerOrigin {
    /// Request originated from a human at a TTY (stdin/stderr owned by the
    /// caller). Highest trust — the approval UI renders to this peer.
    HumanTty,
    /// Request from a known local IPC peer (Unix peer cred, Windows named-pipe
    /// ACL). High trust — the requestor is a known local user process.
    HumanIpc,
    /// Request from a pre-configured CI identity (run ID, repository,
    /// environment). Medium trust — binding established at install time.
    Ci,
    /// Request from a remote event-relay channel authenticated at request
    /// time by a per-deployment relay credential that Arbitraitor verifies
    /// in constant time during ingress-envelope evaluation. Medium trust —
    /// the binding is established at deployment setup. Envelope metadata
    /// fields (repository, event type, run id, head SHA) remain
    /// self-reported per the §23.1.1 spoofing rules.
    CiRelay,
    /// Request from an MCP server (transport-bound). Medium trust when local;
    /// low when remote until remote transport binding is implemented.
    McpServer,
    /// Request from an agent session (self-reported session ID from a trusted
    /// integrator). Low trust — session IDs are self-reported unless bound to
    /// `HumanTty` approval.
    AgentSession,
    /// Request from the local daemon (Unix-socket peer cred on the daemon
    /// socket). Medium trust — matches the daemon's authenticated local
    /// user.
    DaemonLocal,
    /// Default for requests where the origin could not be determined.
    /// Lowest trust — treated as untrusted unless policy explicitly handles it.
    #[default]
    Unknown,
}

impl CallerOrigin {
    /// Returns the string label used in receipts and diagnostics.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::HumanTty => "human_tty",
            Self::HumanIpc => "human_ipc",
            Self::Ci => "ci",
            Self::CiRelay => "ci_relay",
            Self::McpServer => "mcp_server",
            Self::AgentSession => "agent_session",
            Self::DaemonLocal => "daemon_local",
            Self::Unknown => "unknown",
        }
    }

    /// Returns `true` if this origin is spoofable by a malicious local process
    /// without transport-level authentication.
    ///
    /// `HumanTty` and `HumanIpc` are **not** self-reported because they are
    /// authenticated by the OS (TTY process group or Unix peer credentials).
    /// All other origins are self-reported: their identity fields are
    /// asserted by the caller and may be forged unless the transport
    /// independently verifies them.
    #[must_use]
    pub fn is_self_reported(&self) -> bool {
        !matches!(self, Self::HumanTty | Self::HumanIpc)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ci_relay_serde_round_trips() -> Result<(), Box<dyn std::error::Error>> {
        let serialized = serde_json::to_string(&CallerOrigin::CiRelay)?;
        assert_eq!(serialized, "\"ci_relay\"");
        assert_eq!(
            serde_json::from_str::<CallerOrigin>(&serialized)?,
            CallerOrigin::CiRelay
        );
        Ok(())
    }

    #[test]
    fn ci_relay_as_str_label() {
        assert_eq!(CallerOrigin::CiRelay.as_str(), "ci_relay");
    }

    #[test]
    fn ci_relay_envelope_metadata_is_self_reported() {
        // The relay channel is authenticated by the per-deployment
        // credential, but the envelope metadata fields it carries are
        // asserted by the sender per the §23.1.1 spoofing rules.
        assert!(CallerOrigin::CiRelay.is_self_reported());
    }
}
