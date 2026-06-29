//! Caller-origin classification for the policy engine per spec §23.1.1.
//!
//! Every operation request carries a caller-origin class. Policy may branch
//! on this class to express rules such as "an MCP request from server X
//! requires human approval, but the same operation requested directly by a
//! human does not".

use serde::{Deserialize, Serialize};

/// The origin class of an operation request.
///
/// Spoofing rules: all non-`HumanTty` classes are spoofable by a malicious
/// local process unless the transport authenticates them. Policy must not
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
    /// Request from an MCP server (transport-bound, see §33). Medium trust
    /// when local; low when remote until §33.6 is implemented.
    McpServer,
    /// Request from an agent session (self-reported session ID from a trusted
    /// integrator). Low trust — session IDs are self-reported unless bound to
    /// `HumanTty` approval.
    AgentSession,
    /// Request from the local daemon (Unix-socket peer cred on the daemon
    /// socket, §40.2). Medium trust — matches the daemon's authenticated local
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
            Self::McpServer => "mcp_server",
            Self::AgentSession => "agent_session",
            Self::DaemonLocal => "daemon_local",
            Self::Unknown => "unknown",
        }
    }

    /// Returns `true` if this origin is spoofable by a malicious local process
    /// without transport-level authentication.
    #[must_use]
    pub fn is_self_reported(&self) -> bool {
        !matches!(self, Self::HumanTty | Self::HumanIpc)
    }
}
