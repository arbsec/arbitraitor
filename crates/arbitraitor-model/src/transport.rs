//! Transport metadata recorded in fetch receipts.

use serde::{Deserialize, Serialize};

/// Outcome of redirect credential-secrecy enforcement.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RedirectCredentialSecrecy {
    /// No credential-bearing cross-protocol redirect was observed.
    #[default]
    Ok,
    /// A bearer token would have crossed into a non-HTTP redirect target.
    BearerLeaked,
    /// Cookie credentials would have crossed into a non-HTTP redirect target.
    CookieLeaked,
    /// Default `.netrc` credentials would have crossed into a non-HTTP redirect target.
    NetrcDefaultLeaked,
}
