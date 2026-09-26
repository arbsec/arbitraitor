//! Headless (non-interactive) plan-bound approval prompt family.
//!
//! Implements the store-based half of the [`ApprovalPrompt`] family requested
//! by issue #746: headless embedders (orchestrators spawning one-shot workers
//! without a TTY) register [`HeadlessApprovalPrompt`] in place of
//! [`StdinApprovalPrompt`]. The prompt never touches a terminal: every
//! approval request persists a [`PendingApprovalRecord`] into a
//! [`PendingApprovalStore`] and returns "not approved" until a trusted
//! resolver path (an embedder-owned UI calling
//! [`PendingApprovalStore::resolve`]) approves the exact canonical plan
//! digest. A later retry of the same request then mints the plan-bound token
//! exactly once per human approval.
//!
//! ADR-0013 invariant mapping:
//!
//! - **Plan-bound approval (§9 invariant 23):** records key on the canonical
//!   plan digest over `(artifact, plan, execution context)` — the same
//!   [`canonical_plan_digest`] the token issuer uses — and resolution must
//!   re-present that digest, so approval stays bound to the full plan.
//! - **Agent capability separation (H-11, §33.3):** the agent-facing MCP
//!   tools can only create pending records; resolution exists solely as this
//!   module's Rust API and is never registered as an MCP tool. The agent that
//!   proposes an operation cannot manufacture its approval.
//! - **Trusted-UI rule:** the resolver renders the record's artifact,
//!   sanitized plan text, and plan digest through the embedder's trusted UI;
//!   the issued token records `approval_method = "headless-trusted-ui"` and
//!   the resolver-attested approver identity for audit (§33.4).
//! - **Time-limited approvals:** records lapse after
//!   [`DEFAULT_PENDING_APPROVAL_LIFETIME`] (configurable on
//!   [`HeadlessApprovalPrompt`]); a lapsed record denies and must be
//!   refreshed by re-requesting. The token minted after resolution remains
//!   bounded by [`DEFAULT_APPROVAL_TOKEN_LIFETIME`].
//! - **Non-authoritative index (§9 invariant 22):** a store record never
//!   authorizes execution by itself — authority is the HMAC-signed,
//!   plan-bound, single-use token minted by `RequestApprovalTool` only after
//!   the prompt consumes an approved record.
//!
//! [`StdinApprovalPrompt`]: crate::StdinApprovalPrompt
//! [`DEFAULT_APPROVAL_TOKEN_LIFETIME`]: crate::DEFAULT_APPROVAL_TOKEN_LIFETIME

use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use arbitraitor_model::ids::Sha256Digest;
use hmac::{KeyInit, Mac as _};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use super::{
    ApprovalDecision, ApprovalPrompt, ApprovalPromptError, HmacSha256, PlanContext,
    canonical_plan_digest,
};

/// Default lifetime of a pending-approval record: one hour.
///
/// A pending record that is not resolved within its lifetime lapses: the
/// prompt fails closed and the resolver refuses stale records. This bounds
/// the *request queue*, not the signed token — the token minted after
/// resolution is bounded by [`crate::DEFAULT_APPROVAL_TOKEN_LIFETIME`].
pub const DEFAULT_PENDING_APPROVAL_LIFETIME: Duration = Duration::from_mins(60);

/// Maximum byte length of the untrusted plan text persisted per record
/// (1 MiB). Bound so a single request cannot force unbounded durable state
/// (§9 invariant 4).
const MAX_PENDING_PLAN_BYTES: usize = 1024 * 1024;

/// Maximum number of pending-approval record files a single store holds at
/// once (1000). Beyond the cap, registering a *new* request fails closed;
/// [`PendingApprovalStore::prune_expired`] is the escape hatch. See the
/// capacity notes on [`PendingApprovalStore`].
pub const MAX_PENDING_RECORDS: usize = 1000;

/// Domain-separation tag for the record authentication MAC.
const RECORD_MAC_DOMAIN: &[u8] = b"arbitraitor-mcp-headless-pending-approval-record-v1";

/// Current pending-approval record schema version.
const PENDING_APPROVAL_SCHEMA_VERSION: u32 = 1;

/// Approval method label recorded into tokens minted from a trusted headless
/// resolution. Distinct from the historical `stdin-human-confirmation` label
/// retained by the interactive prompt, so audit consumers can tell which
/// channel satisfied approval.
pub const HEADLESS_APPROVAL_METHOD: &str = "headless-trusted-ui";

/// Lifecycle state of a [`PendingApprovalRecord`].
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PendingApprovalState {
    /// Awaiting a trusted resolution.
    Pending,
    /// Approved by a trusted resolver; not yet consumed by a token issue.
    Approved,
    /// Denied by a trusted resolver. Denials are sticky until the record
    /// expires, so a retrying agent cannot spam the resolver queue.
    Denied,
    /// Approval consumed: one plan-bound token was minted from it. Any
    /// replay of the request requires a fresh human approval.
    Consumed,
}

/// Durable record of a headless approval request.
///
/// Field selection deliberately mirrors the plan-bound vocabulary of the CLI
/// approval file (ADR-0013): the record binds the artifact digest, the plan
/// text, the canonical plan digest, and the execution-context snapshot that
/// fed the digest. `human_readable_plan` is untrusted agent-provided text,
/// persisted verbatim; resolver UIs must render it escaped and bounded
/// (ADR-0016), exactly as the stdin prompt does.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PendingApprovalRecord {
    /// Record schema version.
    pub schema_version: u32,
    /// Lifecycle state.
    pub state: PendingApprovalState,
    /// SHA-256 of the artifact the plan executes (lowercase hex).
    pub artifact_sha256: String,
    /// Untrusted agent-provided plan text, persisted verbatim.
    pub human_readable_plan: String,
    /// Canonical plan digest over `(artifact, plan, execution context)`; also
    /// the record's store key and filename stem.
    pub plan_digest: String,
    /// Interpreter path bound at request time.
    pub interpreter: String,
    /// SHA-256 (hex) of the interpreter binary, or empty when unpinned.
    pub interpreter_digest: String,
    /// Whether network isolation was bound at request time.
    pub network_isolated: bool,
    /// Policy snapshot digest bound at request time, or empty.
    pub policy_snapshot_digest: String,
    /// Detector snapshot digest bound at request time, or empty.
    pub detector_snapshot_digest: String,
    /// Intelligence snapshot digest bound at request time, or empty.
    pub intelligence_snapshot_digest: String,
    /// Request timestamp (Unix seconds).
    pub requested_at_unix_seconds: u64,
    /// Record expiry (Unix seconds). After this point the record lapses: the
    /// prompt denies and [`PendingApprovalStore::resolve`] refuses it.
    pub expires_at_unix_seconds: u64,
    /// Approver identity attested by the trusted resolver (set on resolution).
    pub approver: Option<String>,
    /// Resolution timestamp (Unix seconds), set on resolution.
    pub resolved_at_unix_seconds: Option<u64>,
    /// HMAC-SHA-256 (lowercase hex) authenticating this record, keyed with
    /// the store's embedder-supplied key. Covers the canonical serialization
    /// of the record's security-relevant fields (state, approver, resolution
    /// and expiry and request timestamps, plan digest, artifact digest); the
    /// MAC field itself is excluded from the computation. Records with a
    /// missing, malformed, or mismatching MAC fail closed as
    /// [`PendingApprovalError::Corrupt`].
    pub record_mac: String,
}

/// Canonical serialization of a [`PendingApprovalRecord`]'s MAC-covered
/// fields. Field order of this struct defines the canonical byte order of
/// the MAC input, mirroring the struct-serialization canonicalization the
/// plan digest uses (`super::canonical_plan_digest`).
#[derive(Serialize)]
struct RecordMacBody<'record> {
    state: PendingApprovalState,
    approver: Option<&'record str>,
    resolved_at_unix_seconds: Option<u64>,
    expires_at_unix_seconds: u64,
    plan_digest: &'record str,
    artifact_sha256: &'record str,
    requested_at_unix_seconds: u64,
}

/// A trusted resolver's decision for a pending record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ApprovalResolution {
    /// Approve the exact plan the resolver UI displayed.
    Approve {
        /// Approver identity recorded for audit (must be non-empty).
        approver: String,
        /// Full canonical plan digest the resolver UI displayed to the
        /// operator. Must equal the stored digest; a mismatch means the
        /// record changed between listing and resolution and the resolution
        /// is refused. This is the headless counterpart of the typed
        /// plan-digest prefix the stdin prompt requires.
        expected_plan_digest: String,
    },
    /// Deny the pending record (sticky until the record expires).
    Deny {
        /// Approver identity recorded for audit (must be non-empty).
        approver: String,
        /// Displayed plan digest, as in [`Self::Approve`].
        expected_plan_digest: String,
    },
}

/// Errors from the pending-approval store.
#[derive(Debug, Error)]
pub enum PendingApprovalError {
    /// Filesystem or serialization failure; `stage` identifies the operation.
    /// Also used for fail-closed policy refusals: the stage
    /// `pending-record-capacity` rejects new requests beyond
    /// [`MAX_PENDING_RECORDS`], and stage `open` rejects an empty MAC key or
    /// (Unix) a group/world-writable store directory.
    #[error("pending-approval store failure during {stage}: {message}")]
    Store {
        /// Operation stage.
        stage: &'static str,
        /// Safe diagnostic message.
        message: String,
    },
    /// No record exists for the supplied plan digest.
    #[error("pending-approval record not found for plan digest")]
    NotFound,
    /// The record is not pending (already approved, denied, or consumed).
    #[error("pending-approval record is not pending and cannot be resolved")]
    NotResolvable,
    /// The resolver's expected plan digest does not match the stored digest.
    #[error("pending-approval plan digest mismatch: record changed between listing and resolution")]
    PlanDigestMismatch,
    /// The record fails integrity checks: stored plan fields do not reproduce
    /// its plan digest, its filename key does not match its embedded plan
    /// digest, its record MAC is missing/malformed/mismatched under the store
    /// key, or a record marked approved carries no approver identity.
    #[error(
        "pending-approval record is corrupt: stored fields are inconsistent with its plan digest"
    )]
    Corrupt,
    /// The record schema version is unsupported.
    #[error("pending-approval record schema version is unsupported: {0}")]
    UnsupportedSchema(u32),
    /// The record expired before it could be resolved.
    #[error("pending-approval record has expired")]
    Expired,
    /// A required resolution input was empty.
    #[error("pending-approval resolution missing required field: {field}")]
    MissingField {
        /// Name of the missing field.
        field: &'static str,
    },
    /// The untrusted plan text exceeds the per-record size bound.
    #[error("pending-approval plan text exceeds the {max} byte limit")]
    PlanTooLarge {
        /// Maximum permitted plan byte length.
        max: usize,
    },
}

/// Durable pending-approval store: one JSON record per canonical plan digest
/// in a dedicated directory.
///
/// ## Location and retention
///
/// The directory is chosen by the embedder at construction;
/// [`Self::default_dir`] documents the conventional location,
/// `$HOME/.arbitraitor/pending-approvals/`, alongside the receipt directory
/// and CAS state the CLI already materializes under `~/.arbitraitor/`.
/// Records carry the TTL configured on [`HeadlessApprovalPrompt`]
/// ([`DEFAULT_PENDING_APPROVAL_LIFETIME`] by default): a record lives until
/// it is consumed, lapses, or is removed by [`Self::prune_expired`]. There is
/// no further retention policy.
///
/// ## Trust model (ADR-0013, §33.3, §9 invariant 22)
///
/// Approval authority stays separated by capability surface: agent-facing MCP
/// tools can only create pending records and re-read their state through
/// [`HeadlessApprovalPrompt`]; resolution is reachable only through this
/// store's Rust API, which is never exposed as an MCP tool. A record on disk
/// never authorizes execution by itself: spending approval requires the
/// HMAC-signed, plan-bound, single-use token minted by `RequestApprovalTool`
/// after the prompt consumes the approved record.
///
/// ### Record authentication (HMAC-SHA-256)
///
/// Every record carries an HMAC-SHA-256 over the canonical serialization of
/// its security-relevant fields (state, approver, resolution, expiry, and
/// request timestamps, plan digest, artifact digest), keyed with the `key`
/// handed to [`Self::open`]. The embedder generates the key and distributes
/// it to the MCP server process and the trusted resolver; the key MUST
/// never be persisted adjacent to the store and MUST NOT be derivable from
/// store contents. The MAC defends record integrity against tampering or
/// forgery by processes that do not hold the key — in particular
/// agent-side workers that share the OS user owning the store directory —
/// so a planted "approved" record cannot mint a token. It does NOT protect
/// against a key-holder: any process with the key can mint approvals, so
/// key disclosure is resolver compromise. Records with a missing, malformed,
/// or mismatching MAC fail closed as [`PendingApprovalError::Corrupt`] on
/// [`Self::get`], [`Self::list_pending`], [`Self::resolve`], and the
/// prompt's consume path; [`Self::prune_expired`] instead removes them as
/// fail-safe housekeeping (removal grants nothing by itself).
///
/// ### Filesystem posture
///
/// The store directory MUST NOT be writable by any agent-side process:
/// [`Self::open`] refuses group- or world-writable directories on Unix
/// (mode masked with `0o022`). Record files, temporary files, and consumed
/// markers are created `0600`; record writes are atomic
/// create-new-then-rename, so a reader never observes a torn record.
/// Temporary files are named `{digest}.json.tmp-{pid}`; a stale temporary
/// file left by a crashed writer is reclaimed by the next write.
///
/// ### Consumption markers
///
/// Consuming an approval creates an exclusive `{digest}.consumed` marker
/// *before* the approval decision is reported, so two processes racing the
/// same approved record produce exactly one grant. A pre-existing marker
/// for a live record (a cross-process race winner, or the survivor of a
/// crash between claiming and committing) fails closed: the stale approval
/// is treated as already consumed and a fresh pending record is registered
/// for a future approval. A marker is permanent while its record lives ("one
/// approval = one grant ever", across restarts); [`Self::prune_expired`]
/// removes a marker only together with its record or once the record no
/// longer exists.
///
/// ### Capacity
///
/// The store admits at most [`MAX_PENDING_RECORDS`] record files; beyond
/// the cap a new request fails closed with [`PendingApprovalError::Store`]
/// (stage `pending-record-capacity`) and no token is minted. The cap counts
/// record files in the directory regardless of state or expiry —
/// expired-but-unpruned records still count against it — while `resolve`
/// and consumption of an existing record are unaffected. [`Self::prune_expired`]
/// is the escape hatch that frees capacity.
#[derive(Clone)]
pub struct PendingApprovalStore {
    dir: PathBuf,
    mac_key: Arc<[u8]>,
    lock: Arc<Mutex<()>>,
}

impl PendingApprovalStore {
    /// Opens (creating it if needed) the pending-approval store rooted at
    /// `dir`, authenticating records with `mac_key`. On Unix a newly created
    /// directory has `0700` permissions, and `open` refuses an existing
    /// directory that is writable by group or others.
    ///
    /// The embedder owns `mac_key` lifecycle: the same key must reach the
    /// MCP server process and the trusted resolver, must never be persisted
    /// adjacent to the store, and must not be derivable from store contents.
    ///
    /// # Errors
    ///
    /// Returns [`PendingApprovalError::Store`] when the directory cannot be
    /// created, the path exists and is not a directory, the directory is
    /// group- or world-writable (Unix), or the key is empty.
    pub fn open(dir: impl Into<PathBuf>, mac_key: Arc<[u8]>) -> Result<Self, PendingApprovalError> {
        let dir = dir.into();
        if mac_key.is_empty() {
            return Err(PendingApprovalError::Store {
                stage: "open",
                message: "pending-approval record MAC key must not be empty".to_owned(),
            });
        }
        if !dir.exists() {
            create_restricted_dir(&dir)?;
        }
        if !dir.is_dir() {
            return Err(PendingApprovalError::Store {
                stage: "open",
                message: "pending-approval store path exists and is not a directory".to_owned(),
            });
        }
        refuse_permissive_dir(&dir)?;
        Ok(Self {
            dir,
            mac_key,
            lock: Arc::new(Mutex::new(())),
        })
    }

    /// Conventional store directory: `$HOME/.arbitraitor/pending-approvals/`.
    ///
    /// # Errors
    ///
    /// Returns [`PendingApprovalError::Store`] when `HOME` is not set.
    pub fn default_dir() -> Result<PathBuf, PendingApprovalError> {
        std::env::var_os("HOME")
            .map(PathBuf::from)
            .map(|home| home.join(".arbitraitor").join("pending-approvals"))
            .ok_or(PendingApprovalError::Store {
                stage: "default-dir",
                message: "HOME is not set".to_owned(),
            })
    }

    /// Returns the record stored for `plan_digest`, if any.
    ///
    /// # Errors
    ///
    /// Returns [`PendingApprovalError::Store`] on I/O or JSON failure,
    /// [`PendingApprovalError::UnsupportedSchema`] on a foreign schema
    /// version, and [`PendingApprovalError::Corrupt`] when the record's plan
    /// fields no longer reproduce its plan digest.
    pub fn get(
        &self,
        plan_digest: &str,
    ) -> Result<Option<PendingApprovalRecord>, PendingApprovalError> {
        match self.read_record(plan_digest)? {
            Some(record) => {
                self.verify_record_integrity(&record)?;
                Ok(Some(record))
            }
            None => Ok(None),
        }
    }

    /// Lists records that are pending and unexpired at `now`, ordered oldest
    /// first, for rendering by a trusted resolver UI. Files that are not
    /// valid record names (for example in-flight temporary files) are
    /// skipped.
    ///
    /// # Errors
    ///
    /// Returns [`PendingApprovalError::Store`] when the directory or a record
    /// cannot be read, and [`PendingApprovalError::Corrupt`] /
    /// [`PendingApprovalError::UnsupportedSchema`] when any record fails
    /// integrity checks: one bad record must not let the UI resolve the rest
    /// on partial knowledge.
    pub fn list_pending(
        &self,
        now: SystemTime,
    ) -> Result<Vec<PendingApprovalRecord>, PendingApprovalError> {
        let now_seconds = unix_seconds(now)?;
        let entries =
            std::fs::read_dir(&self.dir).map_err(|error| PendingApprovalError::Store {
                stage: "read-dir",
                message: error.to_string(),
            })?;
        let mut records = Vec::new();
        for entry in entries {
            let entry = entry.map_err(|error| PendingApprovalError::Store {
                stage: "read-dir-entry",
                message: error.to_string(),
            })?;
            let file_name = entry.file_name();
            let Some(name) = file_name.to_str() else {
                continue;
            };
            let Some(stem) = name.strip_suffix(".json") else {
                continue;
            };
            let Ok(key) = normalize_plan_digest_key(stem) else {
                continue;
            };
            let Some(record) = self.read_record(&key)? else {
                continue;
            };
            self.verify_record_integrity(&record)?;
            if record.state == PendingApprovalState::Pending
                && now_seconds < record.expires_at_unix_seconds
            {
                records.push(record);
            }
        }
        records.sort_by_key(|record| record.requested_at_unix_seconds);
        Ok(records)
    }

    /// Resolves a pending record with a trusted decision.
    ///
    /// The record must be pending and unexpired at `now`, the resolution's
    /// `expected_plan_digest` must equal the record's canonical plan digest
    /// (the digest the resolver UI rendered to the operator), and the record
    /// must pass integrity recomputation. Any violation leaves the record on
    /// disk untouched, so a mismatched or tampered record never silently
    /// gains a decision.
    ///
    /// # Errors
    ///
    /// Returns [`PendingApprovalError::MissingField`] for an empty approver,
    /// [`PendingApprovalError::NotFound`] when no record exists,
    /// [`PendingApprovalError::NotResolvable`] unless the record is pending,
    /// [`PendingApprovalError::PlanDigestMismatch`] when the displayed digest
    /// does not match, [`PendingApprovalError::Corrupt`] /
    /// [`PendingApprovalError::UnsupportedSchema`] on integrity failure,
    /// [`PendingApprovalError::Expired`] when the record lapsed, and
    /// [`PendingApprovalError::Store`] on I/O or serialization failure.
    pub fn resolve(
        &self,
        plan_digest: &str,
        resolution: ApprovalResolution,
        now: SystemTime,
    ) -> Result<PendingApprovalRecord, PendingApprovalError> {
        let is_approval = matches!(resolution, ApprovalResolution::Approve { .. });
        let (approver, expected_plan_digest) = match resolution {
            ApprovalResolution::Approve {
                approver,
                expected_plan_digest,
            }
            | ApprovalResolution::Deny {
                approver,
                expected_plan_digest,
            } => (approver, expected_plan_digest),
        };
        if approver.is_empty() {
            return Err(PendingApprovalError::MissingField { field: "approver" });
        }
        let key = normalize_plan_digest_key(plan_digest)?;
        let now_seconds = unix_seconds(now)?;
        let _guard = self.store_lock()?;
        let mut record = self
            .read_record(&key)?
            .ok_or(PendingApprovalError::NotFound)?;
        self.verify_record_integrity(&record)?;
        if record.plan_digest != expected_plan_digest {
            return Err(PendingApprovalError::PlanDigestMismatch);
        }
        if now_seconds >= record.expires_at_unix_seconds {
            return Err(PendingApprovalError::Expired);
        }
        if record.state != PendingApprovalState::Pending {
            return Err(PendingApprovalError::NotResolvable);
        }
        record.state = if is_approval {
            PendingApprovalState::Approved
        } else {
            PendingApprovalState::Denied
        };
        record.approver = Some(approver);
        record.resolved_at_unix_seconds = Some(now_seconds);
        self.write_record(&mut record)?;
        Ok(record)
    }

    /// Removes every record whose expiry has passed at `now`, returning how
    /// many records were removed. Lapsed records fail closed even before
    /// pruning; this is housekeeping so resolver queues and disk do not
    /// accumulate dead records and the [`MAX_PENDING_RECORDS`] capacity cap
    /// can be freed.
    ///
    /// Pruning also removes records that fail integrity verification. Removal
    /// is fail-safe — a record authorizes nothing by itself — so planted junk
    /// (unparseable, wrong MAC, or filename/digest mismatch) is deleted rather
    /// than blocking housekeeping forever; the failing paths (get, list,
    /// resolve, consume) still fail closed on the same records.
    ///
    /// Finally, orphaned `.consumed` markers (whose record no longer exists)
    /// are removed. Marker removal is not included in the returned count, and
    /// markers of records that survive this pass are kept.
    ///
    /// # Errors
    ///
    /// Returns [`PendingApprovalError::Store`] when the directory or a record
    /// cannot be read or a record cannot be removed.
    pub fn prune_expired(&self, now: SystemTime) -> Result<usize, PendingApprovalError> {
        let now_seconds = unix_seconds(now)?;
        let entries =
            std::fs::read_dir(&self.dir).map_err(|error| PendingApprovalError::Store {
                stage: "read-dir",
                message: error.to_string(),
            })?;
        let mut removed = 0;
        for entry in entries {
            let entry = entry.map_err(|error| PendingApprovalError::Store {
                stage: "read-dir-entry",
                message: error.to_string(),
            })?;
            let file_name = entry.file_name();
            let Some(name) = file_name.to_str() else {
                continue;
            };
            let Some(stem) = name.strip_suffix(".json") else {
                continue;
            };
            let Ok(key) = normalize_plan_digest_key(stem) else {
                continue;
            };
            let remove = match self.read_record(&key) {
                Ok(Some(record)) => match self.verify_record_integrity(&record) {
                    Ok(()) => now_seconds >= record.expires_at_unix_seconds,
                    Err(_) => true,
                },
                Ok(None) => continue,
                Err(_) => true,
            };
            if remove {
                std::fs::remove_file(entry.path()).map_err(|error| {
                    PendingApprovalError::Store {
                        stage: "prune-record",
                        message: error.to_string(),
                    }
                })?;
                removed += 1;
            }
        }
        self.prune_orphaned_markers()?;
        Ok(removed)
    }

    /// Removes `.consumed` markers whose record file no longer exists.
    fn prune_orphaned_markers(&self) -> Result<(), PendingApprovalError> {
        let entries =
            std::fs::read_dir(&self.dir).map_err(|error| PendingApprovalError::Store {
                stage: "read-dir",
                message: error.to_string(),
            })?;
        for entry in entries {
            let entry = entry.map_err(|error| PendingApprovalError::Store {
                stage: "read-dir-entry",
                message: error.to_string(),
            })?;
            let file_name = entry.file_name();
            let Some(name) = file_name.to_str() else {
                continue;
            };
            let Some(stem) = name.strip_suffix(".consumed") else {
                continue;
            };
            let Ok(key) = normalize_plan_digest_key(stem) else {
                continue;
            };
            if !self.record_path(&key).exists() {
                std::fs::remove_file(entry.path()).map_err(|error| {
                    PendingApprovalError::Store {
                        stage: "prune-consumed-marker",
                        message: error.to_string(),
                    }
                })?;
            }
        }
        Ok(())
    }

    fn record_path(&self, key: &str) -> PathBuf {
        self.dir.join(format!("{key}.json"))
    }

    fn consumed_marker_path(&self, key: &str) -> PathBuf {
        self.dir.join(format!("{key}.consumed"))
    }

    fn read_record(
        &self,
        plan_digest: &str,
    ) -> Result<Option<PendingApprovalRecord>, PendingApprovalError> {
        let key = normalize_plan_digest_key(plan_digest)?;
        let path = self.record_path(&key);
        let bytes = match std::fs::read(&path) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => {
                return Err(PendingApprovalError::Store {
                    stage: "read-record",
                    message: error.to_string(),
                });
            }
        };
        let record: PendingApprovalRecord =
            serde_json::from_slice(&bytes).map_err(|error| PendingApprovalError::Store {
                stage: "parse-record",
                message: error.to_string(),
            })?;
        // A record whose embedded plan digest does not match its filename key
        // is a mixed-up or copied file; fail closed as corrupt.
        if normalize_plan_digest_key(&record.plan_digest)? != key {
            return Err(PendingApprovalError::Corrupt);
        }
        Ok(Some(record))
    }

    /// Number of live record files in the store directory. Counts files
    /// regardless of record state or expiry; temporary files and consumed
    /// markers are excluded by their suffixes.
    fn pending_record_count(&self) -> Result<usize, PendingApprovalError> {
        let entries =
            std::fs::read_dir(&self.dir).map_err(|error| PendingApprovalError::Store {
                stage: "read-dir",
                message: error.to_string(),
            })?;
        let mut count = 0;
        for entry in entries {
            let entry = entry.map_err(|error| PendingApprovalError::Store {
                stage: "read-dir-entry",
                message: error.to_string(),
            })?;
            let file_name = entry.file_name();
            let Some(name) = file_name.to_str() else {
                continue;
            };
            let Some(stem) = name.strip_suffix(".json") else {
                continue;
            };
            if normalize_plan_digest_key(stem).is_ok() {
                count += 1;
            }
        }
        Ok(count)
    }

    /// Recomputes the record MAC and atomically commits the record. Every
    /// write path re-signs under the caller's store lock, so a state
    /// transition can never persist an unauthenticated mutation.
    fn write_record(&self, record: &mut PendingApprovalRecord) -> Result<(), PendingApprovalError> {
        record.record_mac = self.compute_record_mac(record)?;
        let bytes =
            serde_json::to_vec_pretty(record).map_err(|error| PendingApprovalError::Store {
                stage: "encode-record",
                message: error.to_string(),
            })?;
        let target = self.record_path(&record.plan_digest);
        let tmp = self.dir.join(format!(
            "{}.json.tmp-{}",
            record.plan_digest,
            std::process::id()
        ));
        // `create_new` (not plain `fs::write`) prevents truncating a file we
        // did not create; a stale temp file from a crashed earlier writer is
        // reclaimed once and then creation is retried.
        let mut file = match create_fresh_file(&tmp) {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                std::fs::remove_file(&tmp).map_err(|error| PendingApprovalError::Store {
                    stage: "reclaim-temp-record",
                    message: error.to_string(),
                })?;
                create_fresh_file(&tmp).map_err(|error| PendingApprovalError::Store {
                    stage: "write-record",
                    message: error.to_string(),
                })?
            }
            Err(error) => {
                return Err(PendingApprovalError::Store {
                    stage: "write-record",
                    message: error.to_string(),
                });
            }
        };
        file.write_all(&bytes)
            .map_err(|error| PendingApprovalError::Store {
                stage: "write-record",
                message: error.to_string(),
            })?;
        drop(file);
        // Belt-and-braces: the file was already created `0600` on Unix.
        set_owner_only_permissions(&tmp)?;
        std::fs::rename(&tmp, &target).map_err(|error| PendingApprovalError::Store {
            stage: "commit-record",
            message: error.to_string(),
        })
    }

    /// HMAC-SHA-256 over the canonical serialization of the record's
    /// MAC-covered fields (everything in [`RecordMacBody`]; the MAC field
    /// itself is excluded). Mirrors the struct-serialization canonicalization
    /// `super::canonical_plan_digest` uses.
    fn compute_record_mac(
        &self,
        record: &PendingApprovalRecord,
    ) -> Result<String, PendingApprovalError> {
        let body = RecordMacBody {
            state: record.state,
            approver: record.approver.as_deref(),
            resolved_at_unix_seconds: record.resolved_at_unix_seconds,
            expires_at_unix_seconds: record.expires_at_unix_seconds,
            plan_digest: &record.plan_digest,
            artifact_sha256: &record.artifact_sha256,
            requested_at_unix_seconds: record.requested_at_unix_seconds,
        };
        let canonical = serde_json::to_vec(&body).map_err(|error| PendingApprovalError::Store {
            stage: "encode-record-mac",
            message: error.to_string(),
        })?;
        let mut mac =
            HmacSha256::new_from_slice(&self.mac_key).map_err(|_| PendingApprovalError::Store {
                stage: "record-mac-key",
                message: "record MAC key is rejected by HMAC-SHA-256".to_owned(),
            })?;
        mac.update(RECORD_MAC_DOMAIN);
        mac.update(&canonical);
        Ok(hex::encode(mac.finalize().into_bytes()))
    }

    /// Verifies the record's MAC against the store key using the `hmac`
    /// crate's constant-time tag comparison, after the structural checks in
    /// [`Self::verify_record_integrity`]. Any mismatch fails closed as
    /// [`PendingApprovalError::Corrupt`].
    fn verify_record_mac(
        &self,
        record: &PendingApprovalRecord,
    ) -> Result<(), PendingApprovalError> {
        let stored = hex::decode(&record.record_mac).map_err(|_| PendingApprovalError::Corrupt)?;
        let body = RecordMacBody {
            state: record.state,
            approver: record.approver.as_deref(),
            resolved_at_unix_seconds: record.resolved_at_unix_seconds,
            expires_at_unix_seconds: record.expires_at_unix_seconds,
            plan_digest: &record.plan_digest,
            artifact_sha256: &record.artifact_sha256,
            requested_at_unix_seconds: record.requested_at_unix_seconds,
        };
        let canonical = serde_json::to_vec(&body).map_err(|error| PendingApprovalError::Store {
            stage: "encode-record-mac",
            message: error.to_string(),
        })?;
        let mut mac =
            HmacSha256::new_from_slice(&self.mac_key).map_err(|_| PendingApprovalError::Store {
                stage: "record-mac-key",
                message: "record MAC key is rejected by HMAC-SHA-256".to_owned(),
            })?;
        mac.update(RECORD_MAC_DOMAIN);
        mac.update(&canonical);
        mac.verify_slice(&stored)
            .map_err(|_| PendingApprovalError::Corrupt)
    }

    /// Structural and authenticity checks applied on every record read path.
    fn verify_record_integrity(
        &self,
        record: &PendingApprovalRecord,
    ) -> Result<(), PendingApprovalError> {
        verify_record_integrity(record)?;
        self.verify_record_mac(record)
    }

    /// Verifies the full record (structural integrity + MAC). Test-only hook
    /// that re-signs a record whose fields were legitimately changed under
    /// test control (for example time-travelled expiry).
    #[cfg(test)]
    pub(crate) fn re_seal(
        &self,
        record: &mut PendingApprovalRecord,
    ) -> Result<(), PendingApprovalError> {
        self.write_record(record)
    }

    /// Atomically claims consumption for `key`. Returns `false` when the
    /// marker already exists (another process won the race, or a crashed
    /// consumer left it behind); the caller then fails closed.
    fn claim_consumption(&self, key: &str) -> Result<bool, PendingApprovalError> {
        match create_fresh_file(&self.consumed_marker_path(key)) {
            Ok(_) => Ok(true),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => Ok(false),
            Err(error) => Err(PendingApprovalError::Store {
                stage: "create-consumed-marker",
                message: error.to_string(),
            }),
        }
    }

    #[cfg(test)]
    pub(crate) fn has_consumed_marker(
        &self,
        plan_digest: &str,
    ) -> Result<bool, PendingApprovalError> {
        let key = normalize_plan_digest_key(plan_digest)?;
        Ok(self.consumed_marker_path(&key).exists())
    }

    fn store_lock(&self) -> Result<std::sync::MutexGuard<'_, ()>, PendingApprovalError> {
        self.lock.lock().map_err(|_| PendingApprovalError::Store {
            stage: "store-lock",
            message: "pending-approval store lock is poisoned".to_owned(),
        })
    }

    fn persist_fresh_pending(
        &self,
        sha256: &Sha256Digest,
        plan: &str,
        ctx: &PlanContext,
        plan_digest: &str,
        requested_at_unix_seconds: u64,
        expires_at_unix_seconds: u64,
    ) -> Result<(), PendingApprovalError> {
        // Capacity cap: refuse to create a *new* record file once the store
        // already holds MAX_PENDING_RECORDS files. Refreshes of an existing
        // digest rewrite the same file and do not count against the cap.
        if !self.record_path(plan_digest).exists()
            && self.pending_record_count()? >= MAX_PENDING_RECORDS
        {
            return Err(PendingApprovalError::Store {
                stage: "pending-record-capacity",
                message: format!(
                    "pending-approval store holds the maximum of {MAX_PENDING_RECORDS} \
                     records; prune_expired frees capacity"
                ),
            });
        }
        let mut record = PendingApprovalRecord {
            schema_version: PENDING_APPROVAL_SCHEMA_VERSION,
            state: PendingApprovalState::Pending,
            artifact_sha256: sha256.to_string(),
            human_readable_plan: plan.to_owned(),
            plan_digest: plan_digest.to_owned(),
            interpreter: ctx.interpreter.clone(),
            interpreter_digest: ctx.interpreter_digest.clone(),
            network_isolated: ctx.network_isolated,
            policy_snapshot_digest: ctx.policy_snapshot_digest.clone(),
            detector_snapshot_digest: ctx.detector_snapshot_digest.clone(),
            intelligence_snapshot_digest: ctx.intelligence_snapshot_digest.clone(),
            requested_at_unix_seconds,
            expires_at_unix_seconds,
            approver: None,
            resolved_at_unix_seconds: None,
            record_mac: String::new(),
        };
        self.write_record(&mut record)
    }

    /// Registers the request when no live resolution exists and applies any
    /// stored resolution, consuming an approval at most once.
    ///
    /// Transition table (everything not listed as approving fails closed):
    ///
    /// | Stored record            | Action                      | Outcome   |
    /// |--------------------------|-----------------------------|-----------|
    /// | none                     | create fresh `Pending`      | Pending   |
    /// | Pending, unexpired       | none                        | Pending   |
    /// | Pending, expired         | refresh with new TTL        | Pending   |
    /// | Denied, unexpired        | none (sticky denial)        | Denied    |
    /// | Denied, expired          | refresh to `Pending`        | Pending   |
    /// | Approved, unexpired      | mark `Consumed`             | Approved  |
    /// | Approved, expired        | lapse: refresh to `Pending` | Pending   |
    /// | Consumed (any)           | new request ⇒ `Pending`     | Pending   |
    ///
    /// A single human approval therefore mints at most one token: the record
    /// becomes `Consumed` in the same locked transaction that reports the
    /// approval, and the next request starts a fresh pending record.
    pub(crate) fn register_or_consume(
        &self,
        sha256: &Sha256Digest,
        plan: &str,
        ctx: &PlanContext,
        now: SystemTime,
        lifetime: Duration,
    ) -> Result<HeadlessOutcome, PendingApprovalError> {
        if plan.len() > MAX_PENDING_PLAN_BYTES {
            return Err(PendingApprovalError::PlanTooLarge {
                max: MAX_PENDING_PLAN_BYTES,
            });
        }
        let plan_digest = canonical_plan_digest(sha256, plan, ctx).map_err(|error| {
            PendingApprovalError::Store {
                stage: "canonical-plan-digest",
                message: error.to_string(),
            }
        })?;
        let now_seconds = unix_seconds(now)?;
        let expires_at_unix_seconds = unix_seconds(now.checked_add(lifetime).ok_or(
            PendingApprovalError::Store {
                stage: "expiry-overflow",
                message: "pending lifetime overflows system time".to_owned(),
            },
        )?)?;
        let _guard = self.store_lock()?;
        if let Some(mut record) = self.read_record(&plan_digest)? {
            self.verify_record_integrity(&record)?;
            let expired = now_seconds >= record.expires_at_unix_seconds;
            match (record.state, expired) {
                (PendingApprovalState::Approved, false) => {
                    // Cross-process exclusivity: claim the consumption marker
                    // before reporting the approval. The in-process Mutex above
                    // already serializes same-process consumes; the
                    // `create_new` marker extends exactly-once across separate
                    // store handles/processes sharing this directory.
                    if !self.claim_consumption(&plan_digest)? {
                        // The marker already exists: another process consumed
                        // (or crashed mid-claim) this approval. Treat the stale
                        // approval as consumed and register a fresh pending
                        // record for a future approval.
                        self.persist_fresh_pending(
                            sha256,
                            plan,
                            ctx,
                            &plan_digest,
                            now_seconds,
                            expires_at_unix_seconds,
                        )?;
                        return Ok(HeadlessOutcome::Pending);
                    }
                    let approver = record
                        .approver
                        .clone()
                        .ok_or(PendingApprovalError::Corrupt)?;
                    record.state = PendingApprovalState::Consumed;
                    self.write_record(&mut record)?;
                    Ok(HeadlessOutcome::Approved { approver })
                }
                (PendingApprovalState::Denied, false) => Ok(HeadlessOutcome::Denied),
                (PendingApprovalState::Pending, false) => Ok(HeadlessOutcome::Pending),
                (..) => {
                    self.persist_fresh_pending(
                        sha256,
                        plan,
                        ctx,
                        &plan_digest,
                        now_seconds,
                        expires_at_unix_seconds,
                    )?;
                    Ok(HeadlessOutcome::Pending)
                }
            }
        } else {
            self.persist_fresh_pending(
                sha256,
                plan,
                ctx,
                &plan_digest,
                now_seconds,
                expires_at_unix_seconds,
            )?;
            Ok(HeadlessOutcome::Pending)
        }
    }
}

/// Outcome of registering a request against the store.
pub(crate) enum HeadlessOutcome {
    /// The request is pending trusted resolution.
    Pending,
    /// A trusted resolver denied the request; the denial is sticky until the
    /// record expires.
    Denied,
    /// A trusted resolver approved the request and this call consumed it.
    Approved {
        /// Approver identity attested by the resolver.
        approver: String,
    },
}

/// Headless, non-interactive [`ApprovalPrompt`] implementation: persists each
/// approval request as a [`PendingApprovalRecord`] and lets a trusted
/// resolution flow back on retry.
///
/// # Opt-in wiring
///
/// `HeadlessApprovalPrompt` is never part of the default server registration;
/// interactive runs keep [`StdinApprovalPrompt`]. A headless embedder
/// constructs the store and prompt explicitly and registers the approval
/// tools itself:
///
/// ```no_run
/// # use std::sync::Arc;
/// # use arbitraitor_mcp::{
/// #     ApprovalTokenIssuer, HeadlessApprovalPrompt, InMemoryArtifactStore, McpServer,
/// #     PendingApprovalStore, PlanContext, RequestApprovalTool, RunApprovedArtifactTool,
/// # };
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// // The embedder generates the record MAC key and hands the same bytes to the
/// // MCP server process and the trusted resolver; it is never persisted next
/// // to the store (see the `PendingApprovalStore` trust model).
/// let record_mac_key: Arc<[u8]> = Arc::from(&b"embedder-managed record MAC key"[..]);
/// let store = PendingApprovalStore::open(PendingApprovalStore::default_dir()?, record_mac_key)?;
/// let prompt = Arc::new(HeadlessApprovalPrompt::new(store.clone()));
/// let issuer = ApprovalTokenIssuer::new();
/// let mut server = McpServer::new();
/// server.register(Box::new(RequestApprovalTool::with_prompt(
///     prompt,
///     issuer.clone(),
///     PlanContext::for_bash(true, ""),
/// )));
/// server.register(Box::new(RunApprovedArtifactTool::new(
///     Arc::new(InMemoryArtifactStore::new()),
///     issuer,
/// )));
/// // The trusted resolver UI lists and resolves records out of band:
/// let pending = store.list_pending(std::time::SystemTime::now())?;
/// # Ok(())
/// # }
/// ```
///
/// The type performs no terminal I/O: it never reads stdin and never writes
/// to a TTY, which is what makes it safe to embed under daemons, CI runners,
/// and one-shot orchestrator workers whose standard streams are closed.
///
/// [`StdinApprovalPrompt`]: crate::StdinApprovalPrompt
#[derive(Clone)]
pub struct HeadlessApprovalPrompt {
    store: PendingApprovalStore,
    pending_lifetime: Duration,
}

impl HeadlessApprovalPrompt {
    /// Creates a headless prompt over `store` with the default pending-record
    /// lifetime ([`DEFAULT_PENDING_APPROVAL_LIFETIME`]).
    #[must_use]
    pub const fn new(store: PendingApprovalStore) -> Self {
        Self {
            store,
            pending_lifetime: DEFAULT_PENDING_APPROVAL_LIFETIME,
        }
    }

    /// Overrides the pending-record lifetime. A zero lifetime creates records
    /// that expire immediately (fail-closed; useful in tests).
    #[must_use]
    pub const fn with_pending_lifetime(mut self, lifetime: Duration) -> Self {
        self.pending_lifetime = lifetime;
        self
    }

    /// Returns the backing store so the *trusted resolver path* can list,
    /// resolve, and prune records. Sharing the store is by design: the same
    /// Rust process typically embeds both the MCP server and its resolver UI,
    /// and nothing on the MCP tool surface can reach this API.
    #[must_use]
    pub const fn store(&self) -> &PendingApprovalStore {
        &self.store
    }
}

impl ApprovalPrompt for HeadlessApprovalPrompt {
    fn request_confirmation(
        &self,
        sha256: &Sha256Digest,
        plan: &str,
        ctx: &PlanContext,
    ) -> Result<bool, ApprovalPromptError> {
        Ok(self
            .request_confirmation_attested(sha256, plan, ctx)?
            .approved)
    }

    fn request_confirmation_attested(
        &self,
        sha256: &Sha256Digest,
        plan: &str,
        ctx: &PlanContext,
    ) -> Result<ApprovalDecision, ApprovalPromptError> {
        let outcome = self
            .store
            .register_or_consume(sha256, plan, ctx, SystemTime::now(), self.pending_lifetime)
            .map_err(|error| ApprovalPromptError::Write {
                stage: "pending-approval-store",
                message: error.to_string(),
            })?;
        let HeadlessOutcome::Approved { approver } = outcome else {
            return Ok(ApprovalDecision {
                approved: false,
                approval_method: HEADLESS_APPROVAL_METHOD.to_owned(),
                approver_identity: None,
            });
        };
        Ok(ApprovalDecision {
            approved: true,
            approval_method: HEADLESS_APPROVAL_METHOD.to_owned(),
            approver_identity: Some(approver),
        })
    }
}

fn unix_seconds(time: SystemTime) -> Result<u64, PendingApprovalError> {
    time.duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|_| PendingApprovalError::Store {
            stage: "time-before-epoch",
            message: "system time precedes the Unix epoch".to_owned(),
        })
}

fn normalize_plan_digest_key(plan_digest: &str) -> Result<String, PendingApprovalError> {
    let key = plan_digest.to_ascii_lowercase();
    let valid = key.len() == 64 && key.bytes().all(|byte| byte.is_ascii_hexdigit());
    if valid {
        Ok(key)
    } else {
        Err(PendingApprovalError::Store {
            stage: "plan-digest-key",
            message: "plan digest keys must be 64 hexadecimal characters".to_owned(),
        })
    }
}

fn verify_record_integrity(record: &PendingApprovalRecord) -> Result<(), PendingApprovalError> {
    if record.schema_version != PENDING_APPROVAL_SCHEMA_VERSION {
        return Err(PendingApprovalError::UnsupportedSchema(
            record.schema_version,
        ));
    }
    let sha256: Sha256Digest = record
        .artifact_sha256
        .parse()
        .map_err(|_| PendingApprovalError::Corrupt)?;
    let ctx = PlanContext {
        interpreter: record.interpreter.clone(),
        interpreter_digest: record.interpreter_digest.clone(),
        network_isolated: record.network_isolated,
        policy_snapshot_digest: record.policy_snapshot_digest.clone(),
        detector_snapshot_digest: record.detector_snapshot_digest.clone(),
        intelligence_snapshot_digest: record.intelligence_snapshot_digest.clone(),
    };
    let recomputed =
        canonical_plan_digest(&sha256, &record.human_readable_plan, &ctx).map_err(|error| {
            PendingApprovalError::Store {
                stage: "recompute-plan-digest",
                message: error.to_string(),
            }
        })?;
    if recomputed != record.plan_digest {
        return Err(PendingApprovalError::Corrupt);
    }
    Ok(())
}

/// Create-new file with owner-only permissions on Unix. Used for record
/// temporary files and `.consumed` markers; `AlreadyExists` is surfaced to
/// the caller, which decides between fail-closed refuse and reclaim.
fn create_fresh_file(path: &Path) -> std::io::Result<std::fs::File> {
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    options.open(path)
}

/// Refuses to open a pending-approval store in a directory writable by
/// group or others (Unix). A permissive store directory lets any local
/// process plant, rename, or delete records and consumed markers, so opening
/// fails closed rather than trusting content the MAC alone cannot fully
/// police (deletion is a denial the MAC cannot authenticate).
fn refuse_permissive_dir(dir: &Path) -> Result<(), PendingApprovalError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let metadata = std::fs::metadata(dir).map_err(|error| PendingApprovalError::Store {
            stage: "open",
            message: error.to_string(),
        })?;
        if metadata.permissions().mode() & 0o022 != 0 {
            return Err(PendingApprovalError::Store {
                stage: "open",
                message: format!(
                    "pending-approval store directory {} is writable by group or others; \
                     tighten permissions (e.g. chmod 0700) before opening",
                    dir.display()
                ),
            });
        }
    }
    let _ = dir;
    Ok(())
}

fn create_restricted_dir(dir: &Path) -> Result<(), PendingApprovalError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(dir)
            .map_err(|error| PendingApprovalError::Store {
                stage: "create-dir",
                message: error.to_string(),
            })
    }
    #[cfg(not(unix))]
    {
        std::fs::create_dir_all(dir).map_err(|error| PendingApprovalError::Store {
            stage: "create-dir",
            message: error.to_string(),
        })
    }
}

fn set_owner_only_permissions(path: &Path) -> Result<(), PendingApprovalError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).map_err(|error| {
            PendingApprovalError::Store {
                stage: "restrict-record",
                message: error.to_string(),
            }
        })
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        Ok(())
    }
}
