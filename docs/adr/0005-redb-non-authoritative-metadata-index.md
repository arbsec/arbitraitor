# ADR 0005: redb as non-authoritative metadata index

**Status:** Accepted
**Date:** 2026-06-16
**Issue:** #12

## Context

Arbitraitor needs a metadata index to accelerate digest-to-metadata lookups,
manage retention leases, and index receipts. The adversarial review (H-05)
identified that a metadata database must never become an authorization oracle:
no database row should be sufficient proof that an artifact was approved.

## Decision

Use **`redb`** as the metadata index, with the explicit constraint that it is
**non-authoritative for all security decisions**.

**Storage layout:**

```text
store/
  objects/sha256/ab/cd/<digest>    ← artifact bytes (ordinary files)
  metadata.redb                     ← rebuildable index/cache
  staging/                          ← incomplete objects
  locks/                            ← per-digest leases
  receipts/                         ← immutable signed receipts
```

**Authority model:**

| Component | Authoritative for | Storage |
|-----------|-------------------|---------|
| CAS digest (SHA-256) | Artifact identity | Derived from bytes |
| Signed receipts | Audit trail, approval record | Immutable files |
| Policy evaluation | Release decisions | Re-evaluated on demand |
| **redb metadata** | **Nothing (cache/index only)** | Rebuildable |

**Rules:**

1. A corrupted or missing metadata database **fails closed** (operation
   denied, `doctor` invoked).
2. Approvals are bound to: policy digest, detector snapshot, artifact digest,
   operation, and expiry — **not** a database row.
3. The database can be rebuilt from receipts and CAS objects.
4. Per-digest leases (not a global lock) prevent concurrent operations.
5. Incomplete staging objects are unaddressable.
6. `arbitraitor doctor` reconciles orphaned staging, verifies CAS/metadata
   consistency, and clears stale locks.
7. Migrations are transactional with backup before destructive changes.
8. Metadata decoders are fuzzed.

**Why redb:**

- Pure Rust (no C FFI in the security boundary).
- ACID embedded key-value model.
- Portable single-file storage.
- Sufficient for digest-to-metadata, leases, retention, and receipt indexes.

A `StoreIndex` trait is kept so SQLite remains an option if ad-hoc querying
and operational tooling become important. SQLite is **not** introduced solely
for key-value lookups.

## Consequences

- Database corruption is a denial of service, not an execution bypass.
- No query against the database can authorize release or execution.
- Index rebuild is a recoverable operation.
- Future migration to SQLite or another backend is possible behind the trait.

## Alternatives considered

- **SQLite:** Rejected initially. C FFI adds attack surface. Justified only if
  ad-hoc querying becomes a real need.
- **Sled:** Rejected. Maintenance concerns and API churn.
- **In-memory only:** Rejected. Cannot persist leases or retention across runs.
- **Filesystem-only (no DB):** Rejected. Linear scans for digest lookup are
  too slow at scale.

## References

- `.spec/arbitraitor-tech-stack.md` §5 (Filesystem and content-addressed store)
- `.spec/arbitraitor-adversarial-review-and-gap-analysis.md` H-05 (Metadata as
  authorization oracle)
- [ADR 0013](0013-plan-bound-approval-capability.md) — Approval binds to plan,
  not digest alone
