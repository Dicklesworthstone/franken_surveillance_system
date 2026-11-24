# Daemon recording retention across restarts

The daemon reconstructs its retained recording set from committed pack catalog
roots when opening a deployment. A restart preserves logical occupancy, stable
root identifiers, durable operator holds and the exact recording roots selected
for corroborated events. It does not start a new empty accounting ring.

## Recorded media and durable pins

New daemon GOP roots use the semantic kind `media-gop-v2`. Their FSMC source
chunks and FSPP footage-import metadata retain the existing byte formats.
Startup walks the complete catalog in bounded pages, verifies each live GOP's
metadata digest and its agreement with the source identity, size, frame count,
capture interval and indexed object kind, and restores the source candidate.
Corrupt or missing live metadata refuses opening instead of silently dropping
the recording from retention.

Operator holds are canonical `evidence_hold` deltas, committed with their
metadata through the ordinary pack/ledger/projection owner. The existing
`StorageEngine::pin_candidate_hold` method now reports success only after that
durable commit. Integrators needing typed failures and explicit authority can
use:

```rust,ignore
storage.set_candidate_hold(root_id, hold_id, true, authority_cx, region_tree)?;
storage.set_candidate_hold(root_id, hold_id, false, authority_cx, region_tree)?;
```

Hold identity cannot silently move to a different root. Active canonical holds
on a GOP's source or metadata digest protect that GOP. Canonical releases are
reflected before the next retention decision. Explicit caller-registered
candidates keep their caller-owned reconstruction contract.

When an event reaches corroboration, the engine commits its selected per-sensor
media pins in the same proposal as the event revision. Reopening therefore
keeps the original source roots pinned instead of selecting a newer recording.
The existing conservative event-pin lifetime is preserved; this change does
not introduce automatic event-hold expiry.

Live catalog roots outside the retention inventory also protect recordings they
reference as source or metadata. A paged reference check runs before an eviction
pass; its blockers participate in quota accounting as well as deletion selection.

The maintenance decision, canonical retirement and physical deletion share an
ownership gate with forwarded canonical writes. A forwarded hold cannot be
inserted between the hold snapshot and deletion. Hold/deletion control remains
available under pinned-capacity pressure, so retention controls can clear the
condition that paused recording.

## Retirement and replay

Media expiration first commits canonical footage-deletion deltas, then commits
catalog and object tombstones, and finally compacts eligible sealed packs.
Footage queries therefore stop advertising the retired recordings before their
source objects become unreadable.

Original footage-import metadata, event pins and deletion payloads remain
available for ledger replay from genesis. They are not included in the GOP's
reclaimable source set. Deleting the derived MVCC snapshot consequently does
not depend on the expired video remaining on disk.

Logical capacity accounting includes protected canonical payloads and other
objects outside recoverable media closures. Retiring video cannot make those
bytes disappear from the capacity calculation. Physical pack bytes and actual
compaction reclamation remain separate measurements. If protected data consumes
critical capacity, ingest pauses with the existing
`ERR-STORAGE-QUOTA-PINNED-001` state.

## Interrupted deletion

A canonical retirement may reach disk before any physical tombstone. Its
still-live root remains accounted after restart; the next eligible retention
pass can finish physical cleanup without another semantic retirement.

If the catalog tombstone reached disk before the object tombstone, the engine
tracks that pending root separately. Completion requires the exact catalog
identity, an absent canonical footage row, no current source/metadata hold, and
no retained source reference. The pack owner also checks all live catalog root
and metadata references before committing the original deletion reason. A
newer hold defers completion and keeps the bytes in protected accounting.

Already durable object tombstones are idempotent and repair an interrupted
live-index removal. Sealed-pack reclamation resumes even on a maintenance tick
that selects no new eviction. These recovery operations run while the daemon's
owned writers are quiescent; they do not grant independent deletion authority.

## Existing deployments

Older `media-gop-v1` roots predate durable daemon pins. Their historical
in-memory holds cannot be recovered or proven absent. The engine restores their
occupancy and attaches the explicit
`recovery:legacy-hold-state-unverified` blocker. This records uncertainty; it
does not assert that a legal hold historically existed.

Legacy recordings remain protected from automatic expiration. New v2 recordings
use normal durable hold/release and retention behavior across subsequent
restarts. Explicit historical deletion still requires the deployment's existing
deletion authority. This change cannot recover payloads already removed by an
older daemon, and does not migrate such recordings into an assertion of no hold.

## Focused contracts

The daemon restart contracts exercise restored occupancy and root identities,
durable hold/release behavior, canonical query retirement and rebuild without
the derived projection, event-source pins, and conservative legacy handling.
Pack recovery contracts exercise the catalog-only and object-log-before-
compaction interruption boundaries, original reason preservation, metadata
survival, idempotence, and protected references beyond the first catalog page.

```sh
cargo test --locked -p fss-daemon --test storage_retention_restart_contract
cargo test --locked -p fss-pack --test retention_compaction_contract catalog_retirement_recovery_
```
