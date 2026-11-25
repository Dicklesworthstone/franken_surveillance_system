# Daemon recording retention across restarts

The daemon reconstructs its retained recording set from committed pack catalog
roots when opening a deployment. A restart preserves logical occupancy, stable
root identifiers, durable operator holds and the exact recording roots selected
for corroborated events. It does not start a new empty accounting ring.

## Source handoff and interrupted publication

The ingest cursor advances only after storage accepts ownership of each frame.
A tentative ring read cannot acknowledge the unaccepted remainder of a batch when
an earlier flush fails. Accepted source stays in the GOP buffer through a known
precommit failure; retrying the flush reuses those shared source allocations.

After the canonical commit is acknowledged, storage keeps a pending publication
receipt until the matching catalog root and retention candidate are established.
Retrying that phase does not append another canonical import. An opaque sink
failure has an indeterminate commit outcome: new source submission stops until
storage reopens and replays the ledger. An uncertain catalog append similarly
requires reopen instead of a blind journal retry.

Startup completes a missing daemon GOP root only after verifying its canonical
metadata, bounded source bytes and frame digests, stream identity, frame count,
capture interval, and exact active import batch. The active import's ledger batch
must contain the same object identity, payload digest, generation, family, and
plane. Sharing source bytes with a later import cannot revive an older missing
root. Existing retired or superseded catalog identities keep their lifecycle,
and canonically retired or physically tombstoned footage is never reconstructed
as live evidence.

The canonical import does not identify the original catalog version. A missing
descriptor therefore cannot prove the absence of legacy in-memory holds.
Reconstructed roots retain the existing
`recovery:legacy-hold-state-unverified` blocker; ordinary successful publications
continue to use `media-gop-v2`.

Graceful supervisor shutdown drains the remaining bounded ingest ring before
cancelling storage authority, then flushes each GOP. Drain, publication, or cleanup
failures are reported while source sessions, IPC, and owned regions still receive
cleanup attempts. Storage refuses a clean shutdown receipt while buffered source,
pending publications, or indeterminate commits remain.

These guarantees cover running-process ownership and canonical commits whose
catalog publication was interrupted. Frames that never reached a canonical
commit are not made durable against process termination by this mechanism.

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

The daemon contracts also exercise cancelled flush retries, postcommit catalog
conflicts, exact-once missing-root recovery, retired/superseded and duplicate-content
non-resurrection, partial ring handoff, and shutdown draining beyond the per-tick
ingest budget.

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
