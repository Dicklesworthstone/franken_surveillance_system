# Independently durable archive recovery references

`rtsp::archive_pins::ArchivePinJournal` persists recovery references in an explicit,
separately owned directory. It reuses the existing `fss_ledger::Journal` framing,
body synchronization and commit synchronization. `LOCK` is an actual sidecar
process lock; `pins.journal` is a bounded append-only metadata history. The journal
contains no recording bytes, credentials, camera endpoints or restoration grants.

Create the journal with independently chosen `ArchivePinScope` (journal epoch and
exact archive namespace), independent record/byte bounds and the storage owner's
cancellation/deadline probe. Creation requires a new directory and synchronizes
its entries and parent before success. Existing and partially created directories
are never adopted, removed or automatically repaired. On Unix the new directory
is private to its owner. All path ancestors must be trusted; this is not a sandbox
against hostile filesystem replacement or an encryption boundary.

## Candidate and confirmed work are different

The existing `ArchiveCheckpoint` is opaque and comes from the checkpointed writer.
`persist_candidate` synchronizes its exact slot, root, retirement identity and
original byte quote before returning `ArchivePinReceipt`. Only then may the trusted
caller acknowledge that checkpoint to the existing publication barrier. An exact
current-candidate retry verifies the complete disk history and does not append.

Candidate persistence says nothing about whether the corresponding source/work
root has committed. The preceding confirmed reference remains available alongside
it. `confirm_recovered` loads and source-verifies the candidate's complete work
bundle against current custody and external limits before appending confirmation.
It checks namespace, retirement identity and original payload quote. Missing,
corrupt, superseded or deleted work is an error, not an automatic fallback.

The complete history retains every prior reference even after a new confirmation.
A second different pending candidate, confirmation of the wrong candidate, reused
checkpoint root/retirement identity, repeated genesis, foreign record kind or
noncanonical metadata is refused. No API clears a candidate or rewrites history.

## Cold recovery and startup

`open_existing` requires the accepted scope and external limits. A supplied
`ArchivePinAnchor` is a minimum trusted prefix: verified descendants can recover a
lost acknowledgement, but shorter/different history is refused. Without a minimum
anchor, the caller trusts the protected local journal's identity and completeness;
this does not authenticate against rollback of the whole directory. Protect the
journal independently of the archive and retain stronger external anchors when
that threat is in scope. Neither a directory nor a checksum grants footage access.

Open reads bounded bytes and verifies all framing, application transitions and
scope before allowing a writable owner. Recovered complete records are synchronized
before success. `IncompleteTailPolicy::Reject` is the ordinary recovery choice.
Explicit `Truncate` permits only the existing Journal's verified incomplete suffix
repair, and only after minimum-prefix and application validation. Corruption is
never skipped or truncated. A failed append fences the current owner; close it and
inspect/reopen explicitly rather than acknowledge, retry, or select another pin.

`load_work(Candidate, ...)` and `load_work(Confirmed, ...)` explicitly select which
current recovery reference to verify. They return the ordinary `ArchiveRetirement`
for existing resumption APIs. Selection never falls back when its chosen root fails.
`require_settled` gates a fresh writer: there must be no unconfirmed candidate, and
all work named by the last confirmation must actually exist at its normal archive
slots. A durable auxiliary work root alone cannot make an unpublished recording
safe to forget when a camera restarts.

## Automatic archive and live integration

`JournaledArchiveWriter` exclusively owns the existing checkpointed writer and
borrows the independent pin journal. It exposes no mutable inner owner and no
manual acknowledgement method. `JournaledLiveAvcArchive` applies the same ordering
to the native TCP/Digest/AVC capture-to-archive owner. Its request, response, timing,
seal, flush and finish operations preserve the existing scope and media contracts.
The storage cancellation/deadline capability is explicit on each live call.

Each announced candidate is actually appended and synchronized before the wrapper
acknowledges it to the existing barrier. `PinPersisted` is metadata durability,
not source/work durability. After the complete work root commits, its confirmation
is appended before `WorkConfirmed` returns; the result carries both the original
work-storage receipt and the independent metadata receipt. Only a later step may
publish the recording or catalog at its normal archive slot.

If candidate persistence fails, the wrapper does not acknowledge it. If recording
confirmation fails after the source work commits, the actual work receipt is
retained as `UnrecordedWorkConfirmation`. The standalone writer fences; the live
wrapper closes capture and returns all original network, unsealed and pending
archive work. There is no retry-through-error or unjournaled publication bypass.
The last acknowledged journal prefix can be behind an uncertain append; after a
cold reopen the candidate/confirmed records reveal what actually committed.

No camera socket read/write accompanies a pin append or checkpoint publication.
The live loop performs a bounded current-path/final-trailer check on the journal;
new candidate and confirmation records additionally reverify its entire history.
Readiness cannot bypass storage work. Fixed live leases, storage-pause deadlines,
finite driver allowances, explicit timing, raw-source ownership and genuine EOF
versus owner-stop semantics remain the existing owner's responsibility and are
not reset. A work+confirmation step can perform multiple bounded filesystem calls
across both owners; it is not a one-syscall or preemption guarantee.

Both wrappers refuse a new writer/camera when the journal contains an unresolved
candidate or when its confirmed work is still missing from normal archive slots.
A confirmed work bundle must not become permission to forget a not-yet-archived
recording. Older unprepared indexing can drain through a newly journaled page
barrier after exact original work is restored. Independent directories do not
themselves establish independent failure domains: deployment must protect their
placement, permissions, backup and externally accepted minimum-prefix policy.

## Restore directly from independently stored references

`ArchivePinJournal::restore_work` selects the current candidate, or the last
confirmation only when there is no candidate. It reconstructs and verifies that
exact existing work graph, including original source, namespace, retirement
identity and byte quote. A missing, corrupt, deleted or superseded candidate is
an error; restoration never silently tries the older confirmation instead.

Once candidate work actually verifies, confirmation is synchronized BEFORE any
normal archive publication. Restoration then publishes the original prepared
catalog first, followed by the original pending recording at its reserved ordinal.
It does not contact a camera, remux source bytes, allocate another ordinal, or
construct additional catalog pages. The existing root-last publisher re-verifies
already durable roots on exact retry. `ArchivePinRestoration` returns the original
checkpoint, journal anchor, any new confirmation, actual catalog/window receipts,
and current source-verified snapshot and durable/indexed/page counts.

This ordering preserves restartability when a write succeeds but its response is
lost. The original selected work reference remains valid after either publication
because no unnamed discovery page is added. `restore_work` checks settlement after
writing. Any unprepared indexing remains explicit in its counts; a newly opened
journaled writer can then prepare and protect the next page normally. Do not run
an unjournaled full-drain resumer to create extra pages and expect the old reference
to authorize that newer history.

A restoration failure can follow a successful metadata confirmation or a committed
archive root. Retain the same journal and media storage, reopen/reconcile uncertain
owners, and retry the same selected work. No failure path deletes or resets either
store. Entry time is an admission check, not an elapsed-syscall clock; cancellation
must enforce the runtime's live deadline, retention and revocation at supported
I/O boundaries. Work lost before its complete checkpoint commits is not recoverable
from a reference alone and remains an explicit unresolved obligation.

## Boundaries and validation

All operations are synchronous, owner-driven and bounded, not an Asupersync service
or background task. Full history verification is linear in the retained journal,
with explicit 16 MiB/16,384-record hard ceilings. Append/record capacity does not
silently compact old references. Individual syscalls are not preemptible; the
cancellation capability enforces live authorization/deadline checks at supported
operation boundaries. This is operational metadata, not a second EvidenceDeltaBatch
universe. There are no source format, retention, model or qualification changes.

Native-journal tests cover cold reopen, candidate/predecessor retention, all four
append cut points for both transition kinds, lost acknowledgements, exact retries,
wrong prefixes, competing candidates, actual locking, corruption, replay grammar,
limits, cancellation, missing layouts and Unix symlink refusal. Twelve additional
pipeline tests use actual source-linked AVC, existing filesystem publication and
native loopback sockets. They cover automatic window/page barriers, cold recovery
of confirmed-but-unpublished work, confirmation capacity failure, retained original
bytes, no socket read-ahead, authority revocation, namespace refusal and expiry.
Eight additional restoration tests cover loss of every original in-memory object,
missing candidate custody, exact lost-response retries, uncertain normal root
publication, confirmation capacity, cancellation, deadline, original page identity
and source corruption. The total is 33 authored Rust tests, including one Unix-only
journal-layout test. These counts are not executed results.

```sh
cargo test -p fss-reference --lib rtsp::archive_pins
cargo test -p fss-reference --test archive_pin_pipeline
```

The Rust tests, compilation, rustfmt and Clippy have not run in this authoring
environment, which has no Rust toolchain. Static review and independent state-model
checks are not compiled-Rust evidence, storage qualification or real-camera tests.
