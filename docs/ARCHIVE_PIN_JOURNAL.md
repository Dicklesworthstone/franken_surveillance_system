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
limits, cancellation, missing layouts and Unix symlink refusal.

```sh
cargo test -p fss-reference --lib rtsp::archive_pins
```

The Rust tests, compilation, rustfmt and Clippy have not run in this authoring
environment, which has no Rust toolchain. Static review and independent state-model
checks are not compiled-Rust evidence, storage qualification or real-camera tests.
