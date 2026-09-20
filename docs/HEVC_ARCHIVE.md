# HEVC archive writing, recovery and cross-page retrieval

`rtsp::recording_archive::hevc` connects the typed HEVC catalogs and replay-verified
recordings to the existing bounded local archive inventory and range reader.
This is the cross-page layer: automatic window/page publication, discovery,
source-verified recovery, explicit unindexed tails, and incremental whole-window
retrieval. It creates no storage
backend, directory scanner, codec parser, socket, worker, or authority grant.

## Recover and retrieve

Construct `HevcArchiveNamespace` from the exact `CatalogScope`: sensor, stream,
generation, authority anchor, receive-clock identity, decode-clock identity and
positive tick rate. Pass an already authorized `LocalRootPublisher`, namespace,
`ArchiveLimits` and cancellation probe to `HevcArchiveSnapshot::load`.

Recovery inventories the existing publisher's admitted metadata, not arbitrary
filesystem paths. Every discovered recording is loaded by `load_hevc_recording`,
including native packet/assembly/remux replay; every catalog uses
`load_hevc_catalog`. Pages must form a contiguous indexed prefix, match exact
window slots/roots, and agree with fully recovered descriptors. Broken roots,
unresolved temporary records, ordinal holes, duplicates, overlapping pages,
wrong codec/scope and inconsistent metadata fail rather than being skipped.
A failed or cancelled recovery returns no partial snapshot.

`windows()` includes all verified durable windows. `pages()` includes only
published immutable HEVC catalog pages. `unindexed_windows()` identifies the
bounded durable tail for which a page has not yet been published. Such a tail
is not lost, but remains unindexed in a query. A new page creates a new inventory;
it cannot retroactively alter the meaning of an older snapshot.

`HevcArchiveRead::new` selects a half-open decode interval across all published
pages in that fixed snapshot. Count or output-byte overflow refuses the complete
query. The byte budget charges every selected original window, even for a
one-tick overlap. Every `step` checks request time, cancellation and the storage
owner, reloads the relevant catalog, source-replays one complete recording,
compares its descriptor and actual bytes, then checks cancellation before
returning `HevcArchiveReadProgress::Window`. Output is a typed
`PreparedHevcRecording`, with original packets and replay-verified mappings.

The returned requested interval is metadata, not a cropped or privacy-filtered
rendition. Explicit authorization must cover the WHOLE window. `Complete` is
emitted only after all selected windows passed and every pinned page was
reloaded, including pages relevant only to an unindexed gap. Subsequent calls
are `Exhausted`. A late error preserves earlier caller-owned results but blocks
aggregate success. An empty query result still checks all pinned pages.
Unindexed intervals are neither evidence of scene absence nor camera coverage.

## Automatic window and catalog publication

`HevcRecordingArchiveWriter::open` borrows an exclusive, already-open storage
owner, the exact typed namespace, archive limits, owner admission time, request
deadline and cancellation probe. Recovery replays original windows and checks
catalogs before admitting work. An existing durable unindexed tail is flushed
BEFORE another recording can be offered, even when it is smaller than the page
threshold. Open itself performs no new publication; subsequent steps do that.

Offer a `PreparedHevcRecording` returned by `HevcRecordingCapture` or verified
readback, with its complete-payload reservation and admission time. `offer`
returns the reserved ordinal, deterministic slot and exact root. This is an
ownership/admission receipt, not a durable write. Every refusal returns the same
recording intact. Scope/time mismatch, overlap, duplicates, insufficient
reservation, exhausted metadata bounds and outstanding page work cannot advance
that ordinal or evict existing roots.

Drive `step` until `Ready` before asking capture for another window. The writer
retains at most one media recording plus bounded descriptors and a page builder.
It uses the unchanged `RecordingPublication` protocol to stage source first,
then initialization, media and index, and finally commit the window root last.
Only a durable receipt appends its descriptor to the acknowledged snapshot.
`WindowDurable` does not imply that a catalog page has been published.

At the configured `windows_per_page` threshold, `PageStarted` fixes the current
tail. Each `PageWindowVerified` reloads and source-replays one exact HEVC window
through the existing verifier before adding metadata. `CatalogPrepared` retains
immutable bytes; `CatalogIndexStaged` is custody only. The unchanged publisher's
root-last commit produces `CatalogPublished`, which advances indexed counts.
A caller may `flush` a smaller page or `finish` admission and drain the remaining
window and final partial page. `Finished` is followed only by `Exhausted`, never
a repeated effect or newly asserted successful write.

Cancellation or a failed write blocks this attempt. `retry` requires an explicit
new admission deadline and preserves the exact pending bytes, slots, builder,
and prepared page. A poisoned publisher cannot retry in place: `retire`
transfers pending recordings, prepared metadata and the last acknowledged
snapshot; the caller reopens and reconciles the existing storage owner. No Drop
implementation publishes, deletes, discards orphan temps or retracts custody.

A root rename can succeed without its acknowledgement reaching the driver.
After reopen, the actual durable window/page is recovered at its original
ordinal. A lost window acknowledgement therefore cannot create a second window;
a recovered tail is cataloged first. A lost catalog acknowledgement cannot
create a second page or overwrite the original. Pre-rename temporary and
indeterminate states remain explicit repair obligations. They are never treated
as empty slots or permission for this writer to delete source data.

One writer step publishes one bounded window (at most five existing publication
driver steps), replays one page entry, or advances one index/root operation.
Underlying hash/fsync/closure verification can perform several bounded I/O
operations. Entry timestamps are not syscall-duration measurements; the caller's
cancellation probe must enforce live deadline/revocation at those cut points.
The new writer does not change existing cancellation or durability semantics.

## One implementation, statically pinned codecs

AVC and HEVC use one generic recovery/selection/read/write implementation. The two
family markers implement a sealed trait; external code cannot add a codec or
substitute a verifier. Public aliases fix the family before any I/O. Typed
HEVC namespaces, snapshots, catalogs and recording outputs do not coerce to AVC.
There is no runtime codec auto-detection, public verifier callback, unchecked
wrapper, or widening of catalog/storage module visibility.

Existing `ArchiveNamespace`, `ArchiveSnapshot`, `ArchivePage`, `ArchiveRead` and
AVC progress construction retain their original operations and byte identities.
The AVC namespace domain remains `fss.local_recording_archive_namespace.v1`,
its slot prefix remains `fssa1`, and its snapshot domain remains
`fss.local_recording_archive_snapshot.v1`. Existing catalog and recording bytes
are unchanged. The public read-progress enum retains its name and variant paths;
its default codec is AVC. The same compatibility rule preserves
`ArchiveWriteRefusal`, `ArchiveRetirement` and `RecordingArchiveWriter`; HEVC
adds `HevcArchiveWriteRefusal`, `HevcArchiveRetirement` and
`HevcRecordingArchiveWriter` without a dynamic media variant.

HEVC uses `fss.local_hevc_recording_archive_namespace.v1`, slot prefix `fssh1`,
and snapshot domain `fss.local_hevc_recording_archive_snapshot.v1`. The namespace
body is canonical domain text, sensor/stream text, generation u64, anchor digest,
receive-clock digest, decode-clock digest and time-scale u32. SHA-256 of that body
provides the full 64-hex-digit scope component. Window/page slots end in
`-w-<16-lowercase-hex-ordinal>` / `-c-<16-lowercase-hex-first-ordinal>`.
The snapshot digest follows the existing grammar with its HEVC-specific domain.
Neither digest is a published canonical ledger/head root. A codec migration
cannot overwrite or reinterpret an old namespace.

## Work and trust boundaries

The existing archive ceilings still apply: at most 4,096 retained window
entries, bounded catalog pages, a separately bounded scan of each publisher
metadata inventory, and at most one 64-window unindexed tail. Recovery loads
one full recording at a time, with cancellation between bounded operations.
A read step can perform one full recording replay; completion reloads every
bounded page. Output-byte limits are not syscall, CPU, or RSS budgets. The owner
must enforce live deadline/revocation at the supplied cancellation cut points.
No asynchronous worker or second cancellation tree was added.

This is local unencrypted reference storage. Snapshot metadata is not an
export/retention capability, future retrievability proof, source signature,
decoding-completeness certificate, or live camera continuity witness. Native
camera I/O, encryption/retention/ledger activation and agent/CLI exposure remain
separate boundaries. HEVC capture windows now enter the archive writer directly; collection, storage
publication and recording/catalog retrieval retain their existing semantic owners.

## Regression commands and validation status

```sh
cargo test -p fss-reference --test hevc_archive_read_contract --test hevc_archive_write_contract
```

The tests use the retained synthetic HEVC fixture and the actual publication,
HEVC replay and catalog APIs. They cover separate codec identities with frozen
AVC bytes, three-page read/reopen, durable tails, exact whole-window pricing,
invalid layouts, codec substitution, source/descriptor corruption, cancellation
at each pre-disclosure probe, partial failures, hard deadlines, empty-result
revalidation and recovery bounds. Writer contracts additionally exercise automatic
rotation and final partial pages, small recovered-tail flush, exact ownership on
refusal, cancellation at every window-publication probe, all four root crash cut
points for windows and catalogs, lost acknowledgements, explicit same-root retry,
manual flush, deadlines, fixed capacity, corrupt source before indexing, and the
existing AVC writer/read API. Existing AVC archive tests remain applicable.

Rust compilation, tests, formatting, Clippy and qualification were not run in
the editing environment: it has no Rust toolchain and dependency provisioning
was unavailable. Local source checks are not a passing Rust receipt. The
normative qualification entrypoint and all release gates remain unchanged.
