# Native live capture to durable archive

`rtsp::live_archive::LiveAvcArchive` composes the existing native TCP/Digest/AVC
recording owner with `RecordingArchiveWriter`. One already-open, exclusive
`LocalRootPublisher` remains the storage owner. No new runtime, camera discovery,
credential service, canonical ledger, or media format is introduced.

## Establish and drive the bounded owner

Provide `LiveAvcConfig`, `LiveRecordingConfig`, and `LiveArchiveConfig`. Recording
and archive sensor/stream/generation/receive-clock scope and media tick rate must
match exactly before connecting. Archive limits, maximum complete window bytes,
finite driver calls, an absolute publication deadline, and a finite storage-pause
budget are explicit. Network authority and storage cancellation are independent
owner capabilities; a URI, principal label, or digest grants neither.

`connect` performs bounded recovery reads before the single native connect
attempt. It publishes nothing. Poll the initial storage barrier to `Ready` before
issuing DESCRIBE/SETUP/PLAY. Any recovered durable-but-unindexed tail is flushed
first. The existing request/respond APIs borrow credentials and use the same
Digest lifecycle; there is no automatic authentication fallback or reconnect.

`poll(readiness, now, authority, cancellation)` advances either storage or live
capture, never both kinds of I/O in one call. While storage is busy, even positive
socket readiness causes no network read or write. There is only one accepted
window, retained by the archive writer, not a second accumulating queue. Storage
progress uses its existing bounded steps, including source-first/root-last
publication and one-window-at-a-time catalog verification. A writer step can
perform multiple bounded filesystem calls; it is not a single-syscall promise.

Honor `next_wake_ns` as well as readiness. Waiting storage is immediately runnable.
The original network lease and live authority are checked during storage pauses,
and the independent maximum pause cannot be renewed with failed flush requests.
The inner protocol/collector deadlines are not reset; they are evaluated when
capture resumes. This composition does not preempt a blocking filesystem call or
provide a production Asupersync readiness/timer integration. Storage cancellation
must also enforce the owning runtime's live deadline and revocation checks.

Timing remains explicit. A `TimingRequired` result needs the owner's declared
DTS, positive duration, and composition offset; RTP and socket-arrival time are
not invented substitutes. Invalid timing keeps its original picture available.
`seal` prepares an already completed prefix; it neither invents an EOF boundary
nor publishes bytes. Original wire chunks and unselected/untimed sources remain
caller-owned outputs and must be retained or explicitly accounted for.

## Do not collapse the publication boundaries

A window is intercepted from capture and offered unchanged to the archive. The
following results are intentionally separate:

- `WindowAccepted` reserves the original ordinal and transfers in-memory ownership.
- `WindowDurable` acknowledges the exact recording root and its child custody.
- `CatalogPublished` acknowledges immutable discovery metadata for those windows.

A durable window can remain unindexed until the configured page threshold, an
explicit `flush`, or final drain. Snapshot counts describe acknowledged storage,
not camera coverage, physical absence, replicated custody, or a retention policy.

A genuine terminal capture event triggers final page flushing. The resulting
`Finished` identifies `InputEnded`. `finish_capture` instead stops the live owner,
returns all unsealed/untimed work immediately, and drains only windows already
admitted to storage. That finish is labelled `OwnerStopped`, never synthesized
EOF. Protocol errors and recording discontinuities stop both owners and return
retirement; they cannot masquerade as successful finalization.

After any fatal publication failure, the live socket is closed and the last
acknowledged snapshot, exact pending recording, and any prepared page are
transferred. A window rejected before writer admission is returned separately.
Nothing retracts an already durable root or deletes a staging object. Remote
TEARDOWN uncertainty and raw source obligations remain explicit.

## Resume storage without reopening the camera

`rtsp::archive_recovery::RecordingArchiveResume` handles interrupted AVC archival
work using the existing writer. Retain the `ArchiveRetirement` and independently
pin `archive_retirement_digest(&retirement)`. After the storage owner has been
explicitly reopened/reconciled, supply that exact work, pin, a new finite storage
lease/call budget and a complete pending-window byte allowance to `open`.
Namespace, page size and inventory ceilings remain those of the retired work.
Neither the old pin nor new lease grants network or storage authority.

Opening performs no publication. It rehashes current source custody and requires
an unchanged acknowledged window/page prefix. It accepts at most the specifically
pending window at its original ordinal and specifically prepared page at its
original page boundary. Missing old roots, conflicting valid recordings, unknown
extra publications, and unresolved root temporaries are refused with all original
input intact. A root temporary is an explicit repair obligation, not evidence that
publication failed or permission to remove the file.

`reconciliation()` reports each original pending object as `NotPublished` or
`AlreadyDurable`, or `NotPending` when none existed. A lost acknowledgement after
root rename can therefore be recognized without rereading the camera, remuxing
bytes, assigning another ordinal, or republishing the window. Identical redundant
in-memory bytes are released only after their current counterparts verify.

Explicit `step` calls first drain the recovered tail, then offer an unpublished
original window once at the original ordinal, and finish its discovery page.
A retained unpublished catalog must match the re-prepared page root before any
index/root write; it cannot silently acquire different page boundaries. The
result vocabulary remains the existing archive admission/publication progress.
Storage completion is not proof that the interrupted camera capture completed.

An error fences this recovery attempt. `retire` transfers its latest acknowledged
archive, unoffered window, and any original page awaiting identical preparation.
`into_retry` combines that work only when there are no competing pending identities.
This also preserves a next window waiting behind an older unfinished catalog page.
Pin the newly retired work and explicitly inspect/reopen before another attempt;
no automatic replay, deletion, or socket reconnection occurs.

Recovery needs independently trusted retired metadata. Reopening an arbitrary
snapshot with a checksum taken from the same untrusted source is not anti-rollback
authentication. Cold recovery without a retained work commitment still uses the
existing archive discovery API and cannot reconstruct an unpersisted in-memory
window. Continuous recording across process loss needs its separate source,
clock, generation, service-lifetime and durable work-journal contracts.

## Authored contracts and boundaries

Twenty Rust tests cover native loopback capture, byte-identical reopen across
TCP chunk sizes 1/7/4096, distinct admission/durability/indexing, no read-ahead
during storage pressure, true EOF versus explicit stop, scope and resource
refusals, revocation, fixed pause deadlines, every root-publication cut, lost
window/page acknowledgements, conflicting roots, missing old history, cancelled
recovery, preserved two-stage page/window work, and protocol-failure finalization.
All network endpoints are local fixtures. The tests exercise actual existing
recording and filesystem publication code, not a substitute persistence model.

```sh
cargo test -p fss-reference --lib rtsp::live_archive
cargo test -p fss-reference --test recording_archive_writer_contract
cargo test -p fss-reference --lib rtsp::live_avc
```

These tests were authored but **not executed in the editing environment**, which
has no `cargo` or `rustc`. Lexical checks, API review and exact blob/manifest hashes
are not compilation, passing Rust tests, hardware interoperability or release
qualification. This is a reference Rust API, not a production capture daemon,
TLS/reconnect service, raw-ingress retention system, complete privacy/retention
enforcement layer, or Asupersync service integration. No gate or bead is closed.
