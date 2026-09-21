# Checkpointed archive publication

`recording_archive::checkpoint::write_ahead::CheckpointedArchiveWriter` adds an
opt-in write-ahead work barrier to the existing AVC archive writer. A window or
prepared catalog page cannot reach its normal archive publication through this
owner until its complete recovery work graph is durably published. The ordinary
writer, HEVC API, work format, root identities and resumption protocol are unchanged.

The sequence is **in-memory offer → pin required → owner pin acknowledgement →
work root durable → normal window durable → prepared catalog → its own pin/work
barrier → catalog published**. A prepared page is protected before its normal
index or root is written, including a recovered unindexed tail and final partial
pages. A checkpoint receipt never claims that the normal archive slot is published.

## Owner-driven use

Open with an already-authorized exclusive `LocalRootPublisher`, exact namespace,
`ArchiveLimits`, independent `ArchiveWorkLimits`, finite call budget and absolute
storage deadline. Offer the existing immutable `PreparedRecording` unchanged.
Drive `step(now, cancellation)` and handle `CheckpointedArchiveProgress`:

* `PinRequired`: persist its exact slot/root/retirement commitment in independently
  trusted runtime state, alongside the previous durable pin. Then call
  `acknowledge_checkpoint` with that exact value. No work or archive publication
  occurs while acknowledgement is outstanding. Wrong or stale pins cannot unlock it.
* `WorkDurable`: the existing publisher committed the complete work root. The next
  step, not this receipt, may advance the ordinary archive writer. Acknowledge the
  new durable pin independently before forgetting its predecessor.
* `Archive`: preserve the existing distinctions between window durability,
  catalog preparation/publication, ready and finished.

The acknowledgement API is a **trusted runtime assertion**, not verification of
an external journal. Digests and labels grant neither retention nor disclosure
permission. A runtime must actually protect the candidate and prior pins; the
API cannot establish that an arbitrary caller did so. Do not implement this as
blind auto-acknowledgement in an agent or untrusted transport.

## Recovery and failure

Keep the candidate pin even if a checkpoint write fails or its reply is lost.
Retire and reopen/reconcile the publisher, then use the existing
`load_archive_work` with an independently trusted exact pin and external ceilings.
It returns ordinary `ArchiveRetirement`; `RecordingArchiveResume` or the existing
`fss-archive inspect-work/restore-work` commands handle exact original work.
The previous durable pin remains necessary when the new candidate never committed.
An orphan temporary or ambiguous publisher is a repair/reconciliation obligation,
not permission to erase files, infer absence or replay another ordinal.

The barrier fences on publication, cancellation, capacity and work-budget errors;
there is no retry-through-error API or mutable bare-writer escape. Retirement
returns all original pending bytes plus candidate/last-durable pin identities.
Clock regression is a safe refusal. Pin waits and repeated acknowledgements do not
renew time or call budgets. Finish and flush use the same page barriers.

The checkpoint borrows immutable live work directly: it does not retire/rebuild
the writer, duplicate source/media buffers, or write footage into a second journal.
The underlying content-addressed spool deduplicates the auxiliary and normal
publication graphs. Each checkpoint revalidates the complete bounded historical
closure and uses existing source-first/root-last publication. This is not a cheap
constant-time operation: graph/inventory/byte ceilings may stop a long recording,
and retained work roots consume storage until explicitly managed by retention.

A checkpoint publication step performs multiple bounded filesystem operations.
The cancellation capability must enforce the runtime's live deadline/revocation
at supported cut points; admission time does not make a blocking syscall preemptible.
Raw TCP chunks, unsealed pictures, and work lost before a checkpoint root commits
remain outside this guarantee. This is not continuous crash-safe raw ingress,
a new runtime, TLS/reconnect integration, replicated custody or release qualification.

## Native live capture

`rtsp::live_archive::checkpointed::CheckpointedLiveAvcArchive` applies the same
barrier to the actual TCP/Digest/AVC capture-to-archive owner. Supply the normal
live, recording and archive configuration plus `ArchiveWorkLimits`. Incompatible
work bounds are refused before archive recovery or a native connection attempt.
There is no mutable escape to the legacy owner; its unprotected storage-poll
branch is never invoked through this wrapper. Existing applications using the
legacy constructor retain their existing behavior.

Drive `poll(readiness, now, authority, cancellation)`. Ordinary wire, recording,
archive and completion results are wrapped in `CheckpointedLiveArchiveStep::Live`.
A `Checkpoint` result exposes the same `PinRequired` and `WorkDurable` states as
the standalone writer. Independently retain each candidate, then use the live
owner's `acknowledge_checkpoint` with the exact pin and current authority. Do not
auto-acknowledge an unpersisted pin or treat an acknowledgement as proof of custody.

While pin acknowledgement, work publication, or normal storage progress is
pending, no camera socket read/write occurs, even when both readiness flags are
true. Existing protocol requests and picture timing remain backpressured. The
live grant, original absolute leases, fixed storage-pause ceiling and finite
operation allowance continue to apply. An outstanding pin waits for the owner or
its fixed hard deadline, not an artificial immediate wake. A failed or repeated
command cannot restart the pause. Protocol and collector clocks are not reset;
as in the existing live archive owner, their deadlines are evaluated on resumption.

Revocation, cancellation, expiry and uncertain storage publication close capture
and return all unsealed/pending source together with candidate and last-durable
checkpoint references. An uncertain auxiliary root is never reported as a whole
work checkpoint or a normal archived window. True receiver EOF still produces
`InputEnded`; explicit `finish_capture` returns unsealed input immediately and
produces `OwnerStopped` after protecting and draining only already accepted work.
Checkpointing cannot convert a truncated picture or protocol failure into EOF.

Normal recovery still uses `load_archive_work`, `RecordingArchiveResume`, or the
existing separate-process work commands. The wrapper does not restore a socket,
create a new camera generation, authenticate a new principal, or implement a
persistent pin store. It connects protection to ordinary live publication, not
to every raw network byte or every yet-unsealed picture.

## Validation

Fourteen public-API tests cover cold process-state loss, unchanged work
format/commitments, separate window and catalog barriers, lost checkpoint/window/
page replies, recovered tails, source-buffer ownership, finite budgets, cancellation,
wrong pins, and all four root-publication failure cuts using native AVC fixtures
and the existing local filesystem publisher. Eight additional live tests exercise
actual loopback sockets and encoded AVC through both barriers, including source
identity across TCP chunk sizes 1/7/4096, cold re-open, no read-ahead, revocation,
fixed pin-wait deadlines, uncertain auxiliary publication, recovered tails, and
true EOF versus explicit stop.

```sh
cargo test -p fss-reference --test archive_write_ahead
cargo test -p fss-reference --test archive_work_checkpoint
cargo test -p fss-reference --lib rtsp::live_archive::checkpointed
```

These Rust tests are authored, not executed in the editing environment (no cargo
or rustc). Lexical and content-hash checks are not compilation or qualification.
No gate, bead or production support claim is promoted.
