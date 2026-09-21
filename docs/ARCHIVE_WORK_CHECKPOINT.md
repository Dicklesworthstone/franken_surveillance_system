# Cold recovery of pending archive work

`rtsp::recording_archive::checkpoint` persists the existing `ArchiveRetirement`
using the same exclusive `LocalRootPublisher` as recording and archive custody.
It closes the in-memory-only handoff gap: once its root is durable, a new process
can reconstruct the pending recording and prepared catalog without a camera,
remux, conversation history, or an old Rust object.

## Save one exact work graph

Retire the existing writer (or extract the archive retirement from the live
owner). Preserve all other unsealed/capture/network retirement separately.
Call `PreparedArchiveWork::prepare(&work, &publisher, limits, cancellation)`.
Preparation performs bounded historical-root reads but no writes. Independently
pin its exact `slot()`, `root()`, and `retirement_digest()` before attempting
publication. The pin must be protected independently; a checksum beside an
untrusted file is not authentication or rollback protection.

Call `publish(&mut publisher, now, deadline, cancellation)` on that immutable
plan. The operation uses the existing source-first recording publisher for the
pending recording, publishes any prepared catalog under a separate work slot,
then publishes metadata and the complete work root last. Identical content uses
the same spool objects; no source payload is copied into another journal. Its
flat root closure includes the old acknowledged recording roots, every original
and derived leaf, old catalog metadata, and pending work.

Work slots are content-derived and disjoint from archive ordinal slots. Saving
work does not allocate the next archive ordinal, mark a window archived, publish
its normal discovery page, or report camera capture complete. A failure may have
committed auxiliary roots but never constitutes a successful whole-bundle receipt.
Keep the original work until the exact root has been durably published or
reconciled. An uncertain storage owner must be reopened before another attempt;
temporary roots remain explicit repair obligations, never automatic cleanup.

This API is a bounded synchronous storage operation. One pending recording uses
at most five existing recording-publication steps. Catalog, metadata and final
root publication add bounded operations; root verification can perform multiple
filesystem calls. Admission time is not an elapsed-syscall clock. Cancellation
must enforce the runtime's live deadline, revocation, and retention authorization.
The supplied publisher is a trusted I/O capability, not an agent-facing grant.

## Restart and resume

After reopening/reconciling the same storage owner, call `load_archive_work`
with the exact pinned slot/root and independently supplied `ArchiveWorkLimits`.
It reconstructs the prior acknowledged inventory, replays original recording
bytes, loads the original pending recording/catalog, and compares the canonical
metadata, existing retirement commitment, and complete bundle graph.

Serialized limits cannot widen the caller's inventory, page-size, byte or graph
ceilings. Current custody may contain only the named old prefix and its exact
pending publication. Missing old roots, conflicting windows/pages, unrelated
later publications, altered source bytes, tombstones, and unaccounted graph
children are errors rather than implicit recovery choices. Recovery does not
restore old session grants, renew network leases, or override deletion.

Pass the recovered ordinary `ArchiveRetirement` to `RecordingArchiveResume::open`
with its normal `ArchiveResumeConfig`. That existing engine classifies lost window
and page acknowledgements, drains an older unfinished catalog before its waiting
next window, preserves exact original ordinals, and finishes discovery metadata.
No second resumption protocol or canonical authority history is introduced.

A completed work root remains a historical object. The runtime must choose and
pin the intended checkpoint; there is no automatic "latest" scan. Once later
archive work exceeds this checkpoint's specifically allowed pending publication,
loading this old work fails rather than silently following that newer history.
Retain or explicitly delete work roots under the deployment's graph-aware policy;
they contain source evidence, not just harmless operation metadata.

## Bounds and coverage

`ArchiveWorkLimits` separately constrains stored archive policy ceilings, complete
pending bytes, pre-deduplication graph scratch identities, and new work payloads.
Large histories exceeding the fixed manifest ceiling are refused, not silently
truncated or split into an untracked chain. Reading uses the existing spool's
pre-allocation object ceiling (at most 32 MiB), with stricter metadata-format
limits checked after read. Full historical verification is bounded by the
archive limits but is not a constant-time operation or free of I/O cost.

The initial nine public-API tests use actual source-linked AVC fixtures and local
filesystem publication. They cover cold reconstruction and byte identities,
prepared-page-plus-next-window recovery, exact retries, lost acknowledgements,
all four root cut points, authorization/capacity refusal, unexpected later
history, external ceilings and corrupt source.

```sh
cargo test -p fss-reference --test archive_work_checkpoint
```

These Rust tests were authored but not executed in the editing environment,
which lacks cargo/rustc. This feature is an explicit durable handoff boundary,
not automatic write-ahead capture. A process lost before the work root commits
can still lose unpersisted input. Continuous crash-safe raw ingress, runtime
scheduling, source-clock reconstruction, production storage qualification and
whole-system retention remain separate requirements. No gate or bead is closed.
