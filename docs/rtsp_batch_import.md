# Import independent RTSP sessions into one deployment

`fss-import-rtsp batch` imports between one and sixteen independently retained native
recordings into one destination deployment. It closes the operator gap between
`fss-capture-rtsp reconnect --continue-after-success yes` and analysis of the retained
results. It does not concatenate epochs or reuse their clocks as a continuous timeline.

Each selection is an ordinary `fss-import-rtsp` argument array, without `--approve`.
The existing importer still owns source verification, archive locking, retained
originals, root-last publication, native codec selection, and idempotent recovery.
A batch may contain AVC and HEVC windows, complete catalogs, or ordered page selections.
Every child must name exactly the same destination root, site and principal.

## Review all selections together

Save the selected native argument arrays as a JSON array in an operator-owned file.
The shape is an array of argument arrays, not an object, shell command string, or a
capture transcript. Every key and value is a separate JSON string. For example, a
one-selection request can be constructed from an already reviewed native argument
array by wrapping it in an outer array. Add further independent native argument
arrays to import additional epochs.

Each array must include its own exact source archive, window or catalog slot/root,
sensor, stream, generation, authority anchor, receive clock, receive time and explicit
owner/read-originals/retain-originals approvals. Catalog selections also require
that catalog's decode clock and time scale. Use the receive clock and generation
from the exact capture child plan, not the pre-campaign base clock.

The input file is not opened by FSS; the shell passes its contents as one bounded
UTF-8 argument:

```sh
fss-import-rtsp batch --requests "$(cat /owner/import-selections.json)"
```

This preview performs no filesystem, clock, credential or network operations. It
validates every native request, rejects duplicate canonical requests and embedded
child approvals, and displays each complete native plan. It sums the effective
frame, original-byte, media-byte and work ceilings without widening any child limit.
Timeouts remain cooperative per-child limits; their sum is not a preemptive batch
wall-clock guarantee. Input is bounded to 49,152 bytes. Each complete preview or
output row is bounded to 65,536 bytes; an oversized projection is refused, not cut
mid-object.

After reviewing the entire ordered batch, repeat it with the outer approval:

```sh
fss-import-rtsp batch --requests "$(cat /owner/import-selections.json)" \
  --approve sha256:YOUR_REVIEWED_BATCH_DIGEST
```

Replace the approval placeholder with the exact `approval_digest` emitted by the
batch preview. A native child approval or capture campaign approval is not valid
for this operation. Changing a selection, ordering, destination, clock assumption
or effective limit changes the batch approval. Reordering option/value pairs within
an otherwise identical native selection does not.

## Results and partial failures

Execution emits bounded JSONL under `fss.rtsp_import_batch_operator.v1`. Rows contain
one batch approval and contiguous sequence numbers. `import_completed` embeds the
unchanged native receipt, including its retained import identity, source provenance,
frame counts and `reused` status. Feed each returned `import_identity` into the
existing `fss-file`, watch or corroboration commands using the common deployment.
Destination privacy remains enforced by the original decode/analysis owners.

The batch is deliberately incremental, not atomic. On the first failed or
unconfirmed child, no later import runs. `batch_terminal` distinguishes completed,
failed and unattempted imports. A failed child is labeled
`unconfirmed_may_be_durable`, because a lost acknowledgement can occur after a
storage boundary. Earlier completed imports are not rolled back or deleted.

After restoring a missing archive or otherwise resolving a refusal, repeat the exact
approved batch with all original source archives available. Native idempotent replay
reuses completed imports and reconciles the remaining selections. Do not guess a new
starting index from a truncated JSONL record, or mistake the number of output rows
for an independently durable checkpoint. Output failure also stops before any later
child; the unreported operation can still require reconciliation.

Once import is confirmed, original source archives may be offline during native
verification and decoding from the destination's retained custody. Source recovery
pin journals are not rewritten by import or replay. Distinct source generations and
receive/decode clocks remain distinct; `atomic`, `continuity_between_imports` and
`absence_certifiable` are always false in this wrapper.

## Native checks

Run `bash scripts/check_rtsp_batch_import.sh` on the pinned native toolchain. It
executes both command binaries' unit tests and the existing real-process capture
and reconnect suites. Batch integration captures three independent loopback-camera
sessions, imports them into one deployment, checks exact retries, takes all original
archives offline and decodes each retained result. A second case removes the middle
archive, verifies that the third selection is not attempted, restores the archive,
and checks exact replay reuses only the already completed import before cold decode.
These are native fixture checks, not physical-camera qualification or DSR release
authority. Existing broader qualification lanes are unchanged.
