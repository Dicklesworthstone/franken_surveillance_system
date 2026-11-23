# Restore a copied recording export into a native archive

`fss-archive restore-export` recovers a copied `fss-archive export` bundle into a
**new, queryable native AVC or HEVC archive**. The original archive and original
export directory may already be gone. Supply an independently retained SHA-256
of the original `COMPLETE.json`, the original recording/clock scope, a new output
directory, and the current deployment that owns the sensor's privacy-mask policy.

The existing `verify-export` command remains a read-only check of copied files.
Restoration adds native root-last publication, catalog construction and cold
recovery. It does not contact a camera or remote storage provider.

## Operator workflow

```sh
fss-archive restore-export \
  --root "$COPIED_BUNDLE" --expected-completion "$EXPORT_COMPLETION_DIGEST" \
  --codec hevc --sensor sensor-front --stream stream-front --generation 7 \
  --anchor "$RECORDING_ANCHOR" --receive-clock "$RECEIVE_CLOCK" \
  --decode-clock "$DECODE_CLOCK" --time-scale 90000 \
  --output-dir "$NEW_ARCHIVE" --allow-whole-windows yes \
  --privacy-root "$PRIVACY_DEPLOYMENT" --site "$SITE" \
  --max-windows 64 --max-objects 4096 --max-total-bytes 536870912 \
  --max-read-bytes 4294967296 --max-io-calls 1000000 \
  --max-local-bytes 17179869184 --max-local-operations 4000000 \
  --timeout-ms 300000
```

`EXPORT_COMPLETION_DIGEST` must come from an independently trusted record. Hashing
an untrusted copy and passing that same hash does not authenticate its origin.
The codec is explicit (`avc` or `hevc`); stored tags cannot choose a weaker or
different verifier. All scope identities remain caller supplied.

After a successful restore, the `new_snapshot` field pins the new archive's
inventory. Use the ordinary archive commands with the same scope and new root:

```sh
fss-archive verify \
  --root "$NEW_ARCHIVE" --codec hevc \
  --sensor sensor-front --stream stream-front --generation 7 \
  --anchor "$RECORDING_ANCHOR" --receive-clock "$RECEIVE_CLOCK" \
  --decode-clock "$DECODE_CLOCK" --time-scale 90000 \
  --expected-snapshot "$NEW_SNAPSHOT" --start 0 --end 180000 \
  --max-output-windows 64 --max-output-bytes 536870912
```

The destination's parent must already exist. Restoration requires Linux GNU with
`/proc/self/fd`; hosts without the required descriptor and atomic no-replace
operations are refused. The destination is created exclusively with mode 0700;
its files are private. Existing files, directories and symlinks are never
overwritten, merged into or treated as an implicit retry. A destination inside,
aliasing, or containing the copied bundle or privacy deployment is refused.
Shared writable destination parents without sticky-directory protection are also
refused. The newly created directory is pinned immediately; a failure after that
creation returns an owner so the command can preserve partial-output observations.

## Preserved bytes and reconstructed metadata

The sealed codec-specific `ArchiveCodec::restore_recording` boundary requires the
independently pinned canonical root and complete native source verification before
original objects become publishable. Its 32 MiB aggregate bound includes source,
initialization, media, index and manifest bytes. Scope and time scale must match.
The original recording format does not encode a decode-clock identity; that
catalog coordinate remains an explicit caller assertion checked against the
pinned export's scope.

Every source packet, source-only boundary lookahead packet, initialization object,
media object, index and recording-root byte is preserved. The copied playback
file must equal that window's exact initialization-plus-media concatenation.
Restoration does not transcode media, rewrite timestamps or decode pictures.

The selected recordings receive new contiguous archive ordinals, beginning at
zero, in their original order. Catalog pages are rebuilt with the existing native
writer. For example, an export containing original ordinals 8 and 9 restores as
ordinals 0 and 1 with the same recording-root digests and decode intervals. Gaps
remain gaps. Catalog page and snapshot digests are deterministic; they can equal
the old values only when the reconstructed inventory and page boundaries are
identical.

The original archive's omitted windows, unindexed tail, catalog completeness,
clock-index roots, retained UTC synchronization evidence and coverage history are
not recovered from a selected-window bundle. `original_catalog_reconstructed`
and `original_clock_index_restored` remain false; `coverage_claim` is
`not_claimed`. An empty selected bundle creates a valid empty archive and provides
no physical absence evidence.

## Verification and publication sequence

1. Hold the current privacy-policy owner for the entire operation. A currently
   masked sensor, missing authority deployment, or unavailable policy owner
   refuses original-packet restoration before destination creation. The explicit
   whole-window acknowledgement does not override a mask.
2. Verify the pinned completion, closed file inventory, every file identity,
   playback concatenation and native AVC/HEVC source evidence for every selected
   window. Re-read the complete input and recheck the inventory. This full
   preflight also constructs the prospective catalog metadata and checks exact
   deduplicated object/byte, root and page bounds before any destination exists.
3. Reserve the remaining input allowance and create the private destination.
   Read and verify each selected window again, then publish it through the
   existing native recording archive writer. Only one window's media is retained
   in memory at a time; catalog state is bounded metadata.
4. Re-read and recheck the whole copied bundle again. Its request observation,
   completion, selection and file accounting must agree with preflight. Finish
   publishing the native catalog pages.
5. Close and reopen the destination using the **same** destination I/O account.
   The ordinary native archive loader replays the source evidence and verifies
   every selected root, decode interval, catalog-page digest and snapshot.
6. Write and read back `RESTORE_COMPLETE.json.pending`, sync its file, publish
   `RESTORE_COMPLETE.json` with an exclusive hard link, and sync the destination
   and its pinned parent. Only then can a successful command report acknowledge
   a durable completion receipt.

Automatic catalog pages can become durable during step 3. A later input change
or I/O failure therefore can leave a valid private prefix of recordings and
catalog pages. This does not acknowledge complete restoration of the selection.
No automatic deletion or rollback is attempted.

The v1 source completion does not pin the exact `REQUEST.json` bytes. Both passes
check semantic consistency and must observe the same request digest; reports keep
the existing `semantic_consistency_only_unpinned_by_completion_v1` label. The
operation detects changes it observes, without claiming a frozen atomic
filesystem snapshot or future availability.

## Budgets and operation cost

| Account | Default | Maximum / meaning |
|---|---:|---|
| `--max-windows` | 4,096 | 4,096 selected recordings |
| `--max-pages` | 1,024 | 4,096; native pages hold at most 64 windows |
| `--max-scan-roots` | 16,384 | 65,536 native root entries |
| `--max-objects` | 65,536 | 131,072 destination objects; input filenames additionally capped at 24,579 |
| `--max-total-bytes` | 1 GiB | 1 TiB; independently bounds copied file bytes and deduplicated retained objects |
| `--max-read-bytes` | 4 GiB | 1 TiB across both input passes and their final rereads/EOF probes |
| `--max-io-calls` | 1,000,000 | 4,000,000 input traversal/read/revalidation calls |
| `--max-local-bytes` | 16 GiB | 1 TiB of aggregate destination reads and writes |
| `--max-local-operations` | 4,000,000 | 16,000,000 destination filesystem operations |
| `--timeout-ms` | 30,000 | 3,600,000 for the complete request |

Input budgets never refill between passes. If the remaining allowance cannot pay
for a second pass at least as large as the completed first pass, restoration
refuses before creating the output. A successful second pass reports actual
charged reads. If it fails after admission, its remaining reservation stays
charged and `input_accounting` reports `remaining_reservation_retained`.

Destination bytes include native staging, readback, verification holds, catalog
verification, recovery and receipt I/O. They are not just the retained payload
size. The account is shared across writer and cold reader; reopening cannot reset
it. Each operation checks current request admission. Unlocking an already acquired
lock remains permitted after cancellation so the command can settle ownership.
Native writer steps also have a finite selection-derived bound. No timing,
throughput or peak-memory measurement is implied by these configured bounds.

## Completion and failure reports

Stdout uses `fss.local_archive_export_restoration.v1`. The durable receipt file
uses `fss.local_archive_restore_completion.v1`; its exact byte digest is returned
as `restore_completion_sha256`. The original input pin remains
`completion_sha256`. These are separate identities.

The native publisher preserves both auxiliary receipt names as top-level foreign
entries. Ordinary archive discovery and queries accept them, but the recovery
report's `is_clean()` flag is consequently false. Preflight admits capacity for
both names under the discovery scan bound, including for an empty selection;
their presence is not a request for automatic cleanup or repair.

Success requires every selected window to be indexed, cold recovery to agree,
the final receipt to be acknowledged durable, and the request still to be live.
The report separates `restored_windows`, `restored_pages`, `indexed_windows`,
`destination_cold_verified`, `restore_completion_visible`, and
`restore_completion_durable`.

After destination creation, failures return a bounded partial report with
`complete: false` and a nonzero exit status. Counts describe acknowledged durable
work, not proof that an unacknowledged publication did not happen. The phase,
pending state, charged accounts and `publication_reconciliation_required` flag
support inspection. A late failure can occur after receipt visibility or even
after its durability acknowledgement; those observed facts remain in the partial
report. A visible filename alone does not prove its directory sync succeeded.
Malformed arguments and preflight refusals do not produce a restore report.

Preserve a partial destination and inspect it explicitly. Do not overwrite it,
reinterpret a truncated stdout document as completion, or treat an interrupted
command as permission to delete evidence. A subsequent export from a restored
archive must independently acquire current privacy authority again.

## Focused regression commands and claim scope

```sh
cargo test --locked -p fss-reference --test recording_restore_contract
cargo test --locked -p fss-cli --lib archive_cmd::restore_export
cargo test --locked -p fss-cli --lib archive_cmd::verify_export
```

The authored contracts cover both native codecs, exact source bytes and roots,
HEVC lookahead, sparse intervals, subset ordinal reassignment, source loss,
empty selections, corrupt final windows, wrong pins/scope/codec, privacy policy,
unsafe destinations, bounded I/O, cancellation and source drift after publication.
Execution results and outstanding qualification are recorded in
`IMPLEMENTATION_STATUS.md` and the session handoff. FSS-068 and FSS-135 remain
open for their wider incident-graph, archive and release qualification contracts.
