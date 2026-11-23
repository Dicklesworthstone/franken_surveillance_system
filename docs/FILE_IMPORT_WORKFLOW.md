# Retained camera-file workflow

`fss-file` is an operator utility over the persistent reference deployment and the existing
ADP-FILE adapter. It imports JPEG/MJPEG or Annex-B H.264 source bytes, reopens the resulting
ledgered import without the original file, verifies retained custody, and extracts exact
source segments. It does not run a model, certify live coverage, or claim that H.264 was decoded.

## Import

```sh
cargo run -p fss-cli --bin fss-file -- import \
  --root ./camera-evidence --site site:home \
  --input ./recording.h264 --sensor sensor:driveway --stream stream:main \
  --receive-time-ns 1000000000 --manifest-out ./import.manifest
```

Use a receive timestamp appropriate to the deployment's declared timeline. The example is a
synthetic one-second reference timeline, not a real capture timestamp. Without a complete
`--capture-start-ns`, `--capture-uncertainty-ns`, `--assumed-fps` tuple, capture time remains
`unknown`. A supplied tuple is explicitly an `operator_assumption`, never hardware clock proof.
The import's output reports `absence_certifiable=false` in either case.

Each ordinary `import` drives the core acquisition lifecycle, and a completed import retains it in its
completing ledger batch. `import`, `inspect` and `verify` print it after replaying it through the
core session: `acquisition_history=requested,authenticated,adapter_accepted,degraded,cancelled`,
`acquisition_terminal=cancelled` and `acquisition_ending=end_of_file_source`. A file is not
decoded on import and has no packet sequence or live clock. The session therefore degrades
(`continuity_not_observable`, `first_frame_decode_not_attempted`) instead of observing a first
frame. `acquisition_absence_refusal` is the core's refusal of any absence claim. An import completed
before this lifecycle existed prints `acquisition_history=not_recorded`. This refusal covers live
absence only. It does not block `fss-event watch --retain-coverage` from certifying, over the
recorded capture interval, what the retained pipeline observed in the imported bytes. Such
coverage is labelled `recorded file source; no live continuity` (fss-dt3qf; see
[RECORDED_EVENT_WORKFLOW.md](RECORDED_EVENT_WORKFLOW.md)).

The command reports the actual retained manifest and completion anchor, rather than treating a
newly reconstructed retry receipt as stored truth. A successful import also performs a complete
source-byte verification. Save the printed `import_identity=sha256:...` for subsequent commands.

## Import a finite MPEG-TS recording

Use the explicit `import-ts` operation for a bounded, owner-provided transport file:

```sh
cargo run -p fss-cli --bin fss-file -- import-ts \
  --root ./camera-evidence --site site:home \
  --input ./recording.ts --sensor sensor:driveway --stream stream:main \
  --receive-time-ns 1000000000
```

The command selects one unambiguous AVC or HEVC program/video stream. If the
recording contains multiple candidates, supply `--ts-program N` and/or
`--ts-video-pid N` using decimal numbers. Generic `--media-format` and recorded-RTP
binding options do not apply to this operation.

Standard 188-byte TS is the default. For a recording whose packets have a
four-byte M2TS prefix followed by the 188-byte TS packet, explicitly select
`--ts-framing m2ts192`:

```sh
cargo run -p fss-cli --bin fss-file -- import-ts \
  --root ./camera-evidence --site site:home \
  --input ./recording.m2ts --sensor sensor:driveway --stream stream:main \
  --receive-time-ns 1000000000 --ts-framing m2ts192
```

Only `ts188` and `m2ts192` are accepted; no framing is guessed from a filename,
sync pattern or file length. Truncated packets and incorrect sync positions refuse.
Every four-byte prefix is retained and covered by the original source digest.
Elementary byte mappings use offsets in the complete original M2TS file, while
transport duplicate checks compare only the inner 188-byte packets. The prefix
clock remains opaque and untrusted; it does not establish capture time or live
continuity. Reports identify `ts_framing`, and M2TS reports explicitly state
`source_m2ts_prefix_clock=opaque_untrusted`.

Both the original transport file and reconstructed elementary stream have separate
64 MiB ceilings. The original includes unselected audio, transport headers, exact
duplicate packets and other retained bytes; the import never replaces it with a
reconstructed copy. Its versioned origin proof and original chunks enter the same
root-last publication as the native AVC/HEVC access units. A partial publication
can resume, while a retry refuses to repair corrupted bytes behind a visible root.
An exact completed retry reuses the original identity without new ledger entries.

The output includes the retained import identity, original digest/length, selected
codec/program/PID, elementary length and access-unit count. Successful output waits
for complete retained source verification. Save `import_identity` for the existing
`verify`, `extract`, retained decode, watch, sentinel and event workflows. A cold
reader can reconstruct source provenance without the loose `.ts` file. Direct
manifest-only segment helpers refuse this adapter because they cannot establish
original transport custody.

PES packet groups are not frames. Native splitters identify access units, and the
existing decoders separately decide whether supported pictures can be decoded.
Raw PTS/DTS values remain in the extraction commitment; they are never converted to
capture time. Capture remains `unknown` unless the complete existing capture-hint
tuple supplies an explicit `operator_assumption`. This finite-file adapter does not
establish live continuity or camera absence, and reports no recorded acquisition
lifecycle when one is not present.

Transport limits can be narrowed independently with `--max-ts-packets`,
`--max-ts-psi-sections`, `--max-ts-pes`, `--max-ts-pes-bytes`,
`--max-ts-spans` and `--max-elementary-bytes`. `--max-source-bytes`
bounds the original, and existing chunk/segment ceilings continue to apply.
`--work-units` supplies one nonrenewing allowance for conservative native pass and
I/O reservations, including final verification; it defaults to 1 GiB and is capped
at 4 GiB. These units are not elapsed time or CPU instructions. Cancellation is
checked at bounded native work and publication boundaries.

The focused container parser/receipt suite passed 35 tests on the pinned compiler.
Native retained-import and CLI tests are authored but remain uncompiled/unexecuted
in this session: after a shared-disk failure was resolved, the genuine native
metadata check was killed in unchanged Asupersync 0.5.0 before reaching these
targets. No source diagnostic or native decode pass is claimed. Decoder support
remains the existing native subset. See
[MPEG_TS_RECEIPTS.md](MPEG_TS_RECEIPTS.md) for the extraction receipt contract.

## Reopen, verify and extract

```sh
cargo run -p fss-cli --bin fss-file -- verify \
  --root ./camera-evidence --site site:home --import-id sha256:YOUR_IMPORT_DIGEST

cargo run -p fss-cli --bin fss-file -- extract \
  --root ./camera-evidence --site site:home --import-id sha256:YOUR_IMPORT_DIGEST \
  --segment 0 --output ./first-segment.h264
```

Replace the digest placeholder with the exact 64-character digest reported by import. No input
path is required for these operations. `inspect` performs metadata/authority validation without
reading every source chunk. `verify` checks the full source in recorded chunk order, including
repeated chunks. `extract` verifies touched chunks and the assembled segment checksum before
writing bytes. JPEG/MJPEG extraction produces the original encoded JPEG segment, not a decoded
image. Metadata can be exported by any command with `--manifest-out FILE`; it is the existing
`fss.file_import.manifest.v1` canonical binary, not a new JSON or agent-envelope dialect.

`inspect`, `verify`, `extract` and `select-movie` use immutable retained custody and can run while the
deployment publisher remains open. They do not acquire its writer lock, create a missing
deployment, repair journals or reconcile effects. Acquisition history and recorder-origin
metadata use the same bounded reader as the source manifest. `inspect` can read valid metadata
when original media is unavailable; `verify` and `extract` still require their selected source
bytes and enforce current deletion and privacy authority.

These commands buffer their complete report and any requested source/manifest export
until final payload, publication and authority checks succeed. A custody, deadline or read-budget
refusal leaves stdout empty and creates no export. Successful output adds `deployment_mutated=false`,
`payload_read_bytes` and `payload_read_attempts`; existing source identities and metadata fields
are preserved. Final verification is a bounded observation, not a lease preventing subsequent
changes to the deployment.

| Aggregate option | Default | Maximum |
| --- | ---: | ---: |
| `--max-read-bytes` | 1,073,741,824 | 4,294,967,296 |
| `--max-read-objects` | 1,000,000 | 4,000,000 |

Allowances must use canonical positive decimal spelling. One nonrenewing allowance covers
opening metadata, acquisition and origin receipts, selected source reads and final rereads;
repeated reads count again. These limits are independent of the per-source and per-object
limits below, so inspecting a large source may need an explicit larger aggregate allowance.
A cooperative 60-second deadline is checked at retained-read boundaries; it does not preempt
an ongoing filesystem call. Import and other publication commands keep their operational
deployment ownership and approval behavior.

For retained AVC/HEVC MP4/MOV files, `select-movie --start-movie-tick N --end-movie-tick N`
selects a half-open interval on the container's movie timeline. It verifies the retained
original and reports presentation samples, explicit gaps and required coding-order decode
ranges with exact rational timing. The same shared byte/attempt allowances and final immutable
validation above apply, including complete native RTSP origin verification when applicable.
See [RETAINED_MOVIE_SELECTION.md](RETAINED_MOVIE_SELECTION.md)
for usage, edit-list and preroll semantics, source/read budgets and scope.

## Boundaries

The local operator process and filesystem permissions are the trust boundary. `--principal` is an
audit label, not remote authentication. The reference context grants filesystem operations only;
there is no network-camera discovery, model execution, alert dispatch, or automatic repair here.
Only a completed final authority batch matching the currently visible import root is recoverable.
Missing, inconsistent, tombstoned or incomplete publications fail closed; no root is silently
substituted. Immutable inspection refuses damaged history without truncating it or changing
retention policy. Operational deployment opening for publication commands retains its existing
recovery behavior.

Limits default to 512 MiB per source, 16 MiB per chunk and 16 MiB per returned segment. Set
`--max-source-bytes`, `--chunk-bytes` and `--max-segment-bytes` explicitly to narrow or change
these ceilings. Chunk and segment ceilings cannot exceed 64 MiB. For reads, `--chunk-bytes`
is an admission ceiling, not a request to rechunk stored evidence. Metadata has a fixed 16 MiB
ceiling and bounded collections. Partitioned manifests are refused until part resolution exists.

Exports must be new files outside the deployment. Existing destinations and symlinks are not
overwritten. Unix exports are created with owner-only permissions. Successful writes are fsynced;
this utility does not claim atomic export publication or directory-fsync durability. An I/O error
may leave a partial export for operator inspection. An export or verification failure does not
roll back an already committed import. The command returns a nonzero exit status on that failure.

This adds a usable reference workflow, not production or release qualification. Pinned-nightly
Rust tests and repository qualification must run before promotion.
