# Retained native video frame publications

`fss_reference::ingest::video_publication` is an explicit publication boundary for an
actual `RecordedH264Frame` or `RecordedH265Frame`. Normal range decoding and video
motion remain unpublished. Call `PublishedVideoFrame::publish` with the sealed
native frame, explicit `VideoPublicationLimits`, the authorized deployment and its
`ReplayCx`. Persist the returned `publication_root`; `PublishedVideoFrame::open`
uses that exact identity after restart, without the input path or another codec run.

## Retained format and authority

The format composes the existing `fss.object_manifest.v1` owner with the unchanged
native `fss.recorded_h264_frame_receipt.v2` or
`fss.recorded_h265_frame_receipt.v2` receipt; it introduces no replacement codec or
canonical digest domain. The manifest kind is
`recorded-video-frame:v1:<range_segment_count>:<output_index>`, using canonical
unsigned decimal numbers, no leading zeros, 1..65536 source segments and a display
position smaller than that count. The kind binds the range/output fields that are
not encoded by the existing native receipt. The receipt retains the random-access
start, exact source segment, native decode index, source capsule, decoder semantics,
dimensions, privacy generation and luma/I420 digests.

Metadata is the exact native receipt. The unique child closure also contains the
original import root, import manifest, source capsule and packed I420 payload. The
I420 order is Y, Cb, Cr; chroma dimensions round up for odd visible dimensions. The
packed digest prevents swapped chroma planes from passing custody verification.
The manifest root identifies both slot `fv-<hex-root>` and completion batch
`batch:recorded-video:<hex-root>`. The final single `decode_receipt` delta is in the
**cognition** plane, names the native receipt and witnesses the publication root.
A visible root without this exact completion batch is not a completed frame.

## Admission and recovery

Both publication and cold read verify current import completion, the entire original
recording (including prediction dependencies and container parameter sets), exact
capsule/segment binding and the sensor's current privacy policy. Source deletion is
refused by the retained import owner even when derived pixels remain on disk. A
frame from a superseded mask cannot be published or served. All staged/returned
pixels are already masked; RGB rendering also preserves the policy's fixed fill.

The source and pixel ceilings apply to completed reuse too. Whole-source verification
is intentionally conservative and repeated per operation; this reference path is
not a constant-I/O frame cache. Callers doing bulk publication must budget accordingly.

The writer stages verified children, publishes root-last, then commits completion.
An interruption between root and completion can resume the identical graph. Neither
completed reuse nor a visible-root retry silently repairs missing/corrupt custody.
Cancellation checkpoints are checked before work and at the root-to-completion
boundary, with no fallible work after the final commit.

Cold reads establish retained consistency, not an independent re-execution proof.
Publication of an individual frame does not certify the remainder of its requested
range, live continuity, absence, scene truth, or any authorized external effect.
A handle is admitted under the policy current at open/publication; reopen it when
crossing an authority or policy boundary rather than retaining an old in-memory grant.

## Focused contracts

`cargo test -p fss-reference --test video_publication_contract` exercises both real
codecs, HEVC B-picture display order, native receipt and RGB equality, cold restart,
completion-cut recovery, idempotence, narrower limits, corrupt derived pixels and
source damage after decoding. The module unit test rejects noncanonical or unbounded
manifest range/output identifiers. These contracts supplement, not replace, local
release qualification.
