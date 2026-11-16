# Retained Matroska presentation selection

`fss-file select-matroska` selects a half-open interval from a retained AVC or
HEVC Matroska file and reports the original frame indices and byte ranges needed to review it.
The original pathname can be gone. Selection reads authenticated custody chunks, verifies the
complete original and every frame index, and uses the existing immutable source reader so an
active deployment writer can remain open.

## Use

```sh
cargo run -p fss-cli --bin fss-file -- select-matroska \
  --root ./camera-evidence --site site:home \
  --import-id sha256:REPLACE_WITH_COMPLETED_IMPORT_ID \
  --start-presentation-ns 528000000 \
  --end-presentation-ns 928000000
```

Both endpoints are unsigned Segment presentation nanoseconds after any track CodecDelay.
The start is included and the end excluded. These values are independent of UTC or sensor
capture timestamps; the import's existing `capture_time_class` is preserved.

Only completed original `ADP-FILE-001` imports with `mkvavc` or `mkvhevc`
format are admitted. This command returns a metadata report. Existing segment-based decode
operations can consume the reported coding ranges; this command does not decode or export a
clip, change sentinel selection, create a new persistent record, or certify physical absence.

## Presentation and decoding

Frames appear in display order in `matroska_sample` rows, which may differ from their
coding order when the recording contains B pictures. Each row gives its original coding
`segment`, byte offset and length, full presentation start/end, intersection with the
request, and duration provenance:

- `block_duration`: explicit BlockDuration multiplied by TimestampScale.
- `default_duration`: Track DefaultDuration, which is already nanoseconds.
- `next_presentation`: the next frame's timestamp in display order.
- `unknown`: a final frame without an explicit/default duration or a following timestamp.

An unknown final end is never replaced by a guessed frame rate. A later query conservatively
retains that frame as a possible overlap, prints `presentation_end_ns=unknown` and
`overlap_certainty=possible`, and emits `presentation_unresolved` for the
unresolved interval. A selection can complete successfully while temporal uncertainty remains;
`selection_complete=true` means the bounded request completed, not that every duration
is known. `presentation_gap` describes an interval with no indexed presentation or
possible continuation. It never establishes that a real scene was empty.

`decode_span` rows give consecutive coding ranges starting at an earlier container
keyframe that also contains an AVC IDR or HEVC IDR NAL. `requested_segments` identifies the
actual requested frames; intervening/preroll frames are prerequisites, not selected display
frames. Negative presentation timestamps remain eligible as decoding prerequisites and are
excluded from display selection. An unavailable random-access prerequisite refuses the whole
request. HEVC CRA pictures retain the earlier IDR prerequisite so their leading RASL pictures
remain reconstructible. A BLA picture invalidates that prerequisite; selection refuses frames
in that chain until a later declared IDR. CRA-only starts and BLA-only starts are outside the
current selection profile.

The current temporal profile admits unit TrackTimestampScale and zero TrackOffset,
SeekPreRoll and DiscardPadding. Duplicate presentation timestamps, unsupported timing,
malformed/duplicated timing singletons, and an incomplete retained source refuse explicit
selection. A BlockGroup with track DefaultDuration requires its own BlockDuration. Existing
unlaced, visible-frame AVC/HEVC container admission still applies. These timing restrictions
do not change byte-preserving import acceptance or the historical canonical manifest.

## Bounds and atomicity

The source reader first admits the complete original against `--max-source-bytes` and
the container hard ceiling of 512 MiB. Selecting a short interval does not bypass that full
read. The shared `--max-read-bytes` and `--max-read-objects` allowances cover retained
metadata, source reads and required final custody revalidation without refill.

Selection has independent limits:

| Option | Default | Hard maximum | Counts |
| --- | ---: | ---: | --- |
| `--selection-work-units` | 16,777,216 | 16,777,216 | Frame visits, sorting comparisons/swaps and result rows |
| `--max-selection-rows` | 262,144 | 262,144 | Samples, gaps, uncertainty rows, decode spans and requested indices together |
| `--max-decode-samples` | 65,536 | 65,536 | All coding frames across returned spans, including preroll |
| `--max-decode-bytes` | 128 MiB | 512 MiB | Original length-prefixed frame bytes across those spans |

No Annex-B expansion size is quoted. No media is extracted. The report is buffered by the
immutable reader and released only after final custody validation; failures release neither
success-looking stdout nor an optional `--manifest-out` export. The existing shared
cooperative read deadline applies.

## Library entry points

- `MatroskaVideo::select_presentation_interval` and its checkpoint variant select from
  an already authenticated borrowed source.
- `RetainedFileImport::select_matroska_interval` performs complete source/custody
  reconstruction and returns `RetainedMatroskaSelection`.
- `MatroskaSelection` keeps query bounds, codec delay, samples, gaps, unresolved intervals,
  decode spans, exact charged work, requested bytes and prerequisite bytes separately.

No new persistent schema or canonical encoding is introduced.

## Focused regression commands

The added contracts exercise checked-in AVC/HEVC footage, B-picture ordering, explicit/default/
unknown duration, CodecDelay and negative presentation, exact resource limits, cancellation,
retained index/digest tampering, pathname deletion, an active writer, final cumulative read
limits and atomic refusal on source/history loss.

```sh
cargo test -p fss-container --lib demux::matroska::timeline::tests
cargo test -p fss-reference --lib ingest::retained::matroska::tests
cargo test -p fss-cli --bin fss-file matroska::tests
```

Implementation-time status: these new Rust contracts were authored but could not be compiled
or executed after the execution environment became unavailable. They are not qualification
receipts; broad codec, footage-query and deployment qualification remains open.

The temporal rules follow the official
[Matroska elements](https://www.matroska.org/technical/elements.html) and
[timestamp notes](https://www.matroska.org/technical/notes.html).
