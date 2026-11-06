# Select retained MP4/MOV footage by movie time

`fss-file select-movie` resolves a half-open movie-time interval to original retained
video segments. It applies the container's unit-rate edit list and signed composition
offsets, preserves exact rational boundaries, and reports both the requested presentation
occurrences and the coding-order ranges required to start the existing Annex-B extraction
path. The result contains metadata and source handles, not media bytes or pixels.

This is a local operator command over a completed ADP-FILE-001 MP4/MOV import. It advances
the recorded-file retrieval part of FSS-068 and VIT-008. It does not add a UTC archive query
or change the metadata-only canonical `fss query --target footage` command.

## Use

First import an AVC or HEVC MP4/MOV with the existing file adapter and retain its printed
`import_identity`. The original external path is unnecessary for selection:

```sh
cargo run -p fss-cli --bin fss-file -- select-movie \
  --root ./camera-evidence --site site:home \
  --import-id sha256:YOUR_IMPORT_DIGEST \
  --start-movie-tick 400 --end-movie-tick 800 \
  --max-decode-samples 1024
```

Replace the digest placeholder with the exact import identity. The interval is `[400, 800)`
in **movie ticks**. The report's `movie_timescale` is ticks per second; a scale of 1000 makes
this example 0.4 through 0.8 seconds. The `media_timescale` can differ. Neither scale is a
wall-clock timestamp, and the command never interprets a capture-time assumption as UTC.

The report contains:

| Field or row | Meaning |
| --- | --- |
| `import_identity`, `import_root`, `manifest_digest`, `authority_sequence` | Existing retained source and completion bindings |
| `selection_verified_source_sha256` | Verified digest of the entire original container |
| `selection_source_bytes_read` | Original source bytes read to reconstruct and validate this container |
| `movie_sample` | One presentation occurrence, with original coding `segment`, edit index, exact clipped interval and original byte range |
| `movie_edit` | The intersecting edit, its interval, and media origin; `implicit` denotes an unedited track |
| `movie_gap` | Declared `empty_edit` or `unrepresented` movie time |
| `decode_span` | Original `start_segment`, `segment_count`, selected segment subset, and quoted source/Annex-B byte costs |
| `selection_complete=true` | All selection, custody and budget checks completed |

Every printed `movie_interval=A/D,B/D` means `[A/D, B/D)` **movie ticks**. The denominator
is the media timescale. Numerators are integers and remain exact even where division would
produce a fractional tick or exceed floating-point integer precision. Selection uses interval
overlap; the returned byte range always covers the whole original sample. No encoded sample
is cut at an arbitrary time boundary.

Repeated edits can produce multiple presentation rows for one original segment. Presentation
rows follow movie time. `decode_span` uses original coding order and accounts separately for
the selected segments and all intervening prerequisites. B pictures can therefore make the
order and number of presentation rows differ from the decode range.

The admitted timing profile checks each continuous decode-time run in presentation order.
Adjacent presentation starts must exactly match the previous sample's start plus its declared
duration. This admits reordered and variable-duration material when that relationship is exact;
duplicate, overlapping or otherwise inconsistent presentation grids are refused. A run's last
sample uses its declared duration. A decode-time discontinuity starts a new run, and a decode
span cannot borrow its random-access bootstrap from the previous run. Containers carrying a
`cslg` composition-shift box are explicitly unsupported by selection; the existing ordinal
parser/extractor remains available. These checks avoid guessing presentation durations from
decode deltas when the two differ. See the [QuickTime composition timing documentation](https://developer.apple.com/documentation/quicktime-file-format/composition_offset_atom)
and ISO/IEC 14496-12, sections 8.6.1.3–8.6.1.4.

For example, the checked-in ten-frame AVC fixture has a media edit offset and reordered
B pictures. At movie scale 1000, `[400, 800)` selects original segments 3 then 1 in presentation
order. Their common decode span begins at segment 0 and includes four coding segments.
The sample at exactly 800 is excluded.

The reported spans can be passed to the existing decoder:

```sh
cargo run -p fss-cli --bin fss-file -- decode \
  --root ./camera-evidence --site site:home \
  --import-id sha256:YOUR_IMPORT_DIGEST \
  --segment 0 --segment-count 4 --interpretation ycbcr
```

Use the span values from your own report. The current `fss-file decode` command accepts at most
1024 coding segments per range; keep `--max-decode-samples 1024` when planning for that decoder,
or narrow the movie interval until its required span fits. Decoding a span also processes its prerequisite
frames; selection does not turn that entire span into the requested presentation subset.
Existing codec, current privacy-mask, output and decode-work checks still apply. The selector
quotes the extractor's bootstrap admission and byte cost; it does not certify that a codec
will decode all pictures. In particular, the existing HEVC CRA/BLA leading-picture handling
still governs skipped RASL pictures.

## Custody and bounded work

The retained reader verifies the completed import root, canonical manifest and ordered source
chunks, checks the original whole-file digest, reparses the original container, and compares
every demuxed sample with the retained segment ranges and digests. It rechecks the root and
completion binding before releasing a result. Cancellation or any corrupted, missing,
tombstoned, stale or inconsistent source refuses the whole selection.

The first admitted scope is original ADP-FILE-001 `mp4avc` and `mp4hevc` imports. Partitioned
manifests use the existing retained part-resolution and custody path. Recoverable fragmented
tails use the file adapter's existing prefix policy; unrepresented requested time remains a gap.
Reconstructed native-origin imports are refused rather than treated as original file imports.

Reading the whole container is necessary for the admitted parser and source-identity check.
The source admission ceiling (`--max-source-bytes`) is independent of the selected decode
byte ceiling. `--chunk-bytes` and `--max-segment-bytes` retain their existing read-admission
meaning. The selector additionally exposes:

| Option | Bounded quantity |
| --- | --- |
| `--selection-work-units` | Timeline visits, comparisons and extraction-planning work |
| `--max-selection-rows` | Sample/edit/gap/span metadata, including selected-segment references |
| `--max-decode-samples` | Whole coding samples across the required decode spans |
| `--max-decode-bytes` | Original sample bytes across those decode spans |
| `--max-annex-b-bytes` | Quoted Annex-B output including bootstrap parameter sets and start codes |

All limits must be positive and obey library hard ceilings. The existing parser's independent
input, metadata, box, track, sample, table and NAL limits also apply. A refusal cannot become
an empty successful answer. The command emits no `movie_sample` rows or completion marker
until the native selection has passed its checks. Report delivery also checks cancellation
between rows and selected-segment references, and immediately before the terminal marker.
Cancellation or an output error can leave a partial report; without `selection_complete=true`
it is not a completed selection report.

This utility opens the existing operator deployment through its normal startup/recovery owner.
It is **not** the sealed metadata-only reader used by canonical agent footage discovery. It
does not publish new evidence, export raw media, decode pixels, modify policy or activate
calibration. Its metadata is a source-bound selection aid, not an authorization for a later
export or effect.

An empty edit is a container declaration. An unrepresented interval has no selected sample in
this container. Neither establishes physical absence, live continuity or acquisition coverage.
The report always labels `selection_absence_certifiable=false`.

## Native API

`fss_container::demux::AvcMp4::select_movie_interval` provides the pure borrowed-source
planner, with a checkpointed variant and `MovieSelectionLimits::validate` for pre-I/O admission.
`fss_reference::ingest::RetainedFileImport::select_movie_interval` adds retained source
verification and returns `RetainedMovieSelection` with the exact custody bindings. Existing
parsing, ordinal extraction, manifest and publication formats are unchanged.

The container tests cover timing, edit lists, reordering, byte costs, random access, limits
and cancellation. Retained-library and real command-path tests cover cold reads, original-file
independence, custody mismatches and atomic refusals. The implementation status records which
tests were actually executed; authored tests alone are not qualification evidence.
