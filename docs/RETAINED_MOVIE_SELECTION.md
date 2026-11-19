# Select retained MP4/MOV and MKV/WebM footage by movie time

`fss-file select-movie` resolves a half-open movie-time interval to original retained
video segments. It applies the container's unit-rate edit list and signed composition
offsets, preserves exact rational boundaries, and reports both the requested presentation
occurrences and the coding-order ranges required to start the existing Annex-B extraction
path. The result contains metadata and source handles, not media bytes or pixels.

This is a local operator command over completed AVC/HEVC MP4/MOV or MKV/WebM file imports,
and supported native RTSP MP4/MOV imports. It advances
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

### Matroska and WebM recordings

The existing [`select-matroska` metadata command](RETAINED_MATROSKA_SELECTION.md) preserves
its duration provenance and unresolved presentation intervals. `select-movie` supplies the
stricter exact-duration plan consumed by `export-movie`; both commands remain available.

For retained `mkvavc` and `mkvhevc` sources, movie ticks are **nanoseconds**. Both reported
timescales are 1,000,000,000. `selection_source_format` names the retained format and
`selection_movie_tick_unit=nanosecond` makes the unit explicit. The parser preserves the
original Segment TimestampScale exactly, including scales that do not divide a second.

For example, select 0.5 through 1.5 seconds of retained MKV presentation time:

```sh
cargo run -p fss-cli --bin fss-file -- select-movie \
  --root ./camera-evidence --site site:home \
  --import-id sha256:YOUR_IMPORT_DIGEST \
  --start-movie-tick 500000000 --end-movie-tick 1500000000
```

The admitted Matroska profile requires explicit durations: a SimpleBlock uses the selected
track's `DefaultDuration`, and a BlockGroup uses its `BlockDuration`. Missing durations,
overlapping presentation intervals, unsupported track-time scaling, codec delay, seek
preroll or block timing transforms refuse selection. Ordinal import and extraction remain
available for otherwise valid sources outside that timing profile. These semantics follow
[RFC 9559, sections 5.1.3.5.3 and 11](https://www.rfc-editor.org/rfc/rfc9559.html#section-5.1.3.5.3);
the selector deliberately requires declared durations rather than inferring them from the
next frame. Negative-timestamp frames may be decode prerequisites but are not presented.

Explicit duration gaps remain `unrepresented` intervals. No gap is filled by extending a
nearby frame, and no gap establishes physical absence. Reordered frames retain their
original segment indices and exact coding-order prerequisites. Matroska decode spans require
both the container keyframe assertion and an AVC or HEVC IDR. HEVC spans keep the preceding
IDR across CRA pictures so requested leading RASL pictures retain their references. A BLA
breaks that chain and requires a later IDR. The existing AVC/HEVC decoder still decides which
profiles it can decode, and every selected picture must exist before an export can complete.

The same interval can be passed to `export-movie` with `--interpretation ycbcr`, `--output`,
and the existing output options. `--output-format gray-mkv --output-timing movie` preserves
the selected presentation intervals and gaps in the screened grayscale review file;
`--output-rate NUM/DEN` explicitly requests uniform retiming. Export checks current privacy
masks and complete native decoding before creating the output. The admitted input codecs
remain AVC/HEVC, including when the EBML DocType is `webm`; this does not add VP8, VP9 or AV1.

Matroska track numbers retain their full 64-bit value. New review materializations use the
`fss.file_movie_output.v2` lineage domain with that full-width encoding. Existing import
identities, canonical manifests and historical export receipts are unchanged.

The report contains:

| Field or row | Meaning |
| --- | --- |
| `import_identity`, `import_root`, `manifest_digest`, `authority_sequence` | Existing retained source and completion bindings |
| `selection_verified_source_sha256` | Verified digest of the entire original container |
| `selection_source_format`, `selection_movie_tick_unit` | Exact retained container/codec family and explicit query tick unit |
| `selection_source_bytes_read` | Original source bytes read to reconstruct and validate this container |
| `movie_sample` | One presentation occurrence, with original coding `segment`, edit index, exact clipped interval and original byte range |
| `movie_edit` | The intersecting edit, its interval, and media origin; `implicit` denotes an unedited track |
| `movie_gap` | Declared `empty_edit` or `unrepresented` movie time |
| `decode_span` | Original `start_segment`, `segment_count`, selected segment subset, and quoted source/Annex-B byte costs |
| `selection_complete=true` | All selection, custody and budget checks completed |
| `deployment_mutated=false`, `payload_read_bytes`, `payload_read_attempts` | Immutable read result and aggregate usage, including final verification |

Every printed `movie_interval=A/D,B/D` means `[A/D, B/D)` **movie ticks**. The denominator
is the media timescale. Numerators are integers and remain exact even where division would
produce a fractional tick or exceed floating-point integer precision. Selection uses interval
overlap; the returned byte range always covers the whole original sample. No encoded sample
is cut at an arbitrary time boundary.

Repeated edits can produce multiple presentation rows for one original segment. Presentation
rows follow movie time. `decode_span` uses original coding order and accounts separately for
the selected segments and all intervening prerequisites. B pictures can therefore make the
order and number of presentation rows differ from the decode range.

For MP4/MOV, the admitted timing profile checks each continuous decode-time run in presentation order.
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
still governs skipped RASL pictures when an MP4 range starts at such a picture. Matroska
movie plans retain an earlier IDR across CRA and refuse broken reference chains.

## Custody and bounded work

The retained reader verifies the completed import root, canonical manifest and ordered source
chunks, checks the original whole-file digest, reparses the original container, and compares
every demuxed sample with the retained segment ranges and digests. It rechecks the root and
completion binding before releasing a result. Cancellation or any corrupted, missing,
tombstoned, stale or inconsistent source refuses the whole selection.

The admitted scope includes original ADP-FILE-001 `mp4avc`, `mp4hevc`, `mkvavc` and
`mkvhevc` imports. Partitioned
manifests use the existing retained part-resolution and custody path. Recoverable fragmented
tails use the file adapter's existing prefix policy; unrepresented requested time remains a gap.
Completed native RTSP window, catalog, page and recorder-replay imports retain their original
adapter identities. Their complete packet/index/proof closure must reconstruct the entire
MP4 byte-for-byte, including unselected content, before selection can succeed.

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
| `--max-origin-read-bytes` | Native packet/catalog/replay proof allowance; default and maximum 132 MiB |
| `--max-read-bytes` | Shared payload allowance, including metadata, source/origin reads and final revalidation; default 1 GiB, maximum 4 GiB |
| `--max-read-objects` | Shared payload read attempts, including repeated reads; default 1,000,000, maximum 4,000,000 |

All limits must be positive and obey library hard ceilings. The existing parser's independent
input, metadata, box, track, sample, table and NAL limits also apply. A refusal cannot become
an empty successful answer. The complete report and optional `--manifest-out` export stay
buffered until final source, publication and authority checks succeed. Wrong-site, missing-root,
damaged-history, source-loss and read-budget refusals print no stdout and create no export.
An output-device error can still interrupt delivery of an already verified report.

Selection uses the sealed immutable retained owner and can run while the recorder holds its
writer. It acquires no publisher lock, creates no deployment and performs no journal recovery.
One read allowance covers the complete operation; verification never renews it. A cooperative
60-second deadline is checked at retained-read boundaries and final validation; it does not
preempt container parsing or a filesystem call. A concurrent committed-head change requires a
fresh invocation. Selection publishes no evidence, exports no raw media and decodes no pixels.
Its metadata remains a source-bound selection aid, not authorization for a later export or effect.

An empty edit is a container declaration. An unrepresented interval has no selected sample in
this container. Neither establishes physical absence, live continuity or acquisition coverage.
The report always labels `selection_absence_certifiable=false`.

## Native API

`fss_container::demux::AvcMp4::select_movie_interval` and
`fss_container::demux::MatroskaVideo::select_movie_interval` provide pure borrowed-source
planners, each with a checkpointed variant and `MovieSelectionLimits::validate` for pre-I/O admission.
`fss_reference::ingest::RetainedFileImport::select_movie_interval` adds retained source
verification through `RetainedSource` and returns `RetainedMovieSelection` with the exact custody
bindings. Immutable API callers must complete their owner's final revalidation before releasing
the result. Existing
parsing, ordinal extraction, manifest and publication formats are unchanged.

The container tests cover timing, edit lists, reordering, byte costs, random access, limits
and cancellation. Retained-library and real command-path tests cover cold reads, original-file
independence, custody mismatches and atomic refusals. The implementation status records which
tests were actually executed; authored tests alone are not qualification evidence.
