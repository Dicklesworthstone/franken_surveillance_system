# Lossless timed grayscale Matroska output

`fss-container::matroska_gray` frames unchanged, privacy-screened grayscale
samples as a deterministic Matroska video track. The `fss-file` decoded-output
commands expose it as `--output-format gray-mkv --output-rate NUM/DEN`.
`export-movie` also accepts `--output-format gray-mkv --output-timing movie`
to preserve the selected source movie intervals on a query-relative timeline.
Both modes give a local reviewer explicit timing and exact reconstructed screened
sample values. The existing JPEG derivative remains lossy, including at quality
100; these profiles perform no image compression.

The core returns fixed-size metadata buffers. It does not receive pixel data,
allocate an image, open a file, spawn a process or change a privacy policy. The
consumer validates and writes the existing pixel slice immediately after its
frame prefix.

## Fixed profile

| Property | Admitted behavior |
|---|---|
| Container | Matroska version 4, reader version 2 |
| Video | One progressive `V_UNCOMPRESSED` track, `Y800` FourCC |
| Samples | Packed, top-down, eight-bit grayscale; one byte per pixel |
| Row layout | Exactly width bytes; odd widths have no hidden row padding |
| Colour declaration | Eight bits per channel, full sample range |
| Dimensions | Positive axes at most 4096; at most 4,194,304 sample bytes per frame |
| Count | Zero-based output ordinals 0 through 1023 |
| Uniform timing | Explicit positive rate numerator and denominator, each at most 1,000,000 before reduction |
| Movie timing | Positive explicit frame intervals inside a declared clip duration of at most `2^53` ns |
| Timestamp scale | One nanosecond |
| Frame framing | One finite Cluster and BlockGroup per frame; explicit BlockDuration before the final Block |
| Independence | No lacing or ReferenceBlock; every frame contains all its samples |
| Segment | Unknown-size streaming Segment; initialization is written once; movie mode declares its complete duration before frames |
| Metadata | Fixed application labels; no audio, source dates, filenames, tags, thumbnails or attachments |
| Index | No Cues, SeekHead or final duration rewrite |
| Storage | At most 256 initialization bytes and 64 prefix bytes; no heap allocation in the core |

The format follows [RFC 9559](https://www.rfc-editor.org/rfc/rfc9559.html) and the
[Matroska codec mapping](https://www.matroska.org/technical/codec_specs.html#v_uncompressed).
The mapping requires the uncompressed pixel packing to be declared by FourCC.
RFC 9559 sections 5.1.3.5 and 10.4 describe BlockGroup duration and independent
frames; section 10.4 also illustrates BlockDuration preceding Block. This order
lets the owner write one prefix followed by the borrowed samples, without a
trailer or seek. Section 5.1.4.1.28.15 defines the FourCC element.

The profile intentionally preserves coded sample values. A supplied mask sample
of 0 remains 0; a supplied sample of 16 remains 16. It performs no limited-range
expansion, RGB conversion, contrast adjustment or inferred colour calibration.
Exact sample preservation does not imply that every player's display processing
will reproduce identical screen luminance.

## Uniform playback time

The selected rate is a presentation cadence. It is not inferred from the source
capture interval, arrival times, clip endpoints or output frame count. Source
clock uncertainty remains in the owner's separate lineage receipt.

For a reduced rate `numerator/denominator` frames per second, boundary `n` is:

```text
boundary_ns(n) = floor(n × 1,000,000,000 × denominator / numerator)
timestamp_ns(n) = boundary_ns(n)
duration_ns(n) = boundary_ns(n + 1) − boundary_ns(n)
```

Each boundary uses checked integer arithmetic. Flooring an absolute boundary
introduces less than one nanosecond of error and avoids cumulative drift from
repeatedly adding a rounded period. At 30 fps the first three durations are
33,333,333, 33,333,333 and 33,333,334 ns, ending exactly at 100,000,000 ns.
At 30000/1001 fps the first three frames end at 100,100,000 ns.

Each Cluster contains its frame's absolute timestamp, and each Block has a zero
relative timestamp. Long frame periods therefore do not overflow a signed
16-bit Block offset. The extreme admitted rate and frame count still fit the
checked unsigned nanosecond representation.

Equivalent ratios normalize to one value: 60000/2002 equals 30000/1001. Input
component bounds are checked before normalization, so an oversized declaration
cannot evade the bound by cancelling a common factor.

## Source movie time

`export-movie --output-timing movie` converts the authenticated selection's
clipped presentation intervals to nanoseconds. The query's start movie tick is
the output origin. For an interval endpoint `p/d` in movie ticks, movie timescale
`M`, and query `[Q0,Q1)`, the checked integer conversion is:

```text
boundary_ns(p) = floor((p − Q0*d) × 1,000,000,000 / (d*M))
clip_duration_ns = floor((Q1 − Q0) × 1,000,000,000 / M)
frame_duration_ns = boundary_ns(end) − boundary_ns(start)
```

Each endpoint is floored from its original rational position, independently of
previous frames. Period rounding cannot accumulate, and matching endpoints stay
equal. A selected frame whose interval collapses to zero nanoseconds refuses
before decoding or output creation; exact rational intervals remain in the movie
report and lineage. This preserves movie presentation time, not capture time or UTC.

The complete query duration is written in `Info.Duration`, including leading,
internal and trailing timestamp holes. No pictures are generated for those holes;
a player may hold a prior picture or otherwise choose how to display them.
The clip ceiling is `MAX_TIMED_DURATION_NS = 2^53` nanoseconds, about 104 days.
RFC 9559 [section 5.1.2.10](https://www.rfc-editor.org/rfc/rfc9559.html#section-5.1.2.10)
defines Duration as a positive float in Segment ticks. With the one-nanosecond
TimestampScale, every admitted integer duration is exactly representable in the
chosen big-endian IEEE 754 binary64 encoding, one of the floating-point
representations defined by RFC 8794
[sections 7 and 7.3](https://www.rfc-editor.org/rfc/rfc8794.html#section-7.3).

## Local decoded-output CLI

For an already retained AVC/HEVC range, request an explicit presentation rate:

```sh
fss-file decode --root DEPLOYMENT --site SITE --import-id sha256:HEX \
  --segment 0 --segment-count 8 --interpretation ycbcr \
  --output screened.mkv --output-format gray-mkv --output-rate 30000/1001 \
  --work-units 1000000000 --max-output-bytes 67108864
```

Here `--segment 0` must be the range's valid decoder entry point (AVC IDR or
HEVC IRAP). Existing source, decoder, pixel and segment bounds still apply.
A retained JPEG/MJPEG segment produces one frame. Its `decode`, `read-decoded`
and `verify-decoded` commands also accept bounded `--segment-count` ranges and
share one output owner and cumulative work/byte allowances. A range must fit
the retained manifest, and `--receipt-out` remains single-frame-only. Later
source/receipt/privacy failures fence completion even after earlier frames were
written. See [the retained JPEG range workflow](RETAINED_DECODE_WORKFLOW.md#bounded-retained-jpeg-ranges).
AVC/HEVC range
receipts remain unpublished derivations and retain their existing command scope.

Uniform timing remains the default and requires `--output-rate`. The rate is
refused for other output formats. Only `export-movie` admits source movie timing,
and `--output-timing movie` is mutually exclusive with `--output-rate`.

For an exact MP4/MOV movie-time interval, `fss-file export-movie` automatically
decodes the prerequisite AVC/HEVC spans and feeds only the selected presentation
occurrences to this writer. Repeated/backward edits reuse screened luma; preroll
does not appear in the clip. The frame ceiling applies to output occurrences,
and the separate movie lineage digest binds their original intervals and native
decode receipts. For a source movie timescale of 1000, this clips both ends of
the selected presentation interval and preserves its 300 ms duration:

```sh
fss-file export-movie --root DEPLOYMENT --site SITE --import-id sha256:HEX \
  --start-movie-tick 450 --end-movie-tick 750 --interpretation ycbcr \
  --output selected.mkv --output-format gray-mkv --output-timing movie \
  --work-units 1000000000 --max-output-bytes 67108864
```

For the indexed AVC fixture, the output retains original source segments `[3,1]`
with query-relative intervals `[0,150000000)` and `[150000000,300000000)` ns.
Choose `--output-timing uniform --output-rate NUM/DEN` instead to retime selected
pictures at a supplied cadence. See
[movie-time export](RETAINED_DECODE_WORKFLOW.md#exporting-an-exact-movie-time-selection)
for the complete CLI, memory and cumulative-work contract.
Rate syntax is two positive decimal components separated by one slash, each
bounded to 1,000,000 before reduction; signs, whitespace and decimal rates are
refused. `--jpeg-quality` and `--encode-work-units` remain JPEG-only options.
The default output remains PGM.

The whole-file output allowance defaults to 64 MiB and is capped at 256 MiB.
Initialization, every frame prefix and every sample byte count against it.
One frame fits only when all its remaining bytes fit; the first complete frame
is admitted before hashing the encoder implementation or creating the file. At most 1024
selected frames are emitted, additionally bounded by the requested source range.
The codec profile allows axes up to 4096 and at most 4,194,304 pixels per frame.

This is uncompressed, so storage pressure is explicit: eight 1920×1080 frames
need 16,588,800 sample bytes, plus framing. The writer borrows the screened luma
slice instead of copying it into another image buffer. A lower allowance refuses
the request; it never drops frames, changes resolution or substitutes compression.

### Capture-window selection and uniform presentation

The existing paired `--output-window-ns START:EXCLUSIVE_END` and
`--output-clock-basis BASIS` options also apply. For example, a three-frame
range imported with a 100,000,000 ns start, 1,000 ns uncertainty and 10 fps
assumption can select its middle frame:

```sh
fss-file decode --root DEPLOYMENT --site SITE --import-id sha256:HEX \
  --segment 0 --segment-count 3 --interpretation ycbcr \
  --output selected.mkv --output-format gray-mkv --output-rate 30/1 \
  --output-window-ns 150000000:250000000 --output-clock-basis estimated \
  --work-units 1000000000
```

Selection uses the retained source clock and closed uncertainty intervals.
Playback starts at zero and uses consecutive selected-frame ordinals. The selected
source capture times, omitted intervals and gaps are **not** converted into
Matroska timestamps. The separately reported window request/selection digests
retain the source-time decisions. This capture-window route is separate from
`export-movie` and its movie-tick timing option. The decoder still processes all required
dependencies through successful range EOF; an uncertain late boundary refuses
the entire export even if an earlier selected frame is already on disk.

### Output ownership and completion

The CLI supplies only current-policy-screened luma and the owning decoder's
sealed frame-receipt digest. The writer checks its independent luma SHA-256,
positive bounded shape, stable dimensions and non-laboratory source pin before
admitting a frame. It retains the owner's order: decoded display order for direct
ranges, or selected movie-occurrence order for `export-movie`.

The existing private-output owner creates a new file outside the deployment
and refuses overwrite. On Unix it requests mode 0600 and checks the opened file
and pinned parent device/inode identities; Linux creates through the pinned
directory handle. These platform-specific protections are not claimed for
non-Unix targets.
Hashing and writes use chunks of at most 4096 bytes with cancellation checkpoints.
Short writes retain exact accounting; eight consecutive interrupted writes,
zero progress or impossible progress fence completion. A first-frame quota or
pin refusal creates no file. A later refusal can leave a private incomplete prefix.

After successful source EOF and selection, the writer flushes and the private
owner syncs the file; on Unix it also syncs the pinned parent directory.
Only after those platform-owned durability steps does the command report
`gray_mkv_export_complete=true`, output and lineage digests, and any successful
window completion. A media-export failure cannot emit a successful output digest
or completion receipt; the export error path reports `gray_mkv_export_complete=false`.
An earlier source or destination refusal may stop before that status path.
A complete frame or playable prefix is never promoted to a successful shorter
export. The selected-output success report contains:

| Fields | Meaning |
|---|---|
| `gray_mkv_sha256`, `gray_mkv_bytes`, `gray_mkv_frames` | Exact complete local file and count |
| `gray_mkv_frame_receipts_sha256`, `gray_mkv_frame_receipts_domain` | Ordered source/output derivation |
| `gray_mkv_encoder_identity` | Source-bound encoder/framing generation |
| `gray_mkv_width`, `gray_mkv_height` | Stable packed-luma dimensions |
| `gray_mkv_duration_ns`, `gray_mkv_last_frame_end_ns` | Complete presentation duration and last frame end; movie mode can retain a trailing gap |
| `gray_mkv_rate_numerator`, `gray_mkv_rate_denominator` | Reduced requested cadence; uniform mode only |
| `gray_mkv_movie_lineage_sha256` | Authenticated movie-selection lineage; movie mode only |
| `gray_mkv_hashed_bytes`, `gray_mkv_work_unit_model` | Logical SHA-256 input accounting |
| `gray_mkv_pixel_format=grayscale_luma`, `gray_mkv_lossy=false`, `gray_mkv_exact_luma_preserved=true` | Exact screened sample interpretation |
| `gray_mkv_timing` | `operator_requested_uniform_rate` or `source_movie_intervals` |
| `gray_mkv_source_movie_timing_preserved` | True only for explicit movie timing, with `absolute_boundary_floor_ns` rounding and query-start origin |
| `gray_mkv_gaps_filled=false`, `gray_mkv_gap_display=player_defined` | Timestamp holes remain unfilled in movie mode |
| `gray_mkv_source_capture_timing_preserved=false` | Neither mode establishes capture timing or UTC |
| `gray_mkv_published=false` | No retained derivative custody or delivery publication |

### Ordered lineage and bounded work

The implementation identity hashes the NUL-terminated domain
`fss.file_gray_matroska_encoder.v1`, then each source's little-endian u64 byte
length and exact UTF-8 bytes in this order: `gray_matroska_stream/encoder.rs`,
`fss-container/src/matroska_gray.rs`, and its `matroska_gray/ebml.rs` helper.
A change to framing or sample handling therefore changes the identity.

The uniform ordered receipt hashes the NUL-terminated domain
`fss.file_gray_matroska_frame_receipts.v1`, then the encoder identity (32 bytes),
reduced rate and dimensions (four little-endian u32 values): a 48-byte header
after the domain. The movie receipt uses
`fss.file_gray_matroska_movie_frame_receipts.v1`, followed by the encoder identity
(32 bytes), declared query duration (u64), movie-output lineage digest (32 bytes),
and dimensions (two u32 values): an 80-byte header after the domain.

Both modes use the same 96-byte frame row. Each row
contains the selected-output ordinal (u64), owning decode-receipt digest (32 bytes),
screened-luma digest (32 bytes), sample byte count (u64), timestamp (u64) and
duration (u64), in that order. All integers are little-endian.
Its 65-byte trailer is `0xff`, frame count, file byte count, complete duration,
file digest, and total logical hash input bytes; integer counts are u64.
For movie timing the complete duration includes a trailing gap; each frame's
own end is already bound by its timestamp and duration row.
Thus identical pixels from different source or privacy histories have different
lineage, while the file digest continues to describe only exact media bytes.

The work model is `logical_sha256_input_bytes`; it counts bytes supplied to the
hashers, not SHA compression rounds or decoder work. For a successful file with
`F` frames, `L` luma bytes, `B` output bytes, and `I` implementation-identity
input bytes, the total is:

```text
I + receipt_domain_bytes_including_NUL + H + 96*F + L + B + 65
```

`H` is 48 for uniform timing or 80 for movie timing.

There is no user-refillable encode allowance. The fixed source closure, 1024-frame
ceiling and aggregate byte ceiling bound this linear work; existing decode work
remains separately charged. No image-sized encoder allocation or whole-range
buffer is introduced.

## Public core API

`PlaybackRate::new(numerator, denominator)` returns a validated ratio.
`numerator()` and `denominator()` return its reduced components.

`GrayMatroskaConfig::new([width, height], rate)` validates the track. Its
`dimensions()` and `rate()` expose the admitted values.
`initialization()` returns `Initialization`, whose `bytes()` and
`AsRef<[u8]>` views contain the complete header through the track declaration.

`config.frame(output_ordinal)` returns `FrameFraming` with:

- `prefix()`: the complete finite Cluster/BlockGroup/Block framing before samples;
- `payload_bytes()`: the exact required byte count;
- `timestamp_ns()`, `duration_ns()` and `end_ns()`: the presentation interval.

`TimedGrayMatroskaConfig::new([width, height], duration_ns)` validates the same
pixel bounds and a clip duration in `1..=MAX_TIMED_DURATION_NS`. Its `dimensions()`
and `duration_ns()` expose those values; `initialization()` includes the complete
Duration. `frame(output_ordinal, start_ns, end_ns)` returns the same `FrameFraming`
type and refuses zero/reversed intervals, an end beyond the declared duration,
or an ordinal outside `0..1024`. It has no rate or inferred cadence.

There is no trailer. The owner writes initialization once, then each prefix and
its exact unchanged sample slice. The core is stateless: retrying the same
configuration and frame arguments produces identical framing, but it does not
authorize repeating a frame in an already-written output. The timed stream owner
also enforces increasing, nonoverlapping intervals before writing.

Refusals distinguish invalid rate, invalid dimensions, frame-count limit,
unrepresentable timeline and bounded-layout failure. They contain no payload,
source identity or path.

## Consumer obligations

The file/stream owner must enforce the complete operation contract:

1. Verify source identity and current privacy/deletion state before output
   creation, and admit only already-screened samples.
2. Check the sample slice length against `payload_bytes()` and keep dimensions
   constant. Preserve decoded display order for direct ranges or the selected
   movie-occurrence order for `export-movie`. Use consecutive selected-output
   ordinals; source segment numbers need not be consecutive or increasing.
3. Reserve cumulative frame, byte and work ceilings before writing. Initialization,
   every prefix and every sample byte all count. A per-frame check cannot renew
   an exhausted stream allowance.
4. Bound each write/hash chunk and observe cancellation. A partial write,
   zero-progress writer, changed shape, invalid source or exhausted budget
   fences successful completion; it must not certify a shorter stream.
5. Bind output bytes, exact source order, screened sample digests, playback rate
   or explicit movie intervals/query duration, and current transform generations
   into derivative lineage. Retain source-time request and selection receipts
   separately when selecting a window.
6. Flush and complete the owner's durability operation before returning a
   successful completion receipt.

An unknown-size Segment makes incremental output possible. It does not prove
that all intended frames were written. Finite Cluster sizes detect truncation
within a frame; an owner receipt is still required to distinguish an intentionally
short stream from a failed operation between complete frames.

This is uncompressed video. Payload bytes are exactly
`width × height × selected_frames`, plus bounded framing. Consumers must retain
a separate aggregate byte ceiling and report pressure rather than silently
resizing, dropping selected frames or substituting lossy encoding.

## Verification status

**The final explicit-time source passed 50 focused native contracts on 2026-11-08:**
six uniform framing, 21 stream, ten movie materialization, eight rational movie
timing and five explicit-time framing contracts. Eight retained-JPEG range
regression contracts also passed. These execute the production source components;
they do not substitute for retained I/O, privacy authorization or filesystem sync.
Eleven movie-export process contracts and the new parser cases remain unexecuted:
both full CLI build attempts were SIGKILLed while compiling the unchanged
Asupersync dependency, before reaching CLI diagnostics. No full CLI or Clippy
success is claimed.

### Historical uniform-rate native validation

At source `ef7972ad2f773fecc501a907dbc2f87bda21c8fa`, the pinned nightly passed
all 72 focused container tests: 50 library tests, six framing contracts and sixteen
stream contracts. The independent production-encoder comparison below also
passed. Complete CLI process validation and Clippy remain separate, incomplete
checks; these results do not certify path authority, filesystem sync or deployment.

The authored core tests comprise six public-API contracts and two internal
EBML contracts. They cover:

- positive bounded rates, normalization and out-of-profile declarations;
- dimensions, maximum pixels and the last admitted frame;
- exact track/metadata closure through an independent bounded EBML reader;
- unchanged odd-row samples, mask values and incomplete finite Clusters;
- all 1024 boundaries at eight rational rates, with an independent
  quotient/remainder time calculation and literal 30-fps/NTSC expectations;
- deterministic equivalent rates and fixed-storage bounds;
- finite EBML size transitions that must skip reserved unknown-size values;
- unsigned integer encoding and bounded-buffer refusal.

The stream owner adds sixteen contracts with an independent EBML reader,
exact odd-width mask samples and ordered/hash-work oracles. They cover exact and
late quotas, lazy creation, the 1024-frame limit and extreme rates, source/dimension
drift, short/invalid/zero/interrupted writes, partial headers and payloads,
cancellation throughout, and flush/create failures. Six AVC/HEVC process contracts
cover exact screened bytes/source receipts, current masks, rational rate
normalization, quota limits, source-time selection and late refusal. One retained
JPEG contract exercises decode/reopen/replay, exact output caps and stable roots.
One parser contract closes rate syntax and incompatible option combinations.
The core and stream tests are included in the completed native run. The eight
CLI/process/parser contracts in this paragraph remain authored without a full
CLI execution result in this session.

### Completed source-movie production encoder comparison

A temporary native driver called the actual production `Encoder::new_movie` and
`frame_at`, linked to the actual first-party core/container libraries. Rust was
`rustc 1.100.0-nightly (908501772 2026-08-30)`. FFmpeg and FFprobe
`6.1.1-3ubuntu5` independently checked four files: **1,032 frames and 331,372 luma
bytes matched exactly**, as did every packet's integer-nanosecond PTS, DTS and
duration. Cases covered leading/internal/trailing holes, one-nanosecond frames,
the `2^53` duration ceiling, 1,024 fractional 30000/1001 boundaries, odd dimensions
and the full 0–255 sample range. Format-level duration matched within FFprobe's
one-microsecond text resolution; native EBML contracts check exact binary64
Duration bytes independently. No black-frame display or seeking claim is made.

| Executed production source | SHA-256 |
|---|---|
| `gray_matroska_stream/encoder.rs` | `ef7160ce52ef7310a8ce5bbd9bc504b6d84825201759e9c3e7fa8c74562b6029` |
| `fss-container/src/matroska_gray.rs` | `d7567476fa196fc2794344f84ad77732ea004443f0296c08b76cb7bb3e730975` |
| `matroska_gray/ebml.rs` | `c727c32e6e8cb91fe84644b1207f83ed2a48c4614b4fbd4f2c66116ec66e479b` |

The resulting encoder identity was
`sha256:cfc7b5a876570b52a54bda66380a46afcce4fbb361cff331fa19962771eb6ab9`.
Fixture pixels and source/receipt pins were explicitly synthetic test inputs;
the encoder, framing, digest implementation and independent media tools were real.

### Historical uniform-rate production encoder comparison

A pinned-native fixture compiled the actual `GrayMatroskaConfig`, EBML helper and
streaming `Encoder` sources, then wrote the production output. FFmpeg/FFprobe
6.1.1-3ubuntu5 independently decoded every sample and checked every packet's
timestamp, duration and count. All 2,078 frames and 40,626 sample bytes matched;
all streams were identified as full-range `rawvideo` / `Y800` / `gray` with a
`1/1000000000` time base, with no decoder errors.

| Case | Dimensions | Frames | Playback rate |
|---|---:|---:|---:|
| Fractional cadence | 7×5 | 1,024 | 30000/1001 |
| Integer rounding alternation | 17×13 | 11 | 30/1 |
| Maximum admitted rate | 7×5 | 16 | 1000000/1 |
| Minimum admitted rate and long boundaries | 1×1 | 1,024 | 1/1000000 |
| Every gray sample value and odd row width | 257×1 | 3 | 10/1 |

The production encoder identity was
`sha256:933c57c1664c781c2869824f36fca4bb7203acd4ea9670675424e9368feecc1b`.
FFmpeg's binary SHA-256 was
`ed16af623947494a72e284b6eb8ff225f2da22b38b5d5069c2fd4b4ba3384e41`;
FFprobe's was
`272f6ebc634a63d9c8b4ca68e964119d980f25154e5aa2c35e5487da48e9a58f`.
This executes the production writer, unlike the earlier prototype below. It
remains a bounded framing/interoperability result, not a full retained-media
process or seeking/player-compatibility qualification.

### Completed format feasibility observation

Before the outage, a separate small prototype constructed a 7×5 grayscale
Matroska stream with three masked frames and the same uncompressed pixel profile.
FFmpeg 7.1.5 decoded all 105 sample bytes exactly. FFprobe reported three
35-byte independent packets at 0, 100,000,000 and 200,000,000 ns, each with
100,000,000 ns duration.

The observed binaries were:

| Binary | SHA-256 |
|---|---|
| FFmpeg 7.1.5 | `e8a8d46f5225f3062cec7c07fb145d58ae73c603cb740dcd5bad34bfb54e455a` |
| FFprobe | `cefc5f81c0b18429cdbf8fa5a89e1e9c759235e10f93f9b329ff1b2fdff26f46` |

That prototype establishes narrow format feasibility. It did not execute the
recovered Rust core and does not qualify other players, seeking, capture-time
accuracy, live sources or privacy-attestation validity.

### Reproduction and remaining integration checks

The current focused native reproduction on the pinned nightly is:

```sh
CARGO_BUILD_JOBS=1 CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0 \
cargo test --locked --offline -p fss-container \
  --test matroska_gray_contract --test gray_matroska_stream_contract \
  --test timed_matroska_gray_contract --test movie_timing_contract \
  --test movie_output_contract
CARGO_BUILD_JOBS=1 CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0 \
cargo test --locked --offline -p fss-codec-jpeg-encode --test file_jpeg_range_contract
```

Both test commands passed. Remaining full CLI and lint checks require a host
with enough memory for the unchanged runtime dependency:

```sh
cargo clippy --locked --offline -p fss-container --lib \
  --test matroska_gray_contract --test gray_matroska_stream_contract \
  --test timed_matroska_gray_contract --test movie_timing_contract \
  --test movie_output_contract \
  --no-deps -- -D warnings
cargo test --locked --offline -p fss-cli --bin fss-file \
  --test decoded_media_cli_contract --test file_video_stream_cli
```

Use the exact final source for integration checks. The measured scope of the
independent comparisons is the four current movie-timed cases and five historical
uniform-rate cases above; the format-only prototype remains separate evidence.

Useful isolated-oracle commands are:

```sh
ffprobe -v error -select_streams v:0 -show_streams -show_packets \
  -show_entries stream=codec_name,codec_tag_string,pix_fmt,width,height,time_base:packet=pts,dts,duration,size,flags \
  -of json fixture.mkv
ffmpeg -v error -i fixture.mkv -map 0:v:0 -c:v rawvideo -pix_fmt gray \
  -fps_mode passthrough -f rawvideo decoded.gray
```

Pin the exact oracle binaries and compare the raw output with the independently
generated expected samples. These tools are laboratory comparators, never
production dependencies or runtime fallbacks.

## Remaining review-export boundary

This container can preserve samples supplied by a privacy owner and can express
a selected cadence or authenticated movie intervals. It does not issue FLDT access grants, validate
payment-mask attestations, authorize a recipient, establish original source
custody or publish an expiring disclosure artifact. Those remain separate
VIT-023 requirements. A timed, lossless local derivative must not be described
as a fully authorized customer review export merely because its pixels and
framing are deterministic.
