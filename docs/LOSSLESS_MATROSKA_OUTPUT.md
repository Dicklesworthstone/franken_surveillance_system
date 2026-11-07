# Lossless timed grayscale Matroska output

`fss-container::matroska_gray` frames unchanged, privacy-screened grayscale
samples as a deterministic Matroska video track. It supplies the container
foundation for a reviewer who needs both playback timing and exact reconstructed
mask samples. The existing JPEG derivative remains lossy, including at quality
100; this profile performs no image compression.

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
| Playback rate | Explicit positive numerator and denominator, each at most 1,000,000 before reduction |
| Timestamp scale | One nanosecond |
| Frame framing | One finite Cluster and BlockGroup per frame; explicit BlockDuration before the final Block |
| Independence | No lacing or ReferenceBlock; every frame contains all its samples |
| Segment | Unknown-size streaming Segment; initialization is written once |
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

## Playback time is explicit

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

There is no trailer. The owner writes initialization once, then each prefix and
its exact unchanged sample slice. The core is stateless: retrying the same
configuration and ordinal produces identical framing, but it does not authorize
repeating a frame in an already-written output.

Refusals distinguish invalid rate, invalid dimensions, frame-count limit,
unrepresentable timeline and bounded-layout failure. They contain no payload,
source identity or path.

## Consumer obligations

The file/stream owner must enforce the complete operation contract:

1. Verify source identity and current privacy/deletion state before output
   creation, and admit only already-screened samples.
2. Check the sample slice length against `payload_bytes()` and keep dimensions
   constant. Preserve decoded display order. Use consecutive selected-output
   ordinals; source segment numbers need not be consecutive.
3. Reserve cumulative frame, byte and work ceilings before writing. Initialization,
   every prefix and every sample byte all count. A per-frame check cannot renew
   an exhausted stream allowance.
4. Bound each write/hash chunk and observe cancellation. A partial write,
   zero-progress writer, changed shape, invalid source or exhausted budget
   fences successful completion; it must not certify a shorter stream.
5. Bind output bytes, exact source order, screened sample digests, playback rate,
   source-time selection and current transform generations into the receipt.
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

**New production code and tests have not been executed natively.** The workspace
disconnected during the first Matroska source write. The authored source was
recovered into GitHub blobs, with independent source review of the arithmetic,
fixed buffers, EBML sizes and public API. No Rust compilation, formatter pass,
Clippy pass, complete-CLI test or final-encoder differential result is established
for these new files.

The authored native tests comprise six public-API contracts and two internal
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

### Required restored checks

On the pinned nightly and exact published source:

```sh
cargo test --locked --offline -p fss-container --lib --test matroska_gray_contract
cargo clippy --locked --offline -p fss-container --lib --test matroska_gray_contract \
  --no-deps -- -D warnings
```

Format the new source and contracts with the pinned formatter, then rerun after
any repairs. A final laboratory comparison should generate bytes through this
actual public API for 1×1, 7×5 and 65×37 synthetic frames at 1, 30 and
30000/1001 fps. Compare every decoded sample, packet timestamp, duration, frame
count and dimension independently. This nine-case run was planned but did not
execute before the outage.

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
a selected playback cadence. It does not issue FLDT access grants, validate
payment-mask attestations, authorize a recipient, establish original source
custody or publish an expiring disclosure artifact. Those remain separate
VIT-023 requirements. A timed, lossless local derivative must not be described
as a fully authorized customer review export merely because its pixels and
framing are deterministic.
