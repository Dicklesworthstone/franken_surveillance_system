# Recorded media: decode, reopen, replay and pixel-change analysis

The `fss-file` operator utility connects retained source custody to canonical JPEG, H.264 and
H.265 decoding and a bounded pixel-change gate. JPEG/MJPEG decoded frames have durable derivative
publications and can be reopened. H.264/H.265 decode and motion use the native retained-range
decoders for Annex-B, MP4/QuickTime (indexed or fragmented), and Matroska imports. Every path
works after the original input file is removed. Supported codec profiles and refusals are those
of the existing pure-Rust decoders; pixel change is not learned object detection.

First import the recording using the [file import workflow](FILE_IMPORT_WORKFLOW.md). Use the
exact printed `import_identity` in the commands below. Examples assume a recording containing
at least two frames. Replace the digest placeholder and explicitly select the component
interpretation matching the source contract: `gray` for one-component JPEG or `ycbcr` for JPEG
YCbCr and all admitted H.264/H.265 profiles.
Neither is guessed from image appearance. RGB/CMYK and unsupported coding modes are refused.

## Decode a retained frame

The single-frame publication commands in this section apply to JPEG/MJPEG.

```sh
cargo run -p fss-cli --bin fss-file -- decode \
  --root ./camera-evidence --site site:home --import-id sha256:YOUR_IMPORT_DIGEST \
  --segment 0 --interpretation ycbcr --work-units 1000000000 \
  --output ./frame-0.pgm --receipt-out ./frame-0.receipt
```

The production `fss-codec-mjpeg` decoder returns full-resolution, full-range Y (luma), not RGB.
Every chroma entropy block is still validated. No orientation, ICC profile, crop or calibration
is silently applied. Raw luma and original compressed bytes are retained in a root-last graph
with the original source capsule and a bounded canonical receipt. PGM is a separate exported
rendering; its digest is not the raw luma digest. The receipt retains the original conservative
capture interval and clock basis. A new timestamp is not fabricated at decode time.

The command reports the decoded graph root, receipt digest, exact decode-completion sequence,
source capsule, dimensions, decoder identity, raw luma digest and charged codec work units.
`authority_sequence` remains the source import's completion sequence;
`decode_authority_sequence` names the later decoded derivative's completion.

## Restart, read and independently reproduce

```sh
cargo run -p fss-cli --bin fss-file -- read-decoded \
  --root ./camera-evidence --site site:home --import-id sha256:YOUR_IMPORT_DIGEST \
  --segment 0 --interpretation ycbcr --output ./frame-0-restored.pgm

cargo run -p fss-cli --bin fss-file -- verify-decoded \
  --root ./camera-evidence --site site:home --import-id sha256:YOUR_IMPORT_DIGEST \
  --segment 0 --interpretation ycbcr --work-units 1000000000
```

No original input path is needed. `read-decoded` verifies retained provenance and checksums;
it does not rerun the codec. `verify-decoded` also reproduces the complete decoder output,
codec accounting and work units, without changing authority. Both refuse incomplete decodes.
A successful `decode` retry is authority-idempotent even though replaying the codec consumes
work again. A newer global anchor does not replace the original decode-completion anchor.
See [the receipt format and recovery contract](RETAINED_DECODE_WORKFLOW.md).

## Find candidate pixel changes in a bounded frame range

```sh
cargo run -p fss-cli --bin fss-file -- motion \
  --root ./camera-evidence --site site:home --import-id sha256:YOUR_IMPORT_DIGEST \
  --start-segment 0 --frame-count 2 --interpretation ycbcr \
  --pixel-delta 16 --minimum-changed-pixels 64 --minimum-changed-ppm 1000 \
  --work-units 2000000000 --max-comparisons 10000000 \
  --report-out ./pixel-changes.json
```

The threshold values above are examples, not calibrated detection policy. A sample changes
when its absolute Y difference is at least `--pixel-delta`. A candidate must meet both the
changed-sample count and the exact changed-fraction threshold; the fraction is compared by
integer cross-products, not rounded percentages. The report gives changed count, total
absolute difference, maximum difference and half-open coded-image bounds covering changed
samples. Those bounds are not an object's bounding box.

The first frame establishes a baseline. Source gaps, skipped sequences, recording/source
changes, geometry changes and decoder/interpretation changes invalidate comparisons.
Every applicable reset reason is retained, with `comparison:null`, rather than fabricated
zero change. A comparable unchanged pair has measured `changed_pixels:0` and `candidate:false`.
Neither outcome certifies absence, live coverage, safe conditions or lack of a person.
Lighting changes and camera movement may also produce candidates. No alerts or other effects
are authorized by this gate.

The library `PixelChangeDetector` retains one bounded prior image, accepts duplicate exact
frame delivery idempotently, refuses backwards replay in a recording and charges comparisons
cumulatively, including rows processed before cancellation. Gaps do not renew its allowance.
The operator scan also shares one codec work budget across the entire requested range.
Frame count must be 1..128; out-of-range requests are refused before any frame is decoded.

## Motion in H.264 and H.265 recordings

The same `motion` command accepts retained H.264/H.265 imports. `--start-segment` must identify
an IDR for H.264 or an IRAP (IDR, CRA or BLA) for H.265. `--frame-count` selects a contiguous
**source segment range**, as `decode --segment-count` does. A predicted picture cannot be opened
alone. A known source gap inside the range refuses the range before any motion is measured;
the stable range-start, source-gap and codec refusal identities are preserved.

```sh
cargo run -p fss-cli --bin fss-file -- motion \
  --root ./camera-evidence --site site:home --import-id sha256:YOUR_IMPORT_DIGEST \
  --start-segment 0 --frame-count 12 --interpretation ycbcr \
  --pixel-delta 16 --minimum-changed-pixels 64 \
  --work-units 200000000 --max-comparisons 10000000 \
  --report-out ./video-pixel-changes.json
```

The range decoder supplies pictures in display order, including B-picture reordering. Each
observation preserves both the original coding-order `segment` and the decoder-sealed
`display_index`. The detector compares consecutive display positions from the same exact range;
it refuses reverse delivery and resets on skipped display positions, range changes, source
changes, dimensions or decoder/privacy changes. Source capture intervals remain unchanged:
codec ordering supplies no new clock calibration.

Video reports use `fss.recorded_pixel_change_report.v2`. Each observation carries a canonical
source-to-pixels receipt in hexadecimal, its `frame_receipt_digest`, the actual predecessor's
receipt digest, retained import root and capsule identities, original capture bounds, masked
luma digest and privacy binding. H.264/H.265 frames remain rebuildable, unpublished derivatives:
`decode_published:false` is explicit, and receipt digests are never presented as decoded
publication roots. Reproducing them decodes the retained source range again. Video `motion`
does not make `read-decoded` or `verify-decoded` available for these codecs.

HEVC may skip leading RASL pictures when opening a CRA/BLA range. The report lists their actual
source positions in `skipped_rasl_segments` and `unobserved_segments`. It emits no fabricated
frame or zero-motion comparison for them. `complete:true` means the range finished and every
returned display picture was analyzed; `all_requested_segments_observed:false` separately
records these admitted random-access omissions. Every report keeps `absence_certifiable:false`.

## Partial results, continuation and export safety

Each successful JPEG frame decode has its own durable publication. A later comparison, frame decode
or export failure does not roll those publications back. On ordinary analysis failure the
report records `complete:false`, the completed observations, the failing `next_segment`, and
`resume_start_segment` including the predecessor needed to reconstruct the comparison baseline.
Rerun the same immutable range with an explicitly supplied work allowance, or resume with that
one-frame overlap. There is no hidden mutable stream cursor or automatic budget renewal.

JPEG reports use the versioned internal operator format `fss.recorded_pixel_change_report.v1`, owned
by the retained-media composition; they are not universal agent response envelopes. Every
observation binds exact decoded roots and source capsule/time bounds. Reports include the
source manifest and threshold digest. Nanosecond bounds are JSON strings to preserve i128
precision. The CLI prints the complete report-byte checksum after successful export.

Video failures likewise preserve earlier successful observations in one complete JSON report,
with `complete:false`, a typed `error`, the failed source segment when known, and all unobserved
source positions. `next_segment` is the first source position not yet observed or classified as
skipped RASL; it can differ from the codec's input cursor because decoding reads ahead for B
pictures. A `failure_segment:null` can represent a failure while flushing buffered output.

Video continuation always uses `resume_start_segment` **and** `resume_segment_count` to replay
the original IDR/IRAP-led range. `resume_strategy` is `replay_original_random_access_range`.
Starting at `next_segment - 1` is unsafe for inter prediction or display reordering. Successful
earlier observations recur with the same receipts when the source, decoder and privacy binding
are unchanged, permitting explicit receipt-based deduplication. A new request requires an
explicit fresh allowance; malformed data or a bad random-access start needs a corrected request.

All outputs use the same new-file-only, outside-deployment export boundary as `extract`.
Existing destinations are never overwritten, and Unix exports use owner-only permissions.
A revoked/cancelled context cannot export a report; already committed JPEG frames and retained
video source remain independently recoverable. An I/O error may leave a partial export, and file fsync is not a claim of atomic
export-root publication or directory-fsync durability. Nonzero exit status must not be ignored.

Codec defaults are a 16 MiB encoded-frame ceiling, 4096 maximum dimension, 4,194,304 pixels,
4096 markers and 100,000,000 work units. Source-read ceilings remain separately configurable.
`--max-pixels`, `--max-dimension`, `--max-markers` and `--work-units` make admission explicit;
no bound silently changes output resolution. Motion defaults to 64,000,000 pixel comparisons.
For video motion, `--max-markers` narrows the codec's slice-per-picture bound. Coded dimensions
and pixels are bounded before codec allocation and never rounded up beyond the caller's ceiling.

Video motion's `--work-units` is a cumulative **admission** allowance with the printed model
`encoded_bytes_plus_coded_luma_capacity.v1`: before each source access unit enters the codec,
reserve its encoded byte length plus the configured coded-luma capacity (`max_macroblocks * 256`
for AVC; `max_luma_samples` for HEVC). Out-of-band parameter sets reserve their encoded bytes.
Decode-ahead, skipped RASL and unsuccessful codec work consume reservations; a refused reservation
does not decode the access unit. Lowering `--max-pixels` reduces this conservative capacity charge
only when the coded images actually fit the lower bound. The default 4,194,304-pixel capacity
therefore reserves about 4.2 million units per source segment, independently of visible frame size.
This accounting is deliberately named separately from JPEG codec work and measured output pixels.

These are bounded reference operations, not measured CPU time, energy, latency or throughput.

This is executable source-to-decoded-evidence and cheap perception functionality, not native
live camera acquisition, trained-model inference, tracking, notification delivery, or release
qualification. The focused native tests below passed on the pinned Rust toolchain; this is not release qualification.

Focused native contracts: `cargo test --locked --offline -p fss-cli --test video_motion_cli_contract
--test decoded_media_cli_contract` and `cargo test --locked --offline -p fss-reference --test
video_motion_contract`. They cover retained AVC/HEVC Annex-B and container inputs, actual
display-order pixel comparisons, receipt reconstruction, decode/comparison pressure, reverse and
duplicate delivery, random-access refusals, source gaps, RASL, cancellation, corrupt final pictures
and export preservation. The existing codec differential lanes remain the codec correctness gates.

Native execution on 2026-10-07 passed all 7 video CLI tests, 4 existing JPEG CLI tests and
4 video reference integration tests. `fss-file` and its production libraries were built with
`cargo build --locked --offline -p fss-cli --bin fss-file`. The unchanged integration-test
sources were compiled with the same pinned `rustc --test`, the exact Cargo-built libraries
and the CLI binary paths. The whole-workspace qualification lane was not run.
