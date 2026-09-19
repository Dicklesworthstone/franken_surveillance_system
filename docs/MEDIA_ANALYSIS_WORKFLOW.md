# Recorded media: decode, reopen, replay and pixel-change analysis

The `fss-file` operator utility now connects retained source custody to actual canonical JPEG
decoding and a bounded cheap-perception gate. JPEG/MJPEG source can be decoded, retained and
reopened after the original file is removed. Annex-B import remains source custody only;
these commands do not pretend to provide H.264 decoding or learned object detection.

First import the recording using the [file import workflow](FILE_IMPORT_WORKFLOW.md). Use the
exact printed `import_identity` in the commands below. Examples assume a recording containing
at least two frames. Replace the digest placeholder and explicitly select the component
interpretation matching the source contract: `gray` for one component or `ycbcr` for JPEG YCbCr.
Neither is guessed from image appearance. RGB/CMYK and unsupported coding modes are refused.

## Decode a retained frame

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

## Partial results, continuation and export safety

Each successful frame decode has its own durable publication. A later comparison, frame decode
or export failure does not roll those publications back. On ordinary analysis failure the
report records `complete:false`, the completed observations, the failing `next_segment`, and
`resume_start_segment` including the predecessor needed to reconstruct the comparison baseline.
Rerun the same immutable range with an explicitly supplied work allowance, or resume with that
one-frame overlap. There is no hidden mutable stream cursor or automatic budget renewal.

Reports use the versioned internal operator format `fss.recorded_pixel_change_report.v1`, owned
by the retained-media composition; they are not universal agent response envelopes. Every
observation binds exact decoded roots and source capsule/time bounds. Reports include the
source manifest and threshold digest. Nanosecond bounds are JSON strings to preserve i128
precision. The CLI prints the complete report-byte checksum after successful export.

All outputs use the same new-file-only, outside-deployment export boundary as `extract`.
Existing destinations are never overwritten, and Unix exports use owner-only permissions.
A revoked/cancelled context cannot export a report; already committed frames remain independently
recoverable. An I/O error may leave a partial export, and file fsync is not a claim of atomic
export-root publication or directory-fsync durability. Nonzero exit status must not be ignored.

Codec defaults are a 16 MiB encoded-frame ceiling, 4096 maximum dimension, 4,194,304 pixels,
4096 markers and 100,000,000 work units. Source-read ceilings remain separately configurable.
`--max-pixels`, `--max-dimension`, `--max-markers` and `--work-units` make admission explicit;
no bound silently changes output resolution. Motion defaults to 64,000,000 pixel comparisons.
These are bounded reference operations, not measured CPU time, energy, latency or throughput.

This is executable source-to-decoded-evidence and cheap perception functionality, not native
live camera acquisition, trained-model inference, tracking, notification delivery, or release
qualification. The added tests require execution on the pinned Rust toolchain before promotion.
