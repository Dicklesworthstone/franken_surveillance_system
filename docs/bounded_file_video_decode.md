# Bounded native file-video decoding and export

`fss-file decode` streams AVC and HEVC luma in decoder display order from an existing retained import. Annex-B, MP4 and Matroska keep their existing codec/source verification paths. A range must start at the existing native IDR/IRAP boundary. Current privacy masking precedes every returned frame. No new camera access, model invocation, frame publication or effect authority is added.

This closes a concrete ordinary-CLI gap within FSS-054 (bounded decode) and FSS-058 (buffer accounting), tracked by beads `fss-x4a.12.3` and `fss-x4a.12.7`. It is a reference-path increment, not closure of those complete work packages or GATE-040 qualification.

## Example

```sh
fss-file decode \
  --root /absolute/existing/deployment --site site:example \
  --import-id "${IMPORT_ID:?supply a completed retained import}" \
  --segment 0 --segment-count 8 --interpretation ycbcr \
  --work-units 1000000000 \
  --output /absolute/existing/output-directory/new-frames.pgm \
  --max-output-bytes 67108864
```

Use an actual admitted range. `--output` remains optional: without it, no PGM buffer, output path or output hash is created. Each decoded frame is reported and released instead of accumulating a range-sized image vector. Native decoder/reorder buffers and retained-source caches remain independently owned and bounded; this is not a measured peak-RAM claim for the entire process.

The output is the same concatenation of binary P5 images used previously, with native masked luma and per-frame dimensions. Writes borrow each luma plane directly and pass at most 4096 bytes to a writer call. Hashing is incremental over successfully written bytes. No range-wide pixel copy or transcoding occurs.

## Admission and accounting

`--work-units` now applies to ordinary AVC/HEVC decoding, not only motion analysis. One `RecordedVideoDecodeBudget` covers range construction, out-of-band parameter sets and every access unit, including decode-ahead and skipped HEVC RASL input. The model is `encoded_bytes_plus_coded_luma_capacity.v1`: encoded input bytes plus the configured coded-luma capacity per access unit. It is a conservative reservation, not measured CPU instructions or visible-pixel work. The default remains 100,000,000 units. Previously accepted commands which exceeded that ignored allowance now refuse; explicitly choose a sufficient allowance for the intended range.

Pixel and dimension bounds are not rounded upward to a native block minimum. AVC uses whole macroblocks that fit inside `--max-pixels`; a smaller ceiling refuses rather than admitting extra pixels. Slice and NAL limits can only narrow the existing native ceilings. Original-source and per-segment limits remain enforced.

`--max-output-bytes` applies only to a native-video `decode` with `--output`. Its default is 64 MiB and hard maximum is 256 MiB. It counts PGM headers and luma across the whole requested export. Each complete frame is admitted before its header is written. This allowance never refills between frames. The source-unit count remains bounded at 1024. JPEG receipt publication and motion analysis are unchanged; an explicit video-only output option on JPEG refuses before decoding/publication.

Machine-readable fields retain the existing native receipt/pixel identities. `frame_output_index` identifies display order separately from `frame_segment`. Native decode attempts additionally report `decode_work_units`, `decode_work_unit_model`, `maximum_decode_work_units`, `remaining_decode_work_units`, and `decode_complete`. When reporting itself is available, a failed native attempt reports `decode_complete=false`; nonzero process status is still authoritative for command failure. Preflight failures before native decoding can occur before these fields exist. Successful exports report `pgm_sha256`, `pgm_bytes` and `pgm_frames` only after synchronization.

## Failure, retry and filesystem scope

A missing parent, an out-of-scope destination or an already existing output file refuses. The file is created only after a complete first frame passes admission. Unix output permissions are owner-read/write only. Linux pins the parent directory descriptor for file creation; other platforms retain the protected-directory trust boundary and canonical-parent checks. The exporter rechecks parent identity on Unix and never follows or overwrites an existing final symlink.

Unlike the former range-sized in-memory export, a later decode/work failure can leave an already written file prefix. A byte-limit refusal leaves complete earlier PGM frames; an actual I/O failure can leave a partial frame. Neither is certified as a complete range. A failed writer is terminal, including cancellation, zero progress and exhausted bounded interruption retries. Ignoring a refusal cannot turn an earlier prefix into a successful export.

Keep partial output for inspection. Retry from the original random-access range into a different new file; do not blindly append or overwrite an old export. Source custody and the deployment's ledger/effect journals are not changed by video decode/export. A successful PGM digest proves the emitted bytes, not scene coverage, capture-clock accuracy, evidence absence or a durable native frame publication. Use `fss-video` for explicit retained frame publication.

The focused native runner is `bash scripts/test_file_video_stream.sh /absolute/new-evidence-directory`. Its tests exercise both codecs, display-order receipts, exact work/output boundaries, privacy masks, source corruption, file ownership, cancellation, short writes and unchanged JPEG/RTSP-import behavior. Hosted results supplement rather than replace local release qualification.
