# Native decoding from retained RTP custody

This additive reference path advances FSS-054 and FSS-120. It connects a completed
legacy rtpdump import to ordered native AVC decoding without modifying any existing
canonical import/report bytes. It is not a camera, absence, or release qualification.

## Operator command

First import original RTP through the existing `fss-file import --media-format rtpplay`
command. Use its exact `import_root`, not an ordinary file-import identity:

```sh
fss-decode-rtp inspect --root /data/fss --site site:home --source-root sha256:ROOT
fss-decode-rtp decode --root /data/fss --site site:home --source-root sha256:ROOT \
  --output /data/exports/frames.pgm
```

`ROOT` is the 64 hexadecimal characters printed by the import. Inspection verifies
retained originals, reports complete/pending import state, and lists in-source SPS/PPS
digests. Decode may omit `--sps` and `--pps` only when the pair is unambiguous. Otherwise
supply the exact candidate digests; loose files or another root's configuration are
not accepted. No original source path or in-memory import receipt is needed.

Output is one binary PGM luma image per frame in native display order. It is streamed
through the same bounded exporter used by `fss-file`; the destination must be absent
and outside the deployment. All three native planes are privacy-masked by the library
before frame metadata or pixels reach the command. Reports include per-frame plane
digests, original RTP timestamps, unknown capture intervals, decoder recovery epochs,
privacy bindings, and source/refusal/skipped-group/flush counters.

A complete PGM export gets its own byte digest and frame count only after successful
native drain and file synchronization. Malformed tails, skipped groups, recovery after
loss, exhausted bounds or partial I/O return failure and never print a successful
export digest. A partial file may remain for explicit inspection; it is never silently
overwritten, deleted, or relabeled complete. Successful recovery is useful partial
output, not an assertion that missing frames existed.

`--recovery stop|next-idr` selects the existing decoder policy. Independent source/read,
record, frame, dimension, pixel, encoded-byte, NAL-call, source-span, output-byte and
step ceilings are shown by `--help`. Defaults admit up to 1024 observed groups; no
resource limit renews when native decoding restarts. `inspect` rejects decode-only
options rather than ignoring them. Missing deployment directories are not created.

## Library path

1. Call `inspect_rtp_import` with the exact root, a fresh process-local ingress, and
   independent recovery read ceilings. This verifies all original chunks, report,
   NALs, capsules, publication and completion state without the original file.
2. Inventory `RecoveredRtpImport::h264_parameters`. `unique_pair` selects only one
   distinct SPS and PPS from the original generation; ambiguous sets require an
   explicit selection. Decoding validates their exact native syntax and binding.
3. Open `decode_h264(RetainedRtpDecodeRequest, deployment, cx)`. The source recipe,
   not caller overrides, supplies sensor, stream, generation, SSRC, payload and mode.
4. Drive `RetainedRtpH264Decoder::step`. Progress contains payload-free receiver
   facts and native decode effects; frames contain only privacy-projected planes.

Every Y, Cb and Cr plane uses the sensor's current retained mask before delivery.
The raw codec picture and original packet bytes are not exposed by this interface.
A policy-resolution or resolution-mismatch error cannot fall back to unmasked data.

The inspection anchor remains fixed for the entire decode. Any authority change
requires fresh inspection, including unrelated changes: this is a conservative
reference admission rule, not a concurrent deployment service. Root loss, poisoned
publication state, or a tombstone anywhere in the selected graph fences queued
output. Cancellation drops the decoder and queued pixels. No path implicitly resumes
an incomplete import or appends a new frame/effect/coverage record.

The decoder borrows the verified immutable source snapshot. Corrupt physical originals
are detected during cold inspection; this is not continuous disk scrubbing or a
promise of future physical availability. Original capture uncertainty remains
`[0, owner_receive_time]`; sender RTP timestamps are never promoted into capture time.

## Recovery and completeness

The native decoder retains its existing Stop/NextIdr policies and cumulative limits.
Successful decoding after a gap does not erase earlier refusal or skipped-group counts.
`RetainedRtpDecodeStats::complete()` becomes true only after input EOF, native flush,
and all frame delivery, with at least one frame and no refused/fenced/skipped step.
It never means camera continuity, detection completeness, or evidence of absence.

## Checks

`bash scripts/check_rtp_decode.sh tests` runs native recorded/retained decoding,
ordered receiver, cold recovery, shared-exporter and real-process command contracts.
`format` checks the changed implementation. The retained-root cases exercise cold
restart, exact native pixels, all-plane masks, queued-output policy drift, parameter
substitution, output limits, cancellation, malformed tails, incomplete import refusal,
damaged privacy custody, and recovered pixels with explicit incomplete accounting.
The old recovery test now pins the fixture's actual IDR/P/P/IDR structure and all five
surviving pictures after damage. Real-process tests exercise import -> original removal
-> cold decode, PGM digest/retry, mask declaration -> restart -> masked export, and
bounded failures with no successful export receipt.

Implementation and tests are present; execution results must be read from an actual
run. Supplementary GitHub checks do not replace repository-native DSR qualification.
