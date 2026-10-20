# Cold native verification of RTP analysis reports

`fss-decode-rtp verify-detections` verifies an exported detection JSONL report by
reopening the original retained RTP source and rerunning the exact native decode,
current-custody checks, privacy projection, verified model and report producer.
`verify-tracks` additionally reproduces the existing selected-class association owner,
including history-linked identities and recovery resets. Neither command substitutes
a second inference, tracking, serialization or evidence path.

The saved JSON supplies no settings, lengths, thresholds, class selections or completion
claims. It is compared byte-for-byte with newly generated output using 4 KiB scratch.

```sh
fss-decode-rtp verify-detections --root DEPLOYMENT --site SITE \
  --source-root sha256:ROOT --custody current \
  --package detector.fmpk --package-sha256 sha256:PACKAGE \
  --report-in detections.jsonl --report-sha256 sha256:EXPECTED

fss-decode-rtp verify-tracks --root DEPLOYMENT --site SITE \
  --source-root sha256:ROOT --custody current \
  --package detector.fmpk --package-sha256 sha256:PACKAGE --class-index 0 \
  --report-in tracks.jsonl --report-sha256 sha256:EXPECTED
```

Retain each `EXPECTED` independently from that report's original successful export.
Supply the same explicit decoding, threshold, class/tracker and resource options as the
export. Changed source, privacy or interpretation cannot be repaired by rehashing the
saved file. Verification requires complete native analysis, exact EOF and the independently
supplied SHA-256. An exactly reproduced incomplete analysis is still a refusal, not verified
success. These commands verify the JSONL reports from `detect` and `track`, not cascade
reports, separate images, or the distinct portable trajectory transcript format.

There is no temporary export, output path, deletion, model activation, source publication
or report rewrite. Input must be a bounded regular non-symlink file. A replaced or
changed input pathname fails verification even when the original descriptor remains
readable. Linux also uses no-follow and nonblocking input admission. The comparison
observes bytes read during this operation; it is not a guarantee of future disk integrity.
The current report representation is versioned and byte-exact: cross-version replay needs
compatible native interpretation and serialization, not merely semantically similar JSON.

`--max-report-bytes` bounds the saved input and regenerated stream; the existing native
source/read/decode/inference/tracking allowances remain in force. Read interruptions and
cancellation are bounded and checked between reads and at final EOF. A failed comparator
cannot be resumed or made successful with a shorter prefix. No saved JSON is parsed and
no saved length controls allocation. Standard output uses `detection_report_verified` or
`tracking_report_verified` rather than export completion markers. Verification grants no
identity, calibrated probability, physical absence, coverage or effect authority.

## Validation boundary

Fifteen comparator, argument and file-destination contracts passed with the pinned
nightly compiler against the local `ac2f355` source archive and its real digest, ReplayCx
and private-export owners. They cover incremental/short reads, rehashed tampering,
truncation, suffixes, independent digests, cancellation, quotas, replaced descriptors and
unchanged export behavior. New helper/command/test files pass pinned rustfmt; existing
parent-file formatting is deliberately not rewritten.

Six new real-process contracts in `rtp_report_verification_cli` exercise both commands
against real retained H.264 and the committed verified YOLOX-Nano package. They cover cold
read-only reproduction, rehashed tampering and changed interpretation, output/path and
read limits, exactly reproduced incomplete reports, current privacy changes and missing
original evidence. These tests are added to `scripts/check_rtp_tracking.sh` alongside
all existing targets, but have not yet been executed in this environment. The helper passes
are not full-current-head native inference, platform, field or release qualification.

Concurrent capture, trajectory, cascade, discovery, deletion and alert work is preserved.
The ordinary export encodings, native identities, model policy and qualification gates
are unchanged by these verification entrypoints.
