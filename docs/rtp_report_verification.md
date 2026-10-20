# Cold native verification of RTP analysis reports

`fss-decode-rtp verify-detections` verifies an exported detection JSONL report by
reopening the original retained RTP source and rerunning the exact native decode,
current-custody checks, privacy projection, verified model and report producer.
The saved JSON supplies no settings, lengths, thresholds, class selections or completion
claims. It is compared byte-for-byte with newly generated output using 4 KiB scratch.

```sh
fss-decode-rtp verify-detections --root DEPLOYMENT --site SITE \
  --source-root sha256:ROOT --custody current \
  --package detector.fmpk --package-sha256 sha256:PACKAGE \
  --report-in detections.jsonl --report-sha256 sha256:EXPECTED
```

Retain `EXPECTED` independently from the original successful export. Supply the same
explicit decoding, threshold and resource options as that export. Changed source,
privacy or interpretation cannot be repaired by rehashing the saved file. Verification
requires complete native analysis, exact EOF and the independently supplied SHA-256.
An exactly reproduced incomplete analysis is still a refusal, not verified success.

There is no temporary export, output path, deletion, model activation, source publication
or report rewrite. Input must be a bounded regular non-symlink file. A replaced or
changed input pathname fails verification even when the original descriptor remains
readable. Linux also uses no-follow and nonblocking input admission. The comparison
observes bytes read during this operation; it is not a guarantee of future disk integrity.

`--max-report-bytes` bounds the saved input and regenerated stream; the existing native
source/read/decode/inference allowances remain in force. Read interruptions and
cancellation are bounded and checked between reads and at final EOF. A failed comparator
cannot be resumed or made successful with a shorter prefix. No saved JSON is parsed and
no saved length controls allocation. Standard output uses `detection_report_verified`
rather than export completion markers. Verification grants no identity, calibrated
probability, physical absence, coverage or effect authority.

Fifteen comparator, argument and file-destination contracts passed with the pinned
nightly compiler against the local source archive and its real digest, ReplayCx and
private-export owners. They cover incremental/short reads, rehashed tampering, truncation,
suffixes, independent digests, cancellation, quotas, replaced descriptors and unchanged
export behavior. Full-current-head native decode/inference execution remains a separate
validation step; these passes are not production, platform or release qualification.
