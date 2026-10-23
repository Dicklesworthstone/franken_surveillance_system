# Native activity over a retained recording

`fss-infer activity` runs the existing first-party `model:fss-activity:v1` graph over two
explicitly selected JPEG frames from a real retained MJPEG import. It publishes exact source,
decode, invocation and result identities so another process can independently verify the
computation using `fss-evidence verify-activity`.

This is an uncalibrated pixel-change measurement. An `activity` result is not a person,
intrusion, identity, probability, or corroboration determination. `no_activity` never certifies
absence or coverage. Executor exhaustion produces a retained `abstained` result. No event,
alert, model activation, or external effect is performed.

## Import, then explicitly select the computation

Use the ordinary file importer and keep its `import_identity`:

```sh
fss-file import \
  --root /deploy/camera \
  --site site:example \
  --input recording.mjpeg \
  --media-format mjpeg \
  --sensor sensor:porch \
  --stream stream:porch-recording \
  --receive-time-ns 10000000000 \
  --capture-start-ns 1000000000 \
  --capture-uncertainty-ns 1000000 \
  --assumed-fps 10
```

The times above illustrate syntax only; supply the recording's actual owner-known timing and
uncertainty. File timestamps are not capture-time evidence. No live continuity is inferred.

Select an earlier reference segment and a later evaluated segment from that import:

```sh
fss-infer activity \
  --root /deploy/camera \
  --site site:example \
  --import-id sha256:IMPORT_ID \
  --reference-segment 0 \
  --segment 1 \
  --sensor sensor:porch \
  --stream stream:porch-recording \
  --job job:porch-activity-0-1 \
  --interpretation gray \
  --package-digest sha256:417ce1b61cb18192864c76fccf3606536ff4621a99052d1d84721c4915cde52e \
  --policy-generation 1 \
  --threshold-bits 3c23d70a \
  --execution-macs 10000000 \
  --execution-bytes 16777216
```

Replace `sha256:IMPORT_ID` with the exact importer result. `--interpretation gray` is for
grayscale JPEG; use `ycbcr` only for the declared JPEG component interpretation. Both source
capsules must match the explicitly supplied sensor and stream. The job identity is 1–128 ASCII
graphic bytes. Package pin, threshold generation, threshold bits, and execution ceilings are
required; none is silently selected from a previous result.

`3c23d70a` is the exact IEEE-754 bit pattern for `0.01f32`. A finite score strictly greater than
the threshold produces `activity`; a finite score at or below it produces `no_activity`. This
example operating point has no detection-accuracy qualification. Changing the threshold or its
generation produces a distinct policy identity.

The command currently admits two native JPEG frames. AVC, HEVC, and automatic RTSP/watch
integration remain outside this interface. Importing or watching media does not activate the
activity graph implicitly.

## Retention and independent verification

The `fss.recorded_activity_report.v1` JSON response includes:

- Original import identity/root and both exact segment/capsule identities.
- The source-role publication slot/root, result object/root, and complete invocation identity.
- Model/package and policy identities, exact score bits or a typed abstention, and execution
  allowances.
- Source-read and native-decode work counters, plus the final authority anchor.
- `verification_program` and `verification_arguments` for a fresh `fss-evidence` process.

Pass `verification_arguments` as an argument array, without shell interpretation. The recipe
preserves the independently selected sensor, stream, job, interpretation, policy and original
execution budget. It deliberately supplies `grayscale` to the existing verifier when the
production command used `gray`. If the deployment path is not UTF-8,
`verification_root_argument_required` is true: append `--root` and the original native path.

The verifier checks currently retained custody and deletion authority, independently decodes
the original frames, reruns the pinned scalar model, and compares the complete invocation
receipt and result. Its success is a computation check at the observed anchor. It does not
upgrade a pixel-change observation into a physical-world fact. A retained abstention has
`verification_arguments: null`, because the success-score verifier does not certify failed
inference as a score.

The emitted recipe does not supply the verifier's optional `--expected-ledger-root`.
Verification establishes the current observed authority and refuses any head change during its
check; it does not promise that the deployment has remained at the production report's anchor.
An independently obtained current ledger-root pin can be added explicitly when that stronger
precondition is required.

The source-role publication links the original `FileImportManifest` payload as metadata so
canonical deletion can follow its ancestry. Cold verification checks the complete selected
source-role closure: both original JPEGs, both capsules, both decode records, the publication
manifest, and that import-metadata payload. It treats the import metadata as an opaque payload;
it does not recursively hydrate every unused original recording chunk. The producer separately
reassembles and verifies the selected original segments through `RetainedFileImport` before
computation and again before publication. Deletion uses its canonical typed-reference scan to
follow the import ancestry. Any exhausted verification bound refuses without a partial success.

Exact repeated producer requests reopen the same content-addressed publications. Equal-payload
frames retain distinct source-capsule roles while sharing identical objects. A later refusal or
stdout failure can leave valid publications durable; retry the exact request to reconcile.
Damaged existing evidence is refused rather than repaired or overwritten.

## Current restrictions and bounds

Current import deletion and sensor privacy policy are checked before original-pixel work.
The existing native activity receipt cannot bind transformed privacy-mask pixels, so a sensor
with a retained privacy mask is refused. There is no override, original-media export, or
recovery of an old permission. Deleting an import prevents subsequent production and cold
verification of its removed source evidence.

Source byte reads, JPEG work, executor MACs/tensor bytes, staged bytes, and history admissions
have separate bounds. Optional `--max-source-bytes`, `--max-segment-bytes`,
`--max-source-read-bytes`, `--max-frame-pixels`, `--max-dimension`, `--max-decode-work`,
`--max-staged-bytes`, and `--max-history-entries` narrow or explicitly choose those allowances.
Filesystem and native decode calls are bounded; this synchronous operator command has no
preemptive wall-clock deadline. Budget or binding refusals never become a quiet observation.
