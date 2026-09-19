# Retained inference to detections and local tracks

`fss-infer detect` and `fss-infer track` consume the exact retained model runs produced by
[the inference workflow](INFERENCE_OPERATOR_WORKFLOW.md). These commands do not execute a
model, download weights, append detection/track authority, or authorize an alert. They
revalidate retained model/frame evidence and produce bounded, reproducible read projections.

## Explicit detector-output contract

The selected F32 port must have shape `[N,6]` or `[1,N,6]`. Each row is exactly four box
values, a score already in [0,1], and an integer class index into the supplied ordered labels.
The model digest pins graph, parameters and preprocessing. Tensor port, labels, box encoding,
coordinate units, score threshold, NMS threshold and limits are frozen together by
`DetectionContract`. No logits, YOLO channel layout, background index, padding convention,
letterbox inverse, image crop, or class names are guessed.

`xyxy` means left/top/right/bottom; `cxcywh` means center x/y and positive width/height.
`normalized` coordinates refer to the full coded image; `pixels` means coded-image pixels.
Invalid, inverted, nonfinite, out-of-image or fractional-class rows fail the complete operation,
even below the score threshold. Padding rows must be explicitly removed by the model's output
contract; they are not silently treated as valid empty boxes. No clipping is performed.

Valid bounds are outward-rounded to 1/256 pixel precision. Reports label these integers
`bounds_subpixel` and give `box_subpixels=256`. The original retained tensor remains the source
of the pre-quantized values. NMS compares the quantized boxes using exact integer products,
within each class only, in descending score order with original-row-index tie breaks. The
score threshold is inclusive; suppression requires IoU strictly greater than the NMS threshold.
An excess of surviving boxes refuses the result instead of silently applying an undisclosed top-k.

## Detect one retained run

Replace every digest placeholder with the exact recorded SHA-256 identity. Labels below are
examples of an output contract, not bundled model capabilities or calibrated operating points.

```sh
cargo run -p fss-cli --bin fss-infer -- detect \
  --root ./camera-evidence --site site:home \
  --import-id sha256:IMPORT_DIGEST --segment 0 --run-id sha256:RUN_DIGEST \
  --interpretation ycbcr --model-digest sha256:MODEL_DIGEST \
  --output-port detections --labels vehicle,animal \
  --box-format xyxy --coordinates normalized \
  --minimum-score-ppm 500000 --nms-iou-ppm 500000 \
  --report-out ./detections.json
```

The original recording and model file need not remain on disk outside the deployment. Every
result includes the detector projection digest, exact run/frame roots, original source capsule,
sequence, conservative capture interval, clock basis, row/filter/suppression counts, scores,
class indices, and source row indices. A score is an uncalibrated model output, not confidence
that a threat or a particular person is present. An empty result does not certify absence.

## Associate an explicit ordered list of runs

Create `runs.txt` with one `SEGMENT SHA256_RUN_ID` pair per line, in strictly increasing segment
order. All runs in this CLI invocation use the same explicit import and model-output contract.
A skipped segment is permitted but resets association; it is not treated as continuous footage.
The list is bounded to 128 entries and 64 KiB. It contains exact identities, never `latest`.

```sh
cargo run -p fss-cli --bin fss-infer -- track \
  --root ./camera-evidence --site site:home --import-id sha256:IMPORT_DIGEST \
  --interpretation ycbcr --model-digest sha256:MODEL_DIGEST \
  --output-port detections --labels vehicle,animal \
  --box-format xyxy --coordinates normalized --runs ./runs.txt \
  --minimum-iou-ppm 300000 --confirmation-hits 2 --maximum-missed-frames 2 \
  --maximum-tracks 128 --association-work-units 10000000 \
  --report-out ./tracks.json
```

The tracker uses class-gated global bipartite assignment: maximize the number of feasible
matches, then total floor-quantized IoU in millionths. A bounded integer Hungarian solver
uses explicit unmatched dummy columns; deterministic row/column tie breaks do not imply
physical identity certainty. `ambiguous` marks multiple feasible choices at either endpoint,
not a calibrated probability or an exhaustive enumeration of alternate optimum assignments.

Tracks start tentative and confirm after the explicit consecutive-hit threshold. Missed
observations carry `observed_row:null`, the last observed box and `last_seen_sequence` rather
than fabricating a new observation. The missed-frame allowance counts processed frames, not
seconds. Retirement after the allowance is exceeded is not proof of physical departure.
No velocity, identity embedding, cross-camera reidentification, or Kalman prediction is inferred.

The library also resets on import/camera/stream changes, detector contract changes, image-size
changes, skipped source sequences, explicit source gaps, and incompatible clock changes.
All applicable reset reasons and retired IDs remain visible. Exact repeated detector projections
are idempotent. A changed or older sequence is refused. Cancellation, budget or capacity failure
leaves tracker state unchanged; spent work is not refunded. No existing track is silently evicted.

## Bounds, partial results and replay

Detector defaults admit at most 4096 rows and 256 survivors per frame. The shared `--work-units`
allowance counts row validation and same-class suppression comparisons across the entire command.
The separate association allowance counts candidate pairs and solver column probes across the
whole list. These are deterministic reference-operation counters, not CPU time, energy, complete
process memory accounting, or performance guarantees. Tracker capacity is at most 128 hypotheses.

The versioned internal operator report is `fss.detector_track_report.v1`; it is not a universal
agent response envelope. `complete` describes processing the requested list, not observability
or real-world detection completeness. Ordinary source/analysis failure emits completed records,
`complete:false`, a failing `next_entry`/`next_segment`, and a nonzero exit. Invalid arguments,
invalid run lists, deployment-open failures, and export failures are also nonzero. Never ignore
the exit status. A cancelled owner cannot export a report.

Association state is deliberately reconstructed from the exact full ordered history. Replaying
the full list with the same inputs and budgets reproduces its history-linked digests and IDs.
Starting at an arbitrary suffix creates a new hypothesis history, not a silently resumed old
one. There is no persistent tracker checkpoint or background daemon in this increment.

Reports go to stdout and optionally to a new file outside the deployment. Existing files and
symlinks are never overwritten. Unix exports are owner-only and file-fsynced; partial files may
remain on I/O failure, and this is not atomic export-root publication. The local authorized
operator process and filesystem permissions remain the trust boundary; `--principal` is an
audit label, not remote authentication.

The detection and tracking modules own the internal projection encodings `FSSDETS1` and
`FSSTRKS1`, version 1, with canonical source/contract/history bindings. They are derived read
results; hashes are not authentication and do not promote projections into ledger authority.
The regression model is authored arithmetic, not trained detection. Rust tests were added but
not executed in the editing environment. Production model admission, trained detector quality,
appearance/multi-camera tracking, live capture, notification delivery and qualification remain open.
