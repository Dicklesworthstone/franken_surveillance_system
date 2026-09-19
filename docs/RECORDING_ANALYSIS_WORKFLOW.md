# One-command retained recording analysis

`fss-infer analyze` runs a bounded range of an existing JPEG/MJPEG import through
canonical decoding, the exact frozen model, detector-output decoding and local
tracking. It writes the existing canonical `AnalysisReport` rather than asking
operators to run inference separately for every frame and copy run IDs by hand.
The source import must already exist; use `fss-file import` first.

This command uses `run_recording` from [the recording pipeline](RECORDING_PIPELINE.md).
It adds no model runtime, graph dialect, automatic model activation, live camera
connection or notification delivery. A model must already be converted to the
bounded `RecordedModel` format described in [the inference workflow](INFERENCE_OPERATOR_WORKFLOW.md).
There are no bundled trained weights or claims of detector quality. Original
capture uncertainty and source gaps are preserved by the existing media owners.

## Analyze an explicit range

```sh
cargo run -p fss-cli --bin fss-infer -- analyze \
  --root ./camera-evidence --site site:home \
  --import-id sha256:YOUR_IMPORT_DIGEST --first-segment 0 --frames 32 \
  --interpretation ycbcr \
  --model ./approved-local-model.fssmodel --model-digest sha256:YOUR_MODEL_DIGEST \
  --output-port detections --labels vehicle,animal \
  --box-format xyxy --coordinates normalized \
  --minimum-score-ppm 500000 --nms-iou-ppm 500000 \
  --minimum-iou-ppm 300000 --confirmation-hits 2 --maximum-missed-frames 2 \
  --decode-work-units 1000000000 --max-macs 1000000000 \
  --detection-work-units 10000000 --association-work-units 10000000 \
  --max-tensor-bytes 67108864 \
  --report-out ./analysis.bin --runs-out ./runs.txt
```

Replace digest placeholders with independently expected SHA-256 identities. The
class labels and thresholds above illustrate an explicit contract, not a supplied
model's capabilities or calibrated operating point. Choose `gray` for grayscale
source, or `ycbcr` for the source's JPEG YCbCr contract. The exact model freezes
full-resolution luma preprocessing and dimensions. No resize, letterbox inverse,
logit transform, coordinate clipping or class-label interpretation is guessed.
The detector port must be F32 `[N,6]` or `[1,N,6]`, under the existing detector contract.

`--first-segment` and `--frames` are mandatory. At most 256 segments are admitted;
a range outside the original import is refused before derivative publication.
The existing recorded-event workflow currently admits reports of **at most 64
frames**, even though standalone analysis permits 256. Choose an event-compatible
range when the next step is event preparation. A range is a selected observation
window, not a certification of complete physical coverage.

The result reports `report_digest`, `analysis_plan_digest`, `authority_sequence`,
exact `run.SEGMENT` identities, numeric-work charges, new/reused counts and observed
`track` candidates. `analysis.bin` contains canonical FSSARPT1 bytes, not the JSON
produced by the older `detect`/`track` commands. The optional run list is compatible
with those older explicit-run-list commands. Console key/value diagnostics remain
a local operator surface, not a replacement universal agent response envelope.

## Restart without redoing numeric work

Repeat the **same original range** and detector/tracker contract. Supply a new
report output filename because exports never overwrite existing files. Omit
`--model` to recover its exact retained model object using `--model-digest`.
Once every numeric invocation completed, setting `--decode-work-units 0 --max-macs 0`
allows only verified recovery; an uncompleted frame or invocation cannot execute.
Keep adequate detector and association budgets, because the complete history is
reconstructed rather than trusting a serialized tracker checkpoint.

The original recording and external model file need not remain after their bytes
are retained. A model file explicitly supplied through `--model` must match its
expected digest; failure never falls back to another model. When no retained model
object exists yet, an external frozen model file is still required. This recovery
of exact bytes is not model-registry admission or proof of license/calibration.

Changed source ranges, weights, output contracts or tracker policies are different
analysis requests. Starting at an arbitrary suffix can change track identities.
Old runtime-profile runs are not silently relabeled as new-profile results.

## Prepare a candidate event from this exact report

Use the report digest and an observed `track` value printed by `analyze`:

```sh
cargo run -p fss-cli --bin fss-event -- prepare \
  --root ./camera-evidence --site site:home \
  --report ./analysis.bin --report-digest sha256:YOUR_REPORT_DIGEST \
  --track sha256:YOUR_TRACK_DIGEST --event-out ./candidate.json
```

Preparation revalidates the report and does not publish event authority. The
separate `fss-event publish` command still requires the exact reviewed proposal
digest. Neither analysis nor preparation sends alerts or upgrades model scores
into calibrated presence, corroboration, physical identity or evidence of absence.
See [the event workflow](RECORDED_EVENT_WORKFLOW.md) for publication and recovery.

## Bounds and partial failure

JPEG, model, detector and association work buckets apply across the entire command.
The tensor ceiling applies to each invocation, including verified cached results.
`--max-report-bytes` is positive and at most 16 MiB. Reference work counters are not
hardware throughput, CPU time, energy or whole-process peak-memory measurements.

Successful frames and invocations stay retained if a later step fails. Ordinary
pipeline failures print `complete=false`, the stage, pending segment (or `none`
during final analysis), all completed inference IDs and cumulative work. No partial
canonical report is exported. An analysis-stage failure can occur after every
numeric invocation has completed. Retry from the original range with sufficient
fresh budgets; the retained prefix is revalidated and reused.

Failed new inference attempts conservatively retain their reserved remaining
model-work allowance because the executor supplies no trusted partial-work
receipt. `model_work_charged` can therefore be a reservation, not measured executed
work. Missing or corrupt completed decode custody fails closed rather than being
silently regenerated. Corrupt evidence requires a separate authorized repair path.

Invalid arguments, absent deployments/models, export failures and ordinary analysis
failures all exit nonzero. Never treat stdout alone as successful completion. Export
destinations are preflighted before numeric execution and checked again with
new-file-only writes outside the deployment. Unix files are owner-only and file-
fsynced. Report and optional run-list exports are sequential, not atomic together;
partial exports or a completed report can remain after later I/O/stdout failure.
A principal string is an audit label for the filesystem-authorized local process,
not remote authentication. No background process is started.

## Validation boundary

The new CLI tests cover complete analysis, original-file removal, retained-model
recovery, zero-numeric-work retries, direct event preparation, partial failures,
shared budgets, export refusals, absent deployments and empty thresholded results.
Run `cargo test -p fss-cli --bin fss-infer` and
`cargo test -p fss-cli --test recording_analysis_cli_contract` on the pinned toolchain.
The Rust tests were added but not executed in the toolchain-less editing environment.
Source checks and checksum verification do not establish compilation or qualification.
