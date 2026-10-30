# Retained detector-package zone observations

`fss-event package-zones` turns one retained, class-selected trained-package analysis
into observed image-zone entry/exit intervals and conservative sampled-dwell reports.
It reopens the original source custody and native package report; it does not run the
model again or use foreground tracks as a substitute for trained detections.

This completes a bounded operator path for FSS-076/FSS-077: package detection → exact
class-selected assignments → source-linked spatial/temporal observations → independently
approved cognition retention → exact cold reconstruction. It does not change the existing
`fss.package_analysis_report.v2` bytes or canonical package-event semantics.

## Analyze, approve and recover

First use the existing `fss-file import` and `fss-infer package-detect --retain yes`
commands. Select the retained detection report digest printed as
`package_detection_retained`. Dwell requires explicit capture hints on the original
import (`--capture-start-ns`, `--capture-uncertainty-ns`, `--assumed-fps`); those remain
operator assumptions, never hardware clock certification.

```text
fss-event package-zones analyze --root /absolute/deployment --site site:home \
  --package-report sha256:EXACT_RETAINED_DETECTION_REPORT --label person \
  --zone driveway:20:30:240:160:2 --maximum-sample-gap-ns 250000000 \
  --dwell-ns 2000000000 --minimum-observations 8 \
  --confirmation-hits 3 --maximum-missed-frames 2 --minimum-iou-ppm 100000
```

The uppercase digest is a placeholder. Choose the exact vocabulary label and source-pixel
rectangle for your recording; sample values are not a calibrated deployment policy.
Each `--zone` is `NAME:X:Y:WIDTH:HEIGHT[:MARGIN]`; up to 16 distinct zones are accepted.
Margin expands the assigned box before definite membership is evaluated. Omit both
dwell options for spatial observations and entry/exit only. The maximum sample gap is
always explicit. The complete configuration is printed and bound into the report.

Inspect the complete JSON, then rerun the same command with
`--retain sha256:EXACT_APPROVAL_DIGEST` from its `approval_digest`. Approval binds the
principal, complete derivation and exact source-closed root. This writes a
`package_zone_report` cognition object and its immutable proof graph. An exact retry
returns `already_retained` with the original commit anchor.

```text
fss-event package-zones read --root /absolute/deployment --site site:home \
  --report-digest sha256:EXACT_RETAINED_ZONE_REPORT
```

Cold read always reopens original retained source bytes and the exact native detector
analysis, rebuilds tracking and zone/dwell derivation, and compares every canonical byte.
It needs no original media path, loose package file, report file or new inference allowance.
There is no metadata-only success mode and no automatic repair of missing custody.

## What the report establishes

The `fss.package_zone_report.v1` output includes source/package/model-generation and
class pins, original capture intervals and clock basis, the full tracking policy and zone
configuration, every admitted source frame, every track/zone/frame cell, all derived
transitions, and every qualifying maximal sampled-dwell run. Event addresses are the
complete report digest plus event-array index; track IDs are anonymous local trajectories.
Boxes are the exact assigned detection's source-grid XYXY coordinates in 1/256 pixels.
They are never predicted Kalman positions or a nearby higher-scoring detector row.

Confirmation is evaluated at each actual sample. A track that later confirms does not
retroactively confirm its first tentative samples. Other class labels from the same
detector row cannot fill a missing observation of the selected class.

Strict inside requires the whole expanded assigned box to lie inside the rectangle.
Strict outside requires separation. Touching/intersecting boxes are boundary observations.
A complete boundary observation can connect the earlier and later definite sides of an
observed crossing, but cannot establish a definite side or contribute to inside dwell.
Clipped boxes remain partial. Masked, missing, tentative and time-unreliable observations
interrupt temporal inference; coasting and track disappearance never imply departure.

Sampled dwell is a sequence of actual confirmed inside observations. Its lower duration
uses the first capture interval's latest endpoint and the last interval's earliest endpoint.
Its upper duration preserves the opposite endpoints. The full source-frame timeline is
checked, so a missing assignment, boundary sample, excessive worst-case gap or source
discontinuity breaks the run. The report records both the first threshold-crossing sample
and the full maximal run. It does **not** establish occupancy between samples.

## Refusals and limits

Every read and retention checks current source/deletion/privacy restrictions. A new privacy
generation, withdrawn detection or import, missing capsule, damaged source bytes, altered
proof, foreign principal approval or changed configuration cannot reuse the previous result.
The report preserves explicit source-gap boundaries. Capture timing inferred from nominal
frame indices is ineligible after source omissions; unknown source timing never becomes
elapsed time by using receive time. Changed image dimensions or inconsistent clock/order
are refused rather than silently reinterpreting the image zone.

The complete workload is bounded before processing: at most 64 frames and 8192
track × zone × frame cells, with one aggregate derivation budget, at most 16384 events,
8 MiB canonical bytes and 16 MiB complete JSON. Excess work/output refuses the entire
operation. No observation or uncertainty is dropped by ranking or truncation.

Cancellation before the cognition append may leave a durable publication prefix, which
has no retained-report authority. An exact approved retry revalidates source custody and
completes it once. Later output errors do not undo an already committed retention.

These are uncalibrated model-proposed class/trajectory observations. The operation does
not independently screen original sensor health, establish physical identity, prove
presence/absence, corroborate multiple sensors, assign threat severity, publish a canonical
event revision or authorize an alert/effect. Those facts are explicit in every JSON result.

## Regression evidence

Native tests exercise a small deterministic FMPK through real JPEG import, first-party
Conv2d/Reshape inference, class projection and assignment. This synthetic fixture tests
wiring and chronology, not detector quality. It moves a class-selected box through a
boundary into a zone, qualifies sampled dwell, omits that class while another class remains,
and verifies a distinct subsequent dwell run. Separate bundled YOLOX-Nano proposals test
that actual clipped boxes cannot become strict-inside or dwell evidence.

Tests also cover source gaps, unknown timing, tentative samples, corruption, changed
privacy, source deletion, wrong approvals, root-prefix cancellation and exact cold retry.
The CLI test validates actual analyze/retain/retry/read JSON against the registered schema.
The existing tracker lifecycle is independently compared over missing-observation patterns
to the sample-confirmation accessor; existing v2 analysis encoding is unchanged.
