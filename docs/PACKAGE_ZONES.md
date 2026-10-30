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

Both the v1 and v2 package-zone outputs include source/package/model-generation and
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

These are uncalibrated model-proposed class/trajectory observations. The default v1 report
leaves source health unassessed. Neither version establishes physical identity, proves
presence/absence, corroborates multiple sensors, assigns threat severity, publishes a canonical
event revision or authorizes an alert/effect. Those facts are explicit in every JSON result.

## Require matching historical health screening

Add `--require-health-screening yes` to the analyze command to select
`fss.package_zone_report.v2`. Read selects the retained format automatically.
The native equivalent is `PackageZoneReport::analyze_screened` with explicit
`HealthExposureLimits`; `open_with_health_limits` gives cold reads an explicit
whole-operation allowance, while ordinary `open` uses the default limits.
The original unscreened `analyze` and v1 schema/canonical bytes remain unchanged.

Retain the native diagnostic independently using the existing
`fss-event watch --stream-watch --sensor-health conservative-v1` or screened
whole-recording dwell path, with that diagnostic's exact `--retain-health` approval.
A package-zone preview neither creates a diagnostic nor silently reruns a health scan.

The v2 owner loads one complete retained diagnostic catalog per derivation and assesses
each source frame once. It does not repeat diagnostic reads for each track or rectangle.
Matching requires the exact import identity, import root, sensor, original source segment,
privacy policy and privacy generation. A diagnostic for another source or interpretation
cannot supply missing screening.

| Matching historical evidence | Positive zone, crossing and dwell support |
| --- | --- |
| Complete finite screening without findings | Admitted, subject to the unchanged geometry, confirmation and timing rules |
| No matching diagnostic | Withheld; health remains unknown |
| Any matching incomplete screening | Withheld |
| Any matching retained finding | Withheld over that diagnostic's finite scan, including threshold latency |

A screen without findings describes only a finite heuristic scan. It is not a healthy-camera
certificate or a claim about present health. Later retained evidence can reveal a problem in
previously screened samples. Withheld samples interrupt observation and dwell; they never
become a departure, absence assertion or proof that the scene was empty.

Every actual assigned box, detector row, frame, confirmation flag and geometric relation
remains in the report. The additive `historical_health.frames` projection includes all
matching diagnostic record/root/trace pins, original publication anchors, findings and finite
withholding intervals. `zone_support_allowed` shows the stricter v2 policy; unknown samples
are withheld even when the generic exposure catalog has no finding to report.
The retained trace payload is digest-verified once per distinct selected trace during each
derivation; native trace execution is not replayed and `native_trace_replayed` remains false.

Canonical v2 uses `FSSPZNR2` and separate report/approval domains. Its publication root
includes every selected diagnostic record, provenance root and trace alongside the existing
exact detector/source/privacy closure. Cold reads revalidate this exact selection and compare
every canonical byte. Newly retained relevant diagnostic evidence makes a stale selected
report fail exact reconstruction; its stored bytes are never changed or repaired. Publishing
the report itself does not invalidate it, because current catalog anchors and work counters
are excluded from its identity.

The catalog and selected trace reads share one `HealthExposureLimits` allowance across
the report's initial analysis, pre-retention revalidation, post-publication revalidation and
exact retries. A failed revalidation cannot silently refill that allowance. The complete
`historical_health.operation_usage` describes successful catalog work, selected trace bytes
and read attempts for the current operation; these counters are outside the report digest.

Retention additionally installs a separate cumulative native spool ceiling of **512 MiB
of reserved indexed-read bytes and 65,536 indexed-read attempts**. This covers the complete
retain call, including original source replay, diagnostic publication-closure rereads,
verification, staging retries and post-publication reconstruction. The spool reserves stored
envelope bytes (including the header and one trailing-byte probe) before accessing each
indexed object. Failed admitted reads remain charged. Retention counters are reported as
`retention_indexed_read_bytes_reserved` and `retention_indexed_read_attempts`, with their
limits alongside them. They overlap catalog/trace counts and must not be added to those
counts as if they were disjoint work. Opening recovery, directory/metadata/open syscalls and
non-indexed staging writes are outside this indexed-read allowance and remain governed by
their existing native owners. A preexisting tighter spool cap wins; the cap cannot be
removed or refilled until that deployment owner is dropped. A later report does not widen it.

If a limited retention stops after publishing its root but before the cognition append, the
prefix carries no retained-report authority. A fresh explicit analysis with sufficient
allowance can complete only the same source-verified bytes and approval. Existing reports
never refill their own consumed budget.

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

The v2 native contract adds real clear, unknown, partially screened, incomplete and frozen
source fixtures; later relevant diagnostics; exact pin/trace corruption; changed privacy;
source deletion; original-owner closure and cold reopen; cumulative retention allowances;
and legacy-byte preservation. The CLI fixture validates both schemas through actual
analyze/retain/read commands, verifies partial support and later diagnostic invalidation,
and checks that every assigned box survives the health gate.
