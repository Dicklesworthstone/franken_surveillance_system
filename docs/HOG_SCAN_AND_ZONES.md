# Learned HOG scanning and source-linked zone observations

`fss_twin::hog_scan::scan_hog` executes the existing native grayscale HOG kernel
with the exact coefficients in a `HogModel`, across explicitly selected image
grids. It does not require motion to select a window. The coefficient loader takes
exactly 3781 little-endian F32 values (3780 features followed by the intercept),
an independently supplied SHA-256 and a separate provenance/license-record digest.
No model is downloaded, filled with default weights, activated or qualified here.

This is a perception-to-event reference slice toward comprehensive-plan sections
16–17 and WP-090. It does not close that program's acceptance requirements.
In particular, a model-shaped file and its checksum do not establish a license,
a calibrated class vocabulary, real-camera recall, or compatibility with a foreign
HOG implementation. The native scalar recipe is not bit-identical to OpenCV.
A deployment still needs held-out validation of its exact coefficients, numeric
recipe, resizing, thresholds, camera mode and target distribution.

## Multiscale computation

Each `ScanLevel` names an exact width/height. Levels are canonicalized by descending
pixel count and dimensions; duplicates are rejected. Reordering the same levels
does not change scan identity. A too-small grid stays visible as a zero-window
level; it is not a negative classification. Strides are positive multiples of 8.

Resizing uses pixel-center bilinear interpolation with exact rational weights,
edge clamping and one half-up rounding step. Every nonzero-weight contributor
must be permitted before any intensity enters the interpolation. Denied outputs
are zero with mask=0. Zero-weight neighbors neither contribute data nor create a
false denial. The existing HOG gradient-halo permission rules apply afterward.
Resized images retain the ORIGINAL exposure/camera/capture/calibration, while
pixels, dimensions, image domain and permission identity describe the actual
resampled grid. A crop or scale is not an independent source.

One grid/block cache is processed at a time. Every scheduled window remains in
`HogScan::windows()` with its origin, conservative original-image bounds, margin
or explicit unobservability, and disposition. Windows at or above the configured
margin are ordered by descending score, with canonical window ID breaking ties.
Integer source-box IoU drives inclusive-threshold suppression. Suppressed rows
retain their margin and the ID of the selected row responsible for suppression.
No top-k truncation occurs. Capacity is checked before suppression; an overflow
refuses the whole scan. Missing scales, below-threshold scores, private windows,
and suppressed alternatives are never evidence of scene absence.

The model, native feature recipe, interpolation/mapping rules, selected grids,
threshold, stride, suppression policy and complete-output limits bind the scan
generation. The scan receipt additionally binds the original source, masks, every
resized level and every window outcome. These are internal derivation fingerprints,
not canonical ledger publications or grants of source access/effect authority.

Hard bounds are 16 scales, 16,384 scheduled windows and 1024 above-threshold rows.
Each source/derived grid is bounded to 4096 pixels per axis and 4,194,304 pixels.
Callers must also provide a finite `WorkBudget`; block computation, scoring,
resampling, suppression, encoding and cancellation use that existing owner budget.

## Existing tracking and zone ownership

`fss_twin::screening::tracking::hog::HogZonePipeline` owns an initially empty
`ImageZonePipeline`, not another association algorithm or event state machine.
It consumes an opaque complete `HogScan` and an independently generated opaque
`ScreeningReport` for exactly the same original pixels, mask and capture basis.
Stream generations, screening policy, sequence and receive order are enforced.
A missing health predecessor or skipped sequence degrades assimilation; a new
monitor cannot silently replace the original monitor's history.

Only `NoFaultObserved`, uninterrupted screening history and at least one scored
window can admit measurements. Other health states clamp the frame to disturbed
or unobservable. A screen missing its foreground comparison remains degraded;
this consumer does not clear another subsystem's findings to obtain a positive
result. Selected HOG windows still remain in the tracking report when assimilation
is unavailable. Exceeding the tracker's complete-detection limit refuses all of
them rather than selecting a smaller scene.

Border-touching windows are marked partial. The original anonymous tracker handles
assignment/ambiguity/misses; the original zone monitor handles sampled occupancy,
observed-side transitions and interruptions. These are trajectories of learned
WINDOW PROPOSALS, not proof of a person's identity, true silhouette, ground contact,
continuous occupancy, intent or threat. The complete scan remains the accessible
basis for investigating suppressed alternatives and unobservable regions.

```rust,ignore
let mut learned = HogZonePipeline::new(empty_zone_pipeline, stream_generation, &mut budget)?;
// Generate the independent health report using the exact original image/mask.
let scan = scan_hog(source, pixels, allowed, &model, &levels, policy, &mut budget)?;
let progress = learned.observe(&scan, &screen, &mut budget)?;
// Retain scan, screen, source media, tracking_report() and zone_report() together.
```

`Err` means no new tracking input was consumed. `Pending` means tracking DID consume
this exposure and the existing zone stage must be resumed. `scan_digest()` and
`last_screening()` retain the accepted inputs; `pipeline().zone_report()` returns
None rather than a stale zone result. Call `resume()` with renewed owner budget,
not `observe()` again. New exposures remain blocked until the accepted zone stage
completes. The caller keeps the borrowed scan and source media through all outcomes.
No durable checkpoint or background worker is introduced.

Use `requires_analysis()` as the next screening request's active-track floor.
This lane does not automatically acknowledge the screening monitor's semantic
analysis recommendation, publish canonical event revisions, corroborate independent
cameras, or invoke an alert provider.

## Local operator scan

The read-only example processes an explicit luma plane and local coefficient file:

```sh
cargo run -p fss-twin --example hog_scan -- /absolute/path/manifest.txt
```

The manifest starts with `FSS_HOG_SCAN_1` and requires all 23 keys below. Replace
all placeholders with independently retained identities and actual file paths.
Numerical values are illustrative assumptions, not calibrated security defaults.
The files must be regular local files beneath the manifest directory. This is a
trusted-operator replay interface, not an adversarial-filesystem security boundary.

```text
FSS_HOG_SCAN_1
pixels=frame.luma
pixels_sha256=<64 lowercase hex characters>
mask=frame.mask
mask_sha256=<64 lowercase hex characters>
weights=model.f32le
weights_sha256=<64 lowercase hex characters>
provenance=<64 lowercase hex characters>
width=320
height=240
camera=1
clock=1
capture_earliest_ns=1000000000
capture_latest_ns=1000010000
exposure=<64 lowercase hex characters>
image_domain=<64 lowercase hex characters>
calibration=<64 lowercase hex characters>
levels=320x240,256x192,192x144
minimum_margin=0.5
stride=8x8
suppression_iou_ppm=500000
maximum_windows=4096
maximum_candidates=512
work_units=1000000000
```

Pixels are tightly packed full-range luma. The separate equally sized permission
plane contains only 0/1 values. Output is JSON Lines: one scan identity, all level
receipts, EVERY window with a scored/private/selected/suppressed state, and a
terminal `complete` record with costs. No pixels or coefficients are printed.
A failed scan exits nonzero without emitting successful partial inference. An
output-stream failure can leave a prefix without `complete`; it is not completion.
The example does not itself produce health reports, track, acquire cameras or
classify a model as a validated pedestrian detector.

## Validation boundary

```sh
cargo test -p fss-twin --test hog_scan_contract
cargo test -p fss-twin hog_scan::resize::tests
cargo test -p fss-twin --test hog_zone_contract
cargo test -p fss-twin --example hog_scan
```

Fixtures exercise actual pixels, HOG blocks/dot products, source-matched health,
assignment and zone derivation. Synthetic coefficient fixtures test execution and
ownership, NOT trained detector quality. Tests include masked gradient halos,
scale permutations, complete-output limits, freeze/history degradation, wrong
source/model generations, cancellation and accepted-but-pending zone resumption.
Rust compilation/test execution, rustfmt and Clippy were unavailable in the
authoring environment. Independent arithmetic/privacy checks and exact blob/hash
checks are supplementary, not a Rust build or production qualification.
