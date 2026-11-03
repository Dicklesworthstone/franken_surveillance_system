# Native features from retained source images

The sealed owner in
`fss_reference::ingest::twin_localization::features` extracts image features from
authenticated retained JPEG, AVC/H.264 and HEVC/H.265 sources. Its two public
entry points share original-source custody, current privacy and final
revalidation:

| Entry point | Image interpretation |
|---|---|
| `extract_recorded_features` | Original native decoded luma already belongs to the declared undistorted pinhole grid. |
| `extract_recorded_rectified_features` | An admitted native `RectificationPlan` converts original decoded luma into its exact target pinhole grid before extraction. |

Both return `RecordedFeatures`. Native source facts and the derived feature
image remain separate: `source()` describes the original capsule, encoded
source, decoder receipt, native luma, native dimensions, original exposure and
current privacy binding; `frame()` describes the image grid on which the actual
features were extracted. Rectification can legitimately change pixel digest,
dimensions, allowed-mask digest and image domain. It preserves the original
exposure and cannot create another independent camera observation.

## Correct distorted source pixels before matching

Compile the existing native rectifier under the same cumulative work allowance
used for extraction and downstream geometry. This admits the complete lens
model before decoding can publish a JPEG derivative:

```rust
let rectifier = RectificationPlan::compile(spec, &mut work)?;
let request = RecordedRectifiedFeatureRequest {
    source: selected_retained_source,
    rectifier: &rectifier,
    extraction,
};
let features = extract_recorded_rectified_features(
    &mut deployment,
    &request,
    &source_reads,
    &mut jpeg_work,
    &mut video_admission,
    &mut work,
    &cx,
)?;

// Construct the complete downstream result from features and its original bindings.
features.revalidate(&deployment, &cx, &mut work)?;
// Release the completed derived result only after this check succeeds.
```

`RectificationSpec` explicitly supplies raw source intrinsics, target pinhole
intrinsics, source-domain identity, lens-basis identity, maximum normalized lens
radius and native luma range. Supported lens families are pinhole, polynomial
Brown–Conrady with three radial and two tangential coefficients, and central
fisheye with four angular coefficients. Different source/target intrinsics can
describe an explicit crop or resize. Source and target share optical axes and
center; arbitrary optical rotation and noncentral stitched images are outside
this contract.

The rectifier checks sufficient whole-domain non-folding bounds, constructs its
bounded Q16 backward map, and derives the output image-domain identity from the
exact mode and actual map. The caller cannot independently substitute the
corrected domain. Source dimensions must match the admitted model after the
native decoder authenticates the selected source.

The `full`/`video` luma declaration is an explicit transfer interpretation. Video
range clamps to 16–235 and expands to 0–255 before interpolation. It does not
discover or certify the camera's encoding. Lens and source-domain hashes bind
declared evidence; they do not activate or certify physical calibration.

## Privacy and complete lineage

The retained owner obtains the current original-image allowed mask. A corrected
pixel is unavailable if any positive-weight bilinear source tap is masked.
Out-of-source and out-of-lens samples also remain unavailable. The native
extractor then requires the entire 33×33 descriptor footprint to be allowed on
the corrected grid. Zero-filled unavailable pixels never become observations.

`RecordedFeatures::rectification()` returns an optional immutable record. Its
`spec()` and `receipt()` expose the exact declared model and actual computation:

- Unchanged original exposure, native storage, source mask, source mode, lens
  basis, dimensions, packed row stride and range.
- Actual map digest, corrected pixel identity, target dimensions and derived
  output domain.
- Corrected allowed-mask digest and complete mapped/outside-lens/outside-source/
  privacy-rejected/allowed sample counts.

The existing native decoder receipt remains separately available. Direct
extraction preserves `fss.recorded_native_features.v1` identity bytes and its
charged work. Corrected extraction uses the separate
`fss.recorded_rectified_native_features.v1` identity, binding the complete
original source/feature inventory, model and rectification receipt.

The pure native composition is also available as
`fss_twin::rectification::extract_raw_features`. It returns the existing
`ExtractedFrame` plus the complete native `RectificationReceipt`, with no
retained-custody or camera-calibration authority.

## Resource and revalidation boundaries

Source reads share one nonrenewable `RecordedFeatureReadBudget`, including
original HTTP/RTSP provenance and final revalidation. JPEG work, video encoded
bytes, video coded-luma admission and geometry work are independent axes. Plan
compilation, resampling, mask propagation and extraction all charge the caller's
`WorkBudget`; the owner-local `geometry_work()` excludes plan compilation that
the caller performed before entering the owner.

Either image is bounded to 4,096 per axis and 4,194,304 pixels. A map stores eight
bytes per target pixel. It can be reused for the exact same immutable source
mode; every new exposure still gets its own source/mask/output receipt. No
partial feature set is returned after cancellation or work exhaustion.

Complete AVC/HEVC ranges contain at most 64 coding segments and must finish
decoding, including later pictures and skips. After downstream computation,
`revalidate` reopens original custody and current privacy. JPEG also verifies
its retained decoded pixels and receipt without repairing missing data. Valid
later JPEG publications do not stale an earlier source, but source deletion,
tampering, privacy change or a different authority context refuses release.

Feature coordinates and any downstream `sigma_pixels` belong to the corrected
target grid. Independent output-pixel noise is a declared approximation:
resampling correlations and lens-parameter uncertainty require separate modeling.
This feature applies a frozen lens model; it does not estimate distortion,
rolling shutter, camera motion, time synchronization or calibrated accuracy.
