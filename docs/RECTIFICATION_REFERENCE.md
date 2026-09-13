# Native lens correction into the property-localization pipeline

`fss_twin::rectification` fills the decoded-camera-input boundary shared by
BTI-003/004/005 and FSS-089/092. It is a synchronous first-party Rust implementation,
not a decoder, calibration estimator, foreign runtime, or completed field gate.
The current bead record for FSS-089 is `fss-x4a.17.2`; no broad bead is closed here.

## Implemented behavior

`RectificationPlan::compile` builds an immutable backward-sampling map from a
pinhole output grid to a declared source lens. Pinhole, Brown-Conrady (three radial
and two tangential coefficients), and central four-coefficient angular fisheye
models are explicit enum variants. Zero fisheye coefficients are not pinhole.
Source and target share one optical center and axes. Explicit target intrinsics
can crop/resize; arbitrary optical rotation or stitched/noncentral cameras are
not silently approximated. Both grids use pixel edges, with centers at i+0.5.
OpenCV integer-center calibration inputs require the explicit +0.5 principal-point
conversion before constructing the existing `PinholeIntrinsics` type.

The map uses the forward lens equation at each output bearing, avoiding an
unqualified iterative inverse or arbitrary branch selection. A sufficient
whole-domain non-folding check runs first: outward interval Horner bounds on the
Brown radial-Jacobian eigenvalues must exceed a conservative tangential-Jacobian
norm bound. Fisheye angular derivative must be positive throughout the front
hemisphere. This is conservative and can refuse a valid narrow-field model;
refusal does not establish that the real lens is defective. Model admission does
not prove physical calibration, uncertainty bounds, or rolling-shutter accuracy.

`RawGrayFrame` verifies source exposure, storage, raw image mode, calibration,
explicit row stride and full 0/1 allowed-mask bindings. It is type-distinct from
the pinhole-only `GrayImage`. It accepts an already decoded 8-bit luma plane,
including row padding, not H.264/JPEG/PNG bytes. Full-range versus video-range
16..235 is explicit; video luma is clamped and expanded to full-range u8 before
interpolation. Chroma and its color-space conversion are outside this grayscale
adapter. All original source storage and timing custody remains upstream.

`apply` reuses eight bytes of map per output pixel, with no per-frame trigonometry.
Q16 sampling positions and Q32 integer bilinear weights make sampling arithmetic
explicit. Quantization is at most half a Q16 source pixel per axis; it is not a
physical calibration error bound. Every positive-weight contributing source pixel
must be allowed before any contributing pixel value is read. Excluded, outside-
source and outside-lens samples become zero pixels PLUS a zero validity mask,
never extrapolated border content or a claim of an empty physical scene.
The native feature extractor subsequently enforces its entire output-patch mask.

`RectifiedFrame` keeps image, mask and receipt together and exposes
`as_gray_image` for the existing native extractor. The original exposure identity
survives all derivation; rectifying an atlas source cannot create a new independent
exposure. Output image-domain identity binds the complete source mode, calibration,
lens, target grid, luma conversion and actual map digest. Reusing a plan across a
changed calibration or raw mode fails. A map is not publicly mutable or loadable
from unchecked bytes. All operations are bounded and poll owner cancellation;
no failed operation publishes a partially usable result.

Limits: 4096 per image axis, 4,194,304 logical pixels, 64 MiB padded source storage,
and 32 MiB map storage. The output pixels/mask use at most 8 MiB together. The shared
work allowance is checked before allocations/hashing and during per-pixel work.
A borrowed source hash includes its declared padding; padding never enters image
sampling. A checksum does not grant permission to read source pixels or activate
calibration. There is no new public fss/1 operation or persistent format claim.

## Verification and remaining limits

```sh
cargo test --locked --offline -p fss-twin --test rectification_contract
python3 -B scripts/test_rectification_reference.py
```

Thirteen Rust contracts cover independent OpenCV map goldens, optical-axis/pixel-
center conventions, zero-fisheye behavior, masks and noninterference, exact identity,
crop borders, row padding, luma range, stale generations, malformed models/storage,
folded lenses, complete scope, work exhaustion and cancellation. They are authored
but NOT RUN in the compiler-less authoring container.

Nine independent Python oracle tests executed successfully with OpenCV 4.13.0:
2,000 lens projections across the two families, 2,000 exact-rational interpolation
checks, privacy-footprint controls, pixel-center/range checks and map goldens.
These are not Rust compilation or execution. No real camera, raw recording,
calibration fitting, covariance propagation, detector, source-video decoding, or
always-on service qualification is claimed. The owner must supply an admitted
lens and input mode; unknown distortion is not assumed to be zero. Brown rational,
thin-prism, tilted-sensor and noncentral models remain unsupported.

Primary methodological references (not production dependencies):
- https://docs.opencv.org/4.13.0/d9/d0c/group__calib3d.html
- https://docs.opencv.org/4.13.0/db/d58/group__calib3d__fisheye.html

## Decoded distorted input to camera-pose candidates

`localize_raw_frame` now composes the real rectifier, native feature extractor,
atlas matcher and PnP solver. Target intrinsics and the exact image-domain identity
come from the immutable `RectificationPlan`, not a second caller-supplied camera
that could disagree with the computed pixels. A source exposure already used in
the atlas is refused before resampling, even when its raw/rectified pixel bytes,
crop, mask or domain differ. The coupled result retains the rectification receipt
and the complete localization outcome; low matching support remains unlocalized.
The temporary corrected image does not need to survive once its derived record
has been retained by the existing custody owner.

```rust
let plan = RectificationPlan::compile(spec, &mut budget)?;
let source = RawGrayFrame::new(identity, &luma, &source_allowed, &mut budget)?;
let localized = localize_raw_frame(
    &atlas, &twin, &plan, &source, ImageLocalizationOptions::default(), &mut budget,
)?;
```

The example assumes already admitted objects and imports from
`fss_twin::rectification` and `fss_twin::localization::native`. In a sequence, compile
one plan per immutable source/target mode and reuse it. The source decoder must
still supply actual luma, capture/exposure identities and masks. This is not an
H.264 decoder, a contact detector, or a live transport adapter.

The existing `localize_atlas` file harness keeps its previous 19-field pinhole
configuration unchanged. To supply decoded distorted luma, add **all** of these
fields. The existing `width/height/fx/fy/cx/cy`, `image_domain_sha256`, query hash
and mask hash now describe the source distorted plane. The query hash includes
row padding; the allowed mask remains tightly packed logical pixels.

```text
rectification=brown
source_calibration_sha256=EXACT_ADMITTED_CALIBRATION_HASH
row_stride=1920
luma_range=video
maximum_radius=1.0
target_width=1600
target_height=900
target_fx=CALIBRATED_TARGET_FX
target_fy=CALIBRATED_TARGET_FY
target_cx=CALIBRATED_TARGET_CX
target_cy=CALIBRATED_TARGET_CY
distortion_coefficients=ACTUAL_K1,ACTUAL_K2,ACTUAL_K3,ACTUAL_P1,ACTUAL_P2
```

These dimensions and radius illustrate syntax, not a fitted camera. Supply actual
calibration values. Brown coefficient order is **k1,k2,k3,p1,p2**, deliberately
matching the typed model rather than an arbitrary OpenCV array. `fisheye` requires
four angular coefficients k1..k4; `pinhole` requires the literal `none` for its
coefficients. `luma_range` is exactly `full` or `video`. Partial configurations,
unknown models, coefficient-count errors, nonfinite values and guessed automatic
range selection are refused, never retried as the old pinhole path.

```sh
cargo run --locked --offline -p fss-twin --example localize_atlas -- /private/property/localize.conf
cargo test --locked --offline -p fss-twin --test rectified_localization_contract
cargo test --locked --offline -p fss-twin --example localize_atlas
python3 -B scripts/test_rectified_localization_reference.py
```

On success the distorted-input harness emits a separate bounded derivation record
before the existing localization summary/candidates: original exposure, raw pixel
and mask roots, calibration, raw/output domain roots, actual sampling-map root,
corrected pixel/mask hashes and complete unavailable-pixel counts. The record is
emitted only when the whole composed call completes. It is a development rehearsal
schema, not a registered fss/1 envelope, custody proof, or calibration activation.

## Independent distorted-image integration control

`tests/fixtures/brown_luma_96x96.gray` is a 9,216-byte **synthetic** source frame,
not private property imagery. Its source texture uses the existing seeded native-
feature test pattern. OpenCV 4.13.0 independently applies the inverse Brown mapping
and source rasterization; the new Rust rectifier is not used to manufacture its
input. The source has nonzero radial and tangential distortion. Its SHA-256 is
`5843ec0250942b9ca4ec0fe68ce80289aa60eaa5d796c6c388a71a59f0438538`;
the independently computed Q16-corrected image hash is
`7e31c6e153dded00386436ef3b1bdc98dba5a8dd9049c3fb65bb6ce68bd20e98`.
The reference point depths form a synthetic nonplanar pose control, not a measured
property or a realistic scene/detector validation corpus.

The four new Python tests actually executed: fixture regeneration matches retained
bytes; corrected bytes match the independent golden; the corrected image yields
27 exact physical-feature matches and the expected pose in the laboratory solver;
an 80x80 crop yields 20 correct matches using its changed principal point. The
nine earlier lens/interpolation oracle tests were rerun and passed. These are
Python/OpenCV results, not execution of native Rust.

Six added Rust contracts exercise the real nonzero-distortion-to-pose pipeline,
changed target intrinsics, source-exposure alias refusal, blank/masked input,
stale bases and failed-call reuse. Four example-config tests preserve the legacy
route and reject all partial lens configurations or malformed model parameters.
All ten are authored but **NOT RUN** here: the Rust toolchain remains unavailable.
Real source decoding, lens estimation, recorded-camera accuracy, calibration and
clock uncertainty, reference-view robustness and always-on service integration
remain open. Correcting a nominal lens does not validate that it matches the device.
