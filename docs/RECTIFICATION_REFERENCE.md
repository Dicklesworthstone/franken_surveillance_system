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
