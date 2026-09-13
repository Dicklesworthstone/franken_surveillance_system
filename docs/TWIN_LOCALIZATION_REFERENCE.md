# Native reference-image localization

Implemented reference portions of BTI-002/004; their broader acceptance gates stay
open. `fss_twin::localization` now connects a real-image descriptor atlas to the
existing robust image-to-map pose solver. It does not infer the map itself or
activate a camera calibration. No new production dependency or runtime is added.

## Atlas and matching

`LocalizationAtlas::new` consumes an imported `PropertyTwin`, static landmarks,
reference feature frames, and explicit image-feature/map-point associations. Each
landmark retains its feature, physical-point group, supporting evidence handle,
and unknown or declared coordinate errors. Each reference retains exposure, pixel,
image-domain, and descriptor-generation identities. The atlas pins both the local
geometry basis and the exact twin digest; reusing a local revision handle cannot
make another imported package compatible.

References to the same physical point across different exposures improve matching
but cannot increase the number of PnP correspondences. For each query, matching
computes the minimum Hamming distance over all reference descriptors of a landmark.
The ratio test compares the best two **distinct physical landmarks**, not two
views of the same point. It then requires an unambiguous mutual nearest match.
Repeated texture ties, weak ratios, distant features, and duplicate query matches
remain explicit rejections rather than confident correspondences.

The atlas rejects duplicate physical groups/positions, conflicting bindings,
reference exposure aliases, unused map points/views, nonfinite data, missing
features, and mixed descriptor generations. Source declarations are not proof that
an owner actually observed the feature or measured its location. Independent map
and landmark qualification remains required. The normalized atlas digest binds
all its typed input data; this digest format is not a registered durable schema.

`localize` checks the query's exact image-domain identity and dimensions against
an owner-resolved `LocalizationCamera`, refuses reuse of a reference exposure as
new localization evidence, and passes actual matched correspondences to
`estimate_camera_pose`. Insufficient matches and geometric failure retain the
complete match report. Passing alternatives remain alternatives. Cancellation,
allocation limits, and work exhaustion return errors, not partial success.

The solver currently holds intrinsics and map points fixed and admits nonplanar
pinhole geometry. Map error records do not magically become a calibrated pose
covariance. Excluded physical landmarks can be checked through the existing
`PoseSearch::validate_candidate`; a low fitting error alone is not activation
or proof of physical accuracy. Unknown camera/map error remains unknown.

## Limits and privacy

The scalar reference admits 512 query features, 4096 landmarks, 64 reference views,
and 32768 bound observations. It charges descriptor and decision work and bounds
its distance matrix before allocation. It deliberately does not prune an arbitrary
map subset and call the result exhaustive. Candidate-image retrieval can later
reduce work with explicit search scope and omitted-candidate reporting.

The caller must authorize/filter images, map landmarks and features before import.
Descriptors and exposure mappings can be sensitive and share their sources'
retention/deletion requirements. Atlas/frame Debug output does not dump descriptors
or map geometry. No image, model, file, network, or foreign process is accessed.

## Verification

```sh
cargo test --locked --offline -p fss-twin --test localization_contract
python3 -B scripts/test_localization_matching_reference.py
```

Eleven Rust contracts cover actual matching-to-PnP composition, multiview point
deduplication, repeated textures, mutual ties, stale packages, image/descriptor
bases, reused exposures, full input validation, deterministic fingerprints,
empty queries, work/cancellation, and descriptor bit distances. These Rust tests
have not executed in the authoring environment, which has no Rust compiler.
The Python check executes 36,112 exhaustive/random decision-matrix comparisons
against a separately formulated nearest-neighbor oracle; it does not execute Rust.
Real-property and automatic-reference-map qualification remain outstanding.

Methodological references (not implementation/runtime imports): binary intensity
comparisons and Hamming matching are described by the BRIEF authors at
https://www.epfl.ch/labs/cvlab/research/descriptors-and-keypoints/research-detect-brief/ .
The code here is original; it does not copy their GPL reference implementation.

## Native pixels to camera pose

`localization::native` adds an original scalar FAST-9 detector and a 256-bit
oriented binary-patch descriptor. `GrayImage::new` verifies exact tightly packed
grayscale bytes against the supplied pixel digest and validates a same-sized
0/1 allowed-pixel mask. Inputs must already be in their declared undistorted
pinhole image domain. This code does not decode video or guess lens correction.

`extract_gray` computes circular nine-pixel contrast responses, deterministic
local nonmaximum suppression, spatially diverse bounded tile reservoirs, and
spacing-constrained selection. Descriptor orientation uses intensity moments;
256 fixed pseudo-random pixel-pair comparisons use 3x3 smoothed intensities.
The descriptor construction has an exact algorithm fingerprint; these are not
ORB-compatible descriptors or a copy of another library's implementation.
`describe_reference_pixels` applies the identical descriptor to explicit integer
reference-image positions, without silently rounding subpixel SfM observations.

The entire 33x33 footprint must be permitted, not only the keypoint center.
No excluded pixel can enter its orientation, smoothing, or binary comparisons.
The extractor reports the mask digest, all selection settings, tested centers,
local maxima, selected count, and omitted candidates. Selection is deliberately
bounded, not a claim that no other useful landmark exists. The owner must retain
these source/selection records alongside reference-map associations.

`localize_gray_frame` now composes extraction, atlas matching, and PnP from actual
supplied image pixels. It accepts no query-to-landmark associations or default
pose. Blank/fully masked images remain unlocalized. A new frame must match its
expected image-domain identity and cannot reuse an atlas reference exposure.
All existing map-error, fixed-intrinsics, nonplanar-support, multiple-pose, authority,
and qualification limits still apply. The producer must provide the reference
image-to-map bindings; this does not implement SfM or automatically export an atlas
from every possible Blender reconstruction workflow.

Images are bounded to 4096 per axis and 4,194,304 pixels, with at most 512 selected
features. The work budget covers mask preparation, corner tests, descriptor work,
matching, and geometry. This is a scalar reference baseline, not a speed claim.
It handles in-plane orientation normalization but is not scale- or arbitrary
viewpoint-invariant, and is not qualified for night/IR or aerial-to-ground imagery.
Multiple suitable real reference views remain important. Descriptor floating-point
orientation does not claim bit-identical results on every architecture/compiler.

```sh
cargo test --locked --offline -p fss-twin --test native_localization_contract
python3 -B scripts/test_native_features_reference.py
```

Seven more Rust contracts cover independent descriptor goldens, in-plane rotation,
brightness controls, reference/extracted compatibility, full-patch masking, blank
inputs, digest/shape failures, bounds/cancellation, deterministic selection, and
actual raw-image-to-PnP composition with a rotated synthetic camera. Rust execution
remains unverified in the compiler-less authoring environment.

The independent Python experiment matched 215,296 FAST decisions against OpenCV
4.13.0 and obtained 69 exact physical-feature correspondences between a synthetic
image and its 90-degree rotation, followed by a matching geometric pose through
OpenCV's laboratory solver. These are Python/oracle results, not execution of the
Rust extractor or pose solver and not real-property accuracy evidence.

FAST methodology: https://www.edwardrosten.com/work/fast.html . The OpenCV code is
only invoked by the optional laboratory reference check, never by FSS production.
