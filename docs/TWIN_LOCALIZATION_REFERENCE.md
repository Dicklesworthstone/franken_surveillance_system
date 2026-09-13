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
