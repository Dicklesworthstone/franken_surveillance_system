# An actual pretrained HOG candidate, explicitly selected

`fss_twin::pretrained_hog::load_opencv_people_candidate` loads the real OpenCV
HOGDescriptor default people-detector coefficients through the existing native
`HogModel` loader. It does not synthesize weights. All 3,781 F32LE parameters,
including the intercept, are shipped unchanged with their export provenance and
redistribution license inside `crates/fss-twin/models/opencv_people/`.

```rust,ignore
let model = fss_twin::pretrained_hog::load_opencv_people_candidate(&mut budget)?;
// Use the existing scan_hog or JpegHogPipeline with this explicitly selected model.
```

There is no OpenCV/Python runtime dependency, build script, external model server,
or download. The optional `scripts/export_opencv_people.py` is an offline lab
exporter: it requires an already installed pinned oracle, checks the full weight
hash, and refuses to overwrite its output. The model is NOT automatically selected
by the existing APIs and is NOT a canonical package activation or alert grant.

## Exact identity and source boundary

* Weights SHA-256: `cb2198952eaa5bc7e43d950b9f2aa1966528063c7295c7262133e7fa0d3d564c`.
* Export: `opencv-python 4.13.0.92`, `cv2.HOGDescriptor_getDefaultPeopleDetector`.
* Upstream reference: OpenCV commit `fe38fc608f6acb8b68953438a62305d8318f4fcd`,
  `modules/objdetect/src/hog.cpp` (the 4.13.0 release).

The retained record identifies the actual installed exporter binary. The upstream
reference is not a reproducible-build attestation. The loader verifies weights,
provenance, license and the exact current native feature recipe. Changing the
recipe requires a new candidate rather than silently reusing its identity. The
candidate binds the existing model/scan receipt chain; no alternative model
registry or independent source identity is invented.

This is a replay/shadow candidate toward comprehensive-plan sections 15 and 16,
not closure of their quality, immutable-package, activation or deployment gates.
The native grayscale recipe is not bit-identical to OpenCV. Its score is an SVM
margin, not a probability. The pedestrian class name describes the upstream model,
not proof that a particular selected window contains a person. Masked windows
remain unknown, low scores do not establish absence, and tracked window proposals
are not identities, threats, calibrated silhouettes or physical ground contacts.

## Checks and remaining work

The six Rust contracts exercise exact real assets, expected model identity,
nonconstant image-derived scores, native scanning, denied pixels, resource refusal
and corruption. Run:

```sh
cargo test -p fss-twin --test pretrained_hog_contract
```

These Rust tests were authored but not executed in the authoring environment:
no Rust toolchain was available. They must pass in the pinned Rust environment
before a green-build claim. No qualification gate is marked closed.

An independent Python scalar-recipe mirror was compared with the installed cv2
CPU implementation on 64 procedural 64x128 grayscale images. The maximum observed
absolute score difference was 0.0016209434588638771; the maximum observed descriptor
component difference was 0.00021825730800628662. Ten corresponding numeric examples
are retained in the Rust tests. These are supplementary arithmetic checks, NOT
Rust execution, a global error bound, a training-data audit, detector recall or
real-camera qualification. The offline lab script and full observations are in
`scripts/check_pretrained_hog_oracle.py` and
`crates/fss-twin/models/opencv_people/numeric_smoke.json`.

Real deployment still requires exact-mode held-out people/background clips,
small/partial/dark/crouched/crawling slices, privacy tests, threshold calibration,
false-alert evaluation, cost measurement and explicit owner activation. A
pretrained legacy candidate is not a substitute for a modern qualified detector.
