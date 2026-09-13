# Native source-image foreground candidates

`fss_twin::foreground` implements an image-derived candidate stage for WP-090,
upstream of the property tracker and association system. It compares actual,
verified grayscale pixels rather than accepting hand-authored bounding boxes.
It is not a semantic person/animal detector, contact estimator, decoder, track
identity service or threat decision. The broader tracking/video gates stay open.

## Frozen reference instead of automatic absorption

`BackgroundModel::build` accepts 3-31 owner-selected, temporally disjoint reference
exposures from one exact camera/calibration/image/clock mode. Selection evidence,
reference identities, masks and a finite validity interval are mandatory. A pixel
is comparable only when every reference permits it and their intensity range is
within the supplied stability threshold. Variable foliage and private/unlearned
pixels remain unknown. A newly unmasked pixel is not silently treated as background.
The owner must have a valid reason to select the references; this code does not
establish that those images contain no people, animals or consequential objects.

The model stores a frozen lower/upper luma envelope. Detection cannot update it,
so an object that enters and stops is not gradually learned away. Rebaselining is
an explicit new model with its own source selection. Validity, camera movement,
lighting-mode and calibration changes require owner admission/invalidation; a hash
or a matching camera label is not proof that the scene physically stayed unchanged.

## Actual pixels to complete components

`detect` computes positive and negative differences outside that envelope. Pixels
are classified as unavailable, within threshold, darker or brighter. Both change
polarities participate in four-connected region extraction; diagonals alone do
not connect. Each retained region has its exact changed-pixel count, component
membership, crop rectangle, polarity counts and unknown/image-edge flags. These
are image components, not complete body silhouettes.

Minimum-area filtering retains omitted counts AND all raw component labels. A
small intrusion must not turn into a claim of no appearance change. A complete
region-count overflow rejects the operation instead of returning a top-k prefix.
Widespread change is flagged separately while preserving regions: global lighting,
a bumped camera, a lens obstruction and a large foreground object are not silently
collapsed into a harmless lighting correction. An empty result is never a
CoverageWitness, observed absence, or permission to disable other detection work.

All pixels are tightly packed, full-range 8-bit grayscale in an explicit pixel-edge
image domain. Digests bind source/exposure, capture interval, calibration, masks,
model, policy and complete classification/label maps. The local fingerprint is
not a newly registered canonical durable format. Source custody, privacy projection,
retention/deletion and activation remain with existing owners. Debug views omit
pixel arrays. The detector reads no image intensity behind a denied pixel mask;
whole-input hashing still covers exact source bytes supplied by the authorized owner.

Bounds: 4096 pixels per axis, at most 4,194,304 pixels, 31 references and 4096 retained
regions. Work and allocation bounds apply before growth; cancellation and failure
publish nothing. The scalar reference is linear in image pixels for detection and
linear in reference-count times pixels for model compilation. No performance claim
is made. No I/O, thread, foreign process, model download or new dependency is added.

## Verification

```
cargo test --locked --offline -p fss-twin --test foreground_contract
python3 -B scripts/test_foreground_reference.py
```

Fourteen Rust contracts cover exact component occupancy, stopped objects, unknown
and masked regions, diagonal connectivity, raw small-change retention, broad-change
reporting, strict thresholds, source aliases, camera/calibration/time changes,
malformed bytes, complete-output failure, cancellation and reproducible fingerprints.
One compares all 512 binary 3x3 images to an independent transitive-closure oracle.

Seven Python reference tests have executed successfully, including an independent
set-union component oracle and separately constructed source/model/report goldens.
The 6x5 fixture's model digest is
`e0b90edeef92b0c70bdf95843a8f07803a66afb3bcee665ac9e4fabec28e27a2`;
its report digest is
`3eda58e97b8b3a7e1bc339632f41ee7c7b70bbb01fac1952ba2634c54f266c7c`.
These are synthetic arithmetic/wire controls, not execution of Rust. No Rust
compiler is available in this authoring environment. Native tests, field accuracy,
false-positive/false-negative calibration and full video integration remain NOT_RUN.
The method can miss camouflaged objects or objects already in the references and
can propose shadows/weather/reflections as foreground; later evidence is required.

## Decoded-frame and model-crop composition

`foreground::pipeline::RectifiedBackground` retains the existing native rectifier's
original source receipts as well as the frozen background. Its `detect_luma` path
accepts a `RawGrayFrame`, the exact admitted `RectificationPlan`, capture metadata
and foreground policy. It executes native lens/range/stride correction and actual
pixel comparison together, returning the corrected frame and full foreground report.
No supplied bounding boxes or query-to-target associations enter that operation.
The same path works for decoded recorded or live frames; it does not itself decode
compressed video, open a device, or schedule a service.

`RectifiedForeground::crop` prepares exact bounded context crops for the next model
stage. It returns full-range pixels, a current allowed mask, and a separate exact
component-membership mask. Pixels behind privacy exclusions remain zero AND denied.
Permitted pixels whose BACKGROUND is unknown can still be useful model context, so
background uncertainty is not incorrectly used as a privacy mask. Crop origin and
shape give an exact translation back to the full undistorted pixel-edge image.
All masks, source exposure, foreground report and crop contents remain linked.

`ForegroundCrop::prepare_contact` accepts an explicit external contact-model or
annotation record, its crop-local coordinate interval, and its visible-contact
claim. It checks coordinates and the entire selected mask rectangle, requires
intersection with the selected component, translates the coordinates, and prepares
the existing `UnassignedContact` payload. The attached preparation record retains
full-image source/capture, report and crop identities. A record hash is not proof
that contact is actually visible; this stage cannot authenticate or independently
qualify the upstream model. It never infers feet from the bottom of a change blob.
A genuine contact outside the changed component needs a separate supported proposal
rather than being silently reassigned here. Components touching unknown/image edges
retain that warning in their source report.

These are unassigned contact PROPOSALS, not track mutations. The owner must resolve
content identities into the existing admitted camera/image handles, preserve the
contact record, and use the existing association/adjudication path. The method has
no default visible-contact flag, model class, walking-speed prior or threat policy.
Crops with two objects and merged blobs still need the upstream model to distinguish
them; a foreground component is not a one-to-one physical-target guarantee.

## Read-only file replay

The `foreground_frames` example consumes a bounded manifest and actual decoded,
full-range, already-pinhole `.gray` frames. It uses the numerical detector directly;
for raw distorted frames use the composed `RectifiedBackground` library interface.
The manifest is an owner-run development harness, not a new registered fss/1 API.
All pixel/mask paths are confined beneath the manifest directory and checked against
independently supplied SHA-256 values. No file is modified or uploaded.

First line: `FSS_FOREGROUND_FRAMES_1`. Required `key=value` settings are `width`,
`height`, `camera`, `clock`, `calibration`, `image_domain`, `valid_from`, `valid_until`,
`selection_evidence`, `maximum_spread`, `minimum_change`, `minimum_area`,
`maximum_regions`, `widespread_per_mille`, and `work_units`. Hash settings are nonzero
64-character lowercase SHA-256. Camera/clock are owner-resolved nonzero integers;
validity/capture values are integer nanoseconds on that declared clock. Other values
are the explicitly documented detector bounds, not inferred settings for a camera.

Frame rows are eight whitespace-separated fields:

```
reference|query exposure_sha256 earliest_ns latest_ns pixels_path pixels_sha256 mask_path mask_sha256
```

Require 3-31 reference rows before queries, at least one query, and at most 128 total
frame rows. Paths cannot contain whitespace or escape through symlinks. Arrays must
have exactly width*height bytes; masks contain 0/1. Comments begin with `#`. The
64-KiB manifest and every input file have explicit read bounds. A query prints its
actual report identity and component geometry only after that frame succeeds. A
later bad frame makes the process fail; a `complete` record appears only after all
queries succeed. This completion means replay completion, not qualified surveillance.

```
cargo run --locked --offline -p fss-twin --example foreground_frames -- /private/property/frames.txt
cargo test --locked --offline -p fss-twin --test foreground_pipeline_contract
python3 -B scripts/test_foreground_frames.py
```

The replay driver creates real synthetic files and executes the Rust example twice,
checks the independent report golden, stopped foreground, complete masks, and a
corrupted final input without a false completion record. Missing Cargo returns
`NOT_RUN` with exit code 3; it never prints a substituted successful Rust transcript.
In this authoring environment the driver actually returned NOT_RUN for that reason.
Six additional authored Rust integration tests exercise the actual rectifier-to-
region-to-crop/contact composition, mask holes, unknown context, stale generations,
video-range/padded input and cancelled/invalid crops. Together there are twenty
new Rust contracts; they have not executed. Native compilation, semantic detection,
contact quality, real surveillance footage and runtime qualification remain open.
