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
