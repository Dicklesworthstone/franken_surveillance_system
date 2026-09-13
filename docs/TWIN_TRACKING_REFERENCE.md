# Contact-to-world motion over an imported property

Implemented reference portion of BTI-005, composed with BTI-001's `PropertyTwin`.
This is functional geometry code, not a detector, camera authorization service,
statistical calibration, continuous tracker, or completed field qualification.

## Source contact to terrain

`project_contact` consumes an immutable imported twin, owner-resolved camera snapshot,
source-bearing contact-pixel rectangle, capture interval and shared work budget.
The camera must match the property/revision, image domain, clock and validity interval.
Input pixels are already calibrated **undistorted pinhole pixel-edge** coordinates;
a detector or operator supplies a visible contact observation. An occluded foot or
unknown contact returns `ContactUnknown` with the original 2D observation, not an
invented location obtained from a detector box's bottom centre.

The kernel computes all centre-ray support intersections and, when error bounds are
known, interval intersections with every admitted support triangle. It accounts for
continuous pixel, optical-centre, rotation-entry, focal-length, principal-point, and
per-vertex coordinate errors. Outward arithmetic encloses finite IEEE-754 operation
results; plane intersection, axis slabs and oriented triangle-edge tests reject
only definitely inconsistent candidates. A grazing ray retains a bounded search-
volume alternative rather than pretending precise depth. Work and result limits
refuse the whole result instead of pruning a late protected hypothesis.

These are **conditional deterministic enclosures**, not probabilities. They assume
the supplied error bounds cover the actual camera and same-topology physical mesh.
They do not cover missing geometry, unknown topological changes, arbitrary lens
models, or undeclared deformation. Every result is restricted to the explicit
near/far search volume in **source units**, not automatically metres. No metric
speed or acceleration prior is injected into a relative-scale model.

Unknown map or calibration error yields `NominalOnly`, not zero error. A complete
interval result can contain hypotheses reached only by the error volume, with no
centre-ray hit. Multi-level terrain, steps and decks remain alternatives. A nominal
occlusion flag is retained as a conflict; it is not used to discard a possible
support under uncertain geometry and is not an effective-coverage certificate.

## Observed displacement and future motion

`fit_world_motion` derives position and finite-difference velocity alternatives from
two actual `ContactProjection`s. Every earlier/later support pairing survives unless
the whole pair set exceeds its limit. Shared map or camera errors are conservatively
enclosed, not treated as independent samples that shrink uncertainty.

Velocity uses capture-time intervals. Integer timestamp differences are computed
before conversion to seconds, so nanosecond epoch magnitudes do not cancel through
floating-point subtraction. Overlapping intervals, duplicate evidence or same-camera
exposures, changed image/calibration bases, and stale twins refuse the fit. Cross-
camera fitting requires a retained owner-supplied association-evidence reference;
this numerical layer cannot establish or authenticate identity from that reference.

`propagate_motion` preserves all modes and produces a separate prediction type that
cannot be passed back to the fitter as an observation. It widens position for timing
and explicit per-axis acceleration assumptions. A displacement/time fit is **average**
velocity, not endpoint velocity. For observation separation T and future interval t,
acceleration bound a adds a*(t² + t*T)/2 to positional uncertainty. Omitting the t*T
term would miss accelerated trajectories even when the declared bound is correct.
The acceleration bound must apply during both the observed pair and forecast.
Unknown incoming bounds stay unknown; nominal constant-velocity paths are labelled
separately. Propagation does not impose surface constraints or infer hostile intent.

## API and scope

The added library entrypoints are `project_contact`, `fit_world_motion`, and
`propagate_motion`. All are synchronous, bounded and cancellation-aware and execute
no I/O or effects. They reuse FSS geometry and source digests; caller-resolved u64
handles are not an alternative persistent ID or capability system. The application
must retain source records and canonical calibration/twin/clock identities, apply
capability/privacy filtering before supplying data, and authorize activation through
existing owners. No public fss/1 command is claimed by this reference library.

## Verification

```sh
cargo test --locked --offline -p fss-twin --test tracking_contract
python3 -B scripts/test_twin_tracking_reference.py
```

Ten Rust contracts cover actual triangle versus AABB support, multiple levels,
unknown contact/error, perturbed camera/terrain, capture uncertainty, acceleration,
duplicate exposures, stale modes, cross-camera association and large epoch values.
They have been authored but **not executed** in the compiler-less authoring container.

The Python arithmetic reference executed successfully: 4,000 interval-pair checks
against exact rational endpoint arithmetic, 10,000 independent perturbed-camera/
sloped-ground realizations, and 10,000 velocity/acceleration realizations. This checks
the mathematical approach, not Rust compilation, Rust test execution, the Blender
exporter, real detections, actual error calibration or a property release gate.
