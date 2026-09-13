# Motion and camera-handoff reference kernels

Owning work: BTI-07 / BTI-08 in `BLENDER_TWIN_IMPLEMENTATION_TASKS.md`,
under WP-130 and the Blender twin integration plan. These broad tasks remain open.

## Conditional route motion

`fss_geometry::forecast_routes` time-parameterizes supplied property-world route
candidates into bounded piecewise-linear paths. It supports explicit initial
pauses, turns, different speeds as separate alternatives, terminal stopping, and
unknown tails. Speeds use property units/second: a relative-scale twin must not
silently receive meter-based movement priors.

The retained class mixture is [person, bear, other animal, unknown]. Only the
person component receives the explicitly selected pedestrian-path multiplier.
Off-path/protected routes remain present even when their heuristic mass is low.
These are unnormalized heuristic weights, not calibrated probabilities or hostile
intent. The caller must supply appropriate route geometry, dynamics, and variants;
this kernel does not discover a path network, infer class, or turn material names
into traversability. Unknown future motion is never automatically frozen.

Inputs pin owner-resolved property/twin, clock, anonymous track/revision, and
motion-generation handles. They do not authenticate the owner or confer effect
authority. The owner retains canonical input/source identities and resolves these
process-local handles. No geometry, camera, model, filesystem, or network is
mutated. All outputs are predictions, never new observations.

Limits are 64 routes, 256 points/route, and a one-hour horizon. Overflows and
budget exhaustion fail the complete operation instead of silently pruning routes.
The work counter and optional owner cancellation flag bound synchronous work;
no runtime or thread is introduced. Floating arithmetic is reference arithmetic,
not a claim of cross-platform bit identity. Times are rounded upward to integer
nanoseconds before bounded interpolation.

## Verification boundary

`motion_contract` covers pauses/turns/stops, unknown tails, class isolation,
protected alternatives, deterministic route ordering, clipping, degenerate and
malformed suffixes, resource bounds, cancellation, and timestamp overflow.

Run `cargo test --locked -p fss-geometry --test motion_contract` on the accepted
repository toolchain. Rust execution is not claimed from source presence: the
authoring environment has no Rust compiler. Real-property, runtime, clock-error,
model-quality, and cross-camera qualification remain outstanding. The broad
BTI-07/08 and FSS-099 acceptance gates are not closed by this reference slice.
