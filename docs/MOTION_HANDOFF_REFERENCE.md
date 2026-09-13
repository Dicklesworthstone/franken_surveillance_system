# Motion and camera-handoff reference kernels

Owning work: BTI-006 / BTI-007 in `BLENDER_TWIN_IMPLEMENTATION_TASKS.md`,
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
BTI-006/007 and FSS-099 acceptance gates are not closed by this reference slice.

## Visibility-aware next-camera handoff

`predict_camera_handoffs` consumes the retained motion forecast, its exact expected
basis, immutable `TriangleMesh`, an already authorized camera set, and an explicit
body/posture sample binding for **every** route. There is no default human body for
animal routes. The event definition is **first nominal geometry-eligible sampled
capture in a camera not already observing the track**. It is not detector success,
continuous physical visibility, identity association, or observed negative evidence.

The implementation checks each camera's own integer period/phase, snapshot validity,
image mode, known availability, normalized privacy exclusions, required visible
sample fraction, and pixel-extent floor. It projects the body's world-axis offsets,
rejects privacy-intersecting regions before mesh expansion, and performs opaque
segment queries using existing triangle geometry. Its image region encloses visible
probe points; sample counts remain explicit. This is a bounded body approximation,
not a proof that the complete body volume or silhouette is visible. The caller
selects posture/size variants; offsets do not automatically rotate at route turns.

A target can first become eligible by emerging from behind an occluder in the
middle of an image. A continuously visible crossing can also fall entirely between
captures. The kernel does not replace either case with a frustum-border crossing.
Equal first capture times preserve the complete simultaneous-camera group. Per-camera
first samples remain available even when another camera wins the next-camera race.
Capture order is independent of transport/processing arrival order; availability is
computed by checked addition of the supplied latency interval.

Unknown cameras and incompletely valid camera snapshots leave the first-event
answer indeterminate while retaining useful partial predictions. An unknown motion
tail does not become a stationary target: a first event established before the tail
can still be returned, but no event through a partial path is indeterminate. Known
unavailable and already-observing cameras remain explicit in the input-scope record.
`NoModeledObservation` is conditional on these inputs and the horizon. It never
provides a `CoverageWitness` or permission to suppress a threat.

Each route retains its original heuristic mass, protected flag, body generation,
and coupled camera/region/time outcome. No-observation and indeterminate alternatives
are not dropped or renormalized away. No public API or external effect is invoked.

Limits: 64 cameras, 64 distinct body samples per route, 64 privacy rectangles per
camera, and at most one million sampled evaluations per route/camera, further bounded
by the caller's shared work allowance. Exceeding a bound rejects the entire call,
not merely whichever high-loss route was processed last. No per-frame heap allocation
is needed for body projection. Mesh traversal is the scalar linear reference; no
performance or hardware-support claim is made.

This initial implementation uses fixed camera/clock and piecewise-linear trajectory
hypotheses. It does **not** propagate a continuous calibration/clock covariance,
unknown occluder geometry, or learned detector recall. Explicit alternative routes,
speeds, postures, and separate world scenarios are required where applicable. An
integer nominal timestamp is not a claim of nanosecond physical accuracy. Unknown
wake times must remain unknown, not invented periodic capture schedules.

`handoff_contract` adds interior-frame emergence, capture-versus-arrival order,
simultaneous cameras, route-tail handling, masks, sparse capture, unavailable and
unknown cameras, stale bases/validity, output bounds, cancellation, duplicate body
probes, and 49,600 exhaustive small capture-schedule comparisons.

```sh
cargo test --locked -p fss-geometry --test motion_contract --test handoff_contract
cargo clippy --locked -p fss-geometry --all-targets -- -D warnings
```

The independently executed Python arithmetic checks cover exact-rational motion,
class isolation, sampling schedules, analytic-versus-triangle occlusion, and the
synthetic first-capture examples. They are not execution of the Rust suite. The
accepted-toolchain build, full qualification, real recordings, automatic route
extraction, track fitting, continuous reachable envelope, and live Asupersync/agent
integration remain outstanding. This is an implemented reference portion of
BTI-006/BTI-007, not completion of BTI-008 or FSS-098/099.

## Executable two-route property example

The `predict_handoff` example constructs a synthetic Z-up support mesh, two
properly rotated downward-looking cameras, and two alternative routes from the
same initial contact position. A person profile favors the stone path 4:1 without
removing the protected grass route; a bear profile retains equal heuristic masses.
The two classes use explicitly different eight-point body samples. All camera,
region, and timing output comes from `forecast_routes` and
`predict_camera_handoffs`, not hard-coded output rows.

```sh
cargo run --locked --offline -p fss-geometry --example predict_handoff
python3 -B scripts/test_motion_handoff_replay.py
```

The Python driver runs the actual Rust executable twice, requires identical JSONL,
and checks four coupled route/class outcomes against a separate analytic camera
projection. The expected nominal captures occur at four seconds, with explicitly
supplied availability delays of 0.2-0.4 seconds. These are synthetic fixtures, not
measurements or predictions for any real property. The development-only replay
schema is not a replacement for the registered `fss/1` agent envelope.

No Rust executable was run in the authoring environment: the driver reports
`NOT_RUN` with a nonzero exit when Cargo is absent. Its Python validation functions
were checked independently against one valid analytic transcript and thirteen
corrupted transcripts; this verifies the checker, not the Rust implementation.
Neither the example nor a successful future fixture run qualifies a real detector,
camera, imported Blender package, or property. Recorded-camera integration remains
part of the broader open tasks.
