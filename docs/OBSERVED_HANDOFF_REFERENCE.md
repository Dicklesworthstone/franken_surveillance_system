# Observations to property routes and predicted camera acquisitions

`fss_twin::observed_handoff::forecast_to_feature` composes the imported property,
compiled support network, an exact active `ContactTrack` snapshot, native motion
forecasting and sampled camera visibility. It takes a destination/class/posture
hypothesis, not hand-authored route waypoints or a prescribed walking speed.
This is an implemented synchronous BTI-005/006/007/008 integration slice, not an
always-on video service, a threat classifier or a completed release gate.

## Source-driven composition

For every retained observed support-pair mode, the operation uses its nominal
contact and finite-difference speed. It queries the actual exact-edge support
network for a destination corridor. With a pedestrian cost preference, it also
queries the same network without that preference and protects this alternative.
A separate full-stop branch is retained. Bear, other-animal and unknown profiles
do not inherit the pedestrian preference. The native navigation result determines
which faces/portals a route crosses; display material names do not supply paths.

Average observed speed is not measured endpoint velocity. An explicit speed
multiplier and initial-pause hypothesis remain in the output. Initial-direction
compatibility is reported as a cosine diagnostic, not inferred intent or a
calibrated route likelihood. Destination identity, profile, body generation, tail
behavior and full numerical policy are retained. Choosing a destination is still
an upstream hypothesis, not an automatic claim about where somebody intends to go.

If a mode has no nominal support/velocity, conflicts with nominal occlusion, has
unusable speed, or cannot supply a valid support simplex, its unresolved assessment
survives. Navigation non-route outcomes also survive. These are not evidence that
a physical route is impossible. Zero source displacement cannot silently become
an assumed human walking speed. A stopping alternative is a prediction, not an
observation that motion ceased.

The generated routes feed the existing `forecast_routes` and
`predict_camera_handoffs` implementations. Each camera must match the session's
frozen pose, lens, geometry, image domain and clock. Requested validity is intersected
with admitted calibration validity; a caller cannot extend calibration by giving a
longer forecast interval. The latest observing camera is automatically excluded
from next-new-camera outcomes, while additional observing flags are preserved.
Privacy masks, sampling, latency, health and pixel-extent checks remain active.

The output retains coupled route/camera/image-region/capture/availability outcomes,
complete source-mode assessments, original source observations and the exact session
receipt. `unmodeled_routes` explicitly counts assessments with no nominal trajectory.
The inner motion/handoff total is over modeled branches only: do not normalize it
into a complete distribution that discards the unresolved assessments. All modeled
branches have heuristic mass one; a route preference already used in graph selection
is not counted again as independent probability evidence.

## Uncertainty, alternatives and validity

`reachable` independently propagates ALL source motion modes over the interval from
the latest possible source capture to the forecast end, using declared per-axis
acceleration bounds. These enclosures preserve unknown bounds and are not clipped
to a convenient path or obstacle model. They are conditional on the supplied map,
calibration and acceleration assumptions, not unconditional physical guarantees.
The original capture interval is retained; nominal camera sampling uses its midpoint.

These boxes do not become the pixel/time intervals of the nominal route solver.
Sharp piecewise-linear route turns are timing sketches, not acceleration-certified
motion. Unknown topology, unmodeled destinations and unconstrained future direction
remain outside a finite route enumeration. The separate enclosures/assessments must
travel with the camera predictions; extracting only the most attractive next-camera
row would lose consequential alternatives. No forecast supplies negative-evidence,
identity-association or effect authority.

`check_source_current` checks the full source receipt (including epoch/revision) and
twin digest against an active snapshot. It checks source freshness only, not current
health, privacy, body or motion-policy validity. The owner must revalidate those
before acting. Invalidated sessions cannot issue active snapshots. The owner maps
these process-local handles/results into the existing persistent fss/1 vocabulary;
this API does not invent a public command, calibration activation or durable store.

## API composition

After obtaining admitted twin, cameras, observations and hypothesis inputs:

```rust
let update = track.ingest(&twin, observation, association, &mut budget)?;
let snapshot = track.snapshot(track.revision())?;
let forecast = forecast_to_feature(
    &twin, &network, snapshot, destination, &handoff_cameras, options, &mut budget,
)?;
```

An exact retry's `update.receipt.revision` can be older than the active track. Use
its `replayed` flag for acknowledgement handling; do not roll back the source state
or pass the old revision as though it were current. Missing current pair motion is
`MotionUnavailable`, not a successful empty observation forecast. All resource
failures reject the whole operation instead of pruning late protected routes.

## Tests and evidence boundary

`cargo test --locked --offline -p fss-twin --test stream_contract --test observed_handoff_contract`
contains twenty authored Rust contracts across the two modules. The composed tests
build an independently encoded property with a grass shortcut and stone-path detour,
feed source contact observations, derive distinct network routes, and inspect actual
handoff results. They cover measured-speed changes, class isolation, stopping,
lost contact, stale source/camera state, validity clamping, cancellation and complete
alternative limits. The source revision does not claim these tests have executed.

`python3 -B scripts/test_observed_handoff_reference.py` executed four independent
fixture controls successfully: route selection, analytic source projection,
stopping visibility, and first sampled camera acquisition. At source speeds 0.3
and 0.6 units/second, the fixture reaches its second camera at 12.8 and 6.4 seconds
after the latest nominal observation. Its source observation is at two seconds,
so the Rust contracts expect capture timestamps 14.8 and 8.4 seconds. These are
synthetic fixture results, not measurements of a real property or Rust execution.

No Rust compiler is available in the authoring environment, and network DNS failed
when attempting installation. Native compilation/tests, real recorded-camera replay,
video decoding, detector/contact extraction, multi-target association, covariance-
aware camera-region forecasts, persistent publication and Asupersync service wiring
remain outstanding. No private footage or skill implementation was published.
