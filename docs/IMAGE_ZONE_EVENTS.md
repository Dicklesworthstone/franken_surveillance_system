# Source-linked image-zone events

`fss_twin::image_zones` connects the existing anonymous image trajectories to
owner-selected image polygons. `ImageZoneMonitor` derives first-seen occupancy,
entry/exit between observed sides, sampled dwell, interruptions, and explicit
trajectory retirement. It does not require a metric twin or a semantic detector
run. It does not classify a person, infer intent, certify continuous occupancy,
publish canonical event revisions, or dispatch alerts.

This is a reference implementation slice toward the perception/event connection
in comprehensive-plan sections 16–17 and WP-090 (`fss-x4a.15`). It does not close
that work package or the geometric coverage contract. Image polygons are not
CoverageWitness values, metric property boundaries, or evidence of absence.

## Native processing and retry

For an existing `ImageTracker`, construct `ImageZoneMonitor::new` at its exact
current position, before consuming the next exposure. Supply the camera, capture
clock, calibration, image-domain digest and dimensions; an explicit selection
record and sample-gap policy; and the complete polygon set. Then pass each opaque
`ImageTrackingReport` and the unchanged current tracker to `observe`. Skipped
reports, stale trackers and coordinate-basis mismatches are refused. An exact
retry returns the same report and event identities without accumulating time.
Attaching to a tracker midway begins new zone history, not retroactive events.

For exclusive ownership and resumable stage completion, use
`image_zones::pipeline::ImageZonePipeline`. This owns the existing tracker and its
zone monitor; it does not implement a second association algorithm.

```rust,ignore
let mut pipeline = ImageZonePipeline::new(
    episode, tracking_policy, zone_basis, zone_policy, &zones, &mut budget,
)?;
let progress = pipeline.observe_foreground(&foreground, &mut budget)?;
match progress {
    ZonePipelineProgress::Complete { .. } => {
        // Retain foreground, tracking_report(), and zone_report() together.
    }
    ZonePipelineProgress::Pending { error, .. } => {
        // Tracking already consumed this exposure. Retain tracking_report().
        // Resume only the zone stage with a renewed owner budget:
        let progress = pipeline.resume(&mut renewed_budget)?;
        // Inspect again; Pending must not be treated as completed analysis.
    }
}
```

`observe_foreground` consumes the actual opaque `ForegroundReport`, including its
native component records and detector/background/permission generations. An outer
error means it did not consume a new tracking observation. `Pending` instead means
the upstream observation was accepted and retained: the next exposure is blocked
until `resume` succeeds. While pending, `zone_report()` returns `None`, not a stale
previous result. `tracking_report()` and `foreground_digest()` still identify the
accepted input. The caller retains source media and foreground evidence; the
pipeline does not claim persistent custody or create a checkpoint file.

`analyze_luma` composes raw-plane validation/rectification and the existing frozen
background. `analyze_jpeg` uses the existing native JPEG decoder, explicit encoded
source binding, coded-grid permission mask and decoder limits. Their outer errors
occur before tracking. Successful image outputs retain actual decoded pixels,
masks and source receipts even when the downstream stage refuses. Inspect the
returned `progress()` to distinguish complete, accepted-but-pending, and
not-consumed outcomes. These functions perform no camera/network acquisition.
The immutable `tracker()` plus `tracking_report()` can also feed the existing
conditional image-motion estimator; motion is never a zone observation.

## Whole-box geometry and event meaning

A zone is a strictly convex polygon with integer pixel-edge coordinates. Either
winding and any cyclic vertex start normalize to the same configuration identity.
Duplicate IDs, repeated/collinear vertices, concavity, self-intersection, out-of-
image coordinates and invalid time bounds fail before activation. Nonconvex
regions can be represented by separately named convex zones; they are not silently
approximated by a hull.

Classification uses the complete observed rectangle, expanded by an explicit
L-infinity pixel margin. Exact integer separating-axis tests include both polygon
edge normals and the rectangle axes. `Inside` requires strict containment;
`Outside` requires strict separation. Contact with the boundary or its margin is
`Boundary`, never rounded into a definite side. Incomplete silhouettes are
`Partial`; a component bottom or centroid is not fabricated into ground contact.

`ObservedInside` is a first definite inside sighting, including after lost
observability. It is not an entry claim. `EnteredBetweenObservations` and
`LeftBetweenObservations` retain actual source endpoints on opposite definite
sides of the same anonymous trajectory. Observed boundary samples can connect
those endpoints, but no exact crossing instant or continuous path is asserted.

`SampledDwell` is emitted once per uninterrupted sequence of inside samples when
at least two actual sightings span the configured lower time threshold. For first
capture interval `[a,b]` and latest interval `[c,d]`, its sampled duration interval
is `[max(0,c-b), max(0,d-a)]`. The first sample alone has span `[0,0]`. The **lower**
span must meet the dwell threshold; interval midpoints are never invented.
This is not proof the trajectory remained inside between samples.

Boundary observations reset the inside-sample run. Missing/ambiguous assignments,
partial silhouettes, broad camera/scene disturbances and unavailable frames reset
both dwell and usable side continuity. The maximum allowed sample gap is tested
against the **upper** possible elapsed time, not its midpoint or minimum. These
interruptions cannot become exits, continuous sightings or dwell. Track expiry is
`TrackExpired`, with the last actual sighting, not physical departure.

Every report retains all active and explicitly expired track/zone cells and all
resulting events. Cells explicitly distinguish `Inside`, `Outside`, `Boundary`,
`Partial`, `Unobserved`, `Unobservable`, `Disturbed`, and `Expired`. Each carries the
last actual observation. Consumers must check relation before treating it as a
current sighting. Empty cells/events never imply an empty or safe physical scene.

## Operator replay

The existing command remains:

```sh
cargo run -p fss-twin --example foreground_frames -- /absolute/path/manifest.txt
```

Both `FSS_FOREGROUND_FRAMES_1` and `FSS_FOREGROUND_TRACKING_1` are unchanged.
To enable zone processing, use `FSS_FOREGROUND_ZONES_1`. Keep all 15 foreground
settings and all 11 tracking settings described in `FOREGROUND_TRACKING.md`, then
add exactly these three settings:

```text
zone_selection_evidence=<nonzero lowercase SHA-256 of the owner selection record>
zone_maximum_sample_gap_ns=3000000000
zones=1 2 10000000000 20,1 60,1 60,30 20,30;2 0 off 1,1 10,1 1,10
```

The zone grammar is `ID MARGIN DWELL_NS|off x,y x,y x,y [x,y ...]`. Separate zones
with semicolons, not repeated setting keys. All vertices must fit the configured
image dimensions. The example values are illustrative owner assumptions, not
calibrated security defaults. `off` disables dwell while retaining other events.
A trailing semicolon, incomplete settings, malformed polygon or oversized zone
set is an error, not a partial configuration.

Frame rows and confined input-file/digest validation are unchanged:

```text
reference EXPOSURE_SHA EARLIEST_NS LATEST_NS PIXEL_PATH PIXEL_SHA MASK_PATH MASK_SHA
query EXPOSURE_SHA EARLIEST_NS LATEST_NS PIXEL_PATH PIXEL_SHA MASK_PATH MASK_SHA
```

The command emits `zone_configuration`, the existing `frame` and `tracking`
records, and a `zones` record for each accepted query. Configuration retains the
canonicalized polygons and selection/basis identity. Zone output includes complete
cells, events, sampled spans, counts, source endpoints and current availability.
If zone processing fails after tracking, the command emits `zone_incomplete` with
the accepted tracking identity, flushes the output prefix, and exits nonzero.
It does not consume another exposure or emit `complete`. A terminal `complete`
record means every requested replay row finished, not a production qualification.

## Bounds, authority and validation

The complete set is bounded to 16 zones of at most 32 vertices, over the existing
64-track/64-detection and 4096-exposure tracker ceilings. Classification and result
hashing use the owner's deterministic work budget and cooperative cancellation.
Zone mutations are staged and committed only after successful full encoding;
refused work does not advance the monitor. The pipeline deliberately distinguishes
this from an upstream tracker that already committed before the zone stage failed.

Everything is synchronous safe Rust with no additional dependency, global state,
thread, runtime acquisition, clock read or external effect. Reference fingerprints
are not registered durable schemas, ledger anchors, source-custody proofs or
capability grants. Results remain privacy-scoped derived cognition. Model
classification, sensor-health admission, independent corroboration, canonical
event publication and capability-scoped alert delivery remain separate work.

Targeted checks:

```sh
cargo test -p fss-twin image_zones::tests
cargo test -p fss-twin --test image_zone_pipeline_contract
cargo test -p fss-twin --example foreground_frames
```

The tests cover integer geometry, actual image tracking, uncertain capture
intervals, entry/dwell/exit, missing/partial/ambiguous/disturbed observations,
canonical configuration, exact retries, all work-budget cut points, cancellation,
source/permission drift, raw luma and native JPEG, retained accepted receipts,
operator parsing and complete output. Rust compilation and execution were not
available in the authoring sandbox. An independent Python/Shapely comparison of
40,000 polygon/rectangle cases passed, but is not a Rust build or real-camera
qualification claim. No program bead or release gate is closed by this slice.
