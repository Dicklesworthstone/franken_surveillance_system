# Native foreground trajectory replay

`ImageTracker::update_foreground` consumes actual `ForegroundReport` values from
native luma, rectification, or JPEG/foreground composition. It does not require a
mock model, semantic detector run, metric property twin, visible ground-contact
claim, or supplied track assignments. The existing retained-model
`fss_reference::ingest::tracking::LocalBoxTracker` is unchanged; this is the
foreground-candidate lane, not a replacement canonical track authority.

## Library use

Create `fss_twin::image_tracking::ImageTracker` with an explicit episode digest,
`ImageTrackingPolicy`, and a `WorkBudget`. For each ordered source exposure:

```rust,ignore
let foreground = background.detect(&frame, foreground_policy, &mut budget)?;
let update = tracker.update_foreground(&foreground, &mut budget)?;
// Retain foreground and update together under the source's privacy policy.
// Inspect update.decisions(), update.candidates(), and tracker.tracks().
```

For an existing `RectifiedForeground`, pass `rectified.report()` directly. The
complete input report binds original source/capture identities, frozen baseline,
permission mask, pixel labels, size omissions and disturbance assessment. Each
component gets a distinct report-bound record digest. A crop is not a new source.

## Operator replay

```sh
cargo run -p fss-twin --example foreground_frames -- /absolute/path/manifest.txt
```

Legacy `FSS_FOREGROUND_FRAMES_1` manifests and foreground-only output are unchanged.
To opt into trajectories, change the first line to `FSS_FOREGROUND_TRACKING_1` and
add these **required** settings to the existing 15 foreground settings:

```text
tracking_episode=<nonzero lowercase SHA-256 of the explicit episode record>
tracking_maximum_tracks=32
tracking_maximum_detections=32
tracking_maximum_exposures=128
tracking_minimum_observations=3
tracking_maximum_misses=5
tracking_maximum_gap_ns=2000000000
tracking_maximum_speed=500
tracking_gate_padding=4
tracking_miss_cost=2000
tracking_ambiguity_margin=10
```

These are illustrative assumptions, not calibrated surveillance defaults. Speeds
are conditional per-axis pixels/second; costs are doubled-pixel L1 distances.
Frames are decoded, tightly packed full-range pinhole luma, with a separate 0/1
permission mask. Retain the existing row format:

```text
reference EXPOSURE_SHA EARLIEST_NS LATEST_NS PIXEL_PATH PIXEL_SHA MASK_PATH MASK_SHA
query EXPOSURE_SHA EARLIEST_NS LATEST_NS PIXEL_PATH PIXEL_SHA MASK_PATH MASK_SHA
```

Use 3..31 ordered disjoint reference exposures followed by queries (at most 128
rows total). File paths must stay under the manifest directory; byte lengths and
SHA-256 digests must match. Capture intervals are source times, not receive times.
Unknown settings, partial configuration, changed basis/masks, replayed exposures,
overlapping query intervals, capacity exhaustion and work exhaustion fail instead
of silently changing policy or truncating the scene.

The command emits the original `frame` JSON and an additional `tracking` JSON
record per query: source/report chain, availability, every candidate cost and
ambiguity flag, every detection disposition, current observed/coasting paths and
explicit expiries. Bounds on coasting paths remain the last **observed** bounds.
Only a terminal `complete` record signifies that all requested rows completed;
a failed run can leave an explicitly incomplete output prefix.

## Semantics and limits

Global assignment includes misses. For each selected edge, excluding that edge
and solving again establishes whether an alternative is within the explicit
ambiguity margin. Ambiguous edges do not update trajectories. Every candidate is
retained; unresolved proposals are not forced into new identities. A detection
with any admissible old-path candidate does not start a new path, even when the
objective prefers a miss. Crowded scenes can therefore remain unresolved.

Exact-time, non-partial observations support integer constant-velocity **ranking**.
Uncertain capture intervals use last-observation ranking; their midpoints are not
invented timestamps. Speed gates use the full capture intervals and do not exclude
partial silhouettes by center motion. None of these scores is a calibrated
probability, covariance estimate, cross-camera association or physical identity.

Widespread change and no-comparable-pixel reports cannot supply measurements or
births. Empty available reports do not prove a clear scene. A frozen background
does not learn stopped foreground away. Sensor health, calibration admission,
semantic classification, corroboration and alert authority remain separate.

The engine is synchronous safe Rust, with no I/O, dependencies, runtime acquisition,
threads or hidden clock. Updates are atomic under cancellation/budget failure.
State is bounded to 64 tracks, 64 detections and 4096 source exposures per explicit
episode, with no silent eviction. These local receipt digests are not ledger
anchors or registered durable publications. Restart recovery requires replaying
the retained ordered inputs with the same episode/policies; no checkpoint is added.

## Validation targets

```sh
cargo test -p fss-twin image_tracking::tests
cargo test -p fss-twin --test image_foreground_tracking
cargo test -p fss-twin --example foreground_frames
```

The unit suite covers assignment/edge-exclusion oracles, crossings, ambiguity,
misses, timing, partial boxes, generation/privacy drift, replay and atomic limits.
Pixel-level integration covers moving and stopped components, merges, broad scene
change, unavailable pixels, omitted components and reacquisition. These are
algorithmic fixtures, not claims of real-camera or event-quality qualification.
