# Digital twin, registration, and calibration shuttle

## 1. Objective

Import or construct an uncertainty-aware model of the protected property, with metric
claims only where scale evidence supports them. The model answers:

- where each camera is and what it can currently see;
- which zones overlap and which are blind;
- how long movement between views should take;
- where an observation projects in 3D;
- whether a track can plausibly be the same entity across cameras;
- whether a camera has moved, changed crop/zoom, or drifted;
- what additional drone/static view would reduce uncertainty most;
- which camera is likely to observe a target next, in which image region, and when;
- which class-conditioned routes and protected alternatives remain possible.

A beautiful 3D rendering is not enough. The deliverable is a **calibration certificate** with
residuals, covariance, coverage, evidence, validity, and invalidators.

## 2. Canonical versus derived twin

Canonical geometry records (provenance and accepted state, not infallible physical truth):

- coordinate-frame graph;
- camera intrinsics/distortion/crop/rolling-shutter model;
- camera extrinsics with covariance;
- clock offsets/drift with uncertainty;
- metric scale anchors;
- static mesh/point/occupancy representation with confidence;
- semantic zones and protected boundaries;
- visibility/occlusion and coverage cells;
- calibration observations and residuals.

Derived visualization:

- textured mesh;
- NeRF;
- Gaussian splat;
- floor plan;
- heat map;
- cinematic fly-through.

Derived renderings can be rebuilt or replaced and are never the sole source for security geometry.

### 2.1 Existing Blender twin installation route

The detailed normative companion is
[`BLENDER_TWIN_INTEGRATION_PLAN.md`](BLENDER_TWIN_INTEGRATION_PLAN.md).
Its execution crosswalk is
[`docs/BLENDER_TWIN_IMPLEMENTATION_TASKS.md`](docs/BLENDER_TWIN_IMPLEMENTATION_TASKS.md).
Importing an existing model is a first-class alternative to reconstructing the
property again. Static registration does not require simultaneous drone and
surveillance recordings, overlapping surveillance views, or seeing the physical
camera in the source footage. It requires adequately supported, unchanged common
landmarks. Time alignment remains necessary for moving-target fusion.

The owner-operated authoring environment exports evaluated geometry, semantic
feature identities, coordinate/scale evidence, and a visual localization atlas.
FSS imports immutable neutral data and compiles native geometry and graph objects.
Blender, Python, external reconstruction tools, and private skill code are not
shipping FSS dependencies or live fallbacks. Initial native import does not parse
a raw `.blend`; the export bridge runs separately at content-authoring time.

Preserve original scene/index/member hashes and explicit normalization of legacy
index/manifest and v2 scene-transport formats. Export actual evaluated triangles
and instance transforms, not just origins, dimensions, or geometry fingerprints.
Keep current structure, historical alternatives, construction helpers, reference
planes, apertures, and privacy masks distinct. Preserve feature identity through
mesh merging, instancing, simplification, and derived spatial indexes.

Compile separate visual, geometric, and behavioral representations in one frame.
Terrain, stairs, ramps, decks, paths, grass, fences, gates, and uncertain occluders
need explicit roles. Passage and visibility differ; material alpha or a bounding
box is not an adequate optical or contact model. Scale may remain relative with
honest use limits; metric priors require a supported conversion and uncertainty.

### 2.2 Automatic surveillance-camera localization

Build/reuse real reference-image poses and stable landmark tracks. Each landmark
and observation binds its source image, actual PTS/time base, lens/image domain,
map frame, feature identity, uncertainty, and correlation group. Synthetic views
with depth/feature IDs and architectural point/line matches may propose additional
correspondences; a model rendering cannot verify its own physical accuracy.

Solve the missing 2D-to-3D camera-pose problem with robust PnP and checked bounded
refinement. The existing 3D-to-3D extrinsics alignment is not a substitute. Freeze
the imported scene while solving cameras; retain alternative poses for repetitive
structure, weak support, or planar ambiguity. Lens distortion, crop, stabilization,
zoom, virtual camera mappings, and raw/display pixel conventions are explicit.

For world-to-camera `Xc = R Xw + t`, camera center is `C = -R^T t`. Test known
asymmetric landmark projections and optical-axis/right/up controls independently;
a round trip can preserve the same conversion mistake. Shared map and scale error
must not shrink away by counting correlated landmarks as independent evidence.

Validate on excluded physical landmarks, broad image/depth support, and relevant
path/occlusion boundaries before preparing activation. Emit pose, image-mode,
scale, uncertainty, support, validation, and invalidation bindings. An unobservable
camera remains unregistered or multimodal; targeted correspondence/capture help
must be disclosed rather than disguised as successful automatic registration.

## 3. Optional calibration shuttle

When additional capture is needed, the homeowner manually pilots a lightweight drone through the property while fixed cameras record.
The drone is not asked to fly autonomously. It acts as a moving calibration object and mapping
camera.

### Recommended marker payload

A light, flight-safe marker may provide:

- known printed/fiducial geometry visible from multiple angles;
- a high-contrast LED pattern with a pseudorandom time code;
- optional audible chirp where recording/consent permits;
- known dimensions and attachment transform relative to the drone camera/body;
- no network transmitter or active access to the fixed cameras.

The temporal code helps estimate per-camera delay and frame timing. The known geometry supplies
scale and 2D–3D correspondences. Flight safety and payload limits are hard constraints; a handheld
calibration wand is an alternative when a marker cannot safely be flown.

### Session sequence

1. Survey safe flight volume, people/animals, reflective hazards, wind, and local constraints.
2. Freeze camera modes, privacy masks, and time-sync configuration for a session generation.
3. Place several static scale/fiducial anchors visible to drone footage and/or fixed cameras.
4. Begin all fixed-camera streams and record continuity/time evidence.
5. Start drone recording and telemetry export where officially available.
6. Perform slow passes through each field of view, overlap zones, occlusion boundaries, and
   protected-volume edges.
7. Include deliberate stationary hovers and repeated loops for observability.
8. End capture and seal the session manifest before optimization.
9. Run multiple geometry candidates in the model lab.
10. Jointly optimize and cross-validate.
11. Compute coverage/blind spots and publish or reject the certificate.

## 4. Reconstruction and shuttle geometry pipeline

```text
source footage + metadata
        ↓
frame/time interval extraction
        ↓
features / point tracks / marker detections
        ↓
per-sensor intrinsics and distortion proposals
        ↓
drone trajectory + scene reconstruction proposals
        ↓
fixed-camera 2D observations linked to 3D trajectory/anchors
        ↓
robust joint bundle adjustment
        ↓
metric scale and coordinate-frame alignment
        ↓
residual/covariance/outlier analysis
        ↓
visibility, occlusion, coverage, transit constraints
        ↓
held-out validation pass
        ↓
calibration certificate or explicit rejection
```

Learned models such as VGGT, MASt3R-SLAM, CUT3R, or monocular depth can bootstrap proposals. The
certificate is qualified by geometric consistency, held-out marker/trajectory observations, and
robust residuals—not the model’s confidence prose.

## 5. Time calibration

Camera geometry without time is inadequate for moving-object fusion. FSS estimates:

- static offset;
- drift over session;
- buffering latency distribution;
- rolling shutter readout where material;
- timestamp quantization;
- reconnect discontinuity;
- vendor-cloud relay variability.

Evidence sources can include disciplined host receive times, device timestamps, LED temporal code,
audio chirps, common motion events, and cross-correlation. The result is an interval mapping from
device/frame time to the property time basis. Uncertainty is propagated into association gates.

## 6. Coverage certificate

Coverage is not “the image looks wide.” A certificate evaluates a declared protected volume or
surface under:

- camera pose/intrinsics uncertainty;
- static occluders;
- dynamic vegetation/doors/vehicles scenarios;
- minimum target size and contrast;
- day/night/IR modes;
- image-quality floor;
- expected network continuity;
- detector operating envelope.

Outputs:

- lower-bound observed fraction;
- singly and multiply covered cells;
- blind/weak cells;
- approach paths with insufficient observability;
- camera criticality and correlated failure domains;
- recommended camera repositioning or added sensor;
- certificate validity and invalidators.

A disconnected or blurred camera removes its cells from current effective coverage; the static
installation certificate does not override live health.

## 7. Invalidation and drift

A certificate degrades or invalidates when:

- camera moves or mount flex exceeds tolerance;
- firmware changes crop, stabilization, distortion, orientation, or timing;
- PTZ/zoom leaves the certified pose without an exact pose model;
- focus/obstruction changes effective imaging;
- major construction/vegetation/seasonal occlusion changes scene geometry;
- time alignment residuals drift;
- held-out landmarks no longer reproject within the registered bound;
- the protected-zone definition or privacy mask changes.

Continuous lightweight landmark checks estimate drift. They may request recalibration; they may not
silently rewrite the certificate.

## 8. Cross-camera association

Association combines:

- overlapping capture-time intervals;
- feasible zone/path transitions;
- geometry and motion direction;
- target size/height uncertainty;
- appearance embeddings with short retention;
- segmentation/shape and carried-object cues;
- negative evidence from cameras that should have seen the track;
- sensor health and occlusion.

Negative evidence is valid only when the camera was healthy, calibrated, continuous, and the
predicted target projection was observable. Otherwise the absence is “not measured.”

### 8.1 World-space tracks and contextual trajectories

Keep source 2D tracks when world localization fails. Lift visible foot/contact
observations through calibrated bearings onto plausible support surfaces, not a
universal ground plane or a detector-box center. Preserve terrain/deck/stair,
occluded-contact, and grazing-ray ambiguity. Synchronized overlapping views may
supply triangulation, subject to identity and time consistency.

A world-track belief carries anonymous identity, class/posture alternatives,
position/velocity hypotheses, support surfaces, shared uncertainty, observed versus
propagated status, source evidence, and exact twin/calibration/model/clock basis.
An avatar is a visualization of this belief, not measured body pose or identity.

Forecast several physically admissible trajectories. Human walking-path preference
is a soft prior: stone walks may be favored but grass is not forbidden. Bears and
unknown quadrupeds do not inherit pedestrian preferences. Class uncertainty retains
multiple movement profiles. Keep a conservative reachable envelope in addition to
the likely-route distribution, including protected high-loss off-path alternatives.
Route novelty alone does not establish threat or authorize any effect.

### 8.2 Next-camera, frame-region, and time forecasts

Project retained futures through each authorized camera's effective observation
model: body/posture extent, positive depth, occlusion, visible fraction, pixel scale,
quality, masks, sample schedule, sensor health, and sleep/wake behavior. Separate
geometric visibility, usable capture, detector output, and system availability.

Define the forecast event and horizon explicitly. First-next-camera outcomes,
simultaneous observations, reacquisition, probability of ever being observed, and
no usable observation within the horizon are not interchangeable. A target may
emerge from behind a hedge in the middle of the frame rather than at its border.
Return a pixel region or distribution bound to the exact raw/derived image domain.

Carry conditional route/class assumptions, capture-time intervals, clock uncertainty,
and separately modeled capture-to-availability delays. Stops, route changes, missing
clock evidence, and unavailable cameras broaden or split outcomes. Uncalibrated
weights must not be advertised as calibrated detection probabilities.

### 8.3 Closed-loop use and invalidation

Forecasts may prioritize bounded evidence acquisition without dropping baseline
source custody or low-probability sentinel coverage. New detections must pass
association checks; arriving where expected is not sufficient identity evidence.
A missing observation requires a coverage/completeness witness before it becomes
negative evidence. Never feed a predicted position back as an independent measurement.

Bind all tracks/forecasts to exact ledger, twin, camera-mode, clock, model, and
privacy generations. Camera movement, changed geometry/crop, occluder changes,
clock drift, or coverage loss invalidates dependent claims. Begin with conservative
invalidation and explicit reactivation; no silent geometry or calibration edits.
Existing fss/1 query, explain, follow, plan/commit, and doctor operations present
these objects without creating a new agent dialect. Optional Blender overlays are
read-only relative to the accepted model and never required for live operation.

## 9. Privacy

The twin stores property geometry and can be highly sensitive. Defaults:

- local-only canonical geometry;
- no street-facing detail beyond the protected/authorized region;
- early masking of neighboring windows/yards/public sidewalks as configured;
- encrypted exports with explicit recipient and expiry;
- no public model-host upload of unredacted geometry;
- deletion closure for derived meshes/splats/thumbnails/indexes and localization
  images/descriptors, reference renders, tracks, and forecasts;
- capability/privacy projection before spatial or graph expansion, including hidden
  camera counts, routes, landmarks, and observation forecasts;
- no private skill source or real property assets in the public FSS repository.

## 10. Acceptance gates

- deterministic synthetic geometry fixture with known truth;
- intrinsics/extrinsics/time recovery error distributions;
- robust outlier and partial-overlap behavior;
- held-out trajectory/marker validation;
- moved-camera detection;
- firmware crop/timing drift fixture;
- coverage lower-bound calibration;
- cross-camera association improvement versus no geometry;
- no regression under absent/failed sensors;
- full evidence root and replay command.

### 10.1 Imported-twin and predictive-handoff evidence

Extend GATE-070 with package integrity and evaluated-geometry correspondence,
2D-to-3D pose validation, shared-error accounting, support-surface localization,
and explicit abstention. Extend the relevant GATE-080 and GATE-115 scenarios with
next-camera, image-region, capture-time and availability-time forecasts; correct
association; protected alternatives; and evidence-bearing explanation.

Test turns/stops, grass crossings, person/bear/unknown classes, hidden feet,
multiple support heights, simultaneous views, interior-frame emergence, no-next-
observation cases, sleeping/failed cameras, and privacy masks. Add stale-generation,
lost-source, cancellation, hostile-import, and Blender-absent execution cases.

Synthetic truth geometry must be independently perturbable from the imported
approximate model. Use held-out real recordings and physical controls before
claiming property accuracy; rendering and scoring the same mesh is insufficient.
Measure residual tails, world-position error, next-camera error, interval/region
coverage and sharpness, identity switches, abstention, drift detection, protected-
route misses, and total resource cost. No fixed accuracy or calibrated probability
is claimed by this plan. Existing bead statuses, assignees, and proof gates are
unchanged by publishing it.
