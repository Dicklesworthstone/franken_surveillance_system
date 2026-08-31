# Digital twin, registration, and calibration shuttle

## 1. Objective

Create a metric, uncertainty-aware model of the protected property that answers:

- where each camera is and what it can currently see;
- which zones overlap and which are blind;
- how long movement between views should take;
- where an observation projects in 3D;
- whether a track can plausibly be the same entity across cameras;
- whether a camera has moved, changed crop/zoom, or drifted;
- what additional drone/static view would reduce uncertainty most.

A beautiful 3D rendering is not enough. The deliverable is a **calibration certificate** with
residuals, covariance, coverage, evidence, validity, and invalidators.

## 2. Canonical versus derived twin

Canonical geometry:

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

## 3. Calibration shuttle concept

The homeowner manually pilots a lightweight drone through the property while fixed cameras record.
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

## 4. Geometry pipeline

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

## 9. Privacy

The twin stores property geometry and can be highly sensitive. Defaults:

- local-only canonical geometry;
- no street-facing detail beyond the protected/authorized region;
- early masking of neighboring windows/yards/public sidewalks as configured;
- encrypted exports with explicit recipient and expiry;
- no public model-host upload of unredacted geometry;
- deletion closure for derived meshes/splats/thumbnails/indexes.

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
