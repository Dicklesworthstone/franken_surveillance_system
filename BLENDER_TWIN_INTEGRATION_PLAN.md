# FSS: Blender-derived property twin, camera registration, and predictive handoff

**Design date:** 2026-09-12  
**Status:** Accepted implementation plan; runtime features and property qualification remain outstanding.  
**Inspected skill revision:** `77b9748bd68c49f1bb70d84ee7111d59d0b4f374` in the owner's private skills repository.  
**Initial FSS source audit:** `f8d6a546174877689487a91bd1d1f366ee3eeee1`.  
**Integration baseline:** `381f3abbd64560926b91ea2c89c7935c510ed946`.  
**Evidence boundary:** The skill, relevant helper source, and FSS architecture/reference contracts were inspected. No actual property `.blend`, reference-image package, or surveillance recording was supplied or tested in this task. No camera poses, accuracy figures, calibrated probabilities, or production-readiness results are claimed.

## 0. Normative adoption and existing-plan crosswalk

This is the accepted detailed implementation companion to
`COMPREHENSIVE_PLAN_FOR_FRANKEN_SURVEILLANCE_SYSTEM.md`, not a replacement for its
constitution. It specializes sections 14, 16, 19, 20, 28, and 29. The existing
capability, privacy, dependency, durable-format, and release rules remain binding.
No source-file presence, planning status, or successful import closes a runtime
bead or establishes GATE-070, GATE-080, or GATE-115 qualification.

| Existing owner | Required extension |
|---|---|
| Section 14; WP-110/WP-120 | Import an existing semantic property twin; recover surveillance camera pose from 2D-to-3D observations; preserve scale, lens, map, and clock uncertainty. |
| Section 16; WP-090/WP-130 | Retain image tracks while lifting supported observations to world-space beliefs; predict several class-conditioned trajectories without inferring identity or hostile intent. |
| Section 19; WP-170 | Compile support, passage, visibility, and association projections from one immutable version universe; retain canonical feature identity through simplification. |
| Section 20; WP-175/WP-180 | Expose world tracks and next-observation forecasts through existing fss/1 operations, SituationCapsules, and bounded evidence-bearing views. |
| Section 28; execution order | Make imported-twin registration an alternative to reconstruction-first installation; prove supplied-correspondence pose solving before automatic matching. |
| Section 29; GATE-070/080/115 | Add measured camera-to-twin, target-location, next-camera, image-region, capture-time, and availability-time evidence with adversarial uncertainty and privacy cases. |

The simultaneous manual calibration shuttle remains an optional route for new
mapping or missing scale/time/landmark evidence. It is not a prerequisite for
registering an already reconstructed property through unchanged static landmarks.
This alternate path does not waive any actual observation, calibration, custody,
or acceptance requirement. Existing dependency edges must be reconciled explicitly
when implementation tasks adopt this route, never ignored implicitly.

The private skill is a separate content producer. This public plan does not copy
its implementation, ship its prompts, require access to its repository, or publish
any property's geometry or source footage. An interoperable implementation must
work from the neutral export contract alone.

## 1. Architectural decision

Make importing an existing property twin a first-class installation route. Do not require a second drone reconstruction or simultaneous drone/camera recording when static shared landmarks already provide adequate registration evidence.

The integration consists of six distinct operations:

1. Export an evidence-linked, immutable scene package from the Blender authoring environment.
2. Compile its geometry, semantics, and uncertainty into FSS-native immutable data.
3. Localize each fixed camera against the common property frame using image-to-3D correspondences.
4. Estimate anonymous, uncertainty-bearing target tracks in that frame.
5. Forecast several class- and context-conditioned future trajectories.
6. Project those futures into each camera to predict next usable observation, image region, and time.

Blender remains an authoring and optional inspection application. The always-on FSS runtime neither embeds Blender nor invokes Python, OpenCV, COLMAP, PyTorch, a browser, or Unreal. An optional Blender-side exporter belongs to the separate owner-operated content-authoring workflow. FSS must operate from its exported package with Blender absent. A raw `.blend` alone is not a supported native FSS import in the initial design.

```text
Blender scene + semantic index + source evidence + recovered reference poses
                              |
              authoring-side export, frozen revision
                              |
          bounded neutral package -> FSS native twin compiler
                              |
         geometry + landmark atlas + semantic surfaces + uncertainty
                              |
Surveillance frames -> camera registration -> validated camera generation
                              |
                    world-space target beliefs
                              |
           multimodal trajectory and visibility prediction
                              |
        next-camera / image-region / time-distribution forecast
                              |
      evidence acquisition, cross-camera association, situation views
```

## 2. Findings from the existing skill and FSS

The skill's most relevant existing contracts are:

- Stable `hhm_feature_id`, `hhm_object_id`, and `hhm_data_id`, separated from mutable display names.
- `DIGITAL_TWIN_INDEX.json`, with a scene hash, coordinate/scale status, feature bindings, relationships, claims, evidence references, and use limitations.
- Explicit separation between current objects, historical alternatives, reference geometry, and aperture/host bindings.
- Camera conventions, source-PTS image domains, recovered-pose reuse, and independent registration versus scored landmarks.
- Optional sparse/dense reconstruction exports with reference poses, point identities, and image provenance.
- Portable geometry delivery, including evaluated modifiers/instances and identity preservation through geometry optimization.

The `digital_twin.py` implementation validates package-reference consistency and supports lexical/relational queries. It does not inspect Blender, solve camera poses, certify geometry, or supply a surveillance-ready geometry engine. Its `neighbors` command follows declared relationships, not physical traversability or visibility.

There is an explicit interchange boundary to normalize: `digital_twin.py` expects `house-digital-twin-index/1` and `house-scene-manifest/1`; the scene tooling also has a bounded `home-model.blender.transport.v2` envelope carrying logical v2 scene results/manifests. Do not assume a console summary, raw v2 envelope, and twin index are interchangeable. Implement a documented adapter, preserving original byte hashes and recording normalization. This is an integration requirement, not evidence that existing package integrity is broken.

FSS already specifies the desired camera/twin/coverage behavior, and has intrinsics certificates and a cross-camera extrinsics reference interface. The inspected extrinsics solver uses Horn-style absolute orientation over **3D-to-3D** correspondences. It is not the **2D-to-3D** pose solver required to register a surveillance image against a known property map. Preserve the useful certificate/identity concepts while adding the missing problem-specific solver and validation.

## 3. Twin import package

Treat the package as a manifest-rooted collection, not an unstructured asset directory. The following are proposed contracts, not existing commands or registered schemas.

### 3.1 Package contents

| Component | Content and role |
|---|---|
| Import manifest | Source-scene hash, source index and manifest hashes, exporter identity/settings, observation epoch, package state, member digests and limits |
| Geometry | Evaluated triangles/instances, full transforms, feature mapping, support surfaces, structural obstacles, occlusion geometry |
| Semantics | Paths, grass, stairs, ramps, decks, gates, doors, fences, water, vegetation, zones; role and uncertainty separate from display material |
| Localization atlas | Real reference images/crops, precise image domains, camera poses/intrinsics, 2D observations, associated 3D landmarks, error/support information |
| Coordinate contract | Local origin, axes, handedness, units, scale evidence, optional geographic mapping, source-to-property transforms |
| Uncertainty and validity | Unsupported regions, approximate surfaces, landmark correlation groups, changed/retired features, relevant date and invalidators |
| Optional visualization | GLB/glTF and textures for inspection, separately bounded and not the semantic authority |

The archive root binds every constituent object. An image deliberately omitted for privacy is represented as unavailable; a hash or filename does not establish retrievability.

### 3.2 Geometry extraction

Export evaluated geometry from the exact saved scene, scene/view layer, and evaluation frame. Apply or explicitly preserve parent, instance, modifier, and object transforms. Preserve a triangle/instance-to-feature map through splitting, merging, and LOD changes. Preserve the original editable master.

Do not infer geometry from object origins or bounding boxes. An object origin can remain stationary while its mesh is edited. Bounds are useful for broad-phase indexing, not roofs, apertures, stairs, contact surfaces, or precise ray intersections.

Export semantic roles explicitly: current physical structure, historical attempt, construction helper, reference plane, privacy mask, and visualization-only object. `hide_render` alone is not a physical-status classifier. A hidden Boolean operand must not become a wall; a reference photograph plane must not become an occluder; a modeled opening must not be filled by an approximate bounding box.

glTF/GLB is a useful neutral mesh interchange. Standard glTF cameras do not encode the full surveillance lens/distortion/crop/clock contract; keep that in versioned sidecars. Custom properties in `extras` are convenience copies, not the only identity authority. The native compiler may accept an explicitly bounded glTF subset and lower it to canonical FSS objects. Unsupported required extensions fail closed; they do not trigger external downloads or hidden decoders.

### 3.3 Compiler safety and admission

Use checked counts, offsets, dimensions, decoded asset sizes, nesting, and instance-expansion budgets. Reject out-of-package paths, implicit URLs, executable payloads, missing required members, nonfinite transforms, invalid topology indices, ambiguous units, and unrecognized required semantics. No imported script or Geometry Nodes code runs in FSS. The authoring exporter performs any required evaluation in its separately authorized environment.

Distinguish `imported`, `structurally_valid`, `registered`, and `qualified_for_use`. A valid package can still have poor physical geometry. Source provenance and reconstruction claims remain attached rather than being promoted to measured truth.

## 4. Three working representations, one coordinate basis

Compile three linked representations:

**Visual scene:** editable/renderable property appearance, suited to human inspection and optional synthetic localization views.

**Geometric scene:** stable landmarks, structural surfaces, support meshes, obstacles, and conservative occlusion geometry with their uncertainty.

**Behavioral scene:** a multilayer traversability graph whose nodes/edges refer to physical surfaces and portals. Surface type, slope, clearance, connectivity, barrier state, and uncertainty influence class-specific movement hypotheses.

These representations share identities and transforms, but they need not have identical tessellation. A million decorative leaves should not imply a million planning nodes. Conversely, a low-detail planning mesh must not erase a narrow passage, retaining wall, step, or drop-off.

Do not reduce the property to one ground plane. Use terrain and connected surface layers for lawns, stone paths, stairs, decks, balconies, ramps, and other distinct heights. Unsupported interior spaces remain outside the reconstructed domain.

Separate passage from visibility. Glass may block a walking path yet transmit some visible light. A fence may be partly visible through but not ordinarily traversable. Vegetation has seasonal, viewpoint-dependent, and motion-dependent occlusion uncertainty. Decorative material alpha is not a calibrated optical transmission model.

## 5. Coordinate and scale contract

Use a nearby local property origin. Geographic coordinates and north are optional metadata, not prerequisites for local camera handoff.

Keep physical scale as `RELATIVE`, `ESTIMATED`, or supported by measured anchors, with a separate uncertainty model. A visually good overlay cannot establish metric scale because uniformly scaling scene positions and camera translations preserves projective images. Relative-space handoffs may still be useful when motion is estimated in the same frame; do not inject meter-based speed or distance priors into an unresolved scale.

Explicitly record:

- Blender-world to property-world transform;
- any glTF axis conversion and unit conversion;
- camera-to-world versus world-to-camera matrix direction;
- camera local basis and pixel-center convention;
- raw, undistorted, cropped, rotated, resized, and displayed image transforms;
- every reconstructed map's own frame and its property alignment.

For world-to-camera extrinsics `X_camera = R X_world + t`, the camera center is `C_world = -R^T t`. Blender's camera-local axes and conventional CV axes differ; do not infer transform direction from a plausible-looking overlay.

A reconstruction with unresolved global scale needs similarity registration (`Sim(3)`), not only rigid registration (`SE(3)`). Scale changes positions and lengths, not the physical angular interpretation of a camera rotation. Global similarity alignment cannot repair local roof or terrain deformation.

Test asymmetric axes, multiple known landmarks at different depths/heights, a known length, optical-axis projection, and right/up image directions independently. A round trip that shares the same wrong conversion is insufficient.

## 6. Automatic camera registration

### 6.1 Freeze the actual imaging configuration

Select high-quality frames from live or recorded video. Group frames by physical camera and effective imaging mode. Retain source identity, capture-time uncertainty, raw dimensions, distortion, crop, stabilization, image orientation, and any main/substream relationship.

Exclude transient foreground, moving foliage, shadows, glare, and overlays from static landmark fitting. Use repeated frames to reject transients and assess repeatability, but do not count adjacent frames as independent geometry evidence. A fixed camera watching a static scene produces no new triangulation baseline merely by recording longer.

PTZ, optical zoom, digital crop, stabilization, stitched panoramas, and dewarped outputs need explicit camera models. Where only an effective virtual camera is observable, do not claim its fitted pose is the physical mount pose. Unsupported noncentral imaging models remain unsupported rather than being forced into pinhole calibration.

### 6.2 Obtain 2D-to-3D correspondences by complementary routes

**Preferred route: real reference-image atlas.** Match a surveillance image to real drone/handheld images already associated with stable 3D landmarks. Retrieve relevant reference views first, match local features, verify the matches geometrically, and transfer the associated 3D point identities. Retain reference-map uncertainty and correlations.

The crucial producer-side addition is therefore a localization atlas, not only a mesh export. Each accepted reference view should expose source image hash and PTS, image-domain transform, camera model, recovered pose, world-map alignment, stable landmark tracks, support region, and validation status. Existing recovered poses should be reused only after exact basis checks.

If no sparse map exists, construct a bounded local map from suitable source footage or explicitly associate visible architectural landmarks with the accepted semantic scene. A landmark created by intersecting an image ray with an approximate modeled surface is model-derived evidence, not equivalent to a measured or independently triangulated point.

**Complementary route: synthetic localization views.** Render views from plausible mounting regions and a bounded orientation/lens search. Export color/features, depth, normals, and triangle/feature IDs. Matching image points can then map to model-surface coordinates. Use synthetic matches as candidate generators and verify with real landmarks and geometric residuals. A render matching its own model cannot independently validate that model.

**Complementary route: architectural geometry.** Use stable corners, roof/eave edges, path junctions, fence posts, and ground/wall intersections. Combine point, line, and plane constraints where justified. Generic object labels can propose correspondences; they cannot certify a unique physical landmark or camera pose.

These routes are alternatives within a bounded search, not a requirement to run every method on every camera.

### 6.3 Solve and refine camera candidates

Solve robust calibrated PnP for each candidate correspondence set. Where focal length or other parameters are uncertain, search a bounded camera-family prior and refine only identifiable parameters. Retain multiple viable solutions for repetitive structure, weak geometry, or planar ambiguity.

A conceptual objective is:

`sum_k robust_loss((u_k - project(X_k, pose, intrinsics, distortion))^T W_k (u_k - project(...))) + justified_priors`

The weights must account for image localization and 3D-map errors. Shared map, scale, and reference-pose errors are shared nuisance variables, not independent noise that disappears as more correlated keypoints are counted.

Refine on a proper rotation/rigid-transform manifold with bounded iterations and numerically checked linear solves. Keep a deterministic reference path, explicit solver bounds, seeded outlier sampling, canonical tie-breaking, and recorded failure classifications. Validate floating-point calculations and rounding separately from canonical serialization; fixed-point output storage alone does not prove cross-platform solver determinism.

Initially freeze the imported scene while solving cameras. Do not allow joint optimization to move walls or terrain to rescue a bad camera match. Later joint scene/camera proposals may be useful, but must preserve the prior accepted world, independent anchors, held-out checks, and a separate activation decision.

### 6.4 Validate before activation

Test excluded physical landmarks, broad image support, multiple depths/heights, cheirality, repeated-structure ambiguity, camera mounting plausibility, image corners, and relevant ground regions. Validate downstream projection accuracy at path junctions and camera handoff boundaries, not only average fitting residual.

Disjoint camera fields of view are acceptable if each camera can be independently registered to the common map. Simultaneous drone footage is unnecessary for static registration when the relevant structure has not changed. Motion fusion and dynamic handoffs still need reliable cross-camera time mapping.

Automatic registration can be insufficient when a camera faces away from the house and only sees unmapped ground, vegetation, sky, or reflective surfaces. Preserve alternative poses or remain unregistered. The fallback is a narrowly targeted owner-assisted correspondence or capture workflow, not guessed coordinates. Adding a few useful landmarks can be more valuable than another unconstrained optimization run.

### 6.5 Proposed camera registration certificate

Bind camera and stream-mode identities, twin/map generations, image-domain chain, intrinsics/distortion, world-to-camera pose, scale status, landmark support, excluded checks, uncertainty and model-discrepancy assumptions, solver identity, time validity, and invalidators. Separate pose validity from sensor health and current detectability.

An identity rigid transform can be a valid geometric result under a chosen coordinate frame. Uncalibrated state should be represented by a type/status, not by banning the identity matrix in a generic new transform primitive. Review this distinction when reusing existing FSS extrinsics code.

## 7. Lift image detections into world-space beliefs

Maintain the original 2D track and evidence even when geometric localization fails.

For a usable ground-contact observation, undistort the pixel to a bearing, transform it to world space, and intersect the ray with admissible support surfaces:

`X(lambda) = C_world + lambda R^T bearing_camera`, with `lambda > 0`.

Prefer visible feet/contact keypoints, segmentation-supported contact, or a justified body/support model. A detector box's bottom center is only a noisy candidate and can be wrong under occlusion, cropping, shadows, or a non-upright posture.

The intersection can be ambiguous among terrain, steps, porch, and other layers. Carry those alternatives rather than selecting the nearest arbitrary triangle. Model/pose/image uncertainty produces a position region, not an exact point. Near-grazing rays require especially conservative depth uncertainty.

For synchronized overlapping cameras, associate candidate observations and triangulate with reprojection checks. Retain identity-assignment alternatives. When no contact or triangulation constraint is available, retain a bearing/frustum or weaker bounded depth belief. Monocular depth may propose a range, but does not become metric measurement without appropriate evidence.

A proposed `TrackWorldBelief` includes anonymous track ID, capture-time interval, class/posture distribution, 3D position/velocity hypotheses, support surface, uncertainty representation, source evidence, twin/calibration/model/clock basis, observed versus propagated status, and expiration policy. A displayed avatar is a view of this belief, not an assertion of precise body pose or personal identity.

## 8. Class- and context-conditioned trajectory forecast

Use a bounded mixture of motion models and route hypotheses. A practical first reference implementation combines constant velocity, turning, stopping, surface-constrained movement, and several candidate destinations or exits. Retain a free-space/off-route component where physically admissible.

A route cost can depend on length, slope, surface class, clearance, turning effort, barrier state, and compatibility with observed motion. Learned terms are versioned priors, not authority or proof of intent.

For a person, ordinary walking-path preference can increase the weight of a stone-walk branch without forbidding grass. For a bear or uncertain quadruped, do not inherit the pedestrian path prior. Use separately supported movement profiles, or broad dynamics when the class is uncertain. Person/crawling/animal/unknown alternatives must not collapse merely because one category currently leads.

Distinguish:

- **Forecast distribution:** likely routes under the current model and observations.
- **Conservative reachable envelope:** less-likely but physically admissible routes relevant to protected outcomes.

A low-weight approach to a protected opening must not vanish because a nominal path looks routine. Conversely, walking on grass or moving unusually is not sufficient evidence of hostile intent. Threat assessment remains a separate evidence-linked decision.

A learned trajectory model can later improve route weights or interaction modeling. It must beat the deterministic baseline on held-out property episodes and preserve class, uncertainty, privacy, and hard constraints. Research methods such as Trajectron++ motivate heterogeneous dynamics and map conditioning; their published implementation is not a compliant FSS production dependency and their datasets do not establish animal prediction quality.

## 9. Forecast next camera, image region, and observation time

Project each weighted future hypothesis through all authorized candidate camera models. Evaluate an approximate body volume, posture, and required visible support, not only a point or camera frustum intersection.

For camera j, evaluate:

- positive depth and image inclusion;
- static and scenario-dependent occlusion;
- target pixel scale and visible fraction;
- view angle and image-quality conditions;
- camera health, sampling schedule, sleep/wake behavior, masks, and detector envelope;
- applicable calibration and clock uncertainty.

Keep distinct events: geometric visibility, usable captured evidence, detector output, and operator/system availability. Where detection probability is not empirically calibrated, expose model weights/intervals rather than falsely precise probabilities.

For each hypothesis, find the first future qualifying observation in a camera not already providing the current observation, or use an explicitly requested reacquisition definition. Track simultaneous-camera outcomes and a **no usable observation within horizon** outcome. Per-camera probability of ever seeing the target is not the same as a mutually exclusive next-camera distribution.

The proposed `CameraHandoffForecast` reports:

- source track/world/twin/calibration/model/clock basis;
- event definition and prediction horizon;
- per-camera possible observation intervals;
- normalized pixel-region distribution or conservative region, with exact image-domain identity;
- likely entry boundary or occlusion-emergence region;
- route assumptions, body/class/posture model, and confidence/calibration status;
- simultaneous and no-observation alternatives;
- expected system-availability interval and invalidators;
- explanation and evidence handles.

Targets need not enter at an image border. A target can become visible from behind a hedge near the middle of a frame, emerge from an occluder, or already be in the field when an event-driven camera wakes.

Compute capture-time predictions separately from arrival/availability predictions. The latter includes frame sampling, exposure, device buffering, network/relay delay, decode, and inference. Use the existing conservative timestamp/capture-time approach rather than substituting packet arrival for scene time.

**Illustrative calculation, not a property measurement:** If a selected route has 5.4–6.6 m remaining and a constant-speed hypothesis spans 1.2–1.6 m/s, its simple travel-time envelope is 3.375–5.5 s. Stops, turns, alternate paths, distance uncertainty, clock error, sampling, and pipeline latency require additional modeling. The range is conditional on the route and speed assumptions, not a calibrated 95% interval.

## 10. Close the loop without self-confirming tracking

A forecast may prioritize crops, bounded frame-rate increases where permitted, evidence buffering, or extra model work on the most informative next camera. It must not stop baseline source custody or discard alternative-camera evidence. Keep sentinel coverage for low-probability and protected routes.

A new detection is an association candidate. Compare timing, geometry, feasible routes, shape/class, short-lived appearance where authorized, and contradictions. Do not attach it to the old target only because the forecast expected somebody there. Handle two similar targets, swaps, split hypotheses, and missing detections explicitly.

When the expected observation fails to occur, consider alternative route, stop, occlusion, misclassification, camera failure, detector miss, stale map, or clock/pose error. Negative evidence can affect the posterior only with a current coverage/completeness witness over the predicted region and interval. An absent event clip from a sleeping camera is not such a witness.

Do not feed a predicted target position back into the estimator as an independent observation. Record observations, propagated estimates, forecasts, associations, and adjudicated outcomes as distinct provenance classes. Repeated re-rendering does not add evidence.

## 11. Runtime economy and native architecture

Calibration is installation/change-driven work. Everyday tracking should not require photorealistic rendering or full-scene optimization per frame.

Compile reusable, immutable acceleration data:

- BVH or equivalent ray-query structure over relevant geometry;
- camera bearing/projection lookup tables per calibrated image mode;
- support-surface candidates and uncertainty;
- class/posture-conditioned approximate visibility maps;
- multilayer traversability and transition graphs;
- view/landmark retrieval indexes;
- conservative geometric error bounds for simplified representations.

Update target beliefs and a bounded trajectory set online. Refine ray/visibility queries only near occlusion boundaries or decision-sensitive regions. Adapt work within declared resource budgets while keeping source, uncertainty, alternative-world, and obligation floors.

Asupersync owns task lifetime, cancellation, budgets, and orchestration. Geometry and tracking modules consume immutable typed inputs. Use admitted Franken graph/search/storage mechanisms for derived views and persistence, but do not add dependencies merely because they exist. Optimized geometry must remain differential-testable against a safe scalar reference.

## 12. Generations, persistence, and presentation

Every import, calibration, forecast, and derived geometry publication pins exact generations and ledger anchors. Changing a surface, camera mode, scale transform, model, or clock invalidates dependent outputs. Begin with conservative whole-generation invalidation; introduce narrower dependency-based invalidation only with proof that affected support is correctly identified.

FSS records scene imports and activation decisions through existing authority/publication patterns. Large scene objects are immutable object-graph members; the ledger carries identities and roots. Forecasts and tracks are cognition, not evidence that a physical event happened.

Use the existing public grammar: `plan`/`commit` for admitted import or calibration activation, `query` for camera/twin/track projections, `session.follow` for meaningful motion/coverage changes, `explain` for handoff rationale, and `doctor` for registration drift. These are proposed target/payload families, not newly claimed working CLI commands.

The runtime UI should show calibrated camera frusta, current and stale tracks, uncertainty volumes, several future path tubes, predicted observation regions, and unavailable coverage. An optional Blender inspection layer can load a read-only snapshot or separately owned overlay collection without editing accepted geometry. Blender disconnection must not affect FSS tracking.

## 13. Privacy and intellectual-property boundaries

Keep property geometry, source images, surveillance frames, location metadata, and appearance features local by default. Filter capabilities before graph/search/geometry result expansion where hidden camera or region information could leak. Avoid biometrics and cross-property identity graphs; they are not required for geometric continuity.

The private skill remains a separate producer. Public FSS can consume a documented neutral export contract without receiving the skill's prompts, internal scripts, private workspace, or property assets. Any future public implementation should be original FSS code against that contract, not an automatic copy of private skill internals.

Evidence retention/deletion applies to localization images, descriptors, crops, reference renderings, tracks, scene derivatives, and forecasts as applicable. An export hash does not authorize sharing its referenced images.

## 14. High-impact implementation sequence

### A. Import an actual existing twin

Add a producer-side neutral package exporter and native importer/compiler. Exercise current-versus-historical geometry, displaced origins, instances, apertures, coordinates, scale status, source hashes, and missing evidence. Establish a working geometry/semantic lookup without any pose claims.

### B. Register one camera from supplied correspondences

Implement the 2D-to-3D pose problem with the existing lens families, robust outlier handling, checked refinement, and held-out validation. Supplied correspondences make the geometry engine independently testable before adding learned matching. Publish a proposed calibration and inspect exact overlays on the camera image and scene.

### C. Automate correspondences with a localization atlas

Export/reuse source-image poses and landmark tracks. Add retrieval/matching and synthetic/architectural fallback proposals. Test both successful registration and principled refusal. Targeted assistance is a supported fallback, not an invisible manual step mislabeled automatic.

### D. Establish one-camera world tracks

Lift visible contact points onto appropriate terrain/layers, preserve ambiguous depth, and validate against independent test trajectories. Keep useful 2D operation when world localization is unavailable.

### E. Demonstrate two-camera predictive handoff

Use recorded synchronized episodes with turns, stops, off-path motion, occlusion, unequal frame rates, and at least one no-next-camera outcome. Produce next-camera, pixel-region, and capture/availability-time forecasts, then compare to actual observations.

### F. Add class-conditioned priors and robust alternatives

Compare human path-biased, animal-specific, and unknown-class baselines. Demonstrate that removing or weakening a class belief broadens forecasts rather than silently inheriting another class's behavior. Retain protected low-probability routes.

### G. Integrate online invalidation and resource scheduling

Exercise camera movement, digital crop, map changes, night/IR conditions, shared clock errors, sensor sleep, packet gaps, and budget pressure. Add the native runtime integration without weakening qualification or introducing foreign production services.

The existing FSS work anchors are FSS-089/090/091/092, FSS-097/098/099, and the related geometry, tracking, association, graph, and agent work packages. New implementation tasks should describe the missing vertical contracts rather than declaring those broad existing tasks complete.

## 15. Acceptance evidence

| Area | Positive test | Essential adversarial test |
|---|---|---|
| Import | Exact current scene, features, and geometric transforms | Retired geometry, duplicate IDs, reference image planes, bad instances, stale hashes |
| Coordinates | Independent asymmetric landmark projections | Double scale, mirrored axis, wrong transform direction, wrong pixel origin |
| Registration | Held-out real landmarks and independent physical checks | Repeated facade, sparse/planar support, wrong lens/crop, noisy or biased map |
| Tracking | Independent ground-contact trajectories | Hidden feet, stairs/deck ambiguity, crawling, truncated boxes, shallow rays |
| Timing | Capture-time alignment and measured availability latency | Buffer changes, stale sender clock, unequal FPS, sleeping camera |
| Handoff | Observed next camera, entry region, and time | Interior-frame emergence, simultaneous views, turns/stops, no next observation |
| Association | Correct anonymous continuity | Similar targets, identity swap, prediction-driven false attachment |
| Coverage | Valid conditional negative evidence | Camera down, mask changed, occluder moved, detector outside operating envelope |
| Forecast | Calibrated route/arrival distributions where claimed | Overconfident wrong route, incorrect animal prior, collapsed residual world |
| Runtime | Bounded source-preserving execution | Cancellation, memory/compute pressure, Blender absent, stale generation |

Use separate true-world and imported-approximate geometry in synthetic tests. Rendering and evaluating against the exact same mesh alone is an inverse-crime-style test: it proves arithmetic consistency but misses reconstruction mismatch. Vary map scale, local surface error, camera intrinsics, noise, occluders, and visibility separately. Hold out entire episodes and physical landmarks, not just adjacent frames or alternate IDs for the same track.

Measure pose/orientation and downstream location error, image reprojection tails, next-camera accuracy, entry-region coverage, arrival-interval coverage and sharpness, association identity errors, abstention, protected-route misses, calibration drift detection, and total resource cost. Report these by lighting, class, posture, range, occlusion, and geometry quality. Minimum-of-many trajectory error alone is insufficient because arbitrary broad guesses can look good under that metric.

## 16. Priority conclusion

The highest-value new producer output is the **evidence-linked visual localization atlas**. The highest-value missing FSS consumer function is **image-to-known-map camera pose registration**, followed by uncertainty-bearing ground/contact projection and visibility-aware first-observation prediction.

This turns the Blender model from a visualization asset into a useful spatial prior without promoting an attractive reconstruction into unquestionable truth. The system can infer likely camera handoffs while retaining the very alternatives, coverage gaps, and uncertainty that matter most in a security deployment.

## Source basis

Private owner material inspected through the connected GitHub tool, under `.claude/skills/drone-flyover-video-to-home-model-in-blender/`:

- `SKILL.md`.
- `references/SEMANTIC-LABELING.md`.
- `references/CAMERA-MATCHING-AND-SCALE.md`.
- `references/LOCAL-DENSE-RECONSTRUCTION.md`.
- `references/CINEMATIC-AND-INTERACTIVE-DELIVERY.md`.
- `references/SCENE-TRANSPORT.md`.
- `scripts/digital_twin.py`, relevant `scripts/spatial_diagnostics.py` sections, and scene-manifest call-site excerpts.

FSS sources: comprehensive plan already reviewed in this conversation; `DIGITAL_TWIN_AND_CALIBRATION.md`; `crates/fss-reference/src/calibration.rs`; `crates/fss-reference/src/extrinsics.rs`; and the packet/time boundary inspected in the preceding implementation task.

Public primary references supporting the methodological choices:

- COLMAP output and camera conventions: https://colmap.github.io/format.html
- OpenCV PnP methodology and reference implementations: https://docs.opencv.org/4.x/d5/d1f/calib3d_solvePnP.html
- Hierarchical Localization, authors' implementation and pipeline: https://github.com/cvg/Hierarchical-Localization
- PixLoc, camera localization by learned features and geometric refinement: https://psarlin.com/pixloc/
- Trajectron++, heterogeneous map- and dynamics-conditioned forecasting: https://arxiv.org/abs/2001.03093
- glTF 2.0 specification: https://registry.khronos.org/glTF/specs/2.0/glTF-2.0.html
- Blender's documented glTF evaluated-mesh, camera, axis, and custom-property export mechanisms (versioned reference): https://docs.blender.org/manual/en/4.1/addons/import_export/scene_gltf2.html

These sources establish methods or existing interfaces. They do not establish accuracy, speed, or supported-camera coverage for this proposed FSS integration. External reference implementations are methodological/laboratory comparisons, not proposed production runtime dependencies.
