# Blender twin integration: executable-work crosswalk

**Status:** Accepted planning decomposition, not implemented functionality or a replacement bead database.  
**Date:** 2026-09-12  
**Normative design:** [BLENDER_TWIN_INTEGRATION_PLAN.md](../BLENDER_TWIN_INTEGRATION_PLAN.md).  
**Owning overview:** [DIGITAL_TWIN_AND_CALIBRATION.md](../DIGITAL_TWIN_AND_CALIBRATION.md).

The goal is a real imported-property -> localized-camera -> world-track ->
next-observation vertical slice. Do not substitute new empty crates, registry rows,
status reports, or synthetic output claims for the specified working behavior.

## Existing requirement and bead ownership

These are reference links, not status or assignment changes. Before claiming work,
read the current `.beads/issues.jsonl`, prerequisites, active assignees, and retained
proofs. Preserve concurrent implementation and do not close or reopen broad seeds
merely because this companion adds an integration task.

| Requirement | Existing bead | Integration responsibility |
|---|---|---|
| FSS-089 | `fss-x4a.18.2` | Reuse exact intrinsics/lens identity; independently validate the camera image-domain chain. |
| FSS-090 | `fss-x4a.18.3` | Reuse extrinsics contracts where applicable; 3D-to-3D alignment does not implement 2D-to-3D PnP. |
| FSS-091 | `fss-x4a.18.4` | Propagate pose, crop, map, scale, clock, and mode invalidation through dependent forecasts. |
| FSS-092 | `fss-x4a.18.5` | Preserve uncertainty-aware mask projection and fail-closed disclosure. |
| FSS-097 | `fss-x4a.19.3` | Add imported-twin registration and automatic image-to-map camera localization. |
| FSS-098 | `fss-x4a.19.4` | Supply effective class/posture/health-aware visibility and observation windows. |
| FSS-099 | `fss-x4a.20.1` | Consume world-track and next-observation hypotheses without self-confirming identity assignments. |

WP-090 supplies detections/tracks; WP-110 supplies timing and calibration; WP-120
owns the twin; WP-130 owns association; WP-170 supplies derived graph/search
mechanisms; WP-175/180 expose the existing agent grammar. No new task acquires
another subsystem's effect authority.

### Reconstruction prerequisite reconciliation

FSS-097 currently includes reconstruction-oriented prerequisites. The imported-twin
route must accept a properly witnessed external reconstruction as an alternative
source of scene/landmark evidence; it must not require rerunning FSS-096 merely to
consume an existing model. When materializing these tasks into Beads, explicitly
split the source-evidence prerequisite into imported-package and newly reconstructed
routes and preserve the common calibration, identity, custody, and qualification
requirements. Do not silently ignore an existing blocking edge or remove proof
requirements. Keep the manual-shuttle/reconstruction branch available.

## Dependency-ordered implementation units

`BTI-*` identifiers below are local plan identifiers, not new FSS registry IDs or
claims that corresponding Beads records already exist. Internal dependencies are
shown here; the owning FSS contracts and runtime prerequisites remain additional
requirements. All units begin unimplemented in this planning crosswalk.

| Unit | Deliverable | Internal dependencies | Priority |
|---|---|---|---|
| BTI-001 | Neutral export contract and native twin import/compiler | none | critical |
| BTI-002 | Real-image localization atlas and stable landmark bindings | BTI-001 | critical |
| BTI-003 | Robust 2D-to-3D pose solver and camera certificate | BTI-001 | critical |
| BTI-004 | Automatic camera correspondence and candidate selection | BTI-002, BTI-003 | critical |
| BTI-005 | Terrain-aware world-track beliefs | BTI-001, BTI-003 | critical |
| BTI-006 | Class-conditioned trajectory mixture and reachable envelope | BTI-005 | critical |
| BTI-007 | Visibility-aware next-camera, frame-region, and time forecast | BTI-006 | critical |
| BTI-008 | Live invalidation, bounded scheduling, and agent inspection | BTI-004, BTI-007 | critical |
| BTI-009 | Independent-world and held-out recording qualification | BTI-008 | release gate |

Security, privacy, bounds, source custody, generation checks, and stale/unknown
semantics apply from the first unit; BTI-008 does not defer those safeguards.
Use supplied observations and deterministic fixtures to prove an earlier unit
without falsely advertising a not-yet-qualified camera, model, or live transport.

### BTI-001: export contract and native import

Produce an immutable manifest-rooted neutral package in the separate Blender
content-authoring workflow; the public consumer must not need the private skill.
Implement the bounded native reader/compiler with explicit source/member hashes,
scene/evaluation scope, schema normalization, coordinates, scale status, evaluated
triangles/instances, feature mappings, semantic roles, omissions, and use limits.

Compile visual, geometric, and behavioral representations without conflating them.
Preserve aperture hosts, original feature identity, actual terrain levels, and
conservative error bounds for simplified geometry. Reject executable content,
external asset fetches, malformed/oversized data, stale members, and ambiguous
required conversions. Publish child objects before roots through existing owners.

Acceptance: a real exported scene can be queried and compared to source evaluated
geometry; tests cover displaced origins, parent/instance transforms, negative scale,
retired replacements, hidden helpers, real openings, corrupted members, double unit
conversion, relative scale, interrupted import, and optional missing imagery. No
Blender process is needed after export. Import success is not physical accuracy.

### BTI-002: reference-image atlas

Bind each real image/crop to original source identity, PTS/time base, image-domain
transform, camera intrinsics/pose, map-to-property transform, landmark observations,
support, uncertainty, correlation groups, and held-out exposure partition. Reuse
existing recovered poses only after exact-basis verification. Keep descriptors and
matching scores bound to their producer generation and licensing/admission state.

Landmarks need durable support: feature/object identity plus source-map point or
revision-bound surface/triangle coordinates and transform. A bare triangle index
must not survive remeshing as though it retained physical identity. Model-raycast,
triangulated, measured, synthetic, and semantically proposed points remain distinct.

Acceptance: feature/image/3D lookup works in both directions from the moved package;
duplicate observations do not inflate independent support; missing private images,
map changes, descriptor generation mismatch, and unregistered components fail or
degrade explicitly. A model without an atlas remains importable but is not labeled
automatically localizable.

### BTI-003: camera pose geometry before automatic matching

Start with supplied 2D-to-3D correspondences. Implement bounded robust PnP,
identifiable lens-parameter refinement, proper rotation/translation handling,
checked numerical solves, outlier sampling, alternative candidates, and exact
image-domain projections. Freeze the imported scene during pose fitting.

Publish a candidate certificate binding camera/stream mode, twin/atlas, calibration,
scale, image transforms, source observations, solver/numeric policy, retained
alternatives, uncertainty, held-out checks, support region, expiry, and invalidators.
Activation uses existing plan/commit/publication authority, never solver confidence.
Generic identity transforms can be valid; uncalibrated state must be explicit.

Acceptance: independent known-point projections and withheld landmarks; repeated
facades, planar/collinear support, wrong crop/fisheye model, shared map bias,
uncertain scale, virtual cameras, nonfinite values, and positive-depth failures.
Report downstream errors at paths and occlusion boundaries, not only fit residuals.
Canonical rounded storage alone does not establish deterministic floating-point
optimization across all hosts.

### BTI-004: automatic camera registration

Retrieve relevant atlas views, match static real-image features, recover their 3D
identities, and pass candidates to BTI-003. Add bounded synthetic depth/feature-ID
views and architectural point/line proposals where they resolve missing support.
Never ship foreign matching runtimes or fetch model assets implicitly. Unsupported
matching models remain unsupported; owner-supplied correspondences still work.

Acceptance: held-out surveillance images including disjoint camera views, night/IR,
repeated windows, transient foreground, and cameras facing unmapped scenery. Report
automatic success, ambiguity, refusal, and explicit assisted fallback separately.
Fitting a plausible pose in a synthetic render does not verify actual geometry.

### BTI-005: world-space target beliefs

Preserve original 2D tracks and source observations. Project calibrated contact
bearings onto admissible support surfaces and retain ambiguous terrain/deck/stair
solutions. Use synchronized multi-camera triangulation only with justified
association. Otherwise retain a ray/frustum or weaker depth belief.

Bind position/velocity, class/posture alternatives, support, time interval, shared
nuisance uncertainty, source evidence, and observed/propagated status to exact
world generations. Expire short-lived anonymous appearance/context independently
of the underlying evidence retention policy.

Acceptance: measured or independent true-world trajectories with feet obscured,
truncated boxes, crawling, slopes, multiple levels, shallow rays, delayed frames,
identity ambiguity, and calibration loss. A rendered avatar is never ground truth.

### BTI-006: contextual motion without blind spots

Implement a deterministic bounded mixture of continuation, turning, stopping,
surface/portal routes, and admissible off-route motion. Separate movement profiles
for human walking, other supported classes/postures, and unknown targets. Surface
and destination preferences are soft, versioned, evidence-qualified priors.

Maintain likely-route weights and a separate conservative reachable envelope.
Preserve protected high-loss hypotheses even when a path-biased model downranks
them. Never infer hostile intent solely from grass crossing or unusual movement.
Unsupported animal-specific behavior uses broad dynamics rather than human priors.

Acceptance: human follows stone path; human crosses grass; bear/unknown quadruped
does not inherit pedestrian constraints; target stops or turns; uncertain gate or
vegetation state; relaxed class evidence; and budget pressure that must not delete
protected alternatives. Compare any later learned model against this reference.

### BTI-007: predictive camera handoff

Combine trajectory hypotheses with FSS-098 effective visibility. Project body and
posture, not just a point. Include occlusion, visible extent, pixel scale, masks,
mode, sample schedule, health, camera sleep, and detector operating envelope.

Define a joint event over next camera or simultaneous-camera group, image region,
and capture time with an explicit horizon and no-observation mass. Preserve route
and class conditioning; do not multiply separately marginalized outputs as though
independent. Distinguish geometric entry, usable capture, detection, and downstream
availability. Missing empirical calibration stays explicit in probability claims.

Acceptance: targets enter at borders and emerge from hedges inside the frame;
simultaneous views, no next camera, stopped targets, sleeping cameras, nonoverlapping
views, clock uncertainty, and changed buffering. Compare forecasts to actual
subsequent observations, including failures, not only successful reacquisitions.
A forecast cannot itself serve as association or negative-evidence authority.

### BTI-008: operational integration

Compose under Asupersync ownership and the current evidence universe. Invalidate
whole dependent generations conservatively first; narrower repair/revalidation
needs proven dependency closure. Retain source and sentinel work when concentrating
extra evidence acquisition on a predicted camera. Respect effect authority for
any device setting, PTZ, or frame-rate change.

Expose exact objects through existing query, explain, follow, doctor, and witnessed
plan/commit operations. Show observed tracks, propagated estimates, path tubes,
uncertainty, predicted ROIs, and unavailable coverage distinctly. Optional Blender
inspection must not mutate the accepted scene or become a live dependency.

Acceptance: camera bump/crop/zoom, map revision, daylight-to-IR, moved occluder,
clock drift, source loss, stale privacy mask, export denial, cancellation, resource
pressure, restart/replay, and no Blender installed. Verify that restricted users
cannot infer hidden camera counts, routes, or masked-region forecasts.

### BTI-009: qualification that tests model-to-reality error

Build independent latent-world and approximate-imported-world fixtures. Vary map
shape/scale, lens, clocks, occluders, class, and actor paths independently; do not
certify accuracy by rendering and scoring the exact same model alone. Add owner-
authorized held-out real recordings and independent controls for property claims.

Retain pose/location errors and tails, next-camera outcomes, image-region and ETA
coverage/sharpness, identity switches, abstention, protected-route misses, drift
latency, and full resource cost by relevant strata. Test predicted negative evidence
only over witnessed observable intervals. GATE-070/080/115 evidence must bind exact
input roots, source commits, model/numeric policy, calibrations, privacy/authority,
seed/fault schedule, outputs, exclusions, and reproduction commands.

No unit is complete solely because its schema, test names, or this document exists.
Keep missing real-scene, camera, compiler, oracle, or measurement evidence explicit.
