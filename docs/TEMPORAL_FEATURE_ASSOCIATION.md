# Automatic moving-feature reconstruction

`fss_twin::temporal_feature_association::associate_temporal_features` connects
native image descriptors across repeated camera exposures and estimates a
conditional 3D position and velocity in an imported property twin. This closes
the correspondence gap before the existing `multiview_motion::fuse_scene_motion`
solver: callers no longer have to supply a common-feature assignment for every
observation.

The operation accepts existing `FeatureView` snapshots and
`TemporalAssociationOptions`. Source custody, current privacy authorization,
camera mapping and clock alignment belong to the enclosing owner. Constructing
a `FeatureView` does not authenticate those facts.

## Sources and time

One operation contains four through sixteen distinct original exposures from
two through eight logical cameras. Each exposure has at most 128 selected
features; the complete inventory, including unmatched and empty views, is at
most 256 features. Every input is validated before descriptor comparison.

Repeated observations of one logical camera require the same camera snapshot,
calibration generation, intrinsics, image domain and mapping declaration. They
retain their shared camera/error basis. An original exposure digest cannot
appear twice, even under a changed camera or pixel wrapper. Identical encoded
bytes or pixel values in different original exposures are permitted; this is
not evidence of independent sensors.

Every view retains its full inclusive capture interval, original exposure,
source/pixel/mask/descriptor identities, privacy namespace and clock evidence.
The complete capture hull must fit the declared limit of at most sixty seconds.
Each interval must also fit `max_capture_uncertainty_ns`. A zero uncertainty
allowance admits exact timestamps only.

The native motion solver uses integer interval midpoints, rounded toward the
start, as its explicitly nominal times. Full intervals remain in the result.
Every fitted component reports position at the **unchanged global requested
scene time**. A component that does not bracket that time refuses; its time is
never silently clamped to a smaller range and no extrapolation is certified.

## Correspondence and complete alternatives

Every unordered pair of source exposures has a complete Cartesian descriptor
table. The exact 256-bit Hamming distance is tested against an absolute ceiling
and a strict best/runner-up ratio in both directions. Every tied nearest
alternative remains visible. An absent runner-up, a tie, or a nonmutual nearest
neighbor does not become a selected correspondence.

No stationary-point epipolar prefilter is used. A moving point seen at different
times need not lie on the other exposure's static epipolar line. Geometry is
checked by fitting the whole component at its original observation times.

Selected descriptor links form conditional components. The result retains
every component and all its links. Outcomes distinguish:

| Outcome | Meaning |
|---|---|
| `Unmatched` | A feature has no selected descriptor link. |
| `ExposureConflict` | A cycle joins different features from the same exposure; none is chosen. |
| `IncompletePairSupport` | At least one direct member pair is unsupported; transitivity does not supply the missing correspondence. |
| `InsufficientObservations` | A closed component has fewer than four observations. |
| `InsufficientCameras` | A closed component has observations from fewer than two logical cameras. |
| `Fused` | The native constant-velocity fit succeeded with every component observation retained. |
| `Refused` | Complete descriptor support failed timing, observability, speed, residual or other geometry checks. |

A fit has one feature per participating **exposure**, so repeated cameras are
valid. Every pair of its members needs a direct selected link. No outlier,
competing feature or weak view is discarded to manufacture a fit. Components
can occupy a subset of the original exposures; the entire original inventory
and its decisions still bind their evidence.

The solver estimates `[x, y, z, vx, vy, vz]`. It retains a full conditional 6x6
pixel-noise covariance, all observation residuals and nominal mesh visibility
at each observation's own time. An opaque-surface conflict remains explicit
even when reprojection is excellent. The fit does not establish object/person
identity, continued constant velocity, a persistent track merge or a static
localization landmark.

## Uncertainty and evidence

Coordinates and velocity use the exact twin's source units and seconds. Relative
scale is not converted to metres. Camera, map, clock, correspondence, lens,
rolling-shutter and acceleration errors are not included in the conditional
pixel covariance. Repeated camera observations do not remove their common
calibration error.

Canonical ordering is camera, full capture interval and original exposure
digest; image features retain their native canonical IDs. Four registered
domain-separated digests bind the whole scene, each exposure pair, each
component and each derived observation. Changing an unused source, mask,
timing declaration, camera or policy changes the scene identity. Permuting
the same input snapshots does not.

Solver exposure handles are the canonical view index plus one; component track
handles are query-local. The complete original source digests remain in the
immutable snapshots and evidence hashes. These handles do not create durable
physical identities or source-access permission.

## Bounded execution

At the full profile there are at most 120 exposure pairs, 30,720 Cartesian
descriptor rows, 3,840 per-pair feature outcomes, 1,920 selected links and 256
components. A feature outcome can retain all 128 nearest ties. Allocation and
work are bounded before expansion, and native geometry uses the same caller
`WorkBudget`.

Insufficient work, allocation limits or cancellation discard the whole pending
result. A smaller output budget must not be implemented by deleting alternatives
or returning a graph prefix. Ordinary motion refusals remain complete component
diagnostics. This pure API performs no source reopening, privacy activation,
filesystem publication, calibration activation or world-state mutation.

An enclosing retained-media command must bind actual source-owner snapshots,
retain complete original/rectified image lineage, and revalidate all original
source ranges and current privacy after complete analysis and serialization.
