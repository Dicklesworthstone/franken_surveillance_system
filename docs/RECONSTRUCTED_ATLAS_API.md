# Native reconstruction to localization atlas

`fss_twin::reconstruction_atlas` connects native pair/multi-camera feature
reconstruction to the existing `LocalizationAtlas` and `FSATLAS1` archive APIs.
A new camera can match against these reconstructed reference landmarks without
re-entering their coordinates or exporting a separate COLMAP model.

This is an explicit producer of an **unactivated candidate atlas**. Its pure
Rust inputs are immutable native association results. The owner must retain the
source records, authorize descriptor use and revalidate source custody/current
privacy before publishing or reusing an archive.

## Inputs and admission

`Reconstruction::Pair(&FeatureAssociation)` accepts the two-camera native
matcher. `Reconstruction::Multiview(&MultiFeatureAssociation)` accepts the
complete three-through-eight-camera graph and its joint point estimates.

`AtlasBuildRequest` contains the exact whole-association evidence digest, an
explicit selection of one through 128 landmarks, and one `ReferenceSource` for
**every original input camera**, including a view that contributes no selected
landmark. Reference records are supplied in any order and normalized by camera.
Their `source_record` pins must name complete records containing the source,
capture/clock alignment, rig camera, image conversion and extraction selection.
A digest alone does not authenticate those records.

Each `LandmarkSelection` supplies:

| Field | Meaning |
|---|---|
| `hypothesis` | Exact existing pair-hypothesis or multi-camera component evidence digest. |
| `landmark` | Nonzero owner-chosen map-local landmark ID. |
| `physical_group` | Nonzero declared distinct physical-point group. Consolidate aliases before selection. |
| `feature` | Existing zero-based feature ordinal in the exact imported property twin. |
| `enduring_static_basis` | Nonzero evidence or explicit assumption supporting use as a static landmark beyond the reconstruction capture window. |

The capture-window static assumption used for triangulation does not establish
that a point remains a suitable long-lived reference. The extra static
declaration and the semantic twin assignment remain owner declarations. They
are not inferred from descriptor similarity or nominal 3D position.

The builder refuses unknown or changed evidence, missing source records,
duplicate landmark/group/hypothesis declarations, repeated member associations,
wrong twin/basis, unknown twin feature ordinals, and any selected unmatched,
conflicted, incomplete or geometrically refused candidate. A solved point with
a nominal opaque-mesh visibility contradiction also refuses admission.
Selecting an eligible subset leaves every other candidate visible in the
receipt; it does not resolve the rest of the scene by omission.

## Actual geometry and descriptors

The producer copies the native solved position unchanged. Every camera/member
binding of each admitted point is retained; there is no per-landmark outlier
removal or replacement correspondence. Complete participating reference frames
retain their actual native descriptors, feature IDs, exposure, pixel/grid
identity and full allowed-mask digest. Unbound features remain in the frame,
but only explicitly admitted bindings contribute atlas matching samples.

Original logical camera handles become local atlas reference handles. They do
not become independently certified physical-camera identities. Multiple views
of one landmark remain one physical support group during localization.

**Absolute landmark error is always unknown (`None`).** Conditional pixel-noise
covariance, reprojection residuals and a twin's map-error diagnostic cannot
establish a deterministic absolute error for a triangulated landmark. The full
conditional covariance and residuals remain in the producer receipt. Coordinates
stay in the twin's original source units and scale basis.

## Build, retain provenance, encode

```rust,ignore
use fss_twin::atlas_archive::encode_atlas;
use fss_twin::reconstruction_atlas::{
    AtlasBuildRequest, Reconstruction, build_reconstruction_atlas,
};

let request = AtlasBuildRequest {
    association_evidence: matches.evidence(),
    selections: &owner_selected_landmarks,
    references: &complete_source_records,
};
let built = build_reconstruction_atlas(
    &twin,
    &request,
    Reconstruction::Multiview(&matches),
    &mut work,
)?;

// Retain a complete manifest with the original source records, exact query/rig,
// native geometry, selection declarations, build receipt and semantic atlas ID.
// It must not include the final package hash: the package pins this manifest.
let archive = encode_atlas(
    built.atlas(),
    exact_manifest_sha256,
    built.references(),
    &mut work,
)?;
// Revalidate all original source owners/current privacy before publication.
```

`ReconstructedAtlas::atlas()` exposes the unchanged localization API.
`references()` exposes the included archive provenance rows in reference order.
`receipt()` exposes all original source records, every native candidate's
eligibility/selection, every admitted landmark's full geometry and member
support, and the normalized atlas digest. Source records for unused views remain
in the receipt even though no archive frame is created for them.

The new canonical domains are `fss.reconstruction_atlas_landmark.v1` and
`fss.reconstruction_atlas_receipt.v1`. Selection/source order does not change
the canonical output. Changes to static declarations, group/support assignment,
source record pins, native geometry or association evidence change the applicable
identities. `FSATLAS1` itself is unchanged.

The pure constructor performs no decoding, I/O, activation or source reopening.
It charges its complete bounded work and returns no partial success on resource
exhaustion or cancellation. All original static matcher bounds continue to
apply: at most eight views and 256 selected features total, with at most 128
admitted landmarks.

## Use in another camera

The encoded bytes load through `decode_atlas` with independent exact package,
provenance and descriptor pins. `LocalizationAtlas::localize` or the existing
retained `fss-file localize` command can then match another exposure and run
native image-to-map camera pose estimation.

The existing localizer rejects any query that reuses an atlas reference
exposure, even if it is given changed pixel/domain wrappers. A fresh exposure
still does not by itself establish a held-out physical camera or independently
validated map. Pose candidates remain fixed-map fits; they do not automatically
activate camera calibration. Field error, landmark stability, map correlation,
appearance changes and sufficient geometric support require separate evidence.
