# Reconstruct adopted cameras with radial lens distortion

The adopted-camera commands support the two-term radial model already stored
in FSSCAL01/02. Use **`fss.scene_camera_rig_adopted.v2`** to opt into verified
native rectification for stereo, multi-camera, moving-feature reconstruction
and static atlas export. The command names and current-adoption checks stay
the same:

```sh
fss-scene-fuse retained-calibrated-match \
  --root deployment --site site:example \
  --twin property.fsstwin --rig adopted-cameras-v2.json \
  --query retained-lens-query.json --report-out corrected-scene.json \
  --work-units 16000000000 --timeout-ms 300000
```

Start with the [adopted-camera workflow](ADOPTED_CALIBRATION_RECONSTRUCTION.md).
The rig retains exactly its existing fields: calibration semantic and whole-file
digests, original camera inputs, current adoption receipts, physical sensors,
twin identity and explicit local handles. Change its `schema` to
`fss.scene_camera_rig_adopted.v2`. No pose, intrinsic or lens override is added
to the rig. Update the query's `camera_rig_digest` to hash the new exact rig bytes.

## Declare each original image model

For a radial camera, use the existing pair/multi-camera **query v2** `image`
object. The temporal query's existing v1 format already includes this explicit
image object. For example:

```json
{
  "kind": "rectified",
  "source_domain_digest": "sha256:ORIGINAL_CALIBRATION_IMAGE_DOMAIN_HEX",
  "lens_basis": "sha256:FSSCAL_SEMANTIC_IDENTITY_HEX",
  "source_intrinsics": {
    "width": 192,
    "height": 128,
    "fx": 160,
    "fy": 160,
    "cx": 96,
    "cy": 64
  },
  "distortion": {
    "kind": "brown_conrady",
    "radial": [-0.08, 0.01, 0],
    "tangential": [0, 0]
  },
  "maximum_radius": 2,
  "luma_range": "full"
}
```

The dimensions and coefficients above are an example. Each source must match
its own adopted calibration exactly:

| Query value | Required origin |
|---|---|
| `source_domain_digest` | Original image domain recovered from the hash-verified calibration observation file or frame metadata. |
| `source_intrinsics` | The refined calibrated camera's original dimensions and `fx`, `fy`, `cx`, `cy`. Seed intrinsics cannot substitute for refined values. |
| `lens_basis` | FSSCAL's semantic identity, not the whole-file hash, adoption receipt hash or rig hash. |
| Brown `radial` | Exactly `[k1, k2, 0]` from that camera's adopted record. |
| Brown `tangential` | Exactly `[0, 0]`. |

The model uses normalized pinhole coordinates with
`r² = x² + y²`, `s = 1 + k1*r² + k2*r⁴`, and distorted coordinates
`[x*s, y*s]`. This is exactly the stored two-term radial calibration model.
Fisheye coefficients, a third radial term, tangential terms or a different
source matrix cannot be substituted through the v2 profile.

`maximum_radius` and `luma_range` remain explicit owner declarations. Radius
is finite and in `[1e-6, 64]`; luma range is `full` or `video`. The native plan
checks the requested lens domain for folding and singular behavior before any
source decode. A smaller declared radius may leave output pixels unmapped;
the coverage receipt preserves those exclusions. The command does not silently
choose a smaller radius to make a model pass.

The target pinhole grid has **exactly the refined original dimensions and
intrinsics**. This profile adds no crop, zoom, rotation or target-matrix override.
The numeric rig `image_domain` is a scene-local handle for that target grid;
the actual derived image-domain digest comes from the compiled native plan.
Raw and corrected image identities remain separate.

## Mixed rigs and existing inputs

V2 rigs may mix corrected radial cameras with direct cameras whose adopted
radial terms are exactly zero. Direct cameras use the existing `pinhole` image
declaration and must retain their original image domain and grid. A nonzero
radial camera always requires explicit correction. Repeated observations of one
fixed camera must keep the same lens declaration.

Rig v1 retains its original direct-pinhole contract, report schemas and semantic
identity encoding. It continues to reject nonzero radial terms and rectification
declarations. Native callers also have distinct resolver and rig-constructor
entrypoints; passing a rectification-profile owner to the old constructor refuses
even when its coefficients happen to be zero.

## Native pixels, privacy and current authority

The command checks every complete source model against the sealed calibration
before preparing any image. All native maps compile before the first decode.
Actual original dimensions, pixels, exposure, map, corrected domain and receipt
are bound after extraction and checked against those prepared plans.

Correction uses the existing first-party native rectifier and sealed retained
feature owner. Privacy follows the full interpolation footprint: every
positive-weight source tap and the complete feature/descriptor support must be
allowed. Corrected pixels do not grant access to excluded source regions. The
report preserves original and corrected pixel/domain identities, map digest,
coverage counts and allowed-mask provenance. Original-source/current-privacy
and adoption/withdrawal revalidation still occur after complete analysis, with
the deployment owner held through publication.

The new reconstruction schema is `fss.scene_feature_match_adopted.v2`, containing
the complete adopted model and conditional covariance as well as every native
source, correspondence alternative, fit and refusal. `sigma_pixels` is declared
on the actual feature output grid; it does not account for interpolation
correlations or lens-parameter uncertainty. Absolute calibration and landmark
error remain unknown. The existing work, read, decoder, output and timeout bounds
remain in force, with map preparation charged to shared geometry work.

## Export corrected landmarks for another camera

Preview the corrected static reconstruction, select its exact association and
hypothesis pins, then use the [adopted atlas workflow](ADOPTED_RECONSTRUCTION_ATLAS.md):

```sh
fss-scene-fuse retained-calibrated-atlas \
  --root deployment --site site:example \
  --twin property.fsstwin --rig adopted-cameras-v2.json \
  --query retained-lens-query.json --selection static-landmarks.json \
  --atlas-out corrected-property.fsatlas --report-out corrected-atlas.json \
  --work-units 16000000000 --timeout-ms 300000
```

The report and manifest use `fss.reconstruction_atlas_adopted.v2` and
`fss.reconstruction_atlas_adopted_provenance.v2`. They preserve full original
and corrected image provenance. **FSATLAS1 and `fss-file localize` remain
unchanged**; use the new package and exact provenance pins returned by this
export. Old preview pins are not interchangeable with corrected reconstruction.
Moving-feature queries still refuse static atlas export. The package remains a
derived candidate; it activates no calibration, twin revision, identity or effect.
