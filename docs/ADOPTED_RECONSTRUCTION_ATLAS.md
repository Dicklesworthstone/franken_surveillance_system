# Export a localization atlas from adopted camera calibration

`fss-scene-fuse retained-calibrated-atlas` connects currently adopted camera
calibration, retained camera images, native 3D reconstruction and portable
localization. The resulting **FSATLAS1** package can be used by the existing
`fss-file localize` command to register another camera into the same property
twin. No manually copied camera poses or replacement landmark coordinates are
needed.

The command accepts the same strict `fss.scene_camera_rig_adopted.v1` rig as
[`retained-calibrated-match`](ADOPTED_CALIBRATION_RECONSTRUCTION.md), and the
existing static retained pair or multi-camera v1/v2 query. Intrinsics and poses
come from the exact FSSCAL01/02 calibration and current retained adoption
receipts. Every rig camera must participate in the query. This initial image
profile requires the original calibrated pinhole domain; radial distortion,
rectification declarations and moving-feature queries refuse explicitly.

## 1. Preview the adopted reconstruction

Keep the calibration artifact, original camera-input files and current adoption
receipt pins described in the [adopted calibration guide](ADOPTED_CALIBRATION_RECONSTRUCTION.md).
The query's `camera_rig_digest` must hash the exact adopted rig JSON bytes.

```sh
fss-scene-fuse retained-calibrated-match \
  --root deployment --site site:example \
  --twin property.fsstwin --rig adopted-cameras.json \
  --query retained-query.json --report-out adopted-preview.json \
  --work-units 16000000000 --timeout-ms 300000
```

Inspect the complete correspondence alternatives. Selection pins come from
`report.analysis.geometry.native_diagnostics` in this preview:

| Selection field | Static pair | Static multi-camera |
|---|---|---|
| `association_evidence` | `scene_evidence` | `scene_evidence` |
| Each `hypothesis` | `hypotheses[i].evidence_digest` | `components[i].evidence_digest` |
| Numerical fit | `hypotheses[i].estimate.state == "estimated"` | `components[i].outcome.state == "estimated"` |
| Visibility contradiction | `hypotheses[i].estimate.nominal_occlusion_conflict` | `components[i].outcome.nominal_occlusion_conflict` |

Only estimated points without a nominal occlusion conflict are eligible.
Review their physical support and enduring static suitability before selection.
All candidates, unselected alternatives and geometric refusals remain in the
export manifest; selecting a useful subset does not resolve the rest of the
scene.

## 2. Select enduring static landmarks

Use the existing `fss.reconstruction_atlas_selection.v1` contract. Replace the
structural digest placeholders below with exact nonzero SHA-256 identities.

```json
{
  "schema": "fss.reconstruction_atlas_selection.v1",
  "association_evidence": "sha256:WHOLE_NATIVE_ASSOCIATION_HEX",
  "landmarks": [
    {
      "hypothesis": "sha256:SELECTED_HYPOTHESIS_OR_COMPONENT_HEX",
      "landmark": "101",
      "physical_group": "301",
      "feature": 0,
      "enduring_static_basis": "sha256:STATIC_REFERENCE_ELIGIBILITY_HEX"
    }
  ]
}
```

`landmark` is a nonzero map-local ID; `physical_group` declares a distinct
physical point after consolidating aliases. `feature` is an existing zero-based
feature ordinal in the exact imported twin. `enduring_static_basis` names the
evidence or explicit owner assumption for using this point beyond the capture
window. These declarations do not authenticate physical identity or prove a
point lies on its assigned twin mesh.

Choose 1–128 landmarks with unique hypothesis, landmark and physical-group IDs.
The 64 KiB document accepts canonical unsigned integer tokens or decimal
strings and rejects unknown or duplicate fields. Coordinates, descriptors and
error overrides are not accepted. One selected point can form an archive;
camera pose estimation needs at least six distinct matched landmarks and
adequate geometry. Multiple depths and broad image coverage improve useful
registration support; repeated views of one point do not increase independent
support.

## 3. Export and use the package

```sh
fss-scene-fuse retained-calibrated-atlas \
  --root deployment --site site:example \
  --twin property.fsstwin --rig adopted-cameras.json \
  --query retained-query.json --selection static-landmarks.json \
  --atlas-out adopted-property.fsatlas --report-out adopted-atlas-report.json \
  --work-units 16000000000 --timeout-ms 300000
```

`--expected-input`, `--expected-selection` and `--expected-anchor` optionally
pin exact query bytes, selection bytes and entry authority. `--principal`
selects the replay principal. Changing source evidence, privacy, image mode,
calibration, rig or correspondence policy can invalidate the preview's
association and hypothesis pins. Run a new preview after such a change.

The report uses `fss.reconstruction_atlas_adopted.v1`. Its `report.archive`
object has the same package-consumer fields as the nominal atlas command:

| Field | Meaning |
|---|---|
| `package_digest` | Whole FSATLAS1 file SHA-256; pass as `--atlas-sha256`. |
| `provenance_digest` | Exact manifest SHA-256; pass as `--atlas-provenance-sha256`. |
| `descriptor_digest` | Native feature-generation pin checked by the localization consumer. |
| `atlas_digest` | Semantic atlas identity, separate from the file checksum. |
| `bytes`, `landmarks`, `references`, `bindings` | Complete archive inventory. |

Use the package and these exact pins in the existing `fss-file localize`
invocation for a fresh retained image, together with its required twin, source
selection, camera intrinsics and image-domain arguments:

```text
--atlas adopted-property.fsatlas
--atlas-sha256 sha256:PACKAGE_HEX
--atlas-provenance-sha256 sha256:PROVENANCE_HEX
```

The archive format and consumer remain unchanged. A reference exposure cannot
be reused as the supposedly fresh localization observation, including through
a changed pixel or image-domain identity. Fresh imagery alone does not prove
an independent physical camera or an independently measured calibration.

## Current authority and exact provenance

The command authenticates original source capsules, calibration bytes, original
camera-input files, selected physical sensors and currently adopted receipts
before decoding. Each original image domain, dimensions and any recorded JPEG
component interpretation must agree with calibration. Missing, superseded,
withdrawn, aliased or corrupt adoption custody refuses.

Native reconstruction and atlas construction retain actual feature descriptors,
solved coordinates and every selected member binding. All source-dependent
serialization and archive construction finish before final original-source,
current-privacy and adoption/withdrawal checks. The exclusive deployment owner
remains held through archive, report and stdout publication. A JPEG derivative
may be retained before a later analysis refusal, following the existing decode
contract.

`report.provenance_manifest_utf8` contains the exact compact JSON manifest as a
string. Hash its decoded UTF-8 bytes directly to reproduce `provenance_digest`;
parsing and reserializing it may change the byte identity. Its schema is
`fss.reconstruction_atlas_adopted_provenance.v1`. The manifest includes:

- Exact twin/source-scene identities, scale, rig/query/selection hashes and
  normalized declarations, plus entry and final authority anchors.
- Complete adopted calibration, original image/input provenance, all joint
  camera generations, selected current receipts, refined geometry and local
  covariance in its original parameter order.
- Every original source record and its exact record hash, native decode/feature
  receipts, privacy and capture support; source cameras have `adopted_current`
  status.
- Complete native geometry and unresolved alternatives, the atlas-build receipt,
  selected static-support declarations and all reference/member bindings.

The manifest includes the semantic atlas hash and excludes the final package
hash. The archive pins that manifest, and the report pins the archive without a
circular hash dependency. `report_digest` separately hashes the exact compact
report-body bytes. Rust readers can use
`fss_cli::json_input::parse_reconstruction_atlas_report` for the bounded report
and manifest profile; parsing alone authenticates no named source.

## Limits and interpretation

Adoption records owner authority. Absolute camera and landmark error remain
**unknown**. Local calibration covariance has no cross-camera blocks;
reconstruction covariance is conditional on the model and pixel noise. Neither
becomes an absolute physical error bound. Shared map, lens, clock and
correspondence errors remain possible. Export produces a derived candidate and
does not activate a calibration, revise the twin, establish a persistent track
or trigger an effect.

Two-camera or 3–8-camera queries retain their original 128-feature-per-view and
256-total-feature limits. Selected calibration inputs share 20 MiB; cumulative
authority reads share 64 MiB and original source reads share 4 GiB, including
their final revalidation. The archive limit is 8 MiB and complete report limit
32 MiB including its newline. `--max-report-bytes` can lower the report ceiling.
Geometry/extraction/build/report work defaults to 8 billion units, maximum
16 billion; JPEG work has a separate 2 billion allowance. Video admission
retains separate 512 MiB encoded-byte and 2,147,483,648 coded-luma ceilings.
Timeout defaults to 30,000 ms, maximum 3,600,000 ms. Final cost includes
revalidation and report serialization; CPU time, energy and peak memory remain
explicitly unmeasured.

Exit **0** means a complete candidate export. Exit **2** covers input, authority,
custody, privacy, cancellation, resource or publication refusal. Invalid twin
feature ordinals and temporal queries refuse before source decoding. Analysis
failures create no output files. Outputs are private (`0600` on Unix) and
create-only; existing files and symlinks refuse. The archive is synchronized
before report/stdout release. Publication failures can leave new partial or
complete files; inspect them and use fresh paths for a retry. Archive checksums
reject truncation, and failed stdout leaves complete files available.

Atlas descriptors and provenance remain source-derived private data. Checksums
grant no access permission and cannot establish future privacy or retention
eligibility. See the [native atlas API](RECONSTRUCTED_ATLAS_API.md) for the
producer/consumer ownership boundary.
