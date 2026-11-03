# Build a localization atlas from retained cameras

`fss-scene-fuse retained-atlas` turns explicitly selected native scene
reconstructions into a portable `FSATLAS1` localization atlas. The existing
`fss-file localize` command can use that atlas to register another camera against
the same imported property twin.

To use currently adopted FSSCAL camera geometry, use
[`retained-calibrated-atlas`](ADOPTED_RECONSTRUCTION_ATLAS.md). It preserves the
same FSATLAS1 archive and consumer while verifying current adoption and original
calibration inputs throughout export.

The command supports the exact existing retained pair and multi-camera v1/v2
queries, including mixed direct and lens-corrected JPEG/AVC/HEVC sources. It
reconstructs the original inputs again and uses actual native descriptors and
solved coordinates. It does not recover descriptors from report hashes or accept
replacement landmark coordinates.

## 1. Preview the reconstruction

Run the existing command for your query and inspect its complete alternatives:

```sh
fss-scene-fuse retained-multimatch \
  --root deployment --site site:example \
  --twin property.fsstwin --rig cameras.json --query cameras-v2.json \
  --work-units 16000000000 --timeout-ms 300000 \
  --report-out reconstruction-preview.json
```

Use `retained-match` for a two-camera query. See
[retained matching](RETAINED_SCENE_MATCHING.md),
[multi-camera matching](RETAINED_MULTICAMERA_MATCHING.md) and
[lens correction](RETAINED_LENS_MATCHING.md) for source selection and image modes.

The relevant preview fields are:

| Selection input | Two-camera report | Multi-camera report |
|---|---|---|
| Whole `association_evidence` | `report.analysis.association_evidence` | `report.analysis.geometry.scene_evidence` |
| Per-landmark `hypothesis` | `report.analysis.hypotheses[i].evidence_digest` | `report.analysis.geometry.components[i].evidence_digest` |
| Solved disposition | `hypotheses[i].estimate.state == "estimated"` | `components[i].outcome.state == "estimated"` |
| Visibility contradiction | `hypotheses[i].estimate.nominal_occlusion_conflict` | `components[i].outcome.nominal_occlusion_conflict` |

Only solved candidates without a nominal occlusion conflict are eligible.
Eligibility does not establish that a feature is a durable architectural
landmark. Inspect its source support and declare that separately. Unmatched,
ambiguous, incomplete, conflicting and geometrically refused evidence remains
in the preview and subsequent export manifest.

## 2. Declare the selected static landmarks

Create a selection document. This example shows its shape; replace every digest
placeholder with a complete nonzero SHA-256 value from the applicable evidence
or an explicitly recorded owner assumption.

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

`landmark` is your nonzero map-local identifier. `physical_group` identifies one
declared distinct physical point; consolidate aliases before selection.
`feature` is a zero-based feature ordinal in the exact imported twin, not a
mutable display name or an image-local feature ID. It is an explicit semantic
assignment and does not prove that the estimated point lies on the named mesh.
`enduring_static_basis` records the evidence or assumption for continued static
use beyond the short reconstruction capture window.

Choose one through 128 landmarks. Hypothesis, landmark and physical-group IDs
must be unique. Multiple landmarks can name the same architectural twin feature
or static-support record. The parser accepts exact canonical unsigned decimal
numbers or strings; landmark/group IDs are bounded to u64 and feature ordinals
to u32. The complete document is at most 64 KiB. Unknown, duplicate or missing
fields and coordinate/descriptor/error overrides refuse.

One landmark is sufficient to create a candidate archive, but camera pose
estimation requires at least six distinct matched landmarks and adequate
geometry. Broad image support, several depths and independently checked
landmarks remain necessary for useful registration. More reference samples of
the same point do not increase the independent support count.

## 3. Export the candidate atlas

```sh
fss-scene-fuse retained-atlas \
  --root deployment --site site:example \
  --twin property.fsstwin --rig cameras.json --query cameras-v2.json \
  --selection static-landmarks.json \
  --atlas-out property.fsatlas --report-out property-atlas-report.json \
  --work-units 16000000000 --timeout-ms 300000
```

Optional `--expected-input`, `--expected-selection` and `--expected-anchor`
pins constrain exact query bytes, selection bytes and the entry authority
anchor. Changing the source, current privacy mask, rig, image mode or matching
policy can change association evidence; inspect a new preview rather than
substituting an old hypothesis ID. Selection ordering has no semantic effect.
The manifest separately retains the original selection-file hash and its
normalized declarations.

Every twin-feature ordinal and source selection is checked before decoding.
All lens plans are admitted before the first native decode can publish a JPEG
derivative. The producer then copies the actual points, all member bindings and
complete participating feature frames. Original exposure, native decoder
receipts, source and corrected image identities, masks and clock alignment stay
separate and explicit.

The complete source records, native geometry, admission receipt, provenance
manifest and archive bytes are serialized before the sealed owners revalidate
every original retained range and current privacy policy. Analysis failure,
source loss, changed privacy, stale pins, cancellation or insufficient allowance
produces no successful export and creates no output files.

## 4. Use the output in camera localization

The report schema is `fss.reconstruction_atlas_retained.v1`. Its `report.archive`
object provides:

| Report field | Use |
|---|---|
| `package_digest` | Exact whole-file SHA-256 for `--atlas-sha256`. |
| `provenance_digest` | Exact manifest SHA-256 for `--atlas-provenance-sha256`. |
| `descriptor_digest` | Native descriptor-generation pin; the existing consumer checks its admitted native generation. |
| `atlas_digest` | Normalized semantic atlas identity, distinct from the package checksum. |
| `bytes`, `landmarks`, `references`, `bindings` | Complete archive inventory. |

Pass `property.fsatlas` and those pins to your existing `fss-file localize`
invocation for a fresh retained exposure, retaining its required twin, source
selection, camera intrinsics and image-domain arguments:

```text
--atlas property.fsatlas
--atlas-sha256 sha256:PACKAGE_HEX
--atlas-provenance-sha256 sha256:PROVENANCE_HEX
```

The consumer rejects an exposure already used as an atlas reference, including
attempts to wrap that exposure in a changed pixel or image-domain identity.
Fresh imagery is still not automatically an independently held-out physical
camera or a measured calibration. Localization returns fixed-map pose candidates;
calibration acceptance and activation retain their existing separate contracts.

## Exact provenance and complete alternatives

`report.provenance_manifest_utf8` contains the **exact compact UTF-8 JSON
manifest as a string**. Hash its decoded UTF-8 bytes directly to reproduce
`provenance_digest`. Do not parse and reserialize it before checking that hash:
different object ordering or number formatting changes the byte identity.

The manifest's `fss.reconstruction_atlas_provenance.v1` schema includes the twin,
rig, query, source records, complete pair/component geometry, selected support
declarations, native atlas-build receipt and entry/final anchors. Each source
record is independently hashed from its exact rendered view. The manifest
contains the semantic atlas hash but excludes the final package hash, avoiding
a circular dependency; the archive pins the manifest, and the final report pins
the archive. The complete report body has its own exact UTF-8 digest.

Rust callers can inspect both the report and extracted manifest with
`fss_cli::json_input::parse_reconstruction_atlas_report`. Its bounded report
profile permits the long embedded manifest while ordinary intent and supervisor
reader limits remain unchanged. Parsing does not authenticate any named source.

## Uncertainty, privacy and publication

The atlas is a derived candidate. Enduring stability, physical groups and twin
feature assignments remain declarations. Absolute landmark error is **unknown**.
Conditional pixel-noise covariance is retained as a diagnostic and is not
converted into an absolute map-error bound. Shared camera, map, lens, clock and
correspondence errors do not disappear as more correlated features are added.
Coordinates retain the exact twin's scale and source units.

Archive hashes grant no source-access permission and do not establish that
future privacy or retention policy still permits the exported descriptors.
Treat the atlas, source records and report as local private derivatives subject
to their source retention/deletion policy. The pure native API and its ownership
boundary are documented in [Reconstructed atlas API](RECONSTRUCTED_ATLAS_API.md).

Output files are create-only and private on Unix (`0600`). A complete archive is
written and synchronized before the optional report file and stdout. Existing
files and symlinks refuse. I/O failure or cancellation during publication can
leave a newly created partial or complete file; inspect those paths before retrying
with fresh names. Checksums reject truncated archives. Stdout failure does not
remove completed files. No canonical world revision or calibration is activated.

## Bounds

The original matcher limits remain: two cameras or 3–8 cameras, at most 128
features per view and 256 actual features total, and bounded complete source
ranges. The builder admits at most 128 landmarks, retains every source/candidate
in provenance and never silently truncates an inventory to fit output.

The selection limit is 64 KiB, archive format limit 8 MiB and complete report
limit 32 MiB including its newline. `--max-report-bytes` can lower that allowance.
Geometry/extraction/rectification/build/report work defaults to 8 billion units
and is capped at 16 billion. Original reads share 4 GiB including final
revalidation; decoder axes remain separate: 2 billion JPEG work units, 512 MiB
video encoded bytes and 2,147,483,648 coded-luma units. Timeout defaults to 30,000
ms, with a 3,600,000 ms maximum. These are resource ceilings, not throughput claims.

Exit 0 means a complete candidate export. Exit 2 covers input, authority,
custody, privacy, cancellation, work/output or publication failure. Unselected
scene conflicts remain diagnostics; selecting an eligible subset does not
resolve or erase them.
