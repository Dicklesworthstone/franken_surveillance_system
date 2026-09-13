# Existing reconstruction -> reloadable atlas -> camera pose

`scripts/export_localization_atlas.py` is a separate owner-run authoring/migration
producer. It reads a frozen COLMAP text model, selected real grayscale reference
images, explicit masks, source exposure records and a map-to-property similarity.
It writes `provenance.json` followed atomically by `atlas.fsatlas`. The always-on
Rust consumer uses neither Python, COLMAP, Pillow nor Blender. No private skill
implementation or property assets are copied into this repository.

This connects existing reconstruction artifacts to BTI-002/004. It is not structure
from motion, automatic map alignment, footage decoding, lens correction, field
qualification or calibration activation. A producer result remains unqualified.

## Input recipe

All file paths are relative to the recipe directory, confined beneath it (including
symlinks), and paired with hashes of their exact encoded bytes. The following
schematic shows required fields; use real identities and selected map IDs, not the
example tokens. Geometry stays in the twin's source units.

```json
{
  "schema": "fss.colmap-atlas-recipe/1",
  "twin": {"path": "property.fsstwin", "sha256": "EXACT_TWIN_HASH"},
  "source_scene_sha256": "EXACT_SAVED_BLEND_HASH",
  "model": {
    "cameras": {"path": "sparse/cameras.txt", "sha256": "CAMERAS_HASH"},
    "images": {"path": "sparse/images.txt", "sha256": "IMAGES_HASH"},
    "points3D": {"path": "sparse/points3D.txt", "sha256": "POINTS_HASH"}
  },
  "map_to_property": {
    "scale": 1.0,
    "rotation": [[1,0,0],[0,1,0],[0,0,1]],
    "translation": [0,0,0]
  },
  "maximum_reference_snap_px": 0.75,
  "maximum_reprojection_px": 3.0,
  "landmarks": {
    "123": {"feature_id": "feature-wall-front", "physical_group": 123, "error": null}
  },
  "references": [{
    "image_id": 17,
    "image_name": "front.pgm",
    "image": {"path": "images/front.pgm", "sha256": "IMAGE_FILE_HASH"},
    "allowed_mask": {"path": "masks/front.bin", "sha256": "MASK_HASH"},
    "image_domain_kind": "undistorted-pinhole-pixel-edge",
    "image_domain_sha256": "EXACT_IMAGE_TRANSFORM_IDENTITY",
    "partition": "mapping",
    "source": {"sha256": "ORIGINAL_VIDEO_HASH", "stream": 0, "pts": 12345, "time_base": [1,90000]}
  }]
}
```

`map_to_property` maps `X_property = scale * R * X_map + t`; it must be an already
supported alignment to the exact exported twin, not an optimizer's guessed frame.
The producer updates reference camera transforms with the same similarity exactly
once. It neither changes the master scene nor assumes that metres in a UI establish
physical scale. Feature assignments and optional coordinate-error bounds are owner
inputs. Unspecified errors stay unknown; reprojection RMS is not a position bound.
The source-file hash/PTS declaration does not establish availability of the original
video; the operator retains that custody independently.

Selected map landmarks must have reciprocal image/point tracks across at least two
source views. This is a consistency test, not a sufficient-parallax or accuracy
certificate. Missing points, repeated physical groups, coincident positions, bad
transforms and unsupported camera models fail explicitly. PINHOLE and SIMPLE_PINHOLE
are supported only for genuinely undistorted pixel-edge images. No half-pixel
conversion, dewarping or resize is guessed. PGM P5/255 and already-gray 8-bit PNG are
accepted; PNG decoding uses Pillow only in the separate authoring process.

Source observations are subpixel, while the current native descriptor uses integer
sample centers. The **explicit** `maximum_reference_snap_px` authorizes a bounded
sampling offset. Every original measured coordinate, sampled coordinate, offset,
and reprojection residual is retained. A zero bound requires exact sample centers.
The sampled position is not relabeled a new 3D-map measurement. The descriptor's
entire 33x33 footprint must be inside a supplied 0/1 allowed mask; there is no
implicit all-allowed mask. Held-out/final-check images are refused as atlas sources.

Within each selected view, up to eight eligible points per 8x8 image tile are
selected by reprojection residual then physical ID, at most 512 total. Rejections,
selection omissions, empty views, unrepresented points and source observations
outside the selected landmark scope stay in provenance. Multiple source views of
one landmark never increase its PnP support count. Source exposure identities
normalize rational PTS/time-base values and ignore incidental metadata, so aliases
cannot masquerade as independent exposures.

## Actual producer command

```sh
python3 -B scripts/export_localization_atlas.py \
  --recipe /private/property/atlas-recipe.json \
  --output-directory /private/property/new-atlas-generation
```

The output directory must not exist. Child provenance and the staged archive are
written, fsynced and read back before a create-only link exposes the archive root.
A failure after the final link can leave a complete result; inspect existing hashes
rather than blindly retrying. Failed staging retains files for reconciliation.
The source manifest root and per-reference record roots are embedded in FSATLAS1.
Archive descriptors use the exact current native descriptor algorithm identity.

Limits include 32 MiB per model file, 100,000 source points, 4096 source images,
1,000,000 source observations, 4096 selected landmarks, 64 selected references,
8192 authored descriptors and the native image/atlas bounds. Exceeding a hard work
or input ceiling is a failure, not unreported truncation. All paths are local;
there are no downloads, network calls, runtime installs, or remote uploads.

## Native file-to-pose harness

`crates/fss-twin/examples/localize_atlas.rs` reads a generated atlas, imported twin
and an explicitly supplied raw grayscale surveillance frame through the real Rust
reader, extractor, matcher and PnP solver. It does not accept query-to-map matches.
It is an owner-operated integration harness, not a new registered fss/1 command.
Place a `key=value` configuration alongside its input files. Required keys are:

```text
twin=property.fsstwin
twin_sha256=EXACT_TWIN_HASH
source_scene_sha256=EXACT_SAVED_BLEND_HASH
atlas=new-atlas-generation/atlas.fsatlas
atlas_sha256=WHOLE_ATLAS_HASH
provenance_sha256=PROVENANCE_JSON_HASH
query=recorded-frame.gray
allowed_mask=recorded-frame.allowed
query_sha256=RAW_PIXEL_HASH
mask_sha256=QUERY_MASK_HASH
exposure_sha256=SOURCE_EXPOSURE_IDENTITY
image_domain_sha256=QUERY_IMAGE_DOMAIN_IDENTITY
width=1920
height=1080
fx=CALIBRATED_FX
fy=CALIBRATED_FY
cx=CALIBRATED_CX
cy=CALIBRATED_CY
work_units=2000000000
```

Hashes are bare 64-character lowercase SHA-256 values. Query pixels are tightly
packed row-major grayscale, not an encoded PNG/video; the same-sized mask contains
0/1 bytes. Supply the actual calibrated dimensions, intrinsics, image-domain and
exposure identity. Images must already be in the supported undistorted domain.
Paths are confined to the config directory. Values shown above are a schematic,
not inferred calibration for a real camera.

```sh
cargo run --locked --offline -p fss-twin --example localize_atlas -- /private/property/localize.conf
```

The harness returns candidate positions/orientations, support and fit error, or an
explicit unlocalized result. It never activates a calibration. A blank or poorly
matched frame is not replaced with a default camera pose. Native feature/viewpoint,
fixed-intrinsics, nonplanar-map, budget and accuracy limitations still apply.

## Executed checks and remaining qualification

`python3 -B scripts/test_export_localization_atlas.py` executes the actual producer.
Its 14 tests passed in the authoring environment, including actual CLI execution, independent semantic-root decoding, byte-stable export,
existing Rust descriptor golden compatibility, source/mask/holdout failures,
explicit subpixel sampling offsets, rational exposure aliasing, reciprocal tracks,
Sim(3) conversion, empty COLMAP rows, filenames with spaces, binary PGM separators,
path/symlink confinement and root-last publication failure injection.

The native archive contract already has an independent Python wire golden. The
Rust archive tests and this native file harness have not executed here because no
Rust compiler is installed. Real reconstruction exports, the owner's property,
recorded-camera localization accuracy, field qualification and the always-on
Asupersync/agent integration remain outstanding. A successful producer invocation
alone establishes neither a truthful map nor a useful camera localization.

Primary format reference: https://colmap.github.io/format.html . The importer treats
IDs as non-contiguous, preserves the image observation-index relation, and uses the
documented Hamilton quaternion and world-to-camera convention. COLMAP is an input
artifact format here, not an admitted production library.
