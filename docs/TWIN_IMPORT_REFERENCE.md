# Native evaluated-twin import

Source implementation of the geometry interchange portion of BTI-001. This is
not completion of the full scene/atlas contract, camera registration, or any
real-property qualification. It leaves the accepted `.blend` unchanged.

## Working boundary

`scripts/export_blender_twin.py` is a separate owner-run **authoring** tool. The
shipping Rust `fss-twin` library consumes its bytes with no Blender, Python,
filesystem, network, plugin, or private-skill dependency. An import returns immutable
unactivated geometry. Existing FSS custody, capability, ledger and plan/commit
owners must authorize publication/activation; hashes are not authentication.

The exporter uses evaluated scene/view-layer/frame meshes, full instance transforms,
triangulation, and negative-transform winding correction. Every physical object
must have `hhm_object_id` and `hhm_feature_id`. Instances retain a revision-bound
identity derived from source/instancer IDs and Blender's persistent instance tuple.
That identity must not be treated as stable across an arbitrary scene revision.

An explicit policy classifies every evaluated mesh as physical or excluded with a
reason. No shader, object name, `hide_render` flag, or stale alternative implicitly
becomes support geometry. A physical policy entry absent from the selected view
layer fails rather than disappearing silently. This initial exporter targets that
view-layer's evaluated mesh instances; curves, volumes and unmodelled interiors
are not inferred. Convert intended non-mesh geometry in a separate authoring copy.

Example policy (replace identities/hashes with those from the actual saved scene):

```json
{
  "schema": "fss.blender-export-policy/1",
  "source_sha256": "<64 lowercase hex characters>",
  "scene": "Scene",
  "view_layer": "ViewLayer",
  "frame": 1,
  "epoch": "observation date unknown",
  "scale": {"status": "relative"},
  "geometry_error": null,
  "objects": {
    "object-stone-path": {"role": "physical", "feature": "feature-stone-path", "surface": "pedestrian_path", "support": true, "opaque": true},
    "object-wall": {"role": "physical", "feature": "feature-wall", "surface": "structure", "support": false, "opaque": true},
    "name:ReferencePhoto": {"role": "exclude", "reason": "source-image reference, not physical geometry"}
  }
}
```

Run from a disposable, saved authoring session, with embedded script auto-execution
disabled. The script does not save, install anything, or invoke a private skill:

```sh
blender --background --disable-autoexec /path/house.blend \
  --python scripts/export_blender_twin.py -- \
  --policy /path/policy.json --output /path/new-property.fsstwin
```

Physical geometry uses source-world right-handed Z-up coordinates. Blender's unit
UI does not establish metres. `estimated` or `measured_anchor` scale records instead
require `metres_per_unit` and `error` (absolute error in the factor, or null).
Geometry error is in source-world units; null is unknown, not zero. These are
producer declarations, not uncertainty bounds certified by FSS.

Publication is create-only: a fully written/fsynced temporary file is linked
without replacing an existing destination. A post-link error may leave complete
output; inspect its hash before retrying. No remote archive durability is claimed.

## Export the placed surveillance cameras with the property

The optional `fss.blender-export-policy/2` adds camera export to the unchanged
FSSTWIN1 geometry format. Add `geometry_basis` and `cameras` to the policy above,
and change its `schema` to `fss.blender-export-policy/2`:

```json
{
  "geometry_basis": {"property": 1, "revision": 1},
  "cameras": {
    "object-front-camera": {
      "camera": 1,
      "calibration": 1,
      "image_domain": 101,
      "clock": 7,
      "privacy_domain": 1,
      "validity_ns": [0, 20000000000],
      "image_model": "undistorted_pinhole",
      "image_size": [1920, 1080],
      "pixel_aspect": [1, 1]
    },
    "object-side-camera": {
      "camera": 2,
      "calibration": 1,
      "image_domain": 102,
      "clock": 7,
      "privacy_domain": 1,
      "validity_ns": [0, 20000000000],
      "image_model": "undistorted_pinhole",
      "image_size": [1280, 720],
      "pixel_aspect": [1, 1]
    }
  }
}
```

The map keys are exact `hhm_object_id` values on the Blender CAMERA objects.
Camera, calibration, image-domain, clock, privacy-domain and geometry handles are
explicit nonzero owner bindings. They are not generated from object order or
names, and do not authenticate a stream. `validity_ns` is an inclusive interval
on the declared capture clock. The example uses a 20-second synthetic clock;
replace it with the interval and generations of the observations being processed.
Sharing a clock handle asserts an already established common time basis; the
exporter does not synchronize physical cameras.

```sh
blender --background --disable-autoexec /path/house.blend \
  --python scripts/export_blender_twin.py -- \
  --policy /path/policy-v2.json \
  --output /path/new-property.fsstwin \
  --rig-output /path/new-property-cameras.json
```

Both files are built and validated before publication. The complete geometry is
published first and the rig that references its digest is published last. The
v1 geometry-only policy remains supported and cannot accidentally emit a rig.

Each selected camera uses its **evaluated instance world matrix** at the same
scene/view-layer/frame as the geometry. Parent transforms and evaluated constraints
are therefore included. A stable camera object instantiated several times is
refused because one sensor binding cannot choose an instance silently. Unbound
authoring/inspection cameras are ignored; a bound camera missing from the selected
view layer fails.

The conversion from Blender's camera local axes (+X right, +Y up, -Z forward) to
FSS's optical axes (+X right, +Y down, +Z forward) is explicit. For the evaluated
camera-to-world rotation `Q` and optical center `C`, the output is
`R = diag(1,-1,-1) Qᵀ`, `t = -R C`. Source geometry and camera translations retain
the same RH Z-up source units; the exporter does not multiply one by a hidden
Blender unit conversion. Camera scale, reflection, shear and non-affine transforms
are refused. Float-matrix roundoff within 1e-6 is orthonormalized before the native
proper-rotation check; this numerical correction is not calibration evidence.

Perspective focal lengths and principal points account for lens millimetres,
sensor width/height, HORIZONTAL/VERTICAL/AUTO sensor fit, pixel aspect and lens
shift. `image_size` and `pixel_aspect` explicitly select each camera's virtual
undistorted image mode, independently of the scene preview resolution. The
calculation follows [Blender 4.1.1's camera view-plane conventions](https://github.com/blender/blender/blob/v4.1.1/source/blender/blenkernel/intern/camera.cc),
including AUTO using sensor width even when the image aspect selects vertical
fit. Image coordinates use pixel edges: the first pixel center is `(0.5, 0.5)`.

Only full perspective, undistorted pinhole images are admitted. Orthographic,
panoramic/custom models and render-border crops fail explicitly. A distorted,
stabilized, rotated, resized or cropped physical feed needs its appropriate
rectification/domain transform before its pixels can use this rig. An authored
Blender lens is a nominal model; matching it to a real camera still needs
registration and validation against independent landmarks.

## Camera rig control JSON and native reader

`fss.scene_camera_rig.v1` is a bounded control-document contract consumed by
`fss_cli::scene_rig`. It carries exactly these root fields:

| Field | Contract |
|---|---|
| `schema` | Exactly `fss.scene_camera_rig.v1`. |
| `source_scene_digest` | Nonzero SHA-256 of the authoring source, equal to the native twin's source digest. |
| `twin_digest` | Nonzero SHA-256 of the complete FSSTWIN1 bytes including trailer. |
| `geometry_basis` | Explicit nonzero `property` and `revision`, equal to the imported twin's owner-resolved basis. |
| `coordinate_frame` | Exactly `RH_Z_UP`. |
| `evaluation_scope` | Exact scope string embedded in the native twin. |
| `cameras` | One to 64 camera rows, canonicalized by sensor ID. |

Each camera row requires `camera`, `calibration`, `image_domain`, `clock`,
`privacy_domain`, `validity_ns`, `source_object_id`, `image_model`,
`world_to_camera`, `intrinsics`, `error` and `status`. `world_to_camera` contains
the row-major 3×3 `rotation` and 3-vector `translation`. `intrinsics` contains
`width`, `height`, `fx`, `fy`, `cx`, `cy`. Image dimensions are 1..65536; focal
lengths are positive and finite; transforms must be finite proper rigid poses.
`image_model` is `undistorted_pinhole`, `status` is `authored_nominal`, and `error`
is always null. Unknown physical pose uncertainty is retained as `None`; it is
never silently replaced by zero or a measured-calibration claim.

The native reader refuses unknown or missing fields, duplicate JSON keys,
duplicate sensor/source-object bindings, changed package/source/scope/basis,
invalid clock intervals, unsupported lens/status claims, malformed rotations,
nonfinite values, cancellation and exhausted work budgets. It opens no file or
URL. `parse_scene_rig` accepts bounded UTF-8 bytes, while
`SceneRig::from_document` accepts the already strictly parsed control document.
Both require a verified `PropertyTwin` and explicit `WorkBudget`.

`SceneRig::camera` and `cameras` expose existing `TrackingCamera` snapshots plus
their source-object and privacy-domain bindings. `SceneRig::digest` identifies the
canonical typed rig, so whitespace, JSON field ordering and input camera ordering
do not change its semantic identity. Callers may additionally retain the original
file digest. These snapshots feed source-linked contact projection and multiview
fusion without a Blender process, external numerical library or camera activation.

## FSSTWIN1 exact wire contract

All integers/f64 bits are little-endian. UTF-8 text is prefixed by u16 byte length,
nonempty, unpadded, with no control characters. f64 values must be finite and
canonical positive zero (negative zero is rejected). Coordinate magnitude is
bounded by 1e12 source units. No URI or executable expression exists in the format.

Header: ASCII `FSSTWIN1` (8 bytes), payload byte length (u64).
Payload in this order:

1. SHA-256 of exact saved source `.blend` (32 nonzero bytes).
2. Scope text (at most 2048 bytes), epoch text (at most 128 bytes).
3. Scale tag u8: 0 relative, 1 estimated, 2 producer-declared measured anchor;
   metres/unit f64; absolute error f64 (-1 unknown). Relative uses 0 and -1.
   Metric factor is positive <=1e9; known error is >=0 and strictly below factor.
4. Geometry error f64 (-1 unknown; otherwise 0..1e12 source units).
5. Four u32 counts: features, objects, vertices, triangles, each nonzero.
6. Features sorted by unique UTF-8 ID: text ID (<=256 bytes), surface u8
   (0 unknown, 1 pedestrian path, 2 grass, 3 stairs, 4 deck, 5 structure).
7. Objects sorted by unique UTF-8 ID: text ID, zero-based feature u32,
   support u8 boolean, opaque u8 boolean.
8. Vertices: three f64 source-world coordinates each, already fully evaluated.
9. Triangles: three zero-based vertex u32 indices, zero-based object u32.

Trailer: SHA-256 of the entire header+payload, exactly 32 bytes. No trailing bytes.
The caller additionally pins SHA-256 of the **whole package including trailer**
and expected source `.blend` hash. Input SHA checks do not prove the exporter
actually evaluated the claimed scene. Every feature/object must be referenced;
degenerate triangles and missing references fail. Original vertex and triangle
ordering is retained; no precision-changing weld is performed during import.

Ceilings: 64 MiB input, 65,536 features/objects, 262,144 vertices, 524,288 triangles.
Counts have a byte-length preflight before allocation. Caller limits may narrow
these. The shared geometry work budget is charged before hashing/allocation and
polled during parsing. The returned `PropertyTwin` has exact bytes identity,
feature/object/triangle mappings, scale/error declarations and `TriangleMesh`.
A new owner-resolved `GeometryBasis` must be assigned whenever input geometry changes.

This narrow interchange intentionally does not claim to decode the private skill's
v1/v2 scene-manifest transport, GLB, native `.blend`, arbitrary lens models, images,
descriptors, claims ledgers, or localized-camera atlases. Common-format authoring
conversion is separate from this native binary reader. It is an original public
producer/consumer contract, not a copy of the private skill implementation.

## Verification

```sh
python3 -B scripts/test_twin_interchange.py
python3 -B scripts/test_scene_camera_rig.py
python3 -B scripts/twin_interchange.py /tmp/new-synthetic.fsstwin
cargo test --locked --offline -p fss-twin
cargo test --locked --offline -p fss-cli --lib scene_rig
```

The public synthetic package is 305 bytes; whole-file SHA-256:
`1d997fa681292b2eac58f73be61ca31c76bbf1e15f3af46c2ddf033ad9782c24`.
Python and Rust fixtures independently encode that byte contract. Rust tests cover
every truncation and one-bit byte mutation, source binding, limits, cancellation,
re-sealed malformed values and identity errors, and an actual mesh support query.

The original geometry-only authoring session ran seven Python encoder/publication
tests and did not run Rust or Blender. The camera-rig extension adds executable
independent-axis, translated/rotated parent, sensor-fit/aspect/shift, transform
refusal, identity, policy compatibility and mocked evaluated-camera tests. Native
rig tests exercise the checked FSSTWIN1 reader and actual two-camera triangulation,
with unknown error, source/basis mismatches, duplicate bindings and cancellation.
The mocked authoring tests do not claim a real Blender run. Synthetic arithmetic
tests and a valid import do not establish real-property reconstruction,
calibration, uncertainty calibration, or threat-detection quality.
