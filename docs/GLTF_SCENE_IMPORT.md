# Import a property and camera placements from glTF or GLB

`scripts/import_gltf_twin.py` converts an explicitly classified static glTF 2.0
scene into the same native property geometry and camera rig used by
[`fss-scene-fuse`](SCENE_FUSION.md). This provides an authoring path for tools that
export glTF or GLB, in addition to the [evaluated Blender exporter](TWIN_IMPORT_REFERENCE.md).
It runs offline with Python's standard library. The native Rust process reads the
resulting files and does not start Blender, parse glTF, or depend on Python.

The importer reads **self-contained GLB 2.0** or **glTF with embedded base64
buffers**. For a `.gltf` that references a separate `.bin`, export a GLB or an
embedded-buffer glTF first. The converter does not follow external file or network
URIs. Textures are unnecessary for this geometry and camera reconstruction path.

## Convert and reconstruct

Export the physical scene as static triangle meshes, together with its perspective
cameras. Identify the mesh and camera **node indices** in the selected glTF scene;
names alone are not unique identifiers. Create an explicit import policy, replacing
the source hash, node indices, object roles, camera identities and image sizes with
the values for that scene. Hash the exact final source bytes:

```sh
sha256sum property.glb
```

An example policy for a ground mesh at node 0 and two cameras at nodes 1 and 2 is:

```json
{
  "schema": "fss.gltf-import-policy/1",
  "source_sha256": "REPLACE_WITH_64_LOWERCASE_HEX_DIGITS",
  "scene": 0,
  "epoch": "property-survey-001",
  "scale": {"status": "relative"},
  "geometry_error": null,
  "geometry_basis": {"property": 1, "revision": 1},
  "objects": {
    "0": {
      "role": "physical",
      "id": "ground",
      "feature": "garden",
      "surface": "grass",
      "support": true,
      "opaque": true
    }
  },
  "cameras": {
    "1": {
      "camera": 1,
      "calibration": 1,
      "image_domain": 1,
      "clock": 1,
      "privacy_domain": 1,
      "validity_ns": [0, 18446744073709551615],
      "width": 1280,
      "height": 720,
      "source_object_id": "camera-west"
    },
    "2": {
      "camera": 2,
      "calibration": 1,
      "image_domain": 1,
      "clock": 1,
      "privacy_domain": 1,
      "validity_ns": [0, 18446744073709551615],
      "width": 1280,
      "height": 720,
      "source_object_id": "camera-east"
    }
  }
}
```

The camera numbers bind actual logical sensors to the authored nodes. They are
owner-supplied identities, as are the calibration/image-domain generations, clock,
privacy domain, property and revision. The validity interval above is illustrative;
use the intended observation interval. Preserve exact JSON integers, including
large nanosecond values. This binding does not authenticate a sensor or accept a
physical calibration.

Run the converter, then use its files with explicitly associated image observations:

```sh
python3 scripts/import_gltf_twin.py property.glb \
  --policy property-policy.json \
  --output property.fsstwin \
  --rig-output property.cameras.json

cargo run -p fss-cli --bin fss-scene-fuse -- \
  --twin property.fsstwin \
  --rig property.cameras.json \
  --observations observations.json \
  --report-out scene-report.json
```

The converter prints the exact twin and camera-rig SHA-256 digests. Put its
`camera_rig_digest` in the observation query. See [SCENE_FUSION.md](SCENE_FUSION.md)
for the query schema, common capture clock, corresponding-feature requirements,
static/supplied-velocity/inferred-velocity modes and report semantics.

Both output files must be new destinations. The converter constructs and validates
both before publishing the complete twin followed by the rig that pins it. It
leaves the source unchanged. A failure while publishing the second output can leave
the complete first file; the error states this and does not overwrite it on retry.
Exit code 0 means the conversion completed; code 2 means an explicit refusal or I/O
failure. An authored scene is still subject to the native reader's validation.

## Physical roles and scope

Every mesh node in the selected scene requires either a physical role or an explicit
exclusion. Every camera node requires a camera binding or an explicit exclusion.
For either mapping, an exclusion has exactly this shape:

```json
{"role": "exclude", "reason": "authoring guide geometry; not a physical surface"}
```

Exclusion is an owner declaration retained through the policy digest. Nodes that
only group children need no role. A node containing both a mesh and a camera needs
an entry in both mappings. An entry referring to an absent node or the wrong node
kind is refused. At least one physical triangle and one bound camera are required;
scene fusion needs at least two usable camera views.

Physical objects have unique IDs. Features may group several objects but must have
one consistent surface class: `unknown`, `pedestrian_path`, `grass`, `stairs`,
`deck` or `structure`. `support` and `opaque` are explicit booleans; glTF materials
do not silently supply physical visibility or support semantics. The importer
includes every primitive of each admitted mesh. It refuses unsupported physical
geometry instead of producing an apparently complete but partial mesh.

The twin retains the exact source-file hash, selected scene, static evaluation
scope and canonical policy hash. The policy hash covers roles, exclusions, sensor
bindings, scale and geometry revision. The rig pins that exact twin and repeats
its source and evaluation scope. Replacing a scene, changing an import decision,
or changing a camera mode therefore changes the relevant identities.

## Coordinate and projection contract

The glTF specification uses a right-handed Y-up scene. The importer applies the
same proper rotation to every mesh vertex and camera-to-world transform:

```text
FSS [x, y, z] = glTF [x, -z, y]
```

Parent transforms are composed before this conversion. Nodes may use glTF TRS
transforms or column-major affine matrices; matrix and TRS forms cannot be mixed
on one node. Reused meshes are evaluated separately for each admitted node.
Geometry scale is retained, including nonuniform scale. A negative determinant
reverses triangle winding to preserve the transformed surface orientation.

glTF cameras look along local negative Z, with positive X right and positive Y up.
The shared rig writer converts them to FSS optical positive Z forward, positive X
right and positive Y down. For a native world point `P`, the camera point is
`R * P + t`; the camera center is `-transpose(R) * t`. The output is a proper rigid
world-to-camera pose in the same RH Z-up frame as the mesh.

For image width `W`, height `H`, vertical field of view `yfov`, and aspect `A`:

```text
fy = H / (2 tan(yfov / 2))
fx = W / (2 A tan(yfov / 2))
cx = W / 2
cy = H / 2
```

`A` comes from the glTF perspective camera when declared, otherwise from `W/H`.
The dimensions explicitly bind that virtual projection to an undistorted image
mode. Image coordinates use pixel edges, with the first pixel center at
`(0.5, 0.5)`. A physical feed must have matching rectification, crop, resize and
image-domain generation before its pixels are compatible.

These transform and projection rules follow the primary
[Khronos glTF 2.0 specification](https://registry.khronos.org/glTF/specs/2.0/glTF-2.0.html).
This implementation deliberately admits a smaller subset: **scaled, reflected or
sheared camera transforms are refused**, including scale inherited from a parent.
The glTF rendering convention ignores camera scale; this authoring bridge requires
an explicitly rigid camera placement. Apply that scale before export. Float-matrix
roundoff within the shared writer's tolerance is orthonormalized; it supplies no
physical calibration evidence.

Coordinates retain source units. Although glTF declares a unit convention, import
does not establish that a particular authored property matches measured dimensions.
Use `relative` until an explicit scale declaration is justified. The FSSTWIN1
`estimated` and `measured_anchor` declarations can retain a `metres_per_unit`
factor and nullable absolute `error`; the converter does not rescale one sensor
independently or turn the declaration into verified evidence. Camera status remains
`authored_nominal`, and unknown map/calibration error stays unknown.

## Supported subset and refusal bounds

| Input | Supported behavior |
|---|---|
| Container | glTF 2.0 embedded buffers, or GLB 2.0 JSON plus optional BIN; exact lengths and padding checked. |
| Geometry | Static TRIANGLES with FLOAT VEC3 positions; indexed u8/u16/u32 or nonindexed; interleaved/strided position buffers. |
| Hierarchy | Single-parent acyclic nodes, explicit scene roots, complete parent transforms, bounded depth. |
| Cameras | Perspective `yfov`, optional `aspectRatio`, valid clipping planes; explicit width and height, each 1..8192. |
| Scene limits | At most 64 MiB source and total decoded buffers, 256 buffers, 8,192 nodes, depth 128, 262,144 evaluated vertices and 524,288 triangles. |
| Control limits | Policy at most 4 MiB, JSON depth 64, strict duplicate-key/nonfinite checks, at most 64 bound cameras through the shared rig writer. |

External buffers, required extensions, compressed or sparse geometry, primitive
restart indices, skinned/morphed geometry, animations, orthographic cameras,
unsupported primitive modes and out-of-range/misaligned accessors are refused.
Export an evaluated static triangle scene for these inputs. The converter neither
infers lens distortion nor turns textures into camera correspondences. Clear mesh
visibility and successful triangulation remain nominal geometric results.

## Run the regression checks

```sh
python3 -m unittest discover -s scripts -p 'test_gltf_twin.py' -v

cargo build --locked --offline -p fss-cli --bin fss-scene-fuse
FSS_SCENE_FUSE_BIN="$PWD/target/debug/fss-scene-fuse" \
  python3 -m unittest discover -s scripts -p 'test_gltf_scene_fusion.py' -v
```

The first suite independently checks asymmetric transforms, camera projection,
reflection, buffer layouts and malformed input. The second invokes both real CLIs:
GLB conversion followed by native scene reconstruction. Its image observations are
calculated directly from synthetic glTF camera centers, independently of the
exported rig. It checks all three motion modes, the common scene time, exact source
pins, unchanged uncertainty status and retention of a failed hypothesis beside
successful ones. It is skipped unless an explicit native executable is supplied;
running only the Python importer tests does not qualify native integration.
