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
descriptors, claims ledgers, or localized-camera atlases. It is an original public
producer/consumer contract, not a copy of the private skill implementation.

## Verification

```sh
python3 -B scripts/test_twin_interchange.py
python3 -B scripts/twin_interchange.py /tmp/new-synthetic.fsstwin
cargo test --locked --offline -p fss-twin
```

The public synthetic package is 305 bytes; whole-file SHA-256:
`1d997fa681292b2eac58f73be61ca31c76bbf1e15f3af46c2ddf033ad9782c24`.
Python and Rust fixtures independently encode that byte contract. Rust tests cover
every truncation and one-bit byte mutation, source binding, limits, cancellation,
re-sealed malformed values and identity errors, and an actual mesh support query.

Authoring-session evidence: the seven Python encoder/publication tests executed and
passed. Rust compilation/tests and the real Blender exporter have **not** executed
in this environment. No compiler is installed. Source tests, a valid synthetic
checksum, or a successful future import do not establish physical reconstruction,
calibration, authority, uncertainty calibration, or threat-detection quality.
