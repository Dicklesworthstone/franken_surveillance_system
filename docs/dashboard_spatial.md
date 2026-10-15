# Property intelligence and the sensor wall

`fss-dashboard` now opens the spatial workspace at `/`. `/sensors` opens the
camera/sensor wall; `/evidence` keeps the existing event explorer, evidence graph,
canonical-record inspector and operations views.

```sh
cargo +nightly-2026-08-31 run --locked --offline -p fss-cli \
  --bin fss-dashboard -- --demo
```

The demo is a frozen **synthetic** property with four camera perspectives, three
other sensors, several unresolved event candidates, alternate localizations,
uncertainty envelopes and an unplaced candidate. Those camera tiles are geometric
renderings, not real camera feeds. A failed real read never selects the demo.

## Connect real inputs

```sh
cargo +nightly-2026-08-31 run --locked --offline -p fss-cli \
  --bin fss-dashboard -- \
  --root /absolute/deployment --site site:your-site \
  --allow-local-metadata yes \
  --scene /absolute/visualization/scene.json
```

The deployment is read through the existing native read-only metadata reader.
The scene is an **explicit operator-local visualization projection**, not a
calibration activation, agent envelope, canonical scene authority or write API.
Use `docs/examples/dashboard_scene.json` as an empty input template. Replace its
site and supply your evaluated mesh and real camera registration results. An
empty or omitted scene stays empty; coordinates and devices are not guessed.

A producer can replace the scene file to supply updated registrations, declared
readings or localizations. The browser refreshes after fifteen seconds following
a successful read. This is retained-snapshot visualization, **not an authenticated
live telemetry subscription or RTSP browser stream**. Status, freshness and
knowledge describe the supplied data, not an independently measured live state.

### Property and coordinates

The scene identifies `format: "fss.operator_scene.v1"`, `site`, `frame`, `scale`,
`ledgerRoot`, `sensors`, `placements`, and exactly one of `mesh` or `nativeTwin`.
Unknown top-level and typed member fields are rejected.

`mesh` carries evaluated `vertices: [[x,y,z], ...]`,
`triangles: [[v0,v1,v2,materialIndex], ...]` and materials with `name`, `role`, and
RGB `color` components between zero and one. Material role `roof` participates in
the roof-cutaway control. No Blender, external model runtime, scene scripting,
network model loader or frontend framework is introduced.

To use the existing first-party twin import, replace `mesh` with:

```json
"nativeTwin": {
  "file": "property.fsstwin",
  "packageDigest": "sha256:<exact package hash>",
  "sourceSceneDigest": "sha256:<exact source-scene hash>",
  "property": 1,
  "revision": 1
}
```

The hashes must be actual 64-lowercase-hex SHA-256 values, not the placeholders.
The binary imports the package through `fss_twin::import_twin`, validating the
package checksum, authoring-source identity, basis, geometry and work bounds.
Native source coordinates remain unchanged; the package's scale evidence replaces
the sidecar scale declaration. Native `Structure` surfaces are not automatically
classified as roofs, so they are not guessed away by the roof toggle.

Coordinates are **right-handed, Z-up**. Scale is `relative`, `estimated`, or
`measured`, with `metresPerUnit` and optional `error`. Relative units never become
meters just because the browser is rendering them. A supplied measurement label
is not an independent accuracy certificate.

### Cameras and other sensors

Every sensor has `id`, `label`, `kind`, `status`, `knowledge`, `basis`, `position`,
`pose`, `intrinsics`, `frame`, and `reading`. Unsupported or unavailable fields
must be explicit `null`. Kinds are `camera`, `motion`, `contact`, `temperature`,
`smoke`, `audio`, and `other`; status is `available`, `offline`, `unknown`, or
`redacted`. Unavailable values are not turned into zero readings.

Camera poses use the existing convention:

```text
X_camera = rotation * X_world + translation
Camera center in world coordinates = -transpose(rotation) * translation
Optical axes: +X right, +Y down, +Z forward
```

The native validator checks proper orthonormal rotation, rejects reflections,
and cross-checks a supplied position against the derived camera center. For a
camera at `[3,5,2]` looking along world +Y, with +X to image right:

```json
"position": [3,5,2],
"pose": {
  "rotation": [[1,0,0],[0,0,-1],[0,1,0]],
  "translation": [-3,2,-5]
},
"intrinsics": {
  "width": 800, "height": 600,
  "fx": 400, "fy": 300, "cx": 310, "cy": 260,
  "imageDomain": "undistorted_pinhole"
}
```

This example explains the convention, not the position of your camera. Supply
actual registration results in the same property frame. Raw distorted image
coordinates are not silently treated as rectified pinhole coordinates. Frusta
represent declared optical geometry, not certified coverage or visibility.

Non-camera readings use `reading: {"value": 18.4, "unit": "deg C",
"observedAtUnixMs": "1789398500000"}` or `null`. The timestamp is an explicit
producer declaration. The wall marks values stale after thirty seconds and
separates clock conflicts from recent values; it invents no historical graph.

### Event positions, hypotheses and epistemic state

The native event inventory remains the source of event identities, revisions and
lifecycle. An unresolved, non-benign event without a matching localization is
listed as **unplaced**. To depict it spatially, its placement must pin BOTH the
current `ledgerRoot` and that event's exact `revisionDigest`:

```json
{
  "eventId": "event:your-event",
  "revisionDigest": "sha256:<exact current revision hash>",
  "knowledge": "inferred",
  "severity": "high",
  "shape": "person",
  "basis": "Describe the registered localization and evidence basis",
  "observedAtUnixMs": "1789398500000",
  "validForMs": 30000,
  "hypotheses": [{"position": [1,2,0], "radii": [1.5,0.8,0.3]}]
}
```

`shape` is a generic person, animal, vehicle or unknown glyph, never identity or
reconstructed body pose. Color conveys the **declared severity**, not certainty.
Position knowledge independently controls visual form: observed is solid,
inferred is wire/dashed, conflicted keeps split rings and individually labeled
alternatives, and stale is gray. Unknown, not-observable and redacted coordinates
must remain absent. Their events remain available in the list.

Radii describe declared axis-aligned spatial bounds in source units, **not an
implicitly calibrated probability/confidence ellipsoid**. Up to eight spatial
alternatives remain individually visible; they are not averaged into a false
single position. An expired or future-clock-conflicted localization becomes stale.
A different event revision or ledger root unplaces it entirely until the producer
supplies a newly bound record. Native event lifecycle remains a separate field.

## Camera image previews

To show real image tiles, additionally pass `--allow-local-frames yes`. Each camera
may then name one **operator-approved, already-redacted** PNG/JPEG preview:

```json
"frame": {
  "file": "front-preview.png",
  "digest": "sha256:<exact image hash>",
  "sourceDigest": "sha256:<retained completed-import root>",
  "capturedAtUnixMs": "1789398500000",
  "privacy": "operator-approved-redacted-preview"
}
```

Files must be regular sibling files of the selected scene, not symlinks, paths,
URLs or credentials. No directory scan or camera connection occurs. For every
image request, the server requires the current scene digest, re-reads the native
deployment, checks the scene's ledger root and retained-import membership, checks
the image hash and pixel bounds, and verifies that scene and deployment did not
change while reading. Revoked access, a changed authority root, removed source
reference or corrupt image refuses rather than serving a stale cached image.

**The preview-to-import association and redaction are operator assertions.** This
path does not decode the source recording, prove that the preview was derived
from it, verify a native redaction receipt, or apply a privacy transform. Use only
approved redacted previews. Image hashes establish byte identity, not scene truth.
These tiles are labeled retained stills and show their declared capture time;
they are never presented as live video. Real missing images are never replaced
with rendered synthetic perspectives. Local processes can access the explicitly
acknowledged metadata/previews; this is not a multi-user authenticated service.

The exact same-origin header and numeric-loopback Host protections apply to
spatial and image endpoints. There is no CORS grant, arbitrary filesystem route,
write endpoint, or cloud/CDN dependency. Do not proxy or tunnel the listener.

## Navigation and resource bounds

Drag to orbit, shift-drag/right-drag to pan, scroll to zoom; use orbit/top/fit,
fullscreen and roof/frustum/event/grid controls. Select a camera to inspect its
basis or enter its geometric viewpoint. Select a candidate to inspect native
lifecycle separately from localization knowledge and severity. The full sensor
wall includes every admitted declared sensor and supports text/type filtering.
Keyboard: `1` property, `2` sensors, `0` fit; arrows and +/- control the focused
property canvas. The legend explains visual semantics without relying on color.

The renderer redraws on demand rather than running a permanent animation loop.
WebGL uses depth testing; the software fallback has a per-pixel depth buffer and
near-plane clipping, not an incorrect painter-only ordering. Neither path makes
an occlusion/coverage certificate. Images load sequentially, are downsampled to
at most 640x360 for the wall, and their full-size decoded bitmaps are released.
Changing scene or view cancels obsolete preview work. Failed/hidden views clear
images, localizations and active camera references rather than retaining private
or current-looking stale content.

Scene JSON is bounded to 1 MiB and the existing strict parser's node limits.
Native twin packages have a 16 MiB, 65,536-vertex, 100,000-triangle ceiling. The
composite response is at most 8 MiB. There are at most 64 sensors, 256 event
placements, eight alternatives per placement, and 4 MiB/4 megapixels per preview.
Existing native deployment read bounds remain in force. Limits refuse the query;
they do not silently truncate the evidence inventory.

## Verification

```sh
bash scripts/check_dashboard.sh
python3 tests/test_spatial_browser.py --offline --artifacts /tmp/fss-spatial
```

The shared check includes the existing model/native/HTTP checks, new geometry and
knowledge-state model tests, native scene/twin validation, and a real native
MJPEG-import-to-PNG-preview HTTP workflow. That workflow checks positive image
readback, unchanged deployment bytes, explicit denial, image corruption, authority
advance, exact scene rebinding, and redacted status. It does not qualify field
cameras or establish preview derivation/redaction correctness.

The browser harness requires Playwright and Chromium as test tools only. Offline
mode injects the shipped modules with explicit synthetic responses and tests
rendering, camera viewpoints, cutaway, filtering, mobile layout, failure clearing
and unplaced events. It does not exercise native HTTP or CSP. Without `--offline`
it uses routed responses under the server's CSP, still not a native deployment.
