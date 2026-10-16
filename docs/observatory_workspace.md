# Observatory: the spatial evidence workspace

The default `fss-dashboard` view is organized around a property scene, linked event
inspection, and camera perspectives. It is still an operator-local, read-only
projection over the existing native deployment and scene inputs. See
[`dashboard_spatial.md`](dashboard_spatial.md) for the exact input, camera-frame,
preview-authorization and privacy contracts; none is replaced by the redesign.

```sh
cargo +nightly-2026-08-31 run --locked --offline \
  -p fss-cli --bin fss-dashboard -- --demo
```

Open the numeric loopback address printed in the terminal. To inspect real inputs:

```sh
cargo +nightly-2026-08-31 run --locked --offline \
  -p fss-cli --bin fss-dashboard -- \
  --root /absolute/path/to/deployment --site site:your-site \
  --allow-local-metadata yes --scene /absolute/path/to/scene.json
```

Previously documented `--allow-local-frames yes` is required for explicitly
selected real preview stills. This increment adds no stream connection, effect
endpoint, data export, privacy grant or automatic calibration.

## Explore a question, not a pile of cards

The property scene is the main workspace. Orbit, plan, fit, fullscreen, roof
cutaway, field-of-view outlines, the coordinate triad and quieter annotations
keep the geometry legible. Camera markers use the supplied native world-to-camera
transform. Numbered event markers open the same selected candidate as the event
list and evidence-time ribbon.

The Context lens presents the property normally. The Uncertainty lens subdues the
property's material colors and emphasizes the supplied spatial bounds. It does
not alter positions, delete geometry, filter candidates, recompute probabilities,
change severity, or activate a different hypothesis. The line treatment and
native state labels retain their meanings in both views.

Scene annotations prioritize the selected candidate, avoid label collisions,
and give a visible count when annotations are off-canvas or condensed. They are
x-ray annotations, not an occlusion or visibility certificate. Every unresolved
candidate remains reachable in the complete list. The Uncertain and Unplaced
tabs filter that list only; they do not silently remove other positions from the
map. A separate persistent tray keeps unplaced candidates visible.

Choosing H1, H2, or another supplied spatial alternative focuses that exact
hypothesis; it never averages competing positions. Smooth camera framing is a
bounded presentation transition and honors reduced-motion preferences.

## Use the project's evidence distinctions

Understanding keeps native lifecycle, localization knowledge, declared severity,
recorded probability interval, freshness and exact revision separate. Inferred
positions are not turned into observations by a rendering. Unknown or redacted
positions are not placed at an arbitrary origin.

Evidence trail exposes the event's declared supporting and contradictory edges. The **Failure-domain constellation** groups those exact references around the selected event so shared dependency structure is visible at a glance: support, contradiction, neutral relationships, repeated object references, and unnamed domains remain distinct.
Other relations remain neutral in the accounting. It also exposes named failure
domains, unassigned domains, repeated object references and exact object digests.
Several rows naming one sensor/domain are not several independent observations. Separate domain nodes are correlation groups only; the interface deliberately does not label them independent witnesses or turn their count into confidence.
Neither distinct names nor a reference count is an independence certificate.

The inline evidence graph is bounded to four references per page, with every
reference reachable. Select a reference to inspect its provenance class, failure
domain, capsule digest and identity reference. This does not hydrate a source or
verify current availability. Open exact record shows the original canonical JSON
without reconstructing it from floating-point timestamps. The separate existing
`/evidence` explorer and native graph-analysis facilities remain available.

Evidence time displays **latest retained revision intervals**, in relative source
coordinates. It is not a historical replay cursor, a current-threat time filter,
or a coverage map. Selecting an interval follows that retained record; resolved
records open their exact contents rather than being reactivated as threats.

Snapshot integrity exposes the authority root, retained position, scene identity,
open obligations, indeterminate effects, journal-tail flags and read accounting.
These are distinct facts, not a combined green system-health score.

## Change perspective without losing the source distinction

The camera dock is linked to map selection. View from here enters the camera's
geometric viewpoint; Expand shows the available bounded image or synthetic
perspective. These are intentionally different actions.

In demo mode, thumbnails are rendered from the synthetic architectural scene and
marked synthetic. In real mode, only explicitly authorized retained stills are
shown. A missing real image is never replaced by a geometric rendering. The
existing native request boundary still checks scene/authority bindings, image
identity and acknowledged access. Preview derivation and redaction remain
operator assertions; this UI does not establish either independently.

The wall supports search and camera/other-sensor filtering. At most six cameras
are mounted per page, and every admitted camera remains reachable. Non-camera
readings preserve their declared value, unit, observation time and freshness.
Unavailable readings are not replaced with zero.

Only the property workspace requests a WebGL context; synthetic thumbnail views
use bounded software rendering. Preview changes cancel obsolete fetches and
release renderer/bitmap resources. Paused snapshots are explicitly labeled, and
failed or hidden views clear geometry, positions, image pixels and open source
inspection dialogs rather than preserving current-looking private data.

## Rendering and navigation

The first-party renderer adds directional lighting and a shadow-map presentation
path, on-demand geometry caching, bounded render resolution and explicit GPU
resource disposal. The software fallback retains per-pixel depth, near clipping
and a bounded directional shadow buffer. Neither rendering path is a semantic
visibility oracle or a calibration result. No model download, external JavaScript
framework, icon font, CDN asset or production Python service is introduced.

`Ctrl-K` / `Cmd-K` searches views, candidate identifiers, zones, cameras and sensors.
Arrow keys choose, Enter opens and Escape closes. `1` opens Property; `2` opens
Sensors; `0` fits the scene; `?` opens the visual guide. The focused property canvas
supports arrows and +/-; drag orbits, shift/right drag pans and wheel zooms.

## Reproducible checks

```sh
bash scripts/check_dashboard.sh
python3 tests/test_observatory_browser.py \
  --chromium /usr/bin/chromium --artifacts /tmp/fss-observatory-previews
```

The shared check retains all prior native/model/HTTP tests and adds deterministic
model cases for evidence accounting, shared domains, repeated objects, all 64
camera declarations, preserved alternatives, authority changes and presentation
geometry. The native spatial HTTP fixture advances authority using a genuinely
different recording/stream, rather than requiring conflicting receive metadata
for the same immutable source to be accepted.

The optional browser harness requires Playwright and Chromium **as test tools**.
It injects the shipped modules and synthetic responses without a network
listener. It checks linked selection, evidence/reference dialogs, alternative
hypotheses, visual lenses, camera viewpoints, preview expansion, sensor filters,
command navigation, exact timestamps, mobile layout, failed-read clearing, retry
and inert untrusted text. It reports the actual renderer selected. Offline
software-rendered checks do not establish native HTTP/CSP behavior, hardware
WebGL support, field-camera accuracy, or production qualification.
