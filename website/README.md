# Alder House

The Franken Surveillance site follows three residential security incidents through one fictional property. A resident reports someone outside after hours, a courier approaches the entrance, and a raccoon crosses the grounds. The site keeps the scene script, rendered camera views and native FSS observations distinct. [Open the observatory](https://franken-surveillance.com/)

The Three.js viewer loads the same estate geometry, rigged characters and calibrated camera plan used to record the films. Switch to a mounted viewpoint, scrub the take or change the person's stature and walking pace. Changing a parameter makes a new reconstruction. The native reports remain attached to the original camera film.

The lead case begins with a fictional resident's report at 02:14. The scene clock gives the local story time. The frame counter and native reports give the time since the recording began. The authored stop near the entrance and the tracker’s sampled time inside an image zone are separate measurements.

Each case links its FFmpeg film, sampled MJPEG import, native import receipt, watch report and detector inspections. Cross-camera candidates are conditional on the authored calibration and shared clock. A published local event includes the original approval, idempotent retry, custody audit and addressed object bytes. The agent desk exposes the native orientation, handoff, resumed workspace and any notification-plan refusal. These replays authorize no physical actions.

## Build and preview

Run the following from this directory with Bun, Node.js and the committed assets. The production build verifies the model, film, JPEG and evidence digests before exporting static HTML and section-specific share images.

```sh
bun install --frozen-lockfile
bun run build
bun run preview
```

With the local Cloudflare preview running, exercise the camera controls, WebGL, evidence links and mobile layout in Chromium.

```sh
bun run check:site http://127.0.0.1:8000
```

## Regenerate the recordings and native evidence

The architectural source is in `art/estate/`. Its asset lock identifies the input materials, vegetation and furnishings. For a different generation of the property, build and freeze the Blender scene and use that same frozen file for the hero, calibrated photographs and interactive mesh. Given its path in `ALDER_BLEND`, the following commands produce the camera plates and compressed scene. Mesh packing requires Pillow and the pinned gltfpack installation.

```sh
stage_dir=$(mktemp -d)
blender -b "$ALDER_BLEND" -P lib/night-scene/export-estate.py -- "$stage_dir/estate.glb"
python3 scripts/pack-estate.py "$stage_dir/estate.glb" public/estate
blender -b "$ALDER_BLEND" -P lib/night-scene/build-plates.py -- public/estate/estate.json "$stage_dir/plates" --preview
python3 lib/night-scene/bind-plates.py "$stage_dir/plates" public
blender -b "$ALDER_BLEND" -P art/estate/render_stills.py -- --views hero --size 2560x1440 --samples 192 --out "$PWD/public/estate"
mkdir -p public/estate/stills
blender -b "$ALDER_BLEND" -P art/estate/render_stills.py -- --views hero_east,terrace_view,pool --size 1920x1080 --samples 112 --out "$PWD/public/estate/stills"
python3 -B art/estate/stills_receipt.py "${ALDER_BLEND%.blend}.json"
```

Set `CHROME_BIN` if Google Chrome is installed outside `/usr/bin/google-chrome`. The capture script requires FFmpeg. Set `FSS_BIN_DIR` to the directory containing the repository's native CLI binaries. The detector package lives under the repository's `models/` directory.

```sh
bun run films
python3 -B scripts/render-estate-briefing.py
python3 -B scripts/estate-evidence.py
bun run build
```

The fictional estate and actors are lab assets. The FSS media and inference crates perform the native analysis. The pinned Cloudflare CLI deploys `out/` as static assets. Both CLIs read the same custom domain and Worker name from `wrangler.jsonc`.

```sh
bun run deploy
```
