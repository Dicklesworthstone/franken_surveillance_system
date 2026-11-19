# Residential property model

Every exhibit uses this fictional property. The scripts in this folder generate a single Blender scene from the site plan and a pinned set of CC0 source assets.

## What is here

| File | Purpose |
|---|---|
| `plan.py` | The site plan: building footprints and heights, drive, walk, terrace, pool, gate, trees, the fixed camera mounts, ground zones and the scripted cases. Pure Python. |
| `emit_plan.py` | Writes `public/estate/estate.json` from `plan.py`. |
| `fetch_assets.py` | Downloads the CC0 inputs into `assets/` and records each file's URL, size and SHA-256 in `assets.lock.json`. |
| `kit.py` | Mesh construction: walls with openings and lapped clapboards, windows, doors, shutters, lanterns, roofs, dormers, gutters, columns. |
| `materials.py` | Every material, including thin architectural glass and the furnished-room views behind lit windows. |
| `house.py` | The buildings: main block, east wing, sunroom, connector, garage, pool house, shed, and three neighbouring houses. |
| `site_works.py` | The grounds: surfaces, terrace, pool, street wall and gate, fences, planting, furniture, cars, exterior lighting. |
| `details.py` | Camera posts, roof fittings, doorbell, mats, grill, loungers, firewood, basement hatch, window boxes, floodlight fixtures. |
| `grass.py` | Scattered grass blades for the lawn. Off by default (`LAWN_BLADES` in `site_works.py`): at night they read as dark speckle. |
| `build_estate.py` | Assembles the scene and saves `build/estate.blend`. |
| `render_stills.py` | Renders named views from the saved scene. |
| `freeze.py` | Packs every image into the scene and saves it read-only under `build/release/`, named by its own SHA-256, with a receipt. |

`assets/` and `build/` are not committed. Both are reproducible from the files above.

## Rebuild

Blender 5.3 with Cycles. An NVIDIA GPU with OptiX is assumed; rendering on CPU works and is slow.

```sh
python3 -B website/art/estate/fetch_assets.py          # about 1.7 GB, once
python3 -B website/art/estate/emit_plan.py
blender -b -P website/art/estate/build_estate.py
blender -b website/art/estate/build/estate.blend -P website/art/estate/render_stills.py -- \
    --views hero,porch,driveway --out /path/to/output --size 1920x1080 --samples 160
```

View names are the plan's camera ids (`porch`, `driveway`, `gate`, `side`, `terrace`, `pool`, `service`, `entry`, `garden`, `overview`) and the beauty viewpoints (`hero`, `hero_east`, `front`, `court`, `street`, `rear`, `terrace_view`, `aerial`). `--day` swaps the night sky for flat daylight, which helps when checking geometry.

## Release generations

`build/estate.blend` is rewritten by every build. Films, plates, the browser model and their receipts must all come from one frozen file:

```sh
blender -b website/art/estate/build/estate.blend -P website/art/estate/freeze.py
```

This writes `build/release/alder-house-<first 12 hex of its SHA-256>.blend`, read-only and self-contained, and a JSON receipt beside it holding the full digest, the digests of `plan.py` and `assets.lock.json`, the Blender version and the stored render settings. The stills in `public/estate/` are rendered from a frozen file.

## Frame

Metres, right-handed. The plan and `estate.json` use +x east, +y up, +z south toward the street, with the origin at finished grade below the centre of the front door threshold. That is the glTF frame. Blender uses (x, -z, y).

## Lighting

The scene is lit for night. The sky is a CC0 panorama at 5% strength with a cool moon. The picture is carried by the practical lamps: wall lanterns, the portico pendant, path lights, gate lanterns, facade and tree uplights, pool lights, lit rooms and three street lamps. Four motion floodlights (`flood_driveway`, `flood_terrace`, `flood_service`, `flood_side`) are present and dark. Each carries its intended power in the custom property `flood_watts`, so a take can switch one on.

The scene stores exposure +2.6 with the AgX Medium High Contrast look, and adds lens bloom in the compositor.

## Sources and licences

- **Architecture, grounds and details**: authored for this project by the scripts in this folder.
- **Textures, night sky, indoor panoramas, trees, shrubs and site furniture**: [Poly Haven](https://polyhaven.com), CC0. The exact files are listed in `assets.lock.json`.
- **Cars**: the BMW benchmark scene by Mike Pan from [Blender's demo files](https://www.blender.org/download/demo-files/), CC0, fetched as `BMW27_2.blend.zip` (SHA-256 `74f5dc6d718fc565e0ff50e355be7f8b1a58983cc9ae79775608d8905c269ee4`). The roundels and number plate are removed and the model is scaled to 4.38 m.

The owner's private model of a real house was looked at as a reference for the level of architectural detail to aim for. No geometry, texture, measurement or layout from it is used here.
