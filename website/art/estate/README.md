# Residential property model

Every exhibit uses this fictional property. The scripts in this folder generate a single Blender scene from the site plan and a pinned set of source assets, and film staged incidents in it with scanned people driven by motion capture.

## What is here

| File | Purpose |
|---|---|
| `plan.py` | The site plan: building footprints and heights, drive, walk, terrace, pool, gate, trees, the fixed camera mounts, ground zones and the scripted cases. Pure Python. |
| `emit_plan.py` | Writes `public/estate/estate.json` from `plan.py`. |
| `fetch_assets.py` | Downloads the CC0 inputs for the property into `assets/` and records each file's URL, size and SHA-256 in `assets.lock.json`. |
| `kit.py` | Mesh construction: walls with openings and lapped clapboards, windows, doors, shutters, lanterns, roofs, dormers, gutters, columns. |
| `materials.py` | Every material of the property, including thin architectural glass and the furnished-room views behind lit windows. |
| `house.py` | The buildings: main block, east wing, sunroom, connector, garage, pool house, shed, and three neighbouring houses. |
| `site_works.py` | The grounds: surfaces, terrace, pool, street wall and gate, fences, planting, furniture, cars, exterior lighting. |
| `details.py` | Camera posts, roof fittings, doorbell, mats, grill, loungers, firewood, basement hatch, window boxes, floodlight fixtures. |
| `grass.py` | Scattered grass blades for the lawn. Off by default (`LAWN_BLADES` in `site_works.py`): at night they read as dark speckle. |
| `build_estate.py` | Assembles the scene and saves `build/estate.blend`. |
| `render_stills.py` | Renders named views from the saved scene. |
| `freeze.py` | Packs every image into the scene and saves it read-only under `build/release/`, named by its own SHA-256, with a receipt. |
| `stills_receipt.py` | Writes `public/estate/stills.json`: each published still of the property with its size and SHA-256, and the frozen scene it was rendered from. |
| `fetch_people.py` | Downloads the scanned people and the motion clips and checks every file against `people.lock.json`. `--update` pins the bytes on disk. |
| `scans.py` | Builds the cast from the scans: armatures in metres, materials from the photographed maps, garment tints, a knit cap. Saves `build/cast.blend`. |
| `mocap.py` | Reads CMU BVH clips, loops gait cycles along site paths, joins clips and retargets them onto a skeleton. |
| `takes.py` | Stages a take on a frozen scene: cast, motion, doorbell lens, infrared illuminators, response lighting, closing gate, and the scripted ground truth. |
| `render_take.py` | Renders one camera of a staged take to linear EXR frames. |
| `camera_looks.py` | Develops the EXR frames into consumer-camera footage, encodes the films and writes `scene.json`. |
| `render_twin.py` | Backdrops for the site twin, lights off and lights on: a plan, a tilted view from the street side (`front`, the one the page opens on) and an axonometric view the page does not use. Writes `twin/twin.json`, the mapping from plan coordinates to each picture. |
| `take_stills.py`, `take_hero.py` | Clean stills and a clean ten-second loop from a take. |
| `render_files.py` | Shared by the film scripts and `fetch_people.py`: writes each output in a private folder and moves it into place whole, and records the staging and render settings a frames folder was made with. |

`assets/` and `build/` are not committed. Both are reproducible from the files above.

## Rebuild

Blender 5.3 with Cycles. An NVIDIA GPU with OptiX is assumed. The take scripts under Films set the OptiX device and denoiser themselves and have not been run without such a card.

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

## Films

A take is a staged incident filmed by several fixed cameras at once. The first is `intrusion`: two men arrive on foot at 02:14, one walks in through the open gate, crosses the lawn and tries the front door while the other keeps watch from the pavement; the floodlights come on, both run, and the gate closes.

```sh
python3 -B website/art/estate/fetch_people.py          # about 135 MB, once
blender -b -P website/art/estate/scans.py
blender -b website/art/estate/build/release/alder-house-<sha12>.blend -P website/art/estate/takes.py -- intrusion
for camera in gate driveway doorbell porch entry; do
    blender -b website/art/estate/build/takes/intrusion.blend -P website/art/estate/render_take.py -- \
        --camera $camera --frames auto --gpu 0
done
blender -b website/art/estate/build/takes/intrusion.blend -P website/art/estate/render_twin.py
python3 -B website/art/estate/camera_looks.py intrusion
blender -b website/art/estate/build/takes/intrusion.blend -P website/art/estate/take_stills.py
blender -b website/art/estate/build/takes/intrusion.blend -P website/art/estate/take_hero.py
```

`camera_looks.py` needs numpy, Pillow and ffmpeg, and draws the on-screen clocks with the DejaVu and Liberation fonts in `/usr/share/fonts/truetype/`, which are not pinned. The outputs land in `public/watch/intrusion/`: one H.264 film per camera with its first frame as the poster, `scene.json`, `twin/`, `stills/`, `hero.mp4` and `hero.jpg`.

The camera, hero and twin frame directories record their truth-file digest and render settings in `staging.json`. Forward and reverse jobs using the same settings may safely share a directory. Only completed pictures are published to their reusable names. Hero test pictures go in `hero/preview/`. A twin run with `--only` publishes the selected picture. Run without `--only` to publish the complete mapping.

Keep the previous directory when changing the staging, camera or render settings. An existing raw frame set can be adopted without its marker only if its saved manifest already identifies the same staging and settings and has a matching prior SHA-256 for each existing frame in its `file_sha256` map. Use an empty directory for raw frames with unknown provenance. The legacy five-camera films can still be used with `camera_looks.py intrusion --scene`: the developer checks their native custody hashes, published frame spans and clock regions against the original truth. Staged Blender files from current builds carry their truth digest; the original archived scene is recognised by the digests of both files. The 4k texture copies beside the scans have a separate lifecycle and must be refreshed when those scans change.

Two tests run without Blender. `python3 -B website/scripts/test_render_files.py` covers how outputs are written and frame directories claimed. `python3 -B website/scripts/test_render_take.py` checks `render_take.py`'s choice of frames and plates against the published take.

Some published files have no script. `hero-still.jpg` is frame 112 of the hero loop, and `plates/floods-1280.jpg` and `plates/floods-2560.jpg` are a 21:9 band cut from `stills/floods.jpg`; all three were made by hand. The five posters now published are frame 0 of each film, extracted with ffmpeg after the films were encoded; `camera_looks.py` writes the same frame when it encodes a film. `CREDITS.txt` is written by hand and has to agree with Sources and licences below.

Blender writes the path of the scene file into a JPEG's metadata. `take_stills.py` turns that off; check any picture rendered another way before publishing it.

**Known differences in the published take.** Everything in `public/watch/intrusion/` (films, hero loop, stills) was rendered from a staging made before `takes.py` held the torch at full power until it goes dark. In those pictures the beam fades from 02:14:34.6 to 02:14:39.7. `camera_looks.py` writes that into the `torch_on` and `torch_off` entries of `scene.json` whenever the truth file comes from that staging, which it recognises by the missing `staging` entry. A new staging holds the torch and then cuts it, and its frames have to be rendered afresh.

The published doorbell film also holds film frames 656 to 662 on its open-gate plate while the gate, 40 m away in its picture, is part-way shut: `render_take.py` then listed only `gate` and `driveway` as taking in the gate. In the encoded film the brightness of the picture around the gate changes by less than half a level of 255 on entering and leaving those frames, under a quarter of what a keyframe does there; `website/scripts/test_render_take.py` measures it. A new render includes them.

**People.** The two men are photogrammetry scans of real people, rigged by their publisher. `scans.py` darkens the intruder's shirt and tie and the lookout's T-shirt through the garment masks that ship with the scans, darkens each whole colour map (by 20% for the intruder and 10% for the lookout), smooths each mesh with one level of subdivision and fits a knit cap to the intruder. `takes.py` adds his backpack and hand torch. For the two infrared cameras `render_take.py` lifts the colour maps with a gamma of 0.74 and sets the garment tints to mid grey, because dyed cloth reads pale in near infrared. No face or body shape is altered.

**Motion.** Every movement is a recorded human performance from the CMU motion capture database. `mocap.py` re-expresses each clip against a common T-pose, so clips from different subjects can be joined and carried to any skeleton that can stand in that pose. Walks are laid along site paths by looping one gait cycle; the hips advance by exactly as much as the planted foot moves back under the body, which keeps feet from sliding whatever the character's proportions. Clips are cross-faded over 0.25 to 0.6 s. One gesture is authored by hand: the right arm lifting to the door knob and rattling it, laid over a captured standing clip.

**Cameras.** Five lenses film the take. `gate`, `driveway`, `porch` and `entry` are rectilinear at the plan's field of view; `doorbell` is an equidistant fisheye of 160 degrees on the door post. The porch lens sits on the face of the portico beam; under the soffit, where the scene file puts it, the beam fills the top of the frame. Frames are rendered to linear EXR at 12 per second with half a frame of motion blur. `--frames auto` renders every frame in which a person is in view, the lighting is changing, or the gate is swinging in a picture that takes it in, and holds one empty plate per lighting state for the rest. Which cameras take in the gate is worked out from their lenses, without regard to what stands in the way: all but `entry`.

**Camera looks.** `camera_looks.py` gives each camera a small sensor model: auto exposure with a time constant, a clipping tone curve, colour or infrared monochrome, noise regenerated on every frame, lens softness with in-camera sharpening, vignetting, and a burned-in clock in that product's style. The clocks disagree on purpose: each camera shows its own time, offset from the take clock by the `clock_offset_s` recorded in `scene.json`. The two infrared cameras are rendered with a lens-mounted illuminator that no other camera sees, and with cloth lifted toward the pale grey that dyed fabric shows in near infrared.

**Ground truth.** `scene.json` (schema `fss.website.watch.v1`) holds what was scripted: the clock, each camera's pose, optics, footprint and on-screen-text rectangles, each person's ground track, heading, speed and action per frame, each person's box and visible fraction per camera per frame, the lighting and gate events, and named beats. Boxes come from the solved joint positions; the visible fraction is the share of body sample points with a clear line to the lens past the house and grounds. The people are left out of that test, so neither blocks the other and a person's own body and props block nothing, and a point outside the frame counts as hidden. All of it is marked `"source": "scripted"`. None of it is output of the surveillance software.

Two things to know when reading it. The named beats are the midpoints of cross-fades between motion clips, so an action is under way a little after its beat: the hand is on the door knob from about 0.7 s after `a_tries_door`, and the lookout is still slowing at `b_stops_at_pier`. The lit site backdrops are rendered after the upstairs room lights up, and the page shows them from `lights_on`, so for 1.7 s the site model shows that window lit before the films do.

## Frame

Metres, right-handed. The plan and `estate.json` use +x east, +y up, +z south toward the street, with the origin at finished grade below the centre of the front door threshold. That is the glTF frame. Blender uses (x, -z, y).

## Lighting

The scene is lit for night. The sky is a CC0 panorama at 5% strength with a cool moon. The picture is carried by the practical lamps: wall lanterns, the portico pendant, path lights, gate lanterns, facade and tree uplights, pool lights, lit rooms and three street lamps. Four motion floodlights (`flood_driveway`, `flood_terrace`, `flood_service`, `flood_side`) are present and dark. Each carries its intended power in the custom property `flood_watts`, so a take can switch one on. The intrusion take drives `flood_driveway` at twice that figure and adds two floods under the front eave.

The scene stores exposure +2.6 with the AgX Medium High Contrast look, and adds lens bloom in the compositor. Films bypass both: they are developed from linear frames by `camera_looks.py`.

## Sources and licences

- **Architecture, grounds and details**: authored for this project by the scripts in this folder.
- **Textures, night sky, indoor panoramas, trees, shrubs and site furniture**: [Poly Haven](https://polyhaven.com), CC0. The exact files are listed in `assets.lock.json`.
- **Cars**: the BMW benchmark scene by Mike Pan from [Blender's demo files](https://www.blender.org/download/demo-files/), CC0, fetched as `BMW27_2.blend.zip` (SHA-256 `74f5dc6d718fc565e0ff50e355be7f8b1a58983cc9ae79775608d8905c269ee4`). The roundels and number plate are removed and the model is scaled to 4.38 m.
- **People**: "[Eric Rigged 001 - Rigged 3D Business Man](https://sketchfab.com/3d-models/a46bc9f67aaa415bb4f3241eef900e7f)" and "[Nathan Animated 003 - Walking 3D Man](https://sketchfab.com/3d-models/143a2b1ea5eb4385ae90a73657aca3bc)" by [Renderpeople](https://sketchfab.com/renderpeople), published by Renderpeople under [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/). Changes: clothing recoloured through the supplied masks, each whole colour map darkened (20% and 10%), textures downsized to 4k, meshes subdivided once, a cap, backpack and torch added, bodies driven by the motion below, and for the two infrared films the colour maps lifted with a gamma of 0.74 and the garment tints set to mid grey. The FBX files and maps are fetched from the mirror named in `people.lock.json`; nothing in this repository verifies that mirror against the publisher's own release. Any page that shows the films must carry this attribution.
- **Motion**: the [CMU Graphics Lab Motion Capture Database](http://mocap.cs.cmu.edu), created with funding from NSF EIA-0196217, in the BVH conversion by Bruce Hahne. The clips used are subject 91 trial 17, 77/28, 77/02, 77/05, 77/10, 09/01, 35/01, 40/10 and 16/55.

The owner's private model of a real house was looked at as a reference for the level of architectural detail to aim for. No geometry, texture, measurement or layout from it is used here.
