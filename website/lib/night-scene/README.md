# Reproduce the residential security recordings

All cameras, pace settings, metric paths and subject heights come from the estate plan. The fixed films share one source model with the orbitable WebGL survey. A Cycles photograph supplies the static light and materials for a registered optical centre. The browser projects the subject through that camera and tests foreground occlusion against the exported mesh. Moving the survey camera switches it to live 3D.

The films run at 24 frames per second. Each frame averages three samples of the scene in linear light over a simulated 1/48-second shutter. The trajectory records the authored foot position at the centre of the sampled exposure. The native detector receives the finished film pixels.

Build the source estate using the [estate instructions](../../art/estate/README.md). Keep the generated scene alongside its source assets. The following commands run from `website/` and use Blender 5.3, libvips, Node, Chrome and FFmpeg. Replace the two paths on the first lines with the chosen source and working directory.

```sh
scene=/path/to/estate/build/approved.blend
stage=/path/to/capture-staging
python3 -B art/estate/emit_plan.py
blender -b "$scene" --python-exit-code 1 -P lib/night-scene/export-estate.py -- "$stage/estate.glb"
python3 scripts/pack-estate.py "$stage/estate.glb" public/estate
blender -b "$scene" --python-exit-code 1 -P lib/night-scene/build-plates.py -- "$PWD/public/estate/estate.json" "$stage/plates" --preview
python3 lib/night-scene/bind-plates.py "$stage/plates" public
node scripts/render-night-estate.mjs
```

The two Blender jobs can run concurrently. The binding step checks the raw export’s authoring-scene digest, the packed model, plan, optical calibration and photograph hashes. The recorder writes each 960 × 540 fixed film and still, then publishes their exact hashes and sampled metric trajectories in `public/night-media/capture.json`. For a still-only visual review, add `--preview /path/to/review` to the recording command.

The visitor and courier use Renderpeople's rigged scans of two different adults. Their GLBs embed photographed colour, tangent normals and roughness. The visitor uses Rocketbox motion captures. The courier uses the walking performance supplied with the Nathan scan. The raccoon uses a textured, subdivided body and a quadruped skeletal clip. The [actor credits](../../public/night-media/actors/CREDITS.txt) identify the original works, licenses and modifications.

To rebuild the human GLBs, run `python lib/night-scene/prepare-humans.py SCAN_CACHE MOTION_DIR public/night-media/actors` from `website/` with Blender 4.3's Python module and Pillow. The script fetches and verifies the pinned Renderpeople source files in `SCAN_CACHE` and the three [Rocketbox motion captures](https://github.com/microsoft/Microsoft-Rocketbox/tree/0943055db6ec570bcef9f2c8b41c9e5467c808f9/Assets/Animations) in `MOTION_DIR`. Both caches can start empty. Regenerate the camera recordings and native evidence after changing either performer.
