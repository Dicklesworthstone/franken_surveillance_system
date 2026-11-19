# Reproduce the Alder House recordings

All cameras, pace settings, metric paths and subject heights come from the estate plan. The fixed films share one source model with the orbitable WebGL survey. A Cycles photograph supplies the static light and materials for a registered optical centre. The browser projects the subject through that camera and tests foreground occlusion against the exported mesh. Moving the survey camera switches it to live 3D.

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

The visitor and courier use licensed, articulated Microsoft Rocketbox meshes and recorded motions. The raccoon has a textured, subdivided body and a quadruped skeletal clip. Inspect the [asset credits](../../public/night-media/actors/CREDITS.txt) for the authors and source revisions. The human sources can be prepared with the Blender 4.3 Python module and `prepare-humans.py source-dir output-dir`. The FFmpeg MP4s and JPGs contain synthetic camera pixels. Native detector outputs are produced separately by the evidence build.
