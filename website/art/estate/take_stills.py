"""Clean stills from a staged take: no camera look, the estate's own grade.

    blender -b build/takes/intrusion.blend -P take_stills.py -- [--only floods] [--gpu 0] [--size 2560x1440]

Each still names a moment in the take and a viewpoint placed relative to the
intruder's position at that moment. Output: public/watch/<take>/stills/<name>.jpg
"""
import argparse
import pathlib
import sys

import bpy
from mathutils import Vector

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import takes  # noqa: E402
import render_files  # noqa: E402

# name: seconds after a beat, camera offset from the intruder in plan metres (east, up, south),
# aim height on the intruder, focal length, exposure.
STILLS = {
    "floods": dict(beat="a_turns_to_run", after=3.6, offset=(-7.5, 1.25, 6.5), aim=(1.2, 1.1, -1.0), lens=30.0, exposure=2.2),
    "door": dict(beat="a_tries_door", after=4.3, absolute=(0.75, 2.05, 5.6), look=(0.0, 1.75, 0.0), lens=34.0, exposure=2.9),
    "drive": dict(beat="a_exits_gate", after=-2.6, offset=(1.6, 1.2, 6.5), aim=(0.0, 1.05, 0.0), lens=38.0, exposure=1.9),
    "watch": dict(beat="a_enters_gate", after=1.3, absolute=(-20.5, 1.7, 31.5), look=(-14.6, 1.2, 38.2), lens=32.0, exposure=2.6),
}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--only", default="")
    parser.add_argument("--gpu", type=int, default=None)
    parser.add_argument("--size", default="2560x1440")
    parser.add_argument("--samples", type=int, default=192)
    parser.add_argument("--out", default="")
    args = parser.parse_args(sys.argv[sys.argv.index("--") + 1:] if "--" in sys.argv else [])
    scene = bpy.context.scene
    take = scene["take"]
    truth, _ = takes.staged_truth(scene)
    out = pathlib.Path(args.out) if args.out else HERE.parent.parent / "public" / "watch" / take / "stills"
    out.mkdir(parents=True, exist_ok=True)
    prefs = bpy.context.preferences.addons["cycles"].preferences
    prefs.compute_device_type = "OPTIX"
    prefs.get_devices()
    cards = [d for d in prefs.devices if d.type == "OPTIX"]
    for device in prefs.devices:
        device.use = False
    for i, device in enumerate(cards):
        device.use = args.gpu is None or i == args.gpu
    scene.cycles.device = "GPU"
    scene.cycles.samples = args.samples
    scene.cycles.use_denoising = True
    scene.render.use_compositing = True
    scene.render.use_motion_blur = True
    scene.render.motion_blur_shutter = 0.35
    width, height = (int(v) for v in args.size.split("x"))
    scene.render.resolution_x, scene.render.resolution_y = width, height
    scene.render.resolution_percentage = 100
    scene.render.image_settings.file_format = "JPEG"
    scene.render.image_settings.quality = 92
    # Blender writes every enabled stamp field into the JPEG's metadata, the path of this
    # file among them. These pictures are published, so none is written.
    for field in dir(scene.render):
        if field.startswith("use_stamp_"):
            setattr(scene.render, field, False)
    for obj in bpy.data.objects:
        if obj.name.startswith("ir_"):
            obj.hide_render = True
    fps = truth["clock"]["fps"]
    track = truth["tracks"]["a"]
    for name, still in STILLS.items():
        if args.only and name not in args.only.split(","):
            continue
        seconds = truth["beats"][still["beat"]] + still["after"]
        f = int(round(seconds * fps))
        person = Vector((track["x"][f], 0.0, track["z"][f]))
        if "absolute" in still:
            eye, target = Vector(still["absolute"]), Vector(still["look"])
        else:
            eye = person + Vector(still["offset"])
            target = person + Vector(still["aim"])
        cam = bpy.data.objects.new(f"still_{name}", bpy.data.cameras.new(f"still_{name}"))
        scene.collection.objects.link(cam)
        cam.data.lens = still["lens"]
        cam.data.clip_start = 0.1
        cam.location = (eye.x, -eye.z, eye.y)
        aim = Vector((target.x, -target.z, target.y)) - cam.location
        cam.rotation_euler = aim.to_track_quat("-Z", "Y").to_euler()
        scene.camera = cam
        scene.view_settings.exposure = still["exposure"]
        scene.frame_set(1 + 2 * f)
        target = out / f"{name}.jpg"
        render_files.render_still(scene, target, bpy.ops.render.render)
        print("STILL", name, "at", round(seconds, 2), "s", target, flush=True)


main()
