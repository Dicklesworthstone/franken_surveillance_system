"""A clean loop for the top of the page: the lights come on and the intruder runs.

    blender -b build/takes/intrusion.blend -P take_hero.py -- [--gpu 0] [--test]

Ten seconds at 24 frames per second from a fixed position on the front lawn,
with the estate's own grade and no camera look or on-screen text. Frames go to
build/takes/<take>/hero/, then ffmpeg writes public/watch/<take>/hero.mp4 and
hero.jpg (the first frame). --test renders three frames only. To share the work,
run one process per GPU with --part 0/2 and --part 1/2, then once more without
--part to encode.
"""
import argparse
import pathlib
import subprocess
import sys

import bpy
from mathutils import Vector

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import takes  # noqa: E402
import render_files  # noqa: E402
EYE = (-9.6, 2.9, 15.2)  # plan x, height, plan z: on the lawn south-west of the portico
LOOK = (-1.2, 1.9, 2.0)
LENS = 30.0
LEAD = 2.2  # seconds of quiet before the lights
SECONDS = 10
EXPOSURE = 2.5


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--gpu", type=int, default=None)
    parser.add_argument("--samples", type=int, default=128)
    parser.add_argument("--test", action="store_true")
    parser.add_argument("--part", default="", help="k/n: render only frames whose index is k modulo n, and do not encode")
    args = parser.parse_args(sys.argv[sys.argv.index("--") + 1:] if "--" in sys.argv else [])
    scene = bpy.context.scene
    take = scene["take"]
    frames_dir = HERE / "build" / "takes" / take / "hero"
    _, staging = takes.staged_truth(scene)
    if args.test:
        frames_dir = frames_dir / "preview"
    frames_dir.mkdir(parents=True, exist_ok=True)
    if not args.test:
        render_files.claim_frames(frames_dir, "h*.png", staging, {"camera": "hero", "samples": args.samples})
    public = HERE.parent.parent / "public" / "watch" / take
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
    scene.render.motion_blur_shutter = 0.5
    scene.render.use_persistent_data = True
    scene.render.resolution_x, scene.render.resolution_y = 1920, 1080
    scene.render.resolution_percentage = 100
    scene.render.image_settings.file_format = "PNG"
    scene.view_settings.exposure = EXPOSURE
    for obj in bpy.data.objects:
        if obj.name.startswith("ir_"):
            obj.hide_render = True
    cam = bpy.data.objects.new("hero", bpy.data.cameras.new("hero"))
    scene.collection.objects.link(cam)
    cam.data.lens = LENS
    cam.location = (EYE[0], -EYE[2], EYE[1])
    aim = Vector((LOOK[0], -LOOK[2], LOOK[1])) - cam.location
    cam.rotation_euler = aim.to_track_quat("-Z", "Y").to_euler()
    scene.camera = cam
    first = int(scene["lights_frame"]) - int(LEAD * scene.render.fps)
    count = SECONDS * scene.render.fps
    wanted = [0, int(LEAD * scene.render.fps) + 8, int(LEAD * scene.render.fps) + 60] if args.test else range(count)
    if args.part:
        k, n = (int(v) for v in args.part.split("/"))
        wanted = [i for i in wanted if i % n == k]
    for i in wanted:
        path = frames_dir / f"h{i:04d}.png"
        if path.exists() and not args.test:
            continue
        scene.frame_set(first + i)
        render_files.render_still(scene, path, bpy.ops.render.render)
        print("HERO", i, flush=True)
    if args.test or args.part:
        return
    # Each file is written beside its published name and moved into place whole.
    with render_files.output_file(public / "hero.mp4") as film, render_files.output_file(public / "hero.jpg") as poster:
        subprocess.run(["ffmpeg", "-v", "error", "-y", "-framerate", "24", "-i", str(frames_dir / "h%04d.png"), "-an",
                        "-frames:v", str(count), "-c:v", "libx264", "-preset", "slow", "-crf", "23",
                        "-pix_fmt", "yuv420p", "-movflags", "+faststart", str(film)], check=True)
        subprocess.run(["ffmpeg", "-v", "error", "-y", "-i", str(frames_dir / "h0000.png"),
                        "-q:v", "3", str(poster)], check=True)
    print("HERO film", public / "hero.mp4")


main()
