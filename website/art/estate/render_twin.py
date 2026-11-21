"""Backdrops for the site twin, rendered from a staged take with nobody in it.

    blender -b build/takes/intrusion.blend -P render_twin.py -- [--only plan_dark] [--gpu 0]

Renders build/takes/<take>/twin/{plan,axo,front}_{dark,lit}.jpg, publishes
smaller copies to public/watch/<take>/twin/, and writes the exact mapping from
plan (x, z) at ground level to normalised image (u, v) to
build/takes/<take>.twin.json and to public/watch/<take>/twin/twin.json. "front"
is the view the page's console uses: from due south, 55 degrees above the
ground, framed on the part of the lot the take happens on. A render already in build/ is reused. "dark" is the lighting before the response,
"lit" after the floods and the upstairs room are on.
"""
import argparse
import json
import math
import pathlib
import subprocess
import sys

import bpy
from mathutils import Vector

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import takes  # noqa: E402
import render_files  # noqa: E402
EXTENT = dict(x=(-38.0, 33.0), z=(-54.0, 48.0))  # plan metres covered by both views
WIDTH = 2560
PUBLISHED = 1600  # width of the copies the site serves
# The console's tilted view: the front of the lot, north at the top like the plan.
FRONT = dict(x=(-31.0, 17.0), z=(-33.0, 47.0), elevation=55.0, size=(1600, 2400), published=1200, top=14.0)
EXPOSURE = 5.0


def arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("--only", default="")
    parser.add_argument("--gpu", type=int, default=None)
    parser.add_argument("--samples", type=int, default=96)
    return parser.parse_args(sys.argv[sys.argv.index("--") + 1:] if "--" in sys.argv else [])


def main():
    args = arguments()
    scene = bpy.context.scene
    take = scene["take"]
    out = HERE.parent.parent / "public" / "watch" / take / "twin"
    out.mkdir(parents=True, exist_ok=True)
    full = HERE / "build" / "takes" / take / "twin"
    full.mkdir(parents=True, exist_ok=True)
    _, staging = takes.staged_truth(scene)
    render_files.claim_frames(full, "*.jpg", staging, {"camera": "twin", "samples": args.samples})
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
    scene.render.use_motion_blur = False
    scene.render.use_compositing = False
    scene.render.image_settings.file_format = "JPEG"
    scene.render.image_settings.quality = 94
    scene.view_settings.exposure = EXPOSURE
    bpy.data.collections["people"].hide_render = True
    for obj in bpy.data.objects:
        if obj.name.startswith("ir_"):
            obj.hide_render = True

    (x0, x1), (z0, z1) = EXTENT["x"], EXTENT["z"]
    span_x, span_z = x1 - x0, z1 - z0
    views = {}

    # Straight down, plan north (-z) at the top of the picture.
    plan_cam = bpy.data.objects.new("twin_plan", bpy.data.cameras.new("twin_plan"))
    scene.collection.objects.link(plan_cam)
    plan_cam.data.type = "ORTHO"
    plan_cam.data.ortho_scale = max(span_x, span_z)
    plan_cam.data.clip_end = 600.0
    plan_cam.location = ((x0 + x1) / 2, -(z0 + z1) / 2, 250.0)
    plan_height = round(WIDTH * span_z / span_x)
    views["plan"] = dict(camera=plan_cam, size=(WIDTH, plan_height),
                         affine=[1 / span_x, 0.0, -x0 / span_x, 0.0, 1 / span_z, -z0 / span_z], per_metre_height=[0.0, 0.0])

    # Axonometric from the south-west, 35 degrees above the ground.
    centre = Vector(((x0 + x1) / 2, -(z0 + z1) / 2, 0.0))
    elevation, azimuth = math.radians(35.0), math.radians(225.0)  # camera sits to the south-west
    offset = Vector((math.cos(elevation) * math.sin(azimuth), math.cos(elevation) * math.cos(azimuth), math.sin(elevation))) * 300.0
    axo_cam = bpy.data.objects.new("twin_axo", bpy.data.cameras.new("twin_axo"))
    scene.collection.objects.link(axo_cam)
    axo_cam.data.type = "ORTHO"
    axo_cam.data.clip_end = 900.0
    axo_cam.location = centre + offset
    axo_cam.rotation_euler = (-offset).to_track_quat("-Z", "Y").to_euler()
    bpy.context.view_layer.update()
    basis = axo_cam.matrix_world.to_3x3()
    right, up = basis @ Vector((1, 0, 0)), basis @ Vector((0, 1, 0))
    corners = [Vector((x, -z, h)) for x in (x0, x1) for z in (z0, z1) for h in (0.0, 19.0)]
    reach_r = max(abs((c - centre).dot(right)) for c in corners)
    low = min((c - centre).dot(up) for c in corners)
    high = max((c - centre).dot(up) for c in corners)
    axo_height = 1600
    metres_wide = max(2 * reach_r, (high - low) * WIDTH / axo_height) * 1.03
    metres_high = metres_wide * axo_height / WIDTH
    shift = (high + low) / 2  # centre the picture on the lot's vertical extent
    axo_cam.location = centre + offset + up * shift
    axo_cam.data.ortho_scale = metres_wide
    # A ground point (x, z) is P = (x, -z, 0); u = 0.5 + (P - c) . right / W, v = 0.5 - ((P - c) . up - shift) / H.
    cx, cy = centre.x, centre.y
    affine = [right.x / metres_wide, -right.y / metres_wide, 0.5 - (cx * right.x + cy * right.y) / metres_wide,
              -up.x / metres_high, up.y / metres_high, 0.5 + (cx * up.x + cy * up.y + shift) / metres_high]
    views["axo"] = dict(camera=axo_cam, size=(WIDTH, axo_height), affine=affine,
                        per_metre_height=[right.z / metres_wide, -up.z / metres_high])

    # From due south: east is to the right and north is up, so this view lines up with the plan.
    (fx0, fx1), (fz0, fz1) = FRONT["x"], FRONT["z"]
    f_centre = Vector(((fx0 + fx1) / 2, -(fz0 + fz1) / 2, 0.0))
    f_elev = math.radians(FRONT["elevation"])
    f_offset = Vector((0.0, -math.cos(f_elev), math.sin(f_elev))) * 300.0
    front_cam = bpy.data.objects.new("twin_front", bpy.data.cameras.new("twin_front"))
    scene.collection.objects.link(front_cam)
    front_cam.data.type = "ORTHO"
    front_cam.data.clip_end = 900.0
    front_cam.location = f_centre + f_offset
    front_cam.rotation_euler = (-f_offset).to_track_quat("-Z", "Y").to_euler()
    bpy.context.view_layer.update()
    f_basis = front_cam.matrix_world.to_3x3()
    f_right, f_up = f_basis @ Vector((1, 0, 0)), f_basis @ Vector((0, 1, 0))
    f_corners = [Vector((x, -z, h)) for x in (fx0, fx1) for z in (fz0, fz1) for h in (0.0, FRONT["top"])]
    f_reach = max(abs((c - f_centre).dot(f_right)) for c in f_corners)
    f_low = min((c - f_centre).dot(f_up) for c in f_corners)
    f_high = max((c - f_centre).dot(f_up) for c in f_corners)
    f_w, f_h = FRONT["size"]
    f_wide = max(2 * f_reach, (f_high - f_low) * f_w / f_h)
    f_tall = f_wide * f_h / f_w
    f_shift = (f_high + f_low) / 2
    front_cam.location = f_centre + f_offset + f_up * f_shift
    front_cam.data.ortho_scale = max(f_wide, f_tall)
    fcx, fcy = f_centre.x, f_centre.y
    views["front"] = dict(
        camera=front_cam, size=FRONT["size"], published=FRONT["published"],
        affine=[f_right.x / f_wide, -f_right.y / f_wide, 0.5 - (fcx * f_right.x + fcy * f_right.y) / f_wide,
                -f_up.x / f_tall, f_up.y / f_tall, 0.5 + (fcx * f_up.x + fcy * f_up.y + f_shift) / f_tall],
        per_metre_height=[f_right.z / f_wide, -f_up.z / f_tall])

    states = {"dark": 3, "lit": int(scene["window_frame"]) + 12}
    twin = {}
    for name, view in views.items():
        published = view.get("published", PUBLISHED)
        small = (published, 2 * round(published * view["size"][1] / view["size"][0] / 2))
        entry = dict(width=small[0], height=small[1], affine=[round(float(v), 8) for v in view["affine"]],
                     per_metre_height=[round(float(v), 8) for v in view["per_metre_height"]],
                     mapping="u = a*x + b*z + c, v = d*x + e*z + f for plan (x, z) on the ground; add per_metre_height times height in metres",
                     exposure=EXPOSURE)
        for state, frame in states.items():
            label = f"{name}_{state}"
            entry[state] = f"/watch/{take}/twin/{label}.jpg"
            if args.only and args.only != label:
                continue
            source = full / f"{label}.jpg"
            if not source.exists():
                scene.camera = view["camera"]
                scene.render.resolution_x, scene.render.resolution_y = view["size"]
                scene.render.resolution_percentage = 100
                scene.frame_set(frame)
                render_files.render_still(scene, source, bpy.ops.render.render)
            with render_files.output_file(out / f"{label}.jpg") as target:
                subprocess.run(["ffmpeg", "-v", "error", "-y", "-i", str(source), "-vf", f"scale={small[0]}:{small[1]}:flags=lanczos",
                                "-q:v", "4", str(target)], check=True)
            print("TWIN", out / f"{label}.jpg", flush=True)
        twin[name] = entry
    if args.only:
        return
    twin["extent"] = EXTENT
    render_files.write_text(HERE / "build" / "takes" / f"{take}.twin.json", json.dumps(twin, indent=1) + "\n")
    render_files.write_text(out / "twin.json", json.dumps(twin, separators=(",", ":")) + "\n")
    print("TWIN json written")


main()
