"""Render stills from build/estate.blend.

    blender -b website/art/estate/build/estate.blend -P website/art/estate/render_stills.py -- \
        --views hero,porch --out <dir> [--size 1920x1080] [--samples 160] [--exposure 0] [--day]

`--day` swaps the night sky for flat daylight, which is useful for checking
geometry. View names are the plan's camera ids and the beauty viewpoints.
"""
import argparse
import math
import sys

import bpy

parser = argparse.ArgumentParser()
parser.add_argument("--views", default="hero")
parser.add_argument("--out", required=True)
parser.add_argument("--size", default="1920x1080")
parser.add_argument("--samples", type=int, default=160)
parser.add_argument("--exposure", type=float, default=None)
parser.add_argument("--day", action="store_true")
parser.add_argument("--format", default="JPEG")
args = parser.parse_args(sys.argv[sys.argv.index("--") + 1:])

scene = bpy.context.scene
scene.render.engine = "CYCLES"
prefs = bpy.context.preferences.addons["cycles"].preferences
prefs.compute_device_type = "OPTIX"
prefs.get_devices()
for device in prefs.devices:
    device.use = device.type in {"OPTIX", "CUDA"}
scene.cycles.device = "GPU"
scene.cycles.samples = args.samples
width, height = (int(v) for v in args.size.split("x"))
scene.render.resolution_x, scene.render.resolution_y = width, height
if args.exposure is not None:
    scene.view_settings.exposure = args.exposure
scene.render.image_settings.file_format = args.format
if args.format == "JPEG":
    scene.render.image_settings.quality = 90

if args.day:
    world = bpy.data.worlds.new("day")
    world.use_nodes = True
    world.node_tree.nodes["Background"].inputs["Color"].default_value = (0.75, 0.85, 1.0, 1.0)
    world.node_tree.nodes["Background"].inputs["Strength"].default_value = 0.9
    scene.world = world
    scene.view_settings.exposure = args.exposure or 0.0
    scene.compositing_node_group = None
    for obj in bpy.data.objects:
        if obj.type == "LIGHT" and obj.data.type == "SUN":
            obj.data.energy = 3.2
            obj.data.color = (1.0, 0.96, 0.9)
            obj.data.angle = math.radians(2.0)

for view in args.views.split(","):
    cam = bpy.data.objects.get("cam_" + view) or bpy.data.objects.get("view_" + view)
    if cam is None:
        print("unknown view", view)
        continue
    scene.camera = cam
    scene.render.filepath = f"{args.out}/{view}"
    bpy.ops.render.render(write_still=True)
    print("RENDERED", view)
