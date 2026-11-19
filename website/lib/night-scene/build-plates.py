"""Render calibrated clean plates from the authored Blender scene that produced estate.glb.
Run Blender in background with the canonical .blend, then this file, --, estate.json and an output directory."""

import hashlib
import json
import math
import sys
from pathlib import Path

import bpy
from mathutils import Vector

options = sys.argv[sys.argv.index("--") + 1 :]
preview_only = "--preview" in options
plan_path, output = map(Path, [v for v in options if v != "--preview"])
plan = json.loads(plan_path.read_text())
glb = plan_path.parent / "estate.glb"


def sha(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


output.mkdir(parents=True, exist_ok=True)
cameras = {c["id"]: c for c in plan["cameras"]}
cameras["overview"] = cameras.get("overview") or plan["overview"]
# The public fixed takes use the survey, entry, porch, garden and garage lenses.
needed = ["overview", "porch", "entry", "garden", "driveway"]
scene = bpy.context.scene
scene.render.engine = "CYCLES"
prefs = bpy.context.preferences.addons["cycles"].preferences
prefs.compute_device_type = "OPTIX"
prefs.get_devices()
for device in prefs.devices:
    device.use = device.type == "OPTIX"
scene.cycles.device = "GPU"
scene.cycles.samples = 48
scene.cycles.use_denoising = True
scene.cycles.denoiser = "OPTIX"
(
    scene.render.resolution_x,
    scene.render.resolution_y,
    scene.render.resolution_percentage,
) = 1280, 720, 100
scene.render.pixel_aspect_x = scene.render.pixel_aspect_y = 1
scene.render.image_settings.file_format = "JPEG"
scene.render.image_settings.quality = 93
scene.render.use_persistent_data = True
# Preserve the architectural source's HDR lighting, view transform, lens bloom and exposure.
data = bpy.data.cameras.new("Calibrated fixed lens")
camera = bpy.data.objects.new("Calibrated fixed lens", data)
scene.collection.objects.link(camera)
scene.camera = camera
data.type = "PERSP"
data.sensor_fit = "VERTICAL"
data.sensor_height = 24
data.clip_start, data.clip_end = 0.07, 260


def vector(p):
    return Vector((p[0], -p[2], p[1]))


receipt = {
    "schema": "fss.website.calibrated_architectural_plates.v1",
    "width": 1280,
    "height": 720,
    "samples": scene.cycles.samples,
    "exposureEv": scene.view_settings.exposure,
    "blendSha256": sha(Path(bpy.data.filepath)),
    "glbSha256": None if preview_only else sha(glb),
    "planSha256": sha(plan_path),
    "views": {},
}
# Retain actual exterior fixtures beside the three paths. The viewer uses the same
# lamp positions for warm spill on moving bodies and keeps the sky contribution cool.
fixtures = []
for obj in scene.objects:
    if obj.type != "LIGHT" or obj.data.type != "POINT" or obj.data.energy <= 0:
        continue
    x, north, y = obj.matrix_world.translation
    z = -north
    if not (-11 <= x <= 5 and 0 <= z <= 14):
        continue
    if not obj.name.lower().startswith(
        ("path light", "lantern", "portico pendant", "entry post", "entry lamp")
    ):
        continue
    fixtures.append(
        dict(position=[x, y, z], colour=list(obj.data.color), power=obj.data.energy)
    )
receipt["practicals"] = fixtures
for name in needed:
    view = cameras[name]
    target = view.get("look_at") or view["target"]
    vfov = view.get("vfov") or view["verticalFovDegrees"]
    camera.location = vector(view["position"])
    camera.rotation_euler = (
        (vector(target) - camera.location).to_track_quat("-Z", "Y").to_euler()
    )
    data.lens = data.sensor_height / (2 * math.tan(math.radians(vfov) / 2))
    path = output / (name + ".jpg")
    scene.render.filepath = str(path)
    bpy.ops.render.render(write_still=True)
    receipt["views"][name] = {
        "eye": view["position"],
        "target": target,
        "verticalFovDegrees": vfov,
        "url": "/night-media/plates/" + name + ".jpg",
        "sha256": sha(path),
    }
receipt_name = "unbound-preview.json" if preview_only else "index.json"
(output / receipt_name).write_text(json.dumps(receipt, indent=2) + "\n")
