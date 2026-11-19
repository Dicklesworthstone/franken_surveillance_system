"""Build Alder House and save it as build/estate.blend.

    blender -b -P website/art/estate/build_estate.py

The model is generated from plan.py and the CC0 inputs listed in
assets.lock.json, so the same inputs give the same scene.
"""
import math
import pathlib
import sys

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import bpy  # noqa: E402
from mathutils import Vector  # noqa: E402

import house  # noqa: E402
import materials  # noqa: E402
import plan  # noqa: E402

try:
    import site_works  # noqa: E402
except ImportError:  # the grounds are optional while the house is being developed
    site_works = None

BUILD = HERE / "build"
COLOURS = {"warm": (1.0, 0.72, 0.44), "warm_white": (1.0, 0.84, 0.66), "cool": (0.75, 0.86, 1.0),
           "pool": (0.35, 0.85, 1.0), "sodium": (1.0, 0.62, 0.3)}


def reset():
    bpy.ops.wm.read_factory_settings(use_empty=True)
    scene = bpy.context.scene
    scene.unit_settings.system = "METRIC"
    return scene


def collection(name, parent=None):
    col = bpy.data.collections.new(name)
    (parent or bpy.context.scene.collection).children.link(col)
    return col


def to_blender(p):
    """Site frame (x east, y up, z south) to Blender (x, -z, y)."""
    return Vector((p[0], -p[2], p[1]))


def add_light(col, name, location, watts, colour="warm", radius=0.04, kind="POINT", **extra):
    data = bpy.data.lights.new(name, kind)
    data.energy = watts
    data.color = COLOURS[colour]
    if kind in ("POINT", "SPOT"):
        data.shadow_soft_size = radius
    for key, value in extra.items():
        setattr(data, key, value)
    obj = bpy.data.objects.new(name, data)
    obj.location = location
    col.objects.link(obj)
    return obj


def aim(obj, target):
    direction = Vector(target) - obj.location
    obj.rotation_euler = direction.to_track_quat("-Z", "Y").to_euler()


def add_cameras(col):
    """The fixed security cameras from the plan, plus beauty viewpoints."""
    made = {}
    for cam in plan.CAMERAS:
        data = bpy.data.cameras.new("cam_" + cam["id"])
        data.sensor_fit = "VERTICAL"
        data.sensor_height = 24.0
        data.lens = 12.0 / math.tan(math.radians(cam["vfov"]) / 2)
        data.clip_start, data.clip_end = 0.05, 600.0
        obj = bpy.data.objects.new("cam_" + cam["id"], data)
        obj.location = to_blender(cam["position"])
        col.objects.link(obj)
        aim(obj, to_blender(cam["look_at"]))
        made[cam["id"]] = obj
    overview = getattr(plan, "OVERVIEW", None)
    if overview:
        data = bpy.data.cameras.new("cam_overview")
        data.sensor_fit = "VERTICAL"
        data.sensor_height = 24.0
        data.lens = 12.0 / math.tan(math.radians(overview["vfov"]) / 2)
        data.clip_start, data.clip_end = 0.1, 800.0
        obj = bpy.data.objects.new("cam_overview", data)
        obj.location = to_blender(overview["position"])
        col.objects.link(obj)
        aim(obj, to_blender(overview["look_at"]))
        made["overview"] = obj
    beauty = {
        # name: (position, look_at, focal length in mm) in the site frame
        # Front door about two-thirds across, garage wing and court dark on the left for a headline.
        "hero": ((-10.0, 1.6, 30.0), (-5.9, 1.6, 0.0), 28.0),
        "hero_east": ((27.0, 1.7, 22.0), (-7.0, 4.0, -3.0), 30.0),
        "street": ((-4.0, 1.6, 43.6), (-6.0, 3.2, 0.0), 35.0),
        "front": ((3.5, 1.6, 21.0), (0.0, 4.0, 0.0), 28.0),
        "court": ((-9.5, 1.6, 13.5), (-20.0, 1.6, -1.0), 28.0),
        "rear": ((-13.0, 1.7, -38.0), (3.0, 3.0, -8.0), 30.0),
        "terrace_view": ((14.5, 1.65, -24.0), (-1.0, 2.6, -11.0), 28.0),
        "aerial": ((-34.0, 30.0, 42.0), (-2.0, 2.0, -10.0), 30.0),
    }
    for name, (position, look_at, lens) in beauty.items():
        data = bpy.data.cameras.new("view_" + name)
        data.lens = lens
        if name == "hero":
            data.shift_y = 0.085  # keep the camera level and lift the frame, so verticals stay vertical
        data.clip_start, data.clip_end = 0.1, 800.0
        obj = bpy.data.objects.new("view_" + name, data)
        obj.location = to_blender(position)
        col.objects.link(obj)
        aim(obj, to_blender(look_at))
        made[name] = obj
    return made


def night_world(scene, strength=0.065):
    """Moonlit sky from a CC0 HDRI, kept dark so the house lights carry the picture."""
    world = bpy.data.worlds.new("night")
    world.use_nodes = True
    nodes, links = world.node_tree.nodes, world.node_tree.links
    background = nodes["Background"]
    env = nodes.new("ShaderNodeTexEnvironment")
    env.image = bpy.data.images.load(str(HERE / "assets" / "hdris" / "qwantani_night_puresky.exr"), check_existing=True)
    mapping = nodes.new("ShaderNodeMapping")
    mapping.inputs["Rotation"].default_value = (0.0, 0.0, math.radians(200.0))
    coord = nodes.new("ShaderNodeTexCoord")
    links.new(coord.outputs["Generated"], mapping.inputs["Vector"])
    links.new(mapping.outputs["Vector"], env.inputs["Vector"])
    tint = nodes.new("ShaderNodeMix")
    tint.data_type = "RGBA"
    tint.blend_type = "MULTIPLY"
    tint.inputs["Factor"].default_value = 1.0
    tint.inputs["B"].default_value = (0.42, 0.6, 1.0, 1.0)
    links.new(env.outputs["Color"], tint.inputs["A"])
    links.new(tint.outputs["Result"], background.inputs["Color"])
    background.inputs["Strength"].default_value = strength
    scene.world = world


def configure_render(scene, samples=160):
    scene.render.engine = "CYCLES"
    prefs = bpy.context.preferences.addons["cycles"].preferences
    prefs.compute_device_type = "OPTIX"
    prefs.get_devices()
    for device in prefs.devices:
        device.use = device.type in {"OPTIX", "CUDA"}
    scene.cycles.device = "GPU"
    scene.cycles.samples = samples
    scene.cycles.use_adaptive_sampling = True
    scene.cycles.adaptive_threshold = 0.02
    scene.cycles.use_denoising = True
    scene.cycles.denoiser = "OPTIX"
    scene.cycles.max_bounces = 8
    scene.cycles.transparent_max_bounces = 16
    scene.cycles.sample_clamp_indirect = 8.0
    scene.cycles.caustics_reflective = False
    scene.cycles.caustics_refractive = False
    scene.render.resolution_x, scene.render.resolution_y = 1920, 1080
    scene.render.resolution_percentage = 100
    scene.view_settings.view_transform = "AgX"
    scene.view_settings.look = "AgX - Medium High Contrast"
    scene.view_settings.exposure = 2.6
    scene.render.use_persistent_data = True
    scene.render.image_settings.file_format = "PNG"
    bloom(scene)


def bloom(scene):
    """Lens bloom around bright lamps, as a real camera shows at night."""
    tree = bpy.data.node_groups.new("estate_bloom", "CompositorNodeTree")
    scene.compositing_node_group = tree
    layers = tree.nodes.new("CompositorNodeRLayers")
    glare = tree.nodes.new("CompositorNodeGlare")
    glare.inputs["Type"].default_value = "Bloom"
    glare.inputs["Quality"].default_value = "High"
    glare.inputs["Threshold"].default_value = 1.2
    glare.inputs["Strength"].default_value = 0.35
    glare.inputs["Size"].default_value = 0.45
    out = tree.nodes.new("NodeGroupOutput")
    tree.interface.new_socket("Image", in_out="OUTPUT", socket_type="NodeSocketColor")
    tree.links.new(layers.outputs["Image"], glare.inputs["Image"])
    tree.links.new(glare.outputs["Image"], out.inputs["Image"])


def main():
    scene = reset()
    mats = materials.library()
    buildings = collection("Buildings")
    heights, frames, lights = house.build(buildings, mats)
    light_col = collection("Lights")
    for name, location, watts, colour, radius in lights:
        add_light(light_col, name, location, watts, colour, radius)
    moon = add_light(light_col, "moon", (-50.0, -40.0, 80.0), 0.07, "cool", kind="SUN")
    moon.data.angle = math.radians(0.8)
    aim(moon, (0.0, 0.0, 0.0))
    if site_works:
        site_works.build(scene, mats, collection, add_light, light_col, frames, heights)
    else:
        ground = bpy.data.meshes.new("ground")
        ground.from_pydata([(-80, -80, 0), (80, -80, 0), (80, 80, 0), (-80, 80, 0)], [], [(0, 1, 2, 3)])
        ground.materials.append(mats["lawn"])
        ground.uv_layers.new(name="UVMap")
        for loop, uv in zip(ground.uv_layers[0].data, [(-80, -80), (80, -80), (80, 80), (-80, 80)]):
            loop.uv = uv
        bpy.context.scene.collection.objects.link(bpy.data.objects.new("ground", ground))
    cameras = add_cameras(collection("Cameras"))
    scene.camera = cameras["hero"]
    night_world(scene)
    configure_render(scene)
    BUILD.mkdir(exist_ok=True)
    bpy.ops.wm.save_as_mainfile(filepath=str(BUILD / "estate.blend"))
    tris = sum(len(p.vertices) - 2 for o in bpy.data.objects if o.type == "MESH" for p in o.data.polygons)
    print("ESTATE objects", len(bpy.data.objects), "triangles", tris)


main()
