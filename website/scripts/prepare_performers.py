"""Prepare the two rigged, photographic human bodies for Blender's motion bake.

Run with Blender 4.3's bpy and Pillow: python prepare_performers.py SOURCE_DIR OUTPUT_DIR.
The authoring cache contains the original FBX and 8K photographs. Published GLBs
embed smaller textures and can be viewed offline. See night-media/actors/CREDITS.txt.
"""

from hashlib import sha256
from pathlib import Path
import sys
from urllib.parse import quote
from urllib.request import urlopen

import bpy
from PIL import Image

REVISION = "e752af943e8cf035def41f17d9efa8e50b1bc135"
SOURCE = f"https://raw.githubusercontent.com/PacktPublishing/Godot-4-Game-Development-Cookbook/{REVISION}/"
PERFORMERS = {
    "courier": ("Nathan", "rp_nathan_animated_003", "walking"),
    "visitor": ("Eric", "rp_eric_rigged_001", "ue4"),
}
DIGESTS = {
    "rp_eric_rigged_001_dif.jpg": "586ca7aa7acdd4a66258045553d434d9cb52f45c6f49a992d897c3fd4705ac2e",
    "rp_eric_rigged_001_mask02.jpg": "704b7a16f97bb5a833986fa790e08127b892a90eebcd9ca8ffe01cad75b5cdf6",
    "rp_eric_rigged_001_gloss.jpg": "73bf1d7c419557b4794897abbf1dbe14db81d650cd6374acae423b5b98832c27",
    "rp_eric_rigged_001_norm.jpg": "9ebc1c277550ead990b62f1c9ea4ba84e79a1a771ece642d2af0fb5c09e47c8f",
    "rp_eric_rigged_001_ue4.fbx": "060e4a29027d0338a0a15fad3ab7c57eec3f6dcf9a324301fb57d663d971025d",
    "rp_nathan_animated_003_dif.jpg": "38eae688b4524559c7337593bdc26a2f860c166be1aee44a646bbd1b3e7eb221",
    "rp_nathan_animated_003_gloss.jpg": "47e3b42b61e962ad875c0b1bd46f57749e572db573a3c7f8150de5edce39ccbe",
    "rp_nathan_animated_003_norm.jpg": "43445715628c596a375f76584aaa4018bd316f2cad1154d01a9f7b7d09cac7a5",
    "rp_nathan_animated_003_walking_ue4.fbx": "7fe682ee9190fd4ef828e822cfdb2c633e17c84ce47e3bb2ecbd5b6bc024a77e",
    "rp_nathan_animated_003_walking.fbx": "7a7a65df5a382049dd6bbb2d0ecbeba260702191916fbca97de537cf952f97ec",
}


def source_file(source_dir, name, filename):
    path = Path(source_dir) / name / filename
    if path.is_file():
        data = path.read_bytes()
    else:
        directory = f"Chapter 9/{name}/" + ("tex/" if path.suffix == ".jpg" else "")
        with urlopen(SOURCE + quote(directory + filename), timeout=90) as response:
            data = response.read()
    if sha256(data).hexdigest() != DIGESTS[filename]:
        raise ValueError(f"Unexpected source bytes for {filename}")
    if not path.is_file():
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
    return path


def texture(source_dir, work_dir, role, channel, size):
    name, prefix, _ = PERFORMERS[role]
    source = source_file(source_dir, name, f"{prefix}_{channel}.jpg")
    with Image.open(source) as original:
        image = original.convert("RGB").resize((size, size), Image.Resampling.LANCZOS)
    if role == "visitor" and channel == "dif":
        # Keep the scan's cloth weave and folds while putting the visitor in a
        # slate shirt. The publisher's wardrobe mask leaves skin and hair intact.
        mask_path = source_file(source_dir, name, f"{prefix}_mask02.jpg")
        with Image.open(mask_path) as original_mask:
            mask = original_mask.convert("L").resize(
                image.size, Image.Resampling.LANCZOS
            )
        dyed = Image.merge(
            "RGB",
            tuple(
                band.point(lambda value, dye=dye: value * dye)
                for band, dye in zip(image.split(), (0.43, 0.55, 0.61), strict=True)
            ),
        )
        image.paste(dyed, mask=mask)
    if channel == "gloss":
        # glTF stores roughness in green and metallic in blue. Both humans wear cloth.
        # Interpret the legacy gloss texture as sRGB before converting it to GGX.
        # A direct inversion makes medium-grey skin and wool look wet. Leave
        # glassy highlights on the eyes and polished shoes while cloth stays matte.
        def ggx_roughness(value):
            encoded = value / 255
            linear = (
                encoded / 12.92
                if encoded <= 0.04045
                else ((encoded + 0.055) / 1.055) ** 2.4
            )
            return round(255 * max(0.24, min(0.94, 1 - linear)))

        roughness = image.convert("L").point(
            [ggx_roughness(value) for value in range(256)]
        )
        image = Image.merge(
            "RGB",
            (
                Image.new("L", image.size, 255),
                roughness,
                Image.new("L", image.size),
            ),
        )
    output = Path(work_dir) / f"{prefix}_{channel}.jpg"
    output.parent.mkdir(parents=True, exist_ok=True)
    image.save(output, quality=92, subsampling=0)
    result = bpy.data.images.load(str(output))
    result.colorspace_settings.name = "sRGB" if channel == "dif" else "Non-Color"
    result.pack()
    return result


def attach_materials(character_objects, source_dir, role, work_dir):
    """Supply the author-sampled colour, tangent normals and roughness to a rigged mesh."""
    meshes = [obj for obj in character_objects if obj.type == "MESH"]
    if len(meshes) != 1:
        raise ValueError(
            f"Expected one skinned body for {role}, received {len(meshes)}"
        )
    mesh = meshes[0]
    material = bpy.data.materials.new(f"{role.title()} clothing and skin")
    material.use_nodes = True
    nodes, links = material.node_tree.nodes, material.node_tree.links
    surface = nodes.get("Principled BSDF")
    surface.inputs["Metallic"].default_value = 0
    colour, normal, physical = (nodes.new("ShaderNodeTexImage") for _ in range(3))
    colour.image = texture(source_dir, work_dir, role, "dif", 2048)
    normal.image = texture(source_dir, work_dir, role, "norm", 2048)
    physical.image = texture(source_dir, work_dir, role, "gloss", 1024)
    bump = nodes.new("ShaderNodeNormalMap")
    channels = nodes.new("ShaderNodeSeparateColor")
    links.new(colour.outputs["Color"], surface.inputs["Base Color"])
    links.new(normal.outputs["Color"], bump.inputs["Color"])
    links.new(bump.outputs["Normal"], surface.inputs["Normal"])
    links.new(physical.outputs["Color"], channels.inputs["Color"])
    links.new(channels.outputs["Green"], surface.inputs["Roughness"])
    links.new(channels.outputs["Blue"], surface.inputs["Metallic"])
    mesh.data.materials.clear()
    mesh.data.materials.append(material)
    return mesh


def prepare_body(role, source_dir, work_dir):
    """Import one clothed body, hand/finger weights and any authored FBX performance."""
    name, prefix, pose = PERFORMERS[role]
    fbx = source_file(source_dir, name, f"{prefix}_{pose}.fbx")
    existing = set(bpy.data.objects)
    bpy.ops.import_scene.fbx(filepath=str(fbx), use_anim=True)
    added = set(bpy.data.objects) - existing
    armature = next(obj for obj in added if obj.type == "ARMATURE")
    if role == "courier":
        # The publisher's full walking FBX includes the skinned body and motion.
        # Align its anatomical joint names with the visitor's rig. Blender also
        # updates vertex groups and animation paths, preserving the captured pose.
        parts = {
            "hip": "pelvis",
            "neck": "neck_01",
            "upperleg": "thigh",
            "lowerleg": "calf",
            "shoulder": "clavicle",
        }
        for bone in armature.data.bones:
            name = bone.name.removeprefix(f"{prefix}_walking_")
            region, _, suffix = name.partition("_")
            renamed = parts.get(region, region) + ("_" + suffix if suffix else "")
            bone.name = renamed.replace("_twist_", "_twist_01_")
    return armature, attach_materials(added, source_dir, role, work_dir)


if __name__ == "__main__":
    source_dir, work_dir = map(Path, sys.argv[-2:])
    for role in PERFORMERS:
        bpy.ops.wm.read_factory_settings(use_empty=True)
        prepare_body(role, source_dir, work_dir)
        bpy.ops.wm.save_as_mainfile(filepath=str(work_dir / f"{role}.blend"))
