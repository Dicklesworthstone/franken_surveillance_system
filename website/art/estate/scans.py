"""The cast: photoscanned people by Renderpeople, CC BY 4.0.

    blender -b -P scans.py

Imports the rigged FBX files, puts each armature in metres at the origin,
builds a path-tracing material from the photographed maps (downsized to 4k),
recolours garments through the supplied masks, adds a knit cap, and saves
build/cast.blend with one collection per person. Each armature carries a
"cmu_map" property so mocap.Retarget can drive it with CMU clips.

Sources and licence: see people.lock.json and the README credits.
"""
import json
import pathlib

import bmesh
import bpy
from mathutils import Matrix, Vector

HERE = pathlib.Path(__file__).resolve().parent
SCANS = HERE / "assets" / "scans"

CAST = {
    "intruder": dict(
        fbx="eric/rp_eric_rigged_001_zup_t.fbx", maps="eric/rp_eric_rigged_001", prefix="",
        # mask01 is the shirt, mask02 the tie, collar and cuffs: all go dark.
        tints=[("mask01", (0.035, 0.038, 0.045)), ("mask02", (0.03, 0.03, 0.035))],
        value=0.8, cap=(0.03, 0.032, 0.036),
    ),
    "lookout": dict(
        fbx="nathan/rp_nathan_animated_003_walking.fbx", maps="nathan/rp_nathan_animated_003",
        prefix="rp_nathan_animated_003_walking_",
        # mask01 is the T-shirt.
        tints=[("mask01", (0.2, 0.17, 0.12))],
        value=0.9, cap=None,
    ),
}

BONES = {"Hips": "hip", "LowerBack": "spine_01", "Spine": "spine_02", "Spine1": "spine_03", "Neck": "neck", "Head": "head"}
SIDED = {"Shoulder": "shoulder", "Arm": "upperarm", "ForeArm": "lowerarm", "Hand": "hand",
         "UpLeg": "upperleg", "Leg": "lowerleg", "Foot": "foot", "ToeBase": "ball"}
FINGERS = ("index", "middle", "ring", "pinky")


def small(path, size=4096):
    """A 4k copy of an 8k map, made once."""
    target = path.parent / "4k" / path.name
    if not target.exists():
        target.parent.mkdir(exist_ok=True)
        image = bpy.data.images.load(str(path))
        image.scale(size, size)
        image.filepath_raw = str(target)
        image.file_format = "JPEG"
        image.save()
        bpy.data.images.remove(image)
    return target


def material(name, spec):
    stem = SCANS / spec["maps"]
    mat = bpy.data.materials.new(f"{name}_scan")
    mat.use_nodes = True
    nodes, links = mat.node_tree.nodes, mat.node_tree.links
    shader = nodes["Principled BSDF"]

    def texture(kind, colour=False):
        node = nodes.new("ShaderNodeTexImage")
        node.image = bpy.data.images.load(str(small(pathlib.Path(f"{stem}_{kind}.jpg"))), check_existing=True)
        if not colour:
            node.image.colorspace_settings.name = "Non-Color"
        return node

    colour = texture("dif", True).outputs["Color"]
    for mask, tint in spec["tints"]:
        mix = nodes.new("ShaderNodeMix")
        mix.name = f"tint_{mask}"
        mix.data_type = "RGBA"
        mix.blend_type = "MULTIPLY"
        mix.inputs["B"].default_value = (*tint, 1.0)
        links.new(texture(mask).outputs["Color"], mix.inputs["Factor"])
        links.new(colour, mix.inputs["A"])
        colour = mix.outputs["Result"]
    level = nodes.new("ShaderNodeMix")
    level.data_type = "RGBA"
    level.blend_type = "MULTIPLY"
    level.inputs["Factor"].default_value = 1.0
    level.inputs["B"].default_value = (spec["value"],) * 3 + (1.0,)
    links.new(colour, level.inputs["A"])
    # Dyed cloth is pale in near infrared: render_take lowers this gamma for infrared cameras.
    lift = nodes.new("ShaderNodeGamma")
    lift.name = "ir_gamma"
    lift.inputs["Gamma"].default_value = 1.0
    links.new(level.outputs["Result"], lift.inputs["Color"])
    links.new(lift.outputs["Color"], shader.inputs["Base Color"])
    invert = nodes.new("ShaderNodeInvert")
    links.new(texture("gloss").outputs["Color"], invert.inputs["Color"])
    rough = nodes.new("ShaderNodeMath")
    rough.operation = "MAXIMUM"
    rough.inputs[1].default_value = 0.42
    links.new(invert.outputs["Color"], rough.inputs[0])
    links.new(rough.outputs["Value"], shader.inputs["Roughness"])
    bump = nodes.new("ShaderNodeNormalMap")
    links.new(texture("norm").outputs["Color"], bump.inputs["Color"])
    links.new(bump.outputs["Normal"], shader.inputs["Normal"])
    return mat


def knit_cap(name, rig, mesh, head_bone, colour, collection):
    """A close knit cap fitted over the scan's own head."""
    group = mesh.vertex_groups[head_bone].index
    brow = rig.data.bones[head_bone].head_local.z + 0.095
    points = []
    for vertex in mesh.data.vertices:
        if vertex.co.z > brow and any(g.group == group and g.weight > 0.5 for g in vertex.groups):
            points.append(vertex.co.copy())
    low = Vector((min(p.x for p in points), min(p.y for p in points), brow))
    high = Vector((max(p.x for p in points), max(p.y for p in points), max(p.z for p in points)))
    centre = Vector(((low.x + high.x) / 2, (low.y + high.y) / 2, brow - 0.015))
    radii = Vector(((high.x - low.x) / 2 + 0.012, (high.y - low.y) / 2 + 0.012, high.z - centre.z + 0.012))
    bm = bmesh.new()
    bmesh.ops.create_uvsphere(bm, u_segments=40, v_segments=24, radius=1.0)
    for vertex in list(bm.verts):
        vertex.co = Vector((vertex.co.x * radii.x, vertex.co.y * radii.y, vertex.co.z * radii.z))
    # Keep the crown: the rim sits on the brow in front and drops over the nape.
    doomed = [v for v in bm.verts if v.co.z < 0.012 - (0.03 if v.co.y < 0 else 0.048) * v.co.y / radii.y]
    bmesh.ops.delete(bm, geom=doomed, context="VERTS")
    for vertex in bm.verts:
        vertex.co += centre
    data = bpy.data.meshes.new(f"{name}_cap")
    bm.to_mesh(data)
    bm.free()
    for polygon in data.polygons:
        polygon.use_smooth = True
    cap = bpy.data.objects.new(f"{name}_cap", data)
    collection.objects.link(cap)
    shell = cap.modifiers.new("thickness", "SOLIDIFY")
    shell.thickness = 0.007
    shell.offset = 1.0
    mat = bpy.data.materials.new(f"{name}_cap")
    mat.use_nodes = True
    nodes, links = mat.node_tree.nodes, mat.node_tree.links
    shader = nodes["Principled BSDF"]
    shader.inputs["Base Color"].default_value = (*colour, 1.0)
    shader.inputs["Roughness"].default_value = 0.92
    wave = nodes.new("ShaderNodeTexWave")
    wave.inputs["Scale"].default_value = 260.0
    wave.inputs["Distortion"].default_value = 1.5
    ridge = nodes.new("ShaderNodeBump")
    ridge.inputs["Strength"].default_value = 0.5
    ridge.inputs["Distance"].default_value = 0.002
    links.new(wave.outputs["Fac"], ridge.inputs["Height"])
    links.new(ridge.outputs["Normal"], shader.inputs["Normal"])
    mat["garment"] = True
    data.materials.append(mat)
    cap.parent = rig
    cap.parent_type = "BONE"
    cap.parent_bone = head_bone
    bpy.context.view_layer.update()
    cap.matrix_world = Matrix.Identity(4)
    return cap


def build(name, collection):
    spec = CAST[name]
    before = set(bpy.data.objects)
    bpy.ops.import_scene.fbx(filepath=str(SCANS / spec["fbx"]), use_anim=False, ignore_leaf_bones=True, automatic_bone_orientation=False)
    new = set(bpy.data.objects) - before
    rig = next(o for o in new if o.type == "ARMATURE")
    mesh = next(o for o in new if o.type == "MESH")
    world = rig.matrix_world.copy()
    rig.parent = None
    rig.matrix_world = world
    bpy.context.view_layer.update()
    for obj in new:
        if obj not in (rig, mesh):
            bpy.data.objects.remove(obj)
    bpy.ops.object.select_all(action="DESELECT")
    for obj in (rig, mesh):
        obj.select_set(True)
    bpy.context.view_layer.objects.active = rig
    bpy.ops.object.transform_apply(location=True, rotation=True, scale=True)
    prefix = spec["prefix"]
    names = {cmu: prefix + bone for cmu, bone in BONES.items()}
    chains = {}
    for side, tag in (("Left", "l"), ("Right", "r")):
        for cmu, bone in SIDED.items():
            names[side + cmu] = f"{prefix}{bone}_{tag}"
        chains[side] = [[f"{prefix}{finger}_0{i}_{tag}" for i in (1, 2, 3)] for finger in FINGERS]
    missing = [bone for bone in names.values() if bone not in rig.data.bones]
    if missing:
        raise KeyError(f"{name}: bones not found: {missing}")
    rig["cmu_map"] = json.dumps(names)
    rig["finger_chains"] = json.dumps(chains)
    rig["person"] = name
    rig.name = f"{name}_rig"
    mesh.name = f"{name}_body"
    mesh.data.materials.clear()
    mesh.data.materials.append(material(name, spec))
    for polygon in mesh.data.polygons:
        polygon.use_smooth = True
    smooth = mesh.modifiers.new("smooth", "SUBSURF")
    smooth.levels = smooth.render_levels = 1
    for obj in (rig, mesh):
        for owner in list(obj.users_collection):
            owner.objects.unlink(obj)
        collection.objects.link(obj)
    if spec["cap"]:
        knit_cap(name, rig, mesh, names["Head"], spec["cap"], collection)
    toe = rig.data.bones[names["LeftToeBase"]].head_local
    arm = rig.data.bones[names["LeftArm"]].head_local
    print("PERSON", name, "height", round(mesh.dimensions.z, 3), "toe", [round(v, 3) for v in toe], "left shoulder", [round(v, 3) for v in arm],
          "vertices", len(mesh.data.vertices))
    return rig, mesh


def main():
    bpy.ops.wm.read_factory_settings(use_empty=True)
    for name in CAST:
        collection = bpy.data.collections.new(f"person_{name}")
        bpy.context.scene.collection.children.link(collection)
        build(name, collection)
    bpy.ops.file.pack_all()
    out = HERE / "build" / "cast.blend"
    bpy.ops.wm.save_as_mainfile(filepath=str(out), compress=True)
    print("CAST saved", out)


if __name__ == "__main__":
    main()
