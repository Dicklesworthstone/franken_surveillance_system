"""Run in Blender's Python with the two Rocketbox FBXs, walk FBX, and body/head JPEGs in source_dir."""

import sys
from pathlib import Path

import bpy

source, output = map(Path, sys.argv[-2:])
for name, role, prefix in [
    ("Male_Adult_07", "visitor", "m013"),
    ("Delivery_Male_01", "courier", "m112"),
]:
    bpy.ops.wm.read_factory_settings(use_empty=True)
    bpy.ops.import_scene.fbx(filepath=str(source / f"{name}.fbx"), use_anim=False)
    character = set(bpy.context.scene.objects)
    armature = next(obj for obj in character if obj.type == "ARMATURE")
    mesh = next(obj for obj in character if obj.type == "MESH")
    for material in mesh.data.materials:
        surface = material.name.split("_")[-1]
        filename = (
            prefix
            + "_"
            + surface
            + "_color."
            + ("png" if surface == "opacity" else "jpg")
        )
        nodes = material.node_tree.nodes
        nodes.clear()
        shader = nodes.new("ShaderNodeBsdfPrincipled")
        shader.inputs["Roughness"].default_value = 0.82
        target = nodes.new("ShaderNodeOutputMaterial")
        colour = nodes.new("ShaderNodeTexImage")
        colour.image = bpy.data.images.load(str(source / filename))
        material.node_tree.links.new(
            colour.outputs["Color"], shader.inputs["Base Color"]
        )
        material.node_tree.links.new(shader.outputs["BSDF"], target.inputs["Surface"])
        if surface == "opacity":
            material.node_tree.links.new(
                colour.outputs["Alpha"], shader.inputs["Alpha"]
            )
        if surface == "body":
            normal_tex = nodes.new("ShaderNodeTexImage")
            normal_tex.image = bpy.data.images.load(
                str(source / (prefix + "_body_normal.jpg"))
            )
            normal_tex.image.colorspace_settings.name = "Non-Color"
            normal = nodes.new("ShaderNodeNormalMap")
            normal.inputs["Strength"].default_value = 0.55
            material.node_tree.links.new(
                normal_tex.outputs["Color"], normal.inputs["Color"]
            )
            material.node_tree.links.new(
                normal.outputs["Normal"], shader.inputs["Normal"]
            )
    motions = [("m_walk_neutral.max.fbx", "Neutral walk")]
    if role == "visitor":
        motions.append(("m_idle_breathe_01.max.fbx", "Standing"))
    clips = []
    for filename, label in motions:
        bpy.ops.import_scene.fbx(filepath=str(source / filename), use_anim=True)
        extra = set(bpy.context.scene.objects) - character
        performer = next(obj for obj in extra if obj.type == "ARMATURE")
        clip = performer.animation_data.action.copy()
        clip.name = label
        clip.use_fake_user = True
        first, last = clip.frame_range
        for curve in list(clip.fcurves):
            if curve.data_path.startswith("pose.bones["):
                if curve.data_path.split('"')[1] not in armature.data.bones:
                    clip.fcurves.remove(curve)
            elif curve.data_path == "location":
                begin, end = curve.evaluate(first), curve.evaluate(last)
                for point in curve.keyframe_points:
                    shift = (
                        begin
                        - armature.location[curve.array_index]
                        + (end - begin) * (point.co.x - first) / (last - first)
                    )
                    point.co.y -= shift
                    point.handle_left.y -= shift
                    point.handle_right.y -= shift
        for obj in extra:
            bpy.data.objects.remove(obj, do_unlink=True)
        clips.append(clip)
    armature.animation_data_create()
    armature.animation_data.action = clips[0]
    for action in list(bpy.data.actions):
        if action not in clips:
            bpy.data.actions.remove(action)
    for obj in character:
        if obj.type not in ("MESH", "ARMATURE"):
            bpy.data.objects.remove(obj, do_unlink=True)
    bpy.context.scene.frame_start = 1
    bpy.context.scene.frame_end = int(max(clip.frame_range[1] for clip in clips))
    bpy.context.scene.frame_set(1)
    bpy.ops.export_scene.gltf(
        filepath=str(output / f"{role}.glb"),
        export_animation_mode="ACTIONS",
        export_force_sampling=True,
        export_frame_range=True,
        export_extras=False,
    )
