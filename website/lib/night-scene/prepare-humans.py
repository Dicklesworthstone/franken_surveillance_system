"""Bake metric skeletal performances onto the two clothed scans.

Run with Blender 4.3's Python: prepare-humans.py SCAN_ROOT ROCKETBOX_MOTIONS OUTPUT.
The Nathan and Eric directories contain their original UE4 FBX and scan materials.
"""

import argparse
import sys
from tempfile import TemporaryDirectory
from pathlib import Path
import bpy
from mathutils import Matrix

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scripts"))
from prepare_performers import prepare_body, source_file, verified_source

ROCKETBOX = "https://raw.githubusercontent.com/microsoft/Microsoft-Rocketbox/0943055db6ec570bcef9f2c8b41c9e5467c808f9/Assets/Animations/"
MOTIONS = [
    (
        "Walk",
        "xy",
        "m_walk_neutral_02",
        "6a4e6f2c8e78214cc3e3b7d85a1ad12c3580b61fb7b429451387ea40db7421d2",
    ),
    (
        "Arrival",
        "xy",
        "m_walk_stop",
        "808f112c37c0db60fd1855fb2785749557ecdb9107e8028cd3f28b11aa9c62b1",
    ),
    (
        "Looking",
        "static",
        "m_idle_look_around_01",
        "018b19ad26695c5ebbd4131e0506da69dc76f4001a8100a9e38fcdb9a202b7a4",
    ),
]


def motion_file(motions, region, name, digest):
    filename = name + ".max.fbx"
    url = ROCKETBOX + "all_animations_max_motextr_" + region + "/" + filename
    return verified_source(motions / filename, url, digest)


# The target's joint names, donor landmarks and a real anatomical endpoint for
# each directed segment. Local joint rotations are never copied across bind poses.
landmarks = {
    "pelvis": "Pelvis",
    "spine_01": "Spine",
    "spine_02": "Spine1",
    "spine_03": "Spine2",
    "neck_01": "Neck",
    "head": "Head",
    "head_end": "HeadNub",
}
segments = {
    "pelvis": "spine_01",
    "spine_01": "spine_02",
    "spine_02": "spine_03",
    "spine_03": "neck_01",
    "neck_01": "head",
    "head": "head_end",
}
for side in ("l", "r"):
    for target, donor, end in (
        ("clavicle", "Clavicle", "upperarm"),
        ("upperarm", "UpperArm", "lowerarm"),
        ("lowerarm", "Forearm", "hand"),
        ("hand", "Hand", "middle_01"),
        ("thigh", "Thigh", "calf"),
        ("calf", "Calf", "foot"),
        ("foot", "Foot", "ball"),
        ("ball", "Toe0", "foot_end"),
        ("foot_end", "Toe0Nub", None),
    ):
        key = f"{target}_{side}"
        landmarks[key] = side.upper() + donor
        if end:
            segments[key] = f"{end}_{side}"
    for j, finger in enumerate(("thumb", "index", "middle", "ring", "pinky")):
        for i, end in ((1, "02"), (2, "03"), (3, "end")):
            key = f"{finger}_{i:02d}_{side}"
            landmarks[key] = f"{side.upper()}Finger{j}" + (str(i - 1) if i > 1 else "")
            segments[key] = f"{finger}_{end}_{side}"
        landmarks[f"{finger}_end_{side}"] = f"{side.upper()}Finger{j}Nub"


def load_fbx(path, animate=True):
    existing = set(bpy.context.scene.objects)
    bpy.ops.import_scene.fbx(filepath=str(path), use_anim=animate)
    objects = set(bpy.context.scene.objects) - existing
    return objects, next(obj for obj in objects if obj.type == "ARMATURE")


def anatomical_frame(up, across):
    up = up.normalized()
    side = (across - up * across.dot(up)).normalized()
    return Matrix((side, up.cross(side), up)).transposed().to_quaternion()


def unwrapped_keys(action, bone, path, samples):
    for i in range(len(samples[0])):
        curve = action.fcurves.new(data_path=bone.path_from_id(path), index=i)
        curve.keyframe_points.add(len(samples))
        curve.keyframe_points.foreach_set(
            "co",
            [
                value
                for frame, sample in enumerate(samples, 1)
                for value in (frame, sample[i])
            ],
        )
        for point in curve.keyframe_points:
            point.interpolation = "LINEAR"
        curve.update()


def bake(target, path, name):
    objects, donor = load_fbx(path)
    animation = donor.animation_data.action
    first, last = map(round, animation.frame_range)
    sc = bpy.context.scene
    sc.frame_set(first)
    native = "pelvis" in donor.pose.bones
    donor_keys = {
        b.name.replace("Bip01", "").replace(" ", ""): b for b in donor.pose.bones
    }
    keys = {
        key: donor_keys[key if native else mapped]
        for key, mapped in landmarks.items()
        if (key if native else mapped) in donor_keys and key in target.pose.bones
    }
    driven = {
        name: child
        for name, child in segments.items()
        if name in keys and child in keys
    }
    # Both source packages define +X as anatomical left and -Y as forward.
    # Cache the original reference matrices before advancing the animated FBX root.
    sr = {k: donor.matrix_world @ b.bone.matrix_local for k, b in keys.items()}
    tr = {k: target.matrix_world @ target.data.bones[k].matrix_local for k in keys}
    ref = {k: tr[k].to_quaternion() for k in keys}
    arm_world = target.matrix_world.to_quaternion()
    chain = [b for b in target.pose.bones if b.name in driven]

    def leg(wh):
        return sum(
            (wh[a].translation - wh[b].translation).length
            for a, b in [("thigh_l", "calf_l"), ("calf_l", "foot_l")]
        )

    scale = leg(tr) / leg(sr)
    rotations = {b.name: [] for b in chain}
    positions, pelvis = [], []
    source_rest_frame = {}
    for k, child in driven.items():
        if k in ("pelvis", "spine_01", "spine_02", "spine_03", "neck_01", "head"):
            left, right = (
                ("thigh_l", "thigh_r")
                if k == "pelvis"
                else ("upperarm_l", "upperarm_r")
            )
            source_rest_frame[k] = (
                left,
                right,
                anatomical_frame(
                    sr[child].translation - sr[k].translation,
                    sr[left].translation - sr[right].translation,
                ),
            )
    for frame in range(first, last + 1):
        sc.frame_set(frame)
        pose = {k: donor.matrix_world @ b.matrix for k, b in keys.items()}
        pelvis.append(pose["pelvis"].translation.copy())
        world = {}
        for bone in chain:
            k, child = bone.name, driven[bone.name]
            desired = (
                pose[k].to_quaternion() @ sr[k].to_quaternion().inverted() @ ref[k]
            )
            if not native and k in source_rest_frame:
                left, right, base = source_rest_frame[k]
                now = anatomical_frame(
                    pose[child].translation - pose[k].translation,
                    pose[left].translation - pose[right].translation,
                )
                desired = now @ base.inverted() @ ref[k]
                # Head turns about an almost vertical axis, which joint endpoints
                # alone cannot capture. Retain the source's axial rotation.
                if k in ("neck_01", "head"):
                    desired = (
                        pose[k].to_quaternion()
                        @ sr[k].to_quaternion().inverted()
                        @ ref[k]
                    )
            local_segment = ref[k].inverted() @ (
                tr[child].translation - tr[k].translation
            )
            expected = desired @ local_segment
            actual = pose[child].translation - pose[k].translation
            if expected.length > 1e-6 and actual.length > 1e-6:
                desired = expected.rotation_difference(actual) @ desired
            world[k] = desired
            parent = bone.parent
            p_ref = (
                (target.matrix_world @ parent.bone.matrix_local).to_quaternion()
                if parent
                else arm_world
            )
            pq = world.get(parent.name, p_ref) if parent else arm_world
            local = (p_ref.inverted() @ ref[k]).inverted() @ pq.inverted() @ desired
            local.normalize()
            if rotations[k] and local.dot(rotations[k][-1]) < 0:
                local.negate()
            rotations[k].append(local)
    travel = pelvis[-1] - pelvis[0]
    # Keep the measured lateral transfer of weight. The calibrated route supplies
    # forward travel, including braking, independently of the armature root.
    for i, p in enumerate(pelvis):
        bounce = p - pelvis[0]
        if name == "Walk":
            bounce.y -= travel.y * i / (len(pelvis) - 1)
        else:
            bounce.y = 0
        xyz = tr["pelvis"].to_3x3().inverted() @ (scale * bounce)
        positions.append(xyz)
    action = bpy.data.actions.new(name)
    action.use_fake_user = True
    for b in chain:
        unwrapped_keys(action, b, "rotation_quaternion", rotations[b.name])
    unwrapped_keys(action, target.pose.bones["pelvis"], "location", positions)
    for obj in objects:
        bpy.data.objects.remove(obj, do_unlink=True)
    print(
        f"{name}: {len(pelvis)} samples, normalized cycle distance {abs(travel.y) * scale:.4f} m"
    )
    return action, abs(travel.y) * scale


def export_performer(role, scan_root, motions, output):
    bpy.ops.wm.read_factory_settings(use_empty=True)
    with TemporaryDirectory() as texture_dir:
        target, mesh = prepare_body(role, scan_root, texture_dir)
    actors = set(bpy.context.scene.objects)
    target.animation_data_clear()
    for b in target.pose.bones:
        b.rotation_mode = "QUATERNION"
        b.matrix_basis = Matrix.Identity(4)
    target.name = f"{role}_skeleton"
    verts = [mesh.matrix_world @ v.co for v in mesh.data.vertices]
    target["height_m"] = max(v.z for v in verts) - min(v.z for v in verts)
    print(role, "bind height", target["height_m"])
    bpy.context.view_layer.update()
    for obj in actors:
        if obj.type == "MESH":
            obj.name = f"{role}_scan"
    if role == "visitor":
        clips = [
            (motion_file(motions, region, name, digest), label)
            for label, region, name, digest in MOTIONS
        ]
    else:
        clips = [
            (
                source_file(
                    scan_root, "Nathan", "rp_nathan_animated_003_walking_ue4.fbx"
                ),
                "Walk",
            )
        ]
    actions = []
    for path, name in clips:
        action, metres = bake(target, path, name)
        actions.append(action)
        if name == "Walk":
            target["cycle_metres"] = metres
    target.animation_data_create()
    for action in actions:
        track = target.animation_data.nla_tracks.new()
        track.name = action.name
        track.strips.new(action.name, 1, action)
        track.mute = True
    target.animation_data.action = actions[0]
    for action in list(bpy.data.actions):
        if action not in actions:
            bpy.data.actions.remove(action)
    sc = bpy.context.scene
    sc.render.fps = 30
    sc.frame_start, sc.frame_end = 1, int(max(a.frame_range[1] for a in actions))
    sc.frame_set(1)
    result = bpy.ops.export_scene.gltf(
        filepath=str(output / f"{role}.glb"),
        export_copyright="Renderpeople, CC BY 4.0. Adapted for Franken Surveillance. Performance sources and license links in CREDITS.txt.",
        export_animation_mode="ACTIONS",
        export_force_sampling=True,
        export_frame_range=True,
        export_extras=True,
        export_optimize_animation_size=True,
    )
    if result != {"FINISHED"}:
        raise RuntimeError(f"Blender could not export {role}: {result}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("scan_root", type=Path)
    parser.add_argument("motions", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args(
        sys.argv[sys.argv.index("--") + 1 :] if "--" in sys.argv else None
    )
    scan_root, motions, output = (
        args.scan_root.resolve(),
        args.motions.resolve(),
        args.output.resolve(),
    )
    output.mkdir(parents=True, exist_ok=True)
    with TemporaryDirectory(dir=output) as scratch:
        stage = Path(scratch)
        actors = ("visitor", "courier")
        for role in actors:
            export_performer(role, scan_root, motions, stage)
        for role in actors:
            (stage / f"{role}.glb").replace(output / f"{role}.glb")
