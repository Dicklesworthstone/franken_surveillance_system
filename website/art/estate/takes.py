"""Takes: the staged incidents the cameras film.

Run inside Blender on a frozen estate file:

    blender -b build/release/alder-house-<sha12>.blend -P takes.py -- intrusion

Adds the cast and their motion, the doorbell lens, infrared illuminators, the
response lighting and the closing gate, then saves build/takes/<take>.blend
and build/takes/<take>.truth.json (tracks, boxes, beats, camera geometry).
Everything this file produces is scripted ground truth.
"""
import hashlib
import json
import math
import pathlib
import sys

import bmesh
import bpy
import numpy as np
from mathutils import Matrix, Vector

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import mocap  # noqa: E402
import plan  # noqa: E402
import render_files  # noqa: E402

RATE = mocap.RATE  # scene frames per second
FILM_FPS = 12  # every second scene frame is filmed
# Revision of the staging itself, written into the truth file. A truth file without it is
# revision 1, in which the torch beam faded from torch_on to torch_off. From 2 the beam holds
# full power until it is switched off. camera_looks.py words the torch effects accordingly.
STAGING = 2


def staged_truth(scene):
    """Read one generation once and verify that Blender actually opened its paired scene."""
    take = scene["take"]
    data = (HERE / "build" / "takes" / f"{take}.truth.json").read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    bound = scene.get("truth_sha256")
    if bound != digest:
        legacy = (bound is None and digest == render_files.LEGACY_TRUTH
                  and render_files.file_digest(bpy.data.filepath) ==
                  "611262545d576b6a1870d33c160899494b8626e8a19b65d8035787aebebebd49")
        if not legacy:
            raise SystemExit(f"The open Blender scene and {take}.truth.json are from different or unknown stagings.")
    return json.loads(data), digest


NORTH = math.pi  # heading of a figure facing the house from the street

CAMERAS = {
    "gate": dict(source="cam_gate", label="Gate", product="Budget Wi-Fi bullet camera", mode="infrared",
                 size=(1280, 720), clock_offset_s=1.8, infrared_watts=1500.0),
    "driveway": dict(source="cam_driveway", label="Driveway", product="Floodlight camera", mode="colour",
                     size=(1280, 720), clock_offset_s=-0.4),
    "doorbell": dict(source=None, label="Front door", product="Video doorbell", mode="colour",
                     size=(960, 960), clock_offset_s=0.9, fisheye_deg=160.0,
                     position=(0.56, 1.82, 0.07), look_at=(0.56, 1.6, 6.0)),
    # Moved from under the soffit to the face of the portico beam: the old mount had the beam in frame.
    "porch": dict(source="cam_porch", label="Front porch", product="Wi-Fi turret camera", mode="colour",
                  size=(1280, 720), clock_offset_s=0.0, position=(1.6, 2.84, 2.82), look_at=(-0.5, 0.5, 10.5)),
    "entry": dict(source="cam_entry", label="Entry walk", product="Battery-powered outdoor camera", mode="infrared",
                  size=(1280, 720), clock_offset_s=0.3, infrared_watts=1300.0),
}

# Site paths in plan coordinates (x east, z south).
APPROACH = [(-23.8, 39.0), (-19.0, 39.0), (-15.4, 39.0), (-13.5, 38.5), (-12.8, 37.0), (-13.0, 34.8),
            (-13.9, 31.5), (-14.5, 28.4), (-13.6, 25.2), (-11.4, 21.6), (-8.4, 17.0), (-5.8, 12.8),
            (-3.4, 9.4), (-1.6, 6.9)]
DOORWAY = [(-1.6, 6.9), (-0.7, 5.4), (-0.1, 4.2), (0.15, 3.0), (0.25, 1.8), (0.25, 0.62)]
ESCAPE = [(-0.2, 7.0), (-1.2, 10.0), (-4.6, 14.6), (-8.6, 20.8), (-11.8, 26.6), (-13.3, 31.5),
          (-12.9, 35.0), (-12.6, 37.4), (-13.7, 38.95), (-17.0, 39.4), (-26.0, 39.4), (-70.0, 39.4)]
TRAIL = [(-25.8, 39.5), (-20.0, 39.5), (-17.4, 39.4), (-16.1, 39.25)]
BOLT = [(-16.1, 39.25), (-18.5, 39.5), (-24.0, 39.6), (-34.0, 39.6), (-80.0, 39.6)]

TAKES = {
    "intrusion": dict(start="2026-11-14T02:14:00-05:00", people=["intruder", "lookout"]),
}


def to_xy(points):
    return [(x, -z) for x, z in points]


def ground(x, y):
    """Height of the walking surface at Blender (x, y): the portico floor and its three steps."""
    z = -y
    floor = plan.PORTICO["floor"]
    if abs(x) <= 2.55 and -0.5 <= z <= 3.69:
        return floor * min(1.0, max(0.0, (3.69 - z) / 0.99))
    return 0.0


def take_frame(seconds):
    """Scene frame for a time in the take."""
    return 1 + int(round(seconds * RATE))


class Schedule:
    """Parts of one person's motion in order, with the action label of each."""

    def __init__(self):
        self.parts, self.labels, self.marks = [], [], {}

    def add(self, motion, label, blend=10, snap=True, mark=None):
        self.parts.append((motion, blend, snap))
        self.labels.append((label, len(motion), blend))
        if mark:
            self.marks[mark] = len(self.parts) - 1

    def build(self):
        motion = mocap.join(self.parts)
        labels, starts, cursor = [], [], 0
        for i, (label, length, blend) in enumerate(self.labels):
            begin = cursor if i == 0 else cursor - min(blend, length)
            starts.append(begin + (0 if i == 0 else min(blend, length) // 2))
            cursor = begin + length
        frames = len(motion)
        for f in range(frames):
            current = 0
            for i, begin in enumerate(starts):
                if f >= begin:
                    current = i
            labels.append(self.labels[current][0])
        seconds = {mark: starts[i] / RATE for mark, i in self.marks.items()}
        return motion, labels, seconds


def stationary(target, clip, start, stop, yaw=None):
    motion = target.fit(mocap.load(clip)).cut(start, stop)
    return motion if yaw is None else mocap.facing(motion, yaw)


def reach(motion, side, begin, rise, hold, fall):
    """Lift one arm to a door knob over a standing motion and rattle it twice.

    The arm's own rotations are replaced, blended in over `rise` frames and
    out over `fall`; the rest of the body keeps its captured sway.
    """
    sign = 1.0 if side == "Left" else -1.0
    quat = motion.quat.copy()
    yaw = motion.yaw()
    index = {part: motion.index(side + part) for part in ("Arm", "ForeArm", "Hand")}
    rest = np.array([sign, 0.0, 0.0])
    for f in range(begin, min(len(motion), begin + rise + hold + fall)):
        k = f - begin
        if k < rise:
            w = (k + 1) / (rise + 1)
        elif k < rise + hold:
            w = 1.0
        else:
            w = 1.0 - (k - rise - hold + 1) / (fall + 1)
        w = w * w * (3 - 2 * w)
        rattle = 0.0
        if rise + 6 <= k < rise + hold - 4:
            rattle = math.sin((k - rise - 6) / RATE * math.tau * 2.6) * 0.09
        upper = np.array([sign * 0.1, -0.5, -0.86])
        lower = np.array([-sign * 0.06, -0.9 * math.cos(rattle) , -0.4 + rattle])
        turn = mocap.rot_z(float(yaw[f]))
        for part, direction in (("Arm", upper), ("ForeArm", lower), ("Hand", lower)):
            goal = mocap.quat_from_matrix(turn @ mocap.shortest_arc(rest, direction / np.linalg.norm(direction)))
            quat[f, index[part]] = mocap.slerp(quat[f, index[part]], goal, w)
    return mocap.Motion(motion.names, motion.root.copy(), quat, motion.hip_height, motion.t_dirs, motion.label)


def gait(target, clip, low, high, search=None, feet=True):
    """A fitted clip with its best gait cycle and, for walks, foot-driven steps."""
    motion = target.fit(mocap.load(clip))
    cost, a, b = mocap.cycle(motion, low, high, search)
    steps = target.strides(motion, a, b) if feet else None
    return motion, a, b, steps


def walk_path(target, clip, points, low, high, search=None, feet=True, lead=0):
    """A gait cycle looped along a site path.

    lead: frames of run-up before the path's first point. During them the
    figure cycles its legs on the spot at the path start, so a cross-fade of
    that length from the previous part changes the pose without covering the
    same ground twice. Join such a part with snap off.
    """
    motion, a, b, steps = gait(target, clip, low, high, search, feet)
    path = mocap.Path(to_xy(points))
    cycle = b - a
    phase = (-lead) % cycle
    run_up = 0.0
    if lead:
        _, arcs = mocap.along(motion, path, a, b, steps=steps, duration=(lead + 1) / RATE, phase=phase)
        run_up = float(arcs[lead] - arcs[0])
    part, arcs = mocap.along(motion, path, a, b, steps=steps, start=-run_up, distance=(path.length + run_up) * 1.02, phase=phase)
    stop = int(np.searchsorted(arcs, path.length - 0.02))
    stop = max(2, min(stop, len(part)))
    speed = (arcs[stop - 1] - arcs[lead]) / ((stop - 1 - lead) / RATE)
    print(f"GAIT {clip} cycle {a}-{b} ({cycle / RATE:.2f}s) path {path.length:.1f} m in {(stop - lead) / RATE:.1f}s at {speed:.2f} m/s")
    return part.cut(0, stop), arcs[:stop], path


def intruder(target):
    """Walk in, cross the lawn, try the door, bolt when the lights come on."""
    plan_a = Schedule()
    approach, arcs, path = walk_path(target, "91_17", APPROACH, 0.8, 1.4, search=(63, 131))
    plan_a.add(approach, "walking", mark="start")
    gate_arc = 0.0
    for s in np.arange(0.0, path.length, 0.05):
        if -path.point(s)[1] <= plan.GATE["z"] and path.point(s)[0] > -14.4:
            gate_arc = s
            break
    leave_arc = next(s for s in np.arange(gate_arc, path.length, 0.05) if -path.point(s)[1] < 27.0)
    beats = {
        "a_enters_gate": float(np.searchsorted(arcs, gate_arc)) / RATE,
        "a_leaves_drive": float(np.searchsorted(arcs, leave_arc)) / RATE,
    }
    careful, _, _ = walk_path(target, "77_28", DOORWAY, 1.0, 2.2, search=(357, 446), lead=12)
    plan_a.add(careful, "approaching door", blend=12, snap=False, mark="careful")
    # At the door: stand, try the knob with the right hand, then crouch to shine a torch through a sidelight.
    stand = stationary(target, "77_02", 20, 100, NORTH)
    stand = reach(stand, "Right", begin=14, rise=11, hold=34, fall=12)
    plan_a.add(stand, "trying door", blend=14, mark="door")
    # The pivot and sprint start, turned so the sprint heads straight down the steps.
    bolt = target.fit(mocap.load("77_10")).cut(74, 139)
    travel = bolt.root[-1, :2] - bolt.root[-12, :2]
    bolt = mocap.turned(bolt, mocap.heading((0.0, -1.0)) - mocap.heading(travel))
    peer_yaw = float(bolt.yaw()[0])
    print("BOLT starts facing", round((math.degrees(peer_yaw) - 180.0 + 180.0) % 360.0 - 180.0, 1), "degrees from north (positive is west); displacement",
          np.round(bolt.root[-1, :2] - bolt.root[0, :2], 2))
    peer = stationary(target, "77_05", 4, 98, peer_yaw)
    plan_a.add(peer, "looking in", blend=14, mark="peer")
    plan_a.add(bolt, "turning to run", blend=9, mark="bolt")
    return plan_a, beats


def finish_intruder(plan_a, target):
    """Add the run out of the gate once the earlier parts are placed."""
    placed, _, _ = Schedule.build(plan_a)
    end = placed.root[-1, :2]
    points = [(float(end[0]), float(-end[1]))] + ESCAPE
    run, arcs, path = walk_path(target, "09_01", points, 0.5, 0.95, feet=False, lead=6)
    plan_a.add(run, "running", blend=6, snap=False, mark="run")
    return points


def lookout(target, run_at):
    """Trail the intruder to the gate, keep watch at the west pier, run when the lights come on."""
    plan_b = Schedule()
    trail, arcs, path = walk_path(target, "35_01", TRAIL, 0.8, 1.5)
    plan_b.add(trail, "walking", mark="start")
    arrive = len(trail) / RATE
    wait_frames = int(round((run_at - arrive) * RATE)) + 12
    wait = target.fit(mocap.load("40_10")).cut(0, wait_frames)
    wait = mocap.turned(wait, math.radians(90.0))
    plan_b.add(wait, "keeping watch", blend=14, mark="wait")
    run, _, _ = walk_path(target, "16_55", BOLT, 0.5, 0.95, feet=False)
    plan_b.add(run, "running", blend=10, mark="run")
    return plan_b, arrive


def append_people(names):
    path = str(HERE / "build" / "cast.blend")
    wanted = [f"person_{n}" for n in names]
    with bpy.data.libraries.load(path, link=False) as (source, into):
        into.collections = [c for c in source.collections if c in wanted]
    root = bpy.data.collections.new("people")
    bpy.context.scene.collection.children.link(root)
    for collection in into.collections:
        root.children.link(collection)
    return root


def simple_material(name, colour, roughness=0.8, metallic=0.0):
    material = bpy.data.materials.new(name)
    material.use_nodes = True
    shader = material.node_tree.nodes["Principled BSDF"]
    shader.inputs["Base Color"].default_value = (*colour, 1.0)
    shader.inputs["Roughness"].default_value = roughness
    shader.inputs["Metallic"].default_value = metallic
    return material


def box_object(name, size, material, collection, bevel=0.0, subdivide=0):
    mesh = bpy.data.meshes.new(name)
    bm = bmesh.new()
    bmesh.ops.create_cube(bm, size=1.0)
    for vertex in bm.verts:
        vertex.co = Vector((vertex.co.x * size[0], vertex.co.y * size[1], vertex.co.z * size[2]))
    if bevel:
        bmesh.ops.bevel(bm, geom=list(bm.edges), offset=bevel, segments=3, affect="EDGES")
    bm.to_mesh(mesh)
    bm.free()
    for polygon in mesh.polygons:
        polygon.use_smooth = True
    mesh.materials.append(material)
    obj = bpy.data.objects.new(name, mesh)
    collection.objects.link(obj)
    return obj


def attach(obj, rig, bone, world):
    """Parent obj to a bone, keeping the given world matrix at the rest pose."""
    obj.parent = rig
    obj.parent_type = "BONE"
    obj.parent_bone = bone
    bpy.context.view_layer.update()
    obj.matrix_world = world


def props_for_intruder(rig, target, collection):
    """A small backpack and a hand torch with a real beam."""
    bones = rig.data.bones
    spine_name, neck_name, hand_name = (target.names[k] for k in ("Spine1", "Neck", "LeftHand"))
    fabric = simple_material("pack_fabric", (0.018, 0.02, 0.024), 0.85)
    fabric["garment"] = True
    spine, neck = bones[spine_name], bones[neck_name]
    centre = (Vector(spine.head_local) + Vector(neck.head_local)) / 2
    pack = box_object("backpack", (0.3, 0.17, 0.42), fabric, collection, bevel=0.05)
    attach(pack, rig, spine_name, Matrix.Translation((centre.x, centre.y + 0.2, centre.z - 0.03)))
    pocket = box_object("backpack_pocket", (0.22, 0.06, 0.2), fabric, collection, bevel=0.025)
    attach(pocket, rig, spine_name, Matrix.Translation((centre.x, centre.y + 0.3, centre.z - 0.1)))
    for sign in (-1, 1):
        strap = box_object(f"backpack_strap_{sign}", (0.045, 0.32, 0.36), fabric, collection, bevel=0.02)
        attach(strap, rig, spine_name, Matrix.Translation((centre.x + sign * 0.11, centre.y + 0.03, centre.z + 0.04)))
    hand = bones[hand_name]
    reach = Vector(bones[target.fingers["Left"][0][0]].head_local) - Vector(hand.head_local)
    palm = Vector(hand.head_local) + reach * 0.75
    metal = simple_material("torch_body", (0.02, 0.02, 0.02), 0.4, 0.8)
    torch = box_object("torch", (0.034, 0.15, 0.034), metal, collection, bevel=0.012)
    attach(torch, rig, hand_name, Matrix.Translation((palm.x, palm.y - 0.035, palm.z - 0.028)))
    beam = bpy.data.lights.new("torch_beam", "SPOT")
    beam.energy = 0.0
    beam.color = (0.86, 0.92, 1.0)
    beam.spot_size = math.radians(34.0)
    beam.spot_blend = 0.55
    beam.shadow_soft_size = 0.012
    beam["torch_watts"] = 26.0
    lamp = bpy.data.objects.new("torch_beam", beam)
    collection.objects.link(lamp)
    lamp.parent = torch
    lamp.location = (0.0, -0.08, 0.0)
    lamp.rotation_euler = (math.radians(-90.0), 0.0, 0.0)  # a spot shines along -z; turn it to -y
    return beam


def add_doorbell(collection):
    spec = CAMERAS["doorbell"]
    data = bpy.data.cameras.new("cam_doorbell")
    data.type = "PANO"
    lens = data if hasattr(data, "panorama_type") else data.cycles
    lens.panorama_type = "FISHEYE_EQUIDISTANT"
    lens.fisheye_fov = math.radians(spec["fisheye_deg"])
    data.clip_start, data.clip_end = 0.03, 600.0
    data.sensor_fit = "HORIZONTAL"
    data.sensor_width = data.sensor_height = 24.0
    cam = bpy.data.objects.new("cam_doorbell", data)
    collection.objects.link(cam)
    x, y, z = spec["position"]
    cam.location = (x, -z, y)
    lx, ly, lz = spec["look_at"]
    aim = Vector((lx, -lz, ly)) - cam.location
    cam.rotation_euler = aim.to_track_quat("-Z", "Y").to_euler()
    body = simple_material("doorbell_body", (0.03, 0.03, 0.035), 0.35)
    case = box_object("doorbell", (0.046, 0.024, 0.13), body, collection, bevel=0.008)
    case.location = (x, -z + 0.035, y - 0.02)
    return cam


def move_mounts():
    """Apply the pose overrides in CAMERAS to lenses that already exist in the estate file."""
    for name, spec in CAMERAS.items():
        if not spec.get("source") or "position" not in spec:
            continue
        cam = bpy.data.objects[spec["source"]]
        x, y, z = spec["position"]
        moved = Vector((x, -z, y)) - cam.location
        cam.location = (x, -z, y)
        lx, ly, lz = spec["look_at"]
        cam.rotation_euler = (Vector((lx, -lz, ly)) - cam.location).to_track_quat("-Z", "Y").to_euler()
        device = bpy.data.objects.get(f"device_{name}")
        if device is not None:
            device.location = device.location + moved
    bpy.context.view_layer.update()


def add_infrared(collection):
    """A lens-mounted illuminator per infrared camera, dark unless that camera is rendering."""
    for name, spec in CAMERAS.items():
        if spec["mode"] != "infrared":
            continue
        cam = bpy.data.objects[spec["source"]]
        data = bpy.data.lights.new(f"ir_{name}", "SPOT")
        data.energy = spec["infrared_watts"]
        data.color = (1.0, 1.0, 1.0)
        data.spot_size = math.radians(118.0)
        data.spot_blend = 0.85
        data.shadow_soft_size = 0.03
        lamp = bpy.data.objects.new(f"ir_{name}", data)
        collection.objects.link(lamp)
        lamp.parent = cam
        lamp.location = (0.0, 0.03, 0.0)
        lamp.hide_render = True


def step_key(target, path, before, after, frame):
    """Hold `before` until the scene frame before `frame`, then `after`."""
    setattr(target, path, before)
    target.keyframe_insert(path, frame=1)
    target.keyframe_insert(path, frame=frame - 1)
    setattr(target, path, after)
    target.keyframe_insert(path, frame=frame)


def emission_socket(material):
    """The socket that sets how bright an emissive material is."""
    for node in material.node_tree.nodes:
        if node.type == "EMISSION":
            return node.inputs["Strength"]
    for node in material.node_tree.nodes:
        if node.type == "BSDF_PRINCIPLED":
            return node.inputs["Emission Strength"]
    raise LookupError(material.name)


def add_response(collection, lights_frame, window_frame):
    """The response in the story: floods and entrance lights to full, then an upstairs room."""
    used = []
    flood = bpy.data.objects["flood_driveway"]
    step_key(flood.data, "energy", 0.0, float(flood["flood_watts"]) * 2.0, lights_frame)
    used.append(flood.name)
    for label, x, aim in (("west", -7.9, (-6.0, 0.0, 15.0)), ("east", 7.9, (5.5, 0.0, 15.0))):
        data = bpy.data.lights.new(f"flood_front_{label}", "SPOT")
        data.color = (1.0, 0.97, 0.9)
        data.spot_size = math.radians(118.0)
        data.spot_blend = 0.5
        data.shadow_soft_size = 0.06
        data["flood_watts"] = 900.0
        lamp = bpy.data.objects.new(data.name, data)
        collection.objects.link(lamp)
        lamp.location = (x, -0.34, 6.2)
        direction = Vector((aim[0], -aim[2], aim[1])) - lamp.location
        lamp.rotation_euler = direction.to_track_quat("-Z", "Y").to_euler()
        step_key(data, "energy", 0.0, 900.0, lights_frame)
        metal = simple_material(f"flood_body_{label}", (0.75, 0.75, 0.73), 0.5)
        body = box_object(f"flood_front_{label}_body", (0.22, 0.1, 0.16), metal, collection, bevel=0.01)
        body.location = (x, -0.2, 6.3)
        used.append(lamp.name)
    pendant = bpy.data.objects["portico pendant"]
    step_key(pendant.data, "energy", pendant.data.energy, 18.0, lights_frame)
    used.append(pendant.name)
    # One upstairs room: dark until the household wakes.
    house = bpy.data.objects["main"]
    backdrop = bpy.data.materials["interior_cabin_195_dim"]
    socket = emission_socket(backdrop)
    for value, frame in ((0.0, 1), (0.0, window_frame - 1), (26.0, window_frame)):
        socket.default_value = value
        socket.keyframe_insert("default_value", frame=frame)
    # The room's own glow panels share a material with other rooms: give this room its own copy.
    glow = None
    for polygon in house.data.polygons:
        name = house.material_slots[polygon.material_index].material.name
        centre = house.matrix_world @ polygon.center
        if name in ("room_glow", "room_glow_dim") and 4.2 < centre.x < 8.4 and 3.6 < centre.z < 6.9 and -0.2 < centre.y < 3.2:
            if glow is None:
                glow = bpy.data.materials[name].copy()
                glow.name = "room_glow_upstairs_east"
                house.data.materials.append(glow)
            polygon.material_index = len(house.material_slots) - 1
    if glow is not None:
        socket = emission_socket(glow)
        level = socket.default_value
        for value, frame in ((0.0, 1), (0.0, window_frame - 1), (max(level, 2.4) * 6.0, window_frame)):
            socket.default_value = value
            socket.keyframe_insert("default_value", frame=frame)
    return used


def split_gate(collection, close_frame, closed_frame):
    """Cut the two gate leaves out of the street wall and swing them shut."""
    wall = bpy.data.objects["street_wall"]
    gate = plan.GATE
    half = gate["opening"] / 2
    iron = next(i for i, slot in enumerate(wall.material_slots) if slot.material and slot.material.name == "iron")
    names = []
    for sign, label in ((-1, "west"), (1, "east")):
        hinge = Vector((gate["x"] + sign * half, -gate["z"], 0.0))
        leaf = wall.copy()
        leaf.data = wall.data.copy()
        leaf.name = f"gate_leaf_{label}"
        collection.objects.link(leaf)
        bm = bmesh.new()
        bm.from_mesh(leaf.data)
        drop = []
        for face in bm.faces:
            c = face.calc_center_median()
            inside = face.material_index == iron and c.z < 2.33 and abs(c.x - hinge.x) < 0.6 and hinge.y - 0.1 < c.y < hinge.y + 2.5
            if not inside:
                drop.append(face)
        bmesh.ops.delete(bm, geom=drop, context="FACES")
        for vertex in bm.verts:
            vertex.co -= hinge
        bm.to_mesh(leaf.data)
        bm.free()
        leaf.location = hinge
        swing = math.radians(82.0) * sign
        leaf.rotation_euler = (0.0, 0.0, 0.0)
        leaf.keyframe_insert("rotation_euler", frame=1)
        leaf.keyframe_insert("rotation_euler", frame=close_frame)
        leaf.rotation_euler = (0.0, 0.0, swing)
        leaf.keyframe_insert("rotation_euler", frame=closed_frame)
        names.append(leaf.name)
    bm = bmesh.new()
    bm.from_mesh(wall.data)
    drop = []
    for face in bm.faces:
        c = face.calc_center_median()
        if face.material_index == iron and c.z < 2.33 and abs(c.x - gate["x"]) < half + 0.7 and -gate["z"] - 0.1 < c.y < -gate["z"] + 2.5:
            drop.append(face)
    bmesh.ops.delete(bm, geom=drop, context="FACES")
    bm.to_mesh(wall.data)
    bm.free()
    return names


# ---------------------------------------------------------------- projection

def camera_model(name):
    spec = CAMERAS[name]
    cam = bpy.data.objects[spec["source"] or f"cam_{name}"]
    world = np.array(cam.matrix_world)
    width, height = spec["size"]
    model = dict(name=name, object=cam.name, world=world, inverse=np.linalg.inv(world), width=width, height=height)
    if spec.get("fisheye_deg"):
        model.update(kind="fisheye_equidistant", fov=math.radians(spec["fisheye_deg"]))
    else:
        vfov = 2.0 * math.atan(cam.data.sensor_height / 2.0 / cam.data.lens)
        model.update(kind="rectilinear", vfov=vfov, hfov=2.0 * math.atan(math.tan(vfov / 2) * width / height))
    return model


def project(model, points):
    """World points (N, 3) to normalised image (u right, v down), depth along the axis, and a validity mask."""
    points = np.asarray(points, dtype=float)
    local = points @ model["inverse"][:3, :3].T + model["inverse"][:3, 3]
    x, y, depth = local[:, 0], local[:, 1], -local[:, 2]
    if model["kind"] == "rectilinear":
        safe = np.where(depth > 1e-6, depth, 1e-6)
        u = 0.5 + x / safe / (2.0 * math.tan(model["hfov"] / 2))
        v = 0.5 - y / safe / (2.0 * math.tan(model["vfov"] / 2))
        valid = depth > 0.05
    else:
        distance = np.linalg.norm(local, axis=1)
        theta = np.arccos(np.clip(depth / np.where(distance > 1e-9, distance, 1e-9), -1.0, 1.0))
        r = theta / (model["fov"] / 2.0)
        phi = np.arctan2(y, x)
        u = 0.5 + 0.5 * r * np.cos(phi)
        v = 0.5 - 0.5 * r * np.sin(phi)
        valid = r <= 1.0
    return u, v, depth, valid


def pixel_radius(model, radius, point):
    """Roughly how large a sphere of `radius` metres appears, in normalised image units (u, v)."""
    origin = model["world"][:3, 3]
    distance = max(0.2, float(np.linalg.norm(np.asarray(point) - origin)))
    if model["kind"] == "rectilinear":
        return radius / distance / (2.0 * math.tan(model["hfov"] / 2)), radius / distance / (2.0 * math.tan(model["vfov"] / 2))
    spread = math.atan2(radius, distance) / (model["fov"] / 2.0) * 0.5
    return spread, spread


BODY = {"Head": 0.12, "Neck": 0.08, "Spine1": 0.17, "Hips": 0.17, "LeftArm": 0.07, "RightArm": 0.07,
        "LeftForeArm": 0.06, "RightForeArm": 0.06, "LeftHand": 0.06, "RightHand": 0.06, "LeftLeg": 0.08,
        "RightLeg": 0.08, "LeftFoot": 0.08, "RightFoot": 0.08, "LeftToeBase": 0.06, "RightToeBase": 0.06}


def body_points(joints, frame):
    points, radii = [], []
    for name, radius in BODY.items():
        points.append(joints[name][frame])
        radii.append(radius)
    head, neck = joints["Head"][frame], joints["Neck"][frame]
    up = head - neck
    up = up / (np.linalg.norm(up) or 1.0)
    points.append(head + up * 0.2)
    radii.append(0.1)
    return np.array(points), radii


def boxes_for(model, joints, frames, depsgraph, scene):
    """Per film frame: [x0, y0, x1, y1, visible fraction] or None."""
    origin = Vector(model["world"][:3, 3])
    out = []
    for frame in frames:
        points, radii = body_points(joints, frame)
        u, v, depth, valid = project(model, points)
        inside = valid & (u >= 0) & (u <= 1) & (v >= 0) & (v <= 1)
        if not inside.any():
            out.append(None)
            continue
        x0 = y0 = 1e9
        x1 = y1 = -1e9
        seen = 0
        for i, point in enumerate(points):
            if not valid[i]:
                continue
            ru, rv = pixel_radius(model, radii[i], point)
            x0, x1 = min(x0, u[i] - ru), max(x1, u[i] + ru)
            y0, y1 = min(y0, v[i] - rv), max(y1, v[i] + rv)
            if inside[i]:
                target = Vector(point)
                direction = target - origin
                reach = direction.length
                hit, location, _, _, _, _ = scene.ray_cast(depsgraph, origin + direction.normalized() * 0.12, direction.normalized(), distance=reach - 0.12)
                if not hit or (location - origin).length > reach - 0.25:
                    seen += 1
        box = [max(0.0, x0), max(0.0, y0), min(1.0, x1), min(1.0, y1)]
        if box[2] <= box[0] or box[3] <= box[1]:
            out.append(None)
            continue
        out.append([round(c, 4) for c in box] + [round(seen / len(points), 3)])
    return out


def contiguous(steps):
    """The seen steps of a full-circle sweep, in order round the fan.

    The sweep starts at east. A fan that straddles east is seen at both ends of the list
    with a gap in the middle, so the list is turned to start just after that gap.
    """
    if steps and steps[0] is not None and steps[-1] is not None and None in steps:
        start = max(i for i, step in enumerate(steps) if step is None) + 1
        steps = steps[start:] + steps[:start]
    return [step for step in steps if step is not None]


def footprint(model, reach=30.0):
    """Ground polygon (plan x, z) the lens can see within `reach` metres, clipped to the lot and street."""
    origin = model["world"][:3, 3]
    steps = []  # per azimuth, in sweep order: the nearest and farthest seen point, or None
    for azimuth in np.radians(np.arange(0.0, 360.0, 2.0)):
        direction = np.array([math.cos(azimuth), math.sin(azimuth)])
        ranges = np.arange(0.4, reach + 0.01, 0.2)
        points = np.stack([origin[0] + direction[0] * ranges, origin[1] + direction[1] * ranges, np.zeros_like(ranges)], axis=1)
        u, v, depth, valid = project(model, points)
        seen = valid & (u >= 0) & (u <= 1) & (v >= 0) & (v <= 1)
        if seen.any():
            first, last = np.argmax(seen), len(seen) - 1 - np.argmax(seen[::-1])
            steps.append((points[first, :2], points[last, :2]))
        else:
            steps.append(None)
    fan = contiguous(steps)
    if not fan:
        return []
    ring = [near for near, _ in fan] + [far for _, far in fan][::-1]
    polygon = [(float(x), float(-y)) for x, y in ring]
    lot_x, lot_z = plan.LOT["x"], (plan.LOT["z"][0], plan.STREET["z"][1])
    return [[round(v, 2) for v in p] for p in clip_polygon(polygon, lot_x[0], lot_x[1], lot_z[0], lot_z[1])]


def clip_polygon(polygon, x0, x1, z0, z1):
    def clip(points, inside, cross):
        out = []
        for i, current in enumerate(points):
            previous = points[i - 1]
            if inside(current):
                if not inside(previous):
                    out.append(cross(previous, current))
                out.append(current)
            elif inside(previous):
                out.append(cross(previous, current))
        return out

    def at_x(limit):
        return lambda p, q: (limit, p[1] + (q[1] - p[1]) * (limit - p[0]) / (q[0] - p[0]))

    def at_z(limit):
        return lambda p, q: (p[0] + (q[0] - p[0]) * (limit - p[1]) / (q[1] - p[1]), limit)

    for inside, cross in ((lambda p: p[0] >= x0, at_x(x0)), (lambda p: p[0] <= x1, at_x(x1)),
                          (lambda p: p[1] >= z0, at_z(z0)), (lambda p: p[1] <= z1, at_z(z1))):
        if polygon:
            polygon = clip(polygon, inside, cross)
    return polygon


# -------------------------------------------------------------------- staging

def stage(take):
    scene = bpy.context.scene
    spec = TAKES[take]
    out_dir = HERE / "build" / "takes"
    out_dir.mkdir(parents=True, exist_ok=True)
    source = pathlib.Path(bpy.data.filepath)
    source_sha = hashlib.sha256(source.read_bytes()).hexdigest()
    people = append_people(spec["people"])
    extras = bpy.data.collections.new("take_rigging")
    scene.collection.children.link(extras)
    rig_a, rig_b = bpy.data.objects["intruder_rig"], bpy.data.objects["lookout_rig"]
    target_a, target_b = mocap.Retarget(rig_a), mocap.Retarget(rig_b)
    target_a.curl["Left"] = (0.9, 1.9, 2.5)  # closed round the torch
    beam = props_for_intruder(rig_a, target_a, bpy.data.collections["person_intruder"])

    plan_a, beats = intruder(target_a)
    _, _, marks = plan_a.build()
    lights_on = marks["bolt"] - 0.55  # he bolts half a second after the lights
    escape_points = finish_intruder(plan_a, target_a)
    motion_a, labels_a, marks_a = plan_a.build()
    run_at = lights_on + 0.9
    plan_b, arrive_b = lookout(target_b, run_at)
    motion_b, labels_b, marks_b = plan_b.build()
    # When he turns to run. The lights are timed from this mark (see lights_on above), not the other way round.
    turn_at = marks_a["bolt"]
    print(f"MARKS intruder { {k: round(v, 2) for k, v in marks_a.items()} } lookout { {k: round(v, 2) for k, v in marks_b.items()} }")

    motion_a = mocap.on_ground(motion_a, ground)
    motion_b = mocap.on_ground(motion_b, ground)
    joints_a, hips_a = target_a.apply(motion_a)
    joints_b, hips_b = target_b.apply(motion_b)

    # Beats that depend on where people are.
    def first_frame(hips, test, after=0):
        for f in range(after, len(hips)):
            if test(hips[f]):
                return f
        return len(hips) - 1

    run_frame = int(marks_a["run"] * RATE)
    exit_frame = first_frame(hips_a, lambda p: -p[1] > plan.GATE["z"] + 0.3, run_frame)
    beats.update(
        b_stops_at_pier=marks_b["wait"],
        a_reaches_steps=first_frame(hips_a, lambda p: -p[1] < 3.7 and abs(p[0]) < 2.5) / RATE,
        a_tries_door=marks_a["door"],
        lights_on=lights_on,
        window_on=lights_on + 1.7,
        a_turns_to_run=turn_at,
        b_runs=marks_b["run"],
        a_exits_gate=exit_frame / RATE,
    )
    beats["gate_starts_closing"] = beats["a_exits_gate"] + 1.6
    beats["gate_closed"] = beats["gate_starts_closing"] + 5.0
    duration = math.ceil(beats["gate_closed"] + 3.0)
    beats = {k: round(float(v), 2) for k, v in beats.items()}
    print("BEATS", json.dumps(beats), "duration", duration)

    scene.render.fps = RATE
    scene.frame_start, scene.frame_end = 1, 1 + duration * RATE
    lights_frame, window_frame = take_frame(beats["lights_on"]), take_frame(beats["window_on"])
    effects_objects = add_response(extras, lights_frame, window_frame)
    step_key(beam, "energy", 0.0, float(beam["torch_watts"]), take_frame(marks_a["peer"] - 0.4))
    # Hold full power until the frame before it goes dark. Without this key the beam fades
    # between the two, which is what the first published films show (see the README).
    beam.keyframe_insert("energy", frame=take_frame(turn_at + 1.2) - 1)
    beam.energy = 0.0
    beam.keyframe_insert("energy", frame=take_frame(turn_at + 1.2))
    leaves = split_gate(extras, take_frame(beats["gate_starts_closing"]), take_frame(beats["gate_closed"]))
    add_doorbell(extras)
    move_mounts()
    add_infrared(extras)

    # Scripted ground truth at film rate.
    frames = duration * FILM_FPS
    tracks = {}
    for actor, hips, motion, labels in (("a", hips_a, motion_a, labels_a), ("b", hips_b, motion_b, labels_b)):
        yaw = motion.yaw()
        velocity = np.linalg.norm(np.gradient(hips[:, :2], axis=0), axis=1) * RATE
        velocity = np.convolve(np.pad(velocity, 6, mode="edge"), np.ones(13) / 13, mode="valid")
        track = dict(x=[], z=[], heading=[], speed=[], action=[])
        for f in range(frames):
            g = 2 * f
            if g >= len(hips):
                for key in track:
                    track[key].append(None)
                continue
            track["x"].append(round(float(hips[g, 0]), 3))
            track["z"].append(round(float(-hips[g, 1]), 3))
            # compass heading: 0 = plan north (toward the house), 90 = east
            facing = (math.sin(yaw[g]), -math.cos(yaw[g]))
            track["heading"].append(round(math.degrees(math.atan2(facing[0], facing[1])) % 360.0, 1))
            track["speed"].append(round(float(velocity[g]), 2))
            track["action"].append(labels[g] if velocity[g] > 0.25 or labels[g] not in ("walking", "running") else "standing")
        tracks[actor] = track

    people.hide_viewport = True
    bpy.context.view_layer.update()
    depsgraph = bpy.context.evaluated_depsgraph_get()
    cameras, boxes = [], {}
    for name, cam_spec in CAMERAS.items():
        model = camera_model(name)
        boxes[name] = {}
        for actor, joints in (("a", joints_a), ("b", joints_b)):
            usable = [2 * f for f in range(frames) if 2 * f < len(joints["Hips"])]
            row = boxes_for(model, joints, usable, depsgraph, scene)
            boxes[name][actor] = row + [None] * (frames - len(row))
        cam = bpy.data.objects[model["object"]]
        position = [round(v, 3) for v in (cam.location.x, cam.location.z, -cam.location.y)]
        axis = cam.matrix_world.to_3x3() @ Vector((0.0, 0.0, -1.0))
        entry = dict(
            id=name, label=cam_spec["label"], product=cam_spec["product"], mode=cam_spec["mode"],
            width=model["width"], height=model["height"], clock_offset_s=cam_spec["clock_offset_s"],
            position=position, look_at=[round(position[0] + axis.x * 10, 3), round(position[1] + axis.z * 10, 3), round(position[2] - axis.y * 10, 3)],
            footprint=footprint(model), object=model["object"],
            world_from_camera=[[round(float(v), 6) for v in row] for row in model["world"]],
        )
        if model["kind"] == "rectilinear":
            fx = model["width"] / 2 / math.tan(model["hfov"] / 2)
            fy = model["height"] / 2 / math.tan(model["vfov"] / 2)
            entry["lens"] = dict(model="rectilinear", vfov=round(math.degrees(model["vfov"]), 4), hfov=round(math.degrees(model["hfov"]), 4))
            entry["intrinsics"] = dict(fx=round(fx, 3), fy=round(fy, 3), cx=model["width"] / 2, cy=model["height"] / 2)
        else:
            entry["lens"] = dict(model="fisheye_equidistant", fov=cam_spec["fisheye_deg"],
                                 note="r = theta / (fov / 2) of half the frame width; image circle touches all four edges")
        cameras.append(entry)
        seen = {actor: sum(1 for b in rows if b and b[4] > 0) for actor, rows in boxes[name].items()}
        print("CAMERA", name, model["kind"], "frames with a visible person", seen)
    people.hide_viewport = False

    effects = [
        dict(t=beats["lights_on"], kind="lights_on", detail="Driveway and front floodlights and the portico pendant go to full", objects=effects_objects),
        dict(t=beats["window_on"], kind="window_on", detail="An upstairs room at the east end of the front lights up", objects=["main: interior_cabin_195_dim, room_glow_upstairs_east"]),
        dict(t=round(marks_a["peer"] - 0.4, 2), kind="torch_on", detail="The intruder switches on a hand torch at the door", objects=["torch_beam"]),
        dict(t=round(turn_at + 1.2, 2), kind="torch_off", detail="The torch goes dark as the intruder runs", objects=["torch_beam"]),
        dict(t=beats["gate_starts_closing"], kind="gate_closing", detail="Both gate leaves start to swing shut", objects=leaves),
        dict(t=beats["gate_closed"], kind="gate_closed", detail="The gate is shut", objects=leaves),
    ]
    truth = dict(
        schema="fss.website.watch.v1", take=take, source="scripted",
        source_blend=source.name, source_blend_sha256=source_sha,
        clock=dict(start=spec["start"], fps=FILM_FPS, frames=frames),
        frame_map="film frame f is scene frame 1 + 2 f at 24 scene frames per second",
        beats=beats, cameras=cameras,
        actors=[dict(id="a", description="Intruder: man in a dark shirt, waistcoat and trousers with a knit cap and a small backpack, carrying a hand torch"),
                dict(id="b", description="Lookout: man in a dark T-shirt, jeans and trainers")],
        tracks=tracks, boxes=boxes, effects=sorted(effects, key=lambda e: e["t"]),
        paths=dict(approach=APPROACH, doorway=DOORWAY, escape=escape_points, lookout_in=TRAIL, lookout_out=BOLT),
        staging=STAGING,
    )
    truth_text = json.dumps(truth) + "\n"
    scene["truth_sha256"] = hashlib.sha256(truth_text.encode()).hexdigest()

    scene.render.use_motion_blur = True
    scene.render.motion_blur_shutter = 1.0
    scene.cycles.seed = 7
    scene.cycles.use_animated_seed = False
    scene["take"] = take
    scene["lights_frame"], scene["window_frame"] = lights_frame, window_frame
    target = out_dir / f"{take}.blend"
    with render_files.publication_lock(out_dir / f".{take}.staging.lock"):
        if "FINISHED" not in bpy.ops.wm.save_as_mainfile(filepath=str(target), compress=False, copy=True):
            raise RuntimeError(f"Blender did not finish saving {target}")
        render_files.write_text(out_dir / f"{take}.truth.json", truth_text)
    print("STAGED", target, "frames", frames, "scene frames", scene.frame_end)


if __name__ == "__main__":
    stage(sys.argv[sys.argv.index("--") + 1])
