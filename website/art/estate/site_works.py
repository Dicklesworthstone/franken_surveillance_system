"""Alder House: the grounds. Runs inside Blender.

Ground surfaces, drive and motor court, terrace, pool, street wall and gate,
fences, planting, site furniture and exterior lighting. Coordinates here are
Blender's: +X east, +Y north (the plan's -z), +Z up.
"""
import math
import pathlib
import random
import re

import bpy
from mathutils import Vector

import kit
import plan
from kit import Frame, Mesh, facade

MODELS = pathlib.Path(__file__).resolve().parent / "assets" / "models"
rng = random.Random(23)
_library = {}

# Scattered grass blades read as dark speckle from every lens at night, so they are
# off. grass.py stays for daylight work, where it needs a denser, finer scatter.
LAWN_BLADES = False


# Motion floodlights: name -> (fixture position, aim point). They stay dark until a
# scenario sets their energy from the "flood_watts" property.
FLOODS = {
    "flood_driveway": ((-13.55, 1.9, 3.15), (-17.5, -6.5, 0.0)),
    "flood_terrace": ((1.2, 10.95, 3.5), (1.5, 15.5, 0.4)),
    "flood_service": ((-25.3, 6.0, 3.1), (-28.5, 5.0, 0.0)),
    "flood_side": ((16.35, 5.2, 3.1), (19.5, 3.0, 0.0)),
}


def xy(points):
    """Plan (x, z) ground points to Blender (x, y)."""
    return [(x, -z) for x, z in points]


def ccw(ring):
    area = sum(a[0] * b[1] - b[0] * a[1] for a, b in zip(ring, ring[1:] + ring[:1]))
    return ring if area > 0 else list(reversed(ring))


def rect(mesh, x0, x1, y0, y1, z, mat):
    mesh.face([(x0, y0, z), (x1, y0, z), (x1, y1, z), (x0, y1, z)], mat, [(x0, y0), (x1, y0), (x1, y1), (x0, y1)])


# --- Imported CC0 models -------------------------------------------------

def model(slug, pattern=None, skip=("rust", "aged", "wdg_"), recentre=True):
    """Append a Poly Haven model once and return a collection to instance.

    pattern: a regular expression choosing objects by name. Without one, the
    collection named after the model is used, minus worn variants and rig widgets.
    Source files lay variants out in a row, so a pattern match is moved back to
    the origin unless recentre is off.
    """
    key = (slug, pattern)
    if key in _library:
        return _library[key]
    path = str(MODELS / slug / (slug + ".blend"))
    with bpy.data.libraries.load(path) as (src, dst):
        if pattern:
            dst.objects = [n for n in src.objects if re.search(pattern, n)]
        else:
            dst.collections = [n for n in src.collections if n == slug]
    col = bpy.data.collections.new("lib_" + slug + ("_" + pattern if pattern else ""))
    if pattern:
        objects = [o for o in dst.objects if o]
    else:
        objects = list(dst.collections[0].all_objects) if dst.collections and dst.collections[0] else []
    keep = []
    for obj in objects:
        if any(word in obj.name for word in skip):
            continue
        if obj.name not in col.objects:
            col.objects.link(obj)
        if pattern and recentre and obj.parent is None:
            obj.location.x = obj.location.y = 0.0
        keep.append(obj)
    bpy.context.view_layer.update()
    for obj in keep:
        # Objects outside the view layer do not refresh their matrices on their own.
        if obj.parent is None:
            obj.matrix_world = obj.matrix_basis
    lo = Vector((1e9, 1e9, 1e9))
    hi = Vector((-1e9, -1e9, -1e9))
    for obj in keep:
        if obj.type != "MESH":
            continue
        for corner in obj.bound_box:
            world = obj.matrix_world @ Vector(corner)
            lo = Vector(map(min, lo, world))
            hi = Vector(map(max, hi, world))
    _library[key] = (col, lo, hi)
    return _library[key]


def place(target, slug, x, y, z=0.0, rot=0.0, scale=1.0, height=None, pattern=None, ground=True, name=None,
          tilt=(0.0, 0.0), recentre=True):
    """Instance a model. height scales it to stand that tall; ground rests its base on z."""
    col, lo, hi = model(slug, pattern, recentre=recentre)
    if height:
        scale = height / max(hi.z - lo.z, 1e-6)
    empty = bpy.data.objects.new(name or slug, None)
    empty.instance_type = "COLLECTION"
    empty.instance_collection = col
    empty.empty_display_size = 0.3
    empty.scale = (scale, scale, scale)
    empty.rotation_euler = (tilt[0], tilt[1], rot)
    empty.location = (x, y, z - (lo.z * scale if ground else 0.0))
    target.objects.link(empty)
    return empty


TREE_MODELS = {
    "oak": [("jacaranda_tree", r"^jacaranda_tree_LOD1$")],
    "maple": [("tree_small_02", r"^tree_small_02_LOD1$"), ("island_tree_01", r"^island_tree_01_LOD1$")],
    "birch": [("island_tree_01", r"^island_tree_01_LOD1$"), ("tree_small_02", r"^tree_small_02_LOD1$")],
    "pine": [("pine_tree_01", r"^pine_tree_01_a_LOD2$"), ("pine_tree_01", r"^pine_tree_01_c_LOD2$"),
             ("pine_tree_01", r"^pine_tree_01_b_LOD2$")],
    "fir": [("fir_tree_01", r"^fir_tree_01_[abc]_LOD2$")],
}


def tree(target, kind, x, y, height):
    slug, pattern = rng.choice(TREE_MODELS[kind])
    return place(target, slug, x, y, rot=rng.uniform(0, math.tau), height=height, pattern=pattern, name=f"tree_{kind}")


# --- Ground ---------------------------------------------------------------

def ground(col, mats):
    mesh = Mesh("ground")
    pool = plan.POOL
    px0, px1, py0, py1 = pool["x"][0], pool["x"][1], -pool["z"][1], -pool["z"][0]
    # Lawn everywhere except the pool basin.
    X0, X1, Y0, Y1 = -110.0, 105.0, -110.0, 120.0
    for a, b, c, d in ((X0, X1, Y0, py0), (X0, X1, py1, Y1), (X0, px0, py0, py1), (px1, X1, py0, py1)):
        rect(mesh, a, b, c, d, 0.0, "lawn")
    # Street, kerb and pavement.
    s0, s1 = -plan.STREET["z"][1], -plan.STREET["z"][0]
    rect(mesh, X0, X1, s0, s1, -0.035, "asphalt")
    mesh.box((X0, s1, -0.2), (X1, s1 + 0.15, 0.1), "concrete")
    mesh.box((X0, s1 + 0.15, -0.2), (X1, -plan.STREET["sidewalk_z"][0] - 0.25, 0.09), "concrete")
    mesh.box((X0, s0 - 0.15, -0.2), (X1, s0, 0.1), "concrete")
    # Drive, court and walk. Each sits a few millimetres above the last.
    gate = plan.GATE
    kit.ribbon(mesh, xy(plan.DRIVEWAY), plan.DRIVEWAY_WIDTH + 0.56, 0.012, "cobble")
    kit.ribbon(mesh, xy(plan.DRIVEWAY), plan.DRIVEWAY_WIDTH, 0.03, "gravel")
    kit.polygon(mesh, ccw(xy(plan.MOTOR_COURT)), 0.034, "gravel")
    rect(mesh, gate["x"] - gate["opening"] / 2, gate["x"] + gate["opening"] / 2, s1, -gate["z"] + 1.2, 0.1, "cobble")
    rect(mesh, gate["x"] - gate["opening"] / 2 - 0.4, gate["x"] + gate["opening"] / 2 + 0.4, s1 - 0.02, s1 + 0.5, 0.102, "cobble")
    gx0, gx1, gy0, _, _ = -25.2, -13.4, 2.0, 0, 0
    rect(mesh, gx0, gx1, gy0 - 1.1, gy0, 0.045, "concrete")
    kit.ribbon(mesh, xy(plan.FRONT_WALK), plan.FRONT_WALK_WIDTH, 0.045, "flagstone")
    # Planting beds along the foundations.
    for a, b, c, d in ((-8.4, -2.9, -1.7, -0.04), (2.9, 8.4, -1.7, -0.04), (8.5, 16.2, 0.2, 1.56),
                       (-13.3, -8.5, 1.3, 2.36), (-7.2, 9.8, 17.6, 18.5), (16.3, 17.6, 1.7, 9.3)):
        rect(mesh, a, b, c, d, 0.008, "mulch")
    return mesh.build(col, mats)


def terrace(col, mats):
    t = plan.TERRACE
    x0, x1, y0, y1, top = t["x"][0], t["x"][1], -t["z"][1], -t["z"][0], t["level"]
    mesh = Mesh("terrace")
    mesh.box((x0, y0, -0.3), (x1, y1, top - 0.07), "stone")
    mesh.box((x0 - 0.04, y0, top - 0.07), (x1 + 0.04, y1 + 0.04, top), "flagstone")
    # Seat walls on the west and north edges, open at the garden steps.
    step_x0, step_x1 = 0.0, 3.4
    for a, b, c, d in ((x0, x0 + 0.45, y0 + 0.6, y1), (x0, step_x0, y1 - 0.45, y1), (step_x1, x1 - 0.6, y1 - 0.45, y1)):
        mesh.box((a, c, top), (b, d, top + 0.42), "stone")
        mesh.box((a - 0.03, c - 0.03, top + 0.42), (b + 0.03, d + 0.03, top + 0.48), "stone_cap")
    for i in range(2):
        z = top - 0.15 * (i + 1)
        mesh.box((step_x0, y1 + 0.34 * i, -0.3), (step_x1, y1 + 0.34 * (i + 1), z - 0.05), "stone")
        mesh.box((step_x0 - 0.03, y1 + 0.34 * i, z - 0.05), (step_x1 + 0.03, y1 + 0.34 * (i + 1) + 0.03, z), "stone_cap")
    # Stepping stones from the terrace to the pool.
    for i in range(9):
        cy = y1 + 1.6 + i * 0.9
        cx = 1.7 + 0.25 * math.sin(i * 1.3)
        mesh.box((cx - 0.38, cy - 0.3, -0.03), (cx + 0.38, cy + 0.3, 0.012), "stone_cap")
    return mesh.build(col, mats)


def pool(col, mats, add_light, light_col):
    p = plan.POOL
    x0, x1, y0, y1, deck, depth = p["x"][0], p["x"][1], -p["z"][1], -p["z"][0], p["deck"], p["depth"]
    mesh = Mesh("pool")
    for a, b, c, d in ((x0 - deck, x1 + deck, y0 - deck, y0), (x0 - deck, x1 + deck, y1, y1 + deck),
                       (x0 - deck, x0, y0, y1), (x1, x1 + deck, y0, y1)):
        rect(mesh, a, b, c, d, 0.04, "pavers")
    for a, b, c, d in ((x0 - 0.32, x1 + 0.32, y0 - 0.32, y0), (x0 - 0.32, x1 + 0.32, y1, y1 + 0.32),
                       (x0 - 0.32, x0, y0, y1), (x1, x1 + 0.32, y0, y1)):
        mesh.box((a, c, -0.02), (b, d, 0.075), "stone_cap")
    floor = -depth
    mesh.face([(x0, y0, floor), (x1, y0, floor), (x1, y1, floor), (x0, y1, floor)], "pool_tile")
    mesh.face([(x0, y0, floor), (x0, y0, 0.0), (x1, y0, 0.0), (x1, y0, floor)], "pool_tile")
    mesh.face([(x1, y1, floor), (x1, y1, 0.0), (x0, y1, 0.0), (x0, y1, floor)], "pool_tile")
    mesh.face([(x0, y1, floor), (x0, y1, 0.0), (x0, y0, 0.0), (x0, y0, floor)], "pool_tile")
    mesh.face([(x1, y0, floor), (x1, y0, 0.0), (x1, y1, 0.0), (x1, y1, floor)], "pool_tile")
    rect(mesh, x0, x1, y0, y1, -0.11, "water")
    mesh.build(col, mats)
    for i in range(4):
        add_light(light_col, f"pool light {i}", (x0 + (x1 - x0) * (i + 0.5) / 4, y0 + 0.25, -0.75), 26.0, "pool", 0.08)
    # Water glow reaching the deck and nearby planting.
    glow = add_light(light_col, "pool glow", ((x0 + x1) / 2, (y0 + y1) / 2, -0.05), 20.0, "pool", kind="AREA")
    glow.data.shape = "RECTANGLE"
    glow.data.size, glow.data.size_y = (x1 - x0) * 0.9, (y1 - y0) * 0.9
    glow.rotation_euler = (math.pi, 0.0, 0.0)


def street_wall(col, mats, add_light, light_col):
    """Fieldstone wall along the street with gate pillars and an open iron gate."""
    gate = plan.GATE
    y = -gate["z"]
    gx, half, pillar = gate["x"], gate["opening"] / 2, gate["pillar"]
    mesh = Mesh("street_wall")
    for a, b in ((plan.LOT["x"][0], gx - half - pillar), (gx + half + pillar, plan.LOT["x"][1])):
        mesh.box((a, y - 0.26, -0.3), (b, y + 0.26, 1.02), "stone")
        mesh.box((a, y - 0.31, 1.02), (b, y + 0.31, 1.09), "stone_cap")
    for sign in (-1, 1):
        cx = gx + sign * (half + pillar / 2)
        top = gate["pillar_height"]
        mesh.box((cx - pillar / 2, y - pillar / 2, -0.3), (cx + pillar / 2, y + pillar / 2, top), "stone")
        mesh.box((cx - pillar / 2 - 0.06, y - pillar / 2 - 0.06, top), (cx + pillar / 2 + 0.06, y + pillar / 2 + 0.06, top + 0.09), "stone_cap")
        mesh.box((cx - 0.2, y - 0.2, top + 0.09), (cx + 0.2, y + 0.2, top + 0.16), "stone_cap")
        # Post lantern on the pillar.
        base = top + 0.16
        mesh.cylinder((cx, y, base), (cx, y, base + 0.1), 0.05, 0.035, "iron", 10)
        for dx in (-0.1, 0.1):
            for dy in (-0.1, 0.1):
                mesh.box((cx + dx - 0.008, y + dy - 0.008, base + 0.1), (cx + dx + 0.008, y + dy + 0.008, base + 0.46), "iron")
        mesh.box((cx - 0.125, y - 0.125, base + 0.09), (cx + 0.125, y + 0.125, base + 0.11), "iron")
        mesh.box((cx - 0.14, y - 0.14, base + 0.46), (cx + 0.14, y + 0.14, base + 0.475), "iron")
        apex = (cx, y, base + 0.6)
        ring = [(cx - 0.14, y - 0.14, base + 0.475), (cx + 0.14, y - 0.14, base + 0.475), (cx + 0.14, y + 0.14, base + 0.475), (cx - 0.14, y + 0.14, base + 0.475)]
        for i in range(4):
            mesh.face([ring[i], ring[(i + 1) % 4], apex], "iron")
        for a, b in (((-0.1, -0.1), (0.1, -0.1)), ((0.1, -0.1), (0.1, 0.1)), ((0.1, 0.1), (-0.1, 0.1)), ((-0.1, 0.1), (-0.1, -0.1))):
            mesh.face([(cx + a[0], y + a[1], base + 0.11), (cx + b[0], y + b[1], base + 0.11),
                       (cx + b[0], y + b[1], base + 0.46), (cx + a[0], y + a[1], base + 0.46)], "lantern_glass")
        mesh.sphere((cx, y, base + 0.27), 0.035, "lamp_warm", 10, 6)
        add_light(light_col, f"gate lantern {sign}", (cx, y, base + 0.27), 9.0, "warm", 0.035)
        # Gate leaf, standing open into the drive.
        hinge = Vector((gx + sign * half, y, 0.0))
        angle = math.radians(82.0)
        direction = Vector((-sign * math.cos(angle), math.sin(angle), 0.0))
        frame = Frame(hinge, direction, (direction.y, -direction.x, 0.0))
        leaf = half - 0.03
        for u0, u1 in ((0.0, 0.05), (leaf - 0.05, leaf)):
            mesh.fbox(frame, (u0, u1), (-0.02, 0.02), (0.08, 1.9), "iron")
        for z0, z1 in ((0.12, 0.17), (0.5, 0.53), (1.68, 1.73)):
            mesh.fbox(frame, (0.05, leaf - 0.05), (-0.018, 0.018), (z0, z1), "iron")
        bars = int((leaf - 0.1) / 0.118)
        for i in range(1, bars):
            u = 0.05 + (leaf - 0.1) * i / bars
            crown = 1.9 + 0.28 * math.sin(math.pi * u / leaf) ** 0.8 * (1.0 if sign else 1.0) * (u / leaf)
            mesh.fbox(frame, (u - 0.008, u + 0.008), (-0.008, 0.008), (0.17, crown), "iron")
            tip = frame.at(u, 0.0, crown + 0.09)
            ring = [frame.at(u - 0.014, -0.014, crown), frame.at(u + 0.014, -0.014, crown), frame.at(u + 0.014, 0.014, crown), frame.at(u - 0.014, 0.014, crown)]
            for k in range(4):
                mesh.face([ring[k], ring[(k + 1) % 4], tip], "iron")
    # House name plaque on the east pillar.
    cx = gx + half + pillar / 2
    mesh.box((cx - 0.22, y - pillar / 2 - 0.012, 1.25), (cx + 0.22, y - pillar / 2, 1.5), "brass")
    return mesh.build(col, mats)


def board_fence(mesh, start, end, height=1.8, gate=None):
    """A close-board timber fence between two ground points, with an optional gate gap."""
    frame, length = facade(start[0], start[1], end[0], end[1])
    spans = [(0.0, length)] if not gate else [(0.0, gate[0]), (gate[1], length)]
    for a, b in spans:
        posts = max(1, round((b - a) / 2.4))
        for i in range(posts + 1):
            u = a + (b - a) * i / posts
            mesh.fbox(frame, (u - 0.05, u + 0.05), (-0.11, -0.01), (-0.2, height + 0.08), "wood_fence")
        for z in (0.3, height - 0.3):
            mesh.fbox(frame, (a, b), (-0.07, -0.02), (z, z + 0.09), "wood_fence")
        count = int((b - a) / 0.148)
        for i in range(count):
            u = a + (b - a) * i / count
            lean = rng.uniform(-0.004, 0.004)
            mesh.fbox(frame, (u + 0.003, u + (b - a) / count - 0.003), (lean - 0.002, lean + 0.02),
                      (0.04, height + rng.uniform(-0.006, 0.006)), "wood_fence")
    if gate:
        a, b = gate
        mesh.fbox(frame, (a + 0.03, b - 0.03), (-0.05, -0.012), (0.1, height - 0.05), "wood_fence")
        for z in (0.2, height - 0.3):
            mesh.fbox(frame, (a + 0.03, b - 0.03), (-0.012, 0.012), (z, z + 0.1), "wood_fence")
        mesh.fbox(frame, (b - 0.16, b - 0.08), (0.012, 0.04), (0.98, 1.06), "iron")


def fences(col, mats):
    lot = plan.LOT
    x0, x1, y_street, y_back = lot["x"][0], lot["x"][1], -plan.GATE["z"], -lot["z"][0]
    mesh = Mesh("fences")
    board_fence(mesh, (x0, y_back), (x0, y_street))
    board_fence(mesh, (x1, y_street), (x1, y_back))
    board_fence(mesh, (x1, y_back), (x0, y_back))
    e, w = plan.SIDE_FENCE_EAST, plan.SIDE_FENCE_WEST
    board_fence(mesh, (e["x"][0], -e["z"]), (e["x"][1], -e["z"]), e["height"], (e["gate_x"][0] - e["x"][0], e["gate_x"][1] - e["x"][0]))
    board_fence(mesh, (w["x"][0], -w["z"]), (w["x"][1], -w["z"]), w["height"], (w["gate_x"][0] - w["x"][0], w["gate_x"][1] - w["x"][0]))
    return mesh.build(col, mats)


def path_light(mesh, x, y, add_light, light_col, lights):
    """A low bollard light with a shaded top."""
    mesh.cylinder((x, y, 0.0), (x, y, 0.42), 0.014, 0.014, "iron", 8)
    mesh.cylinder((x, y, 0.42), (x, y, 0.47), 0.04, 0.04, "lantern_glass", 12)
    mesh.cylinder((x, y, 0.47), (x, y, 0.52), 0.1, 0.03, "iron", 14)
    mesh.sphere((x, y, 0.445), 0.016, "lamp_warm", 8, 5)
    lights.append((x, y))
    add_light(light_col, "path light", (x, y, 0.43), 0.7, "warm", 0.02)


def lighting(col, mats, add_light, light_col):
    """Path lights, facade wash, tree uplights, the street lamp and switched floodlights."""
    mesh = Mesh("path_lights")
    done = []
    walk = kit.smooth_path(xy(plan.FRONT_WALK), 6)
    run, side = 0.0, 1
    for a, b in zip(walk, walk[1:]):
        step = (Vector(b) - Vector(a)).length
        run += step
        if run >= 2.3:
            run = 0.0
            t = (Vector(b) - Vector(a)).normalized()
            n = Vector((-t.y, t.x)) * side * (plan.FRONT_WALK_WIDTH / 2 + 0.3)
            path_light(mesh, b[0] + n.x, b[1] + n.y, add_light, light_col, done)
            side = -side
    drive = kit.smooth_path(xy(plan.DRIVEWAY), 6)
    run, side = 2.0, 1
    for a, b in zip(drive, drive[1:]):
        run += (Vector(b) - Vector(a)).length
        if run >= 5.2:
            run = 0.0
            t = (Vector(b) - Vector(a)).normalized()
            n = Vector((-t.y, t.x)) * side * (plan.DRIVEWAY_WIDTH / 2 + 0.75)
            path_light(mesh, b[0] + n.x, b[1] + n.y, add_light, light_col, done)
            side = -side
    mesh.build(col, mats)

    def spot(name, location, target, watts, colour, size_deg, blend=0.5, radius=0.03):
        lamp = add_light(light_col, name, location, watts, colour, radius, kind="SPOT")
        lamp.data.spot_size = math.radians(size_deg)
        lamp.data.spot_blend = blend
        direction = Vector(target) - Vector(location)
        lamp.rotation_euler = direction.to_track_quat("-Z", "Y").to_euler()
        return lamp

    # Soft wash up the front of the house from the planting beds.
    for x in (-7.0, -4.2, 4.2, 7.0):
        spot(f"facade wash {x}", (x, -1.5, 0.12), (x, 0.0, 5.5), 7.0, "warm_white", 70)
    for x in (10.6, 14.2):
        spot(f"wing wash {x}", (x, 0.4, 0.12), (x, 1.6, 3.4), 3.5, "warm_white", 75)
    # Uplights in the big oak on the front lawn and the maple by the east wing.
    for dx, dy in ((1.6, 0.4), (-1.2, 1.3), (0.2, -1.7)):
        spot("oak uplight", (13.5 + dx, -17.5 + dy, 0.1), (13.5, -17.5, 9.0), 55.0, "warm_white", 70)
    spot("maple uplight", (22.2, -7.0, 0.1), (23.5, -7.5, 7.0), 26.0, "warm_white", 66)
    # Street lamp opposite the gate.
    spot("street lamp", (-3.6, -39.4, 3.75), (-3.6, -40.6, 0.0), 420.0, "sodium", 140, 0.8, 0.09)
    spot("street lamp far", (38.0, -39.4, 3.75), (38.0, -40.6, 0.0), 420.0, "sodium", 140, 0.8, 0.09)
    spot("street lamp west", (-46.0, -39.4, 3.75), (-46.0, -40.6, 0.0), 420.0, "sodium", 140, 0.8, 0.09)
    # Motion floodlights. They are off until a scenario switches them on.
    for name, (location, target) in FLOODS.items():
        lamp = spot(name, location, target, 0.0, "cool", 105, 0.35, 0.06)
        lamp["flood_watts"] = 260.0


def planting(col, mats):
    """Trees from the plan, a screen of conifers around the lot, and foundation shrubs."""
    for kind, x, z, height in plan.TREES:
        tree(col, kind, x, -z, height)
    lot = plan.LOT
    x0, x1, y_back = lot["x"][0], lot["x"][1], -lot["z"][0]
    screen = []
    for i in range(13):
        screen.append((x0 - 4.5 - rng.uniform(0, 5), -30 + i * 7.2 + rng.uniform(-1.5, 1.5)))
        screen.append((x1 + 4.5 + rng.uniform(0, 5), -30 + i * 7.2 + rng.uniform(-1.5, 1.5)))
    for i in range(11):
        screen.append((x0 + 2 + i * 6.6 + rng.uniform(-1.5, 1.5), y_back + 4.5 + rng.uniform(0, 6)))
    for i in range(9):
        screen.append((-60 + i * 15 + rng.uniform(-3, 3), -71 - rng.uniform(0, 12)))
    # A second, deeper belt so no horizon shows between the trunks.
    for i in range(34):
        angle = math.tau * i / 34 + rng.uniform(-0.06, 0.06)
        radius = rng.uniform(70.0, 96.0)
        screen.append((radius * math.cos(angle) * 0.95, 4.0 + radius * math.sin(angle)))
    for x, y in screen:
        if -56.0 < y < -41.0:
            continue
        tree(col, rng.choice(["pine", "pine", "fir"]), x, y, rng.uniform(13.0, 19.0))
    # Street trees and the neighbours' front gardens.
    for x in (-52.0, -40.0, -13.0, 0.0, 26.0, 34.0, 60.0):
        tree(col, rng.choice(["maple", "birch", "oak"]), x, -50.5 - rng.uniform(0, 3.0), rng.uniform(8.0, 13.0))
    shrubs = [("shrub_02", r"^shrub_02_%s_LOD1$" % letter) for letter in "abcd"]
    beds = [(-8.0, -3.2, -0.85), (3.2, 8.0, -0.85)]
    for a, b, y in beds:
        x = a
        while x < b:
            slug, pattern = rng.choice(shrubs)
            place(col, slug, x, y + rng.uniform(-0.15, 0.15), rot=rng.uniform(0, math.tau), scale=rng.uniform(0.5, 0.72), pattern=pattern)
            x += rng.uniform(0.95, 1.3)
    for x in (9.4, 11.0, 12.6, 14.2, 15.6):
        slug, pattern = rng.choice(shrubs)
        place(col, slug, x, 0.85, rot=rng.uniform(0, math.tau), scale=rng.uniform(0.5, 0.7), pattern=pattern)
    for x in (-12.6, -11.2, -9.6):
        slug, pattern = rng.choice(shrubs)
        place(col, slug, x, 1.8, rot=rng.uniform(0, math.tau), scale=rng.uniform(0.42, 0.58), pattern=pattern)
    for i in range(12):
        slug, pattern = rng.choice(shrubs)
        place(col, slug, -6.4 + i * 1.35, 18.1, rot=rng.uniform(0, math.tau), scale=rng.uniform(0.45, 0.7), pattern=pattern)
    for y in (2.4, 4.0, 5.6, 7.4, 8.8):
        slug, pattern = rng.choice(shrubs)
        place(col, slug, 16.95, y, rot=rng.uniform(0, math.tau), scale=rng.uniform(0.45, 0.62), pattern=pattern)
    # Low hedge inside the street wall.
    x = x0 + 1.0
    while x < x1 - 1.0:
        if not (plan.GATE["x"] - 4.5 < x < plan.GATE["x"] + 4.5):
            slug, pattern = rng.choice(shrubs)
            place(col, slug, x, -36.9 + rng.uniform(-0.1, 0.1), rot=rng.uniform(0, math.tau), scale=rng.uniform(0.62, 0.8), pattern=pattern)
        x += rng.uniform(1.3, 1.6)
    # Small ornamental trees at the corners of the house.
    place(col, "island_tree_02", -9.6, -1.6, rot=1.0, height=3.4, pattern=r"^island_tree_02_LOD1$")
    place(col, "island_tree_02", 17.6, -0.8, rot=2.2, height=3.9, pattern=r"^island_tree_02_LOD1$")
    place(col, "island_tree_01", -10.5, 22.5, rot=0.4, height=5.2, pattern=r"^island_tree_01_LOD1$")


def furniture(col, mats):
    """Site furniture and service equipment."""
    place(col, "painted_wooden_bench", -1.75, -1.35, z=plan.PORTICO["floor"], rot=math.pi / 2)
    place(col, "potted_plant_02", 1.95, -2.35, z=plan.PORTICO["floor"], scale=0.9)
    place(col, "potted_plant_02", -1.95, -2.35, z=plan.PORTICO["floor"], scale=0.9, rot=1.4)
    t = plan.TERRACE["level"]
    place(col, "outdoor_table_chair_set_01", -3.4, 14.2, z=t, rot=0.5, scale=1.15)
    place(col, "outdoor_table_chair_set_01", -1.2, 15.6, z=t, rot=2.1, scale=1.15)
    place(col, "stone_fire_pit", 6.2, 14.6, z=t, scale=0.9)
    place(col, "painted_wooden_bench", 6.3, 16.6, z=t, rot=math.pi)
    place(col, "painted_wooden_bench", 8.1, 14.5, z=t, rot=-math.pi / 2)
    place(col, "potted_plant_01", -6.3, 11.4, z=t, scale=0.9)
    place(col, "potted_plant_01", 9.2, 11.5, z=t, scale=0.85, rot=2.0)
    place(col, "planter_box_01", 1.7, 17.25, z=t + 0.48, rot=0.0)
    place(col, "wooden_picnic_table", 20.0, 22.0, rot=0.3)
    # Service yard west of the garage.
    for i, x in enumerate((-26.2, -26.95, -27.7)):
        place(col, "metal_trash_can", x, 9.4, rot=0.4 * i)
    place(col, "exterior_aircon_unit", -19.0, 11.1, rot=math.pi, pattern=r"^exterior_aircon_unit$")
    place(col, "exterior_aircon_unit", -17.6, 11.1, rot=math.pi, pattern=r"^exterior_aircon_unit$")
    place(col, "exterior_aircon_unit", 9.0, 9.9, rot=math.pi, pattern=r"^exterior_aircon_unit$")
    place(col, "covered_car", -29.2, 6.2, rot=0.06)
    place(col, "garden_hose_wall_mounted_01", -25.32, 4.2, z=0.9, rot=math.pi / 2, ground=False)
    place(col, "wooden_ladder", 26.75, 40.6, rot=math.pi / 2)
    place(col, "watering_can_metal_01", 22.6, 39.5, rot=1.0)
    place(col, "utility_box_01", -20.5, -37.0, rot=0.0)
    # Street furniture.
    place(col, "fire_hydrant", 6.5, -39.3, pattern=r"^fire_hydrant(_cap_0[123]|_chain)?$", recentre=False)
    for x in (-3.6, 38.0, -46.0):
        place(col, "street_lamp_01", x, -39.1, rot=-math.pi / 2)
    # Mailbox by the gate.
    mesh = Mesh("mailbox")
    mx, my = -8.2, -38.9
    mesh.box((mx - 0.05, my - 0.05, 0.0), (mx + 0.05, my + 0.05, 1.05), "wood_fence")
    mesh.box((mx - 0.1, my - 0.26, 1.05), (mx + 0.1, my + 0.22, 1.22), "iron")
    mesh.cylinder((mx, my - 0.26, 1.22), (mx, my + 0.22, 1.22), 0.1, 0.1, "iron", 16)
    mesh.build(col, mats)


def security(col, mats):
    """A camera body at each of the plan's mounts, set back so it stays out of its own view."""
    for cam in plan.CAMERAS:
        x, up, z = cam["position"]
        lx, _, lz = cam["look_at"]
        heading = math.atan2(-(lz - z), lx - x)
        back = Vector((lx - x, -(lz - z))).normalized() * -0.3
        slug = "security_camera_02" if cam["id"] in ("porch", "terrace") else "security_camera_01"
        place(col, slug, x + back.x, -z + back.y, z=up + 0.16, rot=heading - math.pi / 2, ground=False, name="device_" + cam["id"])


def drop(obj):
    """Take an object out of every collection that holds it."""
    for owner in list(obj.users_collection):
        owner.objects.unlink(obj)


def vehicles(col):
    """Two cars in the motor court, from the CC0 Blender benchmark model with its badges removed."""
    path = str(MODELS.parent / "vehicles" / "bmw27" / "bmw27_gpu.blend")
    spots = [(-19.7, -4.3, math.radians(96.0), (0.02, 0.022, 0.026)), (-23.6, -2.3, math.radians(84.0), (0.33, 0.34, 0.35))]
    for index, (x, y, rot, colour) in enumerate(spots):
        with bpy.data.libraries.load(path) as (src, dst):
            dst.collections = ["1M"]
        car = dst.collections[0]
        for obj in list(car.all_objects):
            if "Roundel" in obj.name or obj.name.startswith("plate"):
                drop(obj)
            elif obj.instance_collection:
                for inner in list(obj.instance_collection.objects):
                    if "Roundel" in inner.name:
                        drop(inner)
        shell = next(o for o in car.all_objects if o.name.startswith("carShell") and o.type == "MESH" and o.parent is None)
        for slot in shell.material_slots:
            if slot.material and slot.material.node_tree:
                for node in slot.material.node_tree.nodes:
                    for name in ("Base Color", "Color"):
                        socket = node.inputs.get(name)
                        if socket and not socket.is_linked and node.type in ("BSDF_PRINCIPLED", "BSDF_DIFFUSE", "BSDF_GLOSSY"):
                            socket.default_value = (*colour, 1.0)
        # The cars are parked and switched off: no glowing lamps.
        for obj in car.all_objects:
            for slot in obj.material_slots:
                if slot.material and slot.material.node_tree:
                    for node in slot.material.node_tree.nodes:
                        if node.type == "EMISSION":
                            node.inputs["Strength"].default_value = 0.0
                        elif node.type == "BSDF_PRINCIPLED":
                            node.inputs["Emission Strength"].default_value = 0.0
        wheels = [o for o in car.all_objects if o.name.startswith("Tire") and o.type == "EMPTY"]
        base = min(o.matrix_world.translation.z for o in wheels) - 0.47 if wheels else 0.0
        scale = 4.38 / 5.95
        empty = bpy.data.objects.new(f"car_{index}", None)
        empty.instance_type = "COLLECTION"
        empty.instance_collection = car
        empty.scale = (scale, scale, scale)
        empty.rotation_euler = (0.0, 0.0, rot)
        empty.location = (x, y, 0.034 - base * scale)
        col.objects.link(empty)


def build(scene, mats, collection, add_light, light_col, frames, heights):
    site = collection("Site")
    ground(site, mats)
    terrace(site, mats)
    pool(site, mats, add_light, light_col)
    street_wall(site, mats, add_light, light_col)
    fences(site, mats)
    lighting(site, mats, add_light, light_col)
    planting(collection("Planting"), mats)
    props = collection("Props")
    furniture(props, mats)
    security(props, mats)
    vehicles(props)
    import details
    details.build(props, mats, heights, place, add_light, light_col, FLOODS)
    if LAWN_BLADES:
        import grass
        grass.build(site, mats, model)
