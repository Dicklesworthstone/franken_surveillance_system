"""Alder House: mown grass where the lawn is lit or close to a lens. Runs inside Blender.

The lawn texture carries the distance. Near the walk, the drive, the house
front and the terrace, real blades are scattered with Geometry Nodes so the
ground has depth under the path lights. Hard surfaces and beds are left clear.
"""
import math

import bpy
from mathutils import Vector

import kit
import plan
from kit import Mesh

CELL = 1.0
DENSITY = 95.0  # tufts per square metre
REACH = 7.5  # how far from a lit edge the blades extend


def _inside(ring, x, y):
    hit = False
    for (ax, ay), (bx, by) in zip(ring, ring[1:] + ring[:1]):
        if (ay > y) != (by > y) and x < ax + (y - ay) * (bx - ax) / (by - ay):
            hit = not hit
    return hit


def _distance(path, x, y):
    p = Vector((x, y))
    best = 1e9
    for a, b in zip(path, path[1:]):
        a, b = Vector(a), Vector(b)
        t = max(0.0, min(1.0, (p - a).dot(b - a) / max((b - a).length_squared, 1e-9)))
        best = min(best, (p - (a + t * (b - a))).length)
    return best


def cells():
    """Lawn cells that get blades: near a lit edge, and not on paving, beds or buildings."""
    to_xy = lambda pts: [(x, -z) for x, z in pts]
    drive = kit.smooth_path(to_xy(plan.DRIVEWAY), 4)
    walk = kit.smooth_path(to_xy(plan.FRONT_WALK), 4)
    court = to_xy(plan.MOTOR_COURT)
    boxes = []
    for b in plan.BUILDINGS.values():
        boxes.append((b["x"][0] - 0.5, b["x"][1] + 0.5, -b["z"][1] - 0.5, -b["z"][0] + 0.5))
    t, p = plan.TERRACE, plan.POOL
    boxes.append((t["x"][0] - 0.3, t["x"][1] + 0.3, -t["z"][1], -t["z"][0] + 1.4))
    boxes.append((p["x"][0] - p["deck"], p["x"][1] + p["deck"], -p["z"][1] - p["deck"], -p["z"][0] + p["deck"]))
    boxes += [(-8.5, -2.8, -1.8, 0.0), (2.8, 8.5, -1.8, 0.0), (8.4, 16.3, 0.1, 1.7), (-13.4, -8.4, 1.2, 2.5),
              (-2.6, 2.6, -3.9, 0.0), (-25.3, -13.3, 0.8, 2.1)]
    lot = plan.LOT
    out = []
    y = -plan.GATE["z"] + 1.6
    while y < -lot["z"][0] - 1.0:
        x = lot["x"][0] + 0.6
        while x < lot["x"][1] - 0.6:
            cx, cy = x + CELL / 2, y + CELL / 2
            near = min(_distance(drive, cx, cy) - plan.DRIVEWAY_WIDTH / 2, _distance(walk, cx, cy) - plan.FRONT_WALK_WIDTH / 2)
            front = -9.0 < cy < 0.0 and -27.0 < cx < 18.0
            rear = 17.6 < cy < 26.0 and -9.0 < cx < 14.0
            blocked = (near < 0.35 or _inside(court, cx, cy)
                       or any(a < cx < b and c < cy < d for a, b, c, d in boxes))
            if not blocked and (near < REACH or front or rear):
                out.append((x, y))
            x += CELL
        y += CELL
    return out


def build(col, mats, model):
    """Scatter grass tufts over the chosen lawn cells."""
    tufts, _, _ = model("grass_medium_01", r"_LOD2$")
    mesh = Mesh("lawn_blades")
    patch = cells()
    for x, y in patch:
        mesh.face([(x, y, 0.0), (x + CELL, y, 0.0), (x + CELL, y + CELL, 0.0), (x, y + CELL, 0.0)], "lawn")
    obj = mesh.build(col, mats)
    tree = bpy.data.node_groups.new("lawn_blades", "GeometryNodeTree")
    tree.interface.new_socket("Geometry", in_out="INPUT", socket_type="NodeSocketGeometry")
    tree.interface.new_socket("Geometry", in_out="OUTPUT", socket_type="NodeSocketGeometry")
    nodes, links = tree.nodes, tree.links
    source, sink = nodes.new("NodeGroupInput"), nodes.new("NodeGroupOutput")
    scatter = nodes.new("GeometryNodeDistributePointsOnFaces")
    scatter.inputs["Density"].default_value = DENSITY
    library = nodes.new("GeometryNodeCollectionInfo")
    library.inputs["Collection"].default_value = tufts
    library.inputs["Separate Children"].default_value = True
    library.inputs["Reset Children"].default_value = True
    def random_value(kind, low, high):
        """A Random Value node of one type; only that type's sockets are enabled."""
        node = nodes.new("FunctionNodeRandomValue")
        node.data_type = kind
        live = {s.name: s for s in node.inputs if s.enabled}
        live["Min"].default_value = low
        live["Max"].default_value = high
        return next(s for s in node.outputs if s.enabled)

    spin = random_value("FLOAT_VECTOR", (0.0, 0.0, 0.0), (0.12, 0.12, math.tau))
    size = random_value("FLOAT", 0.2, 0.34)
    place = nodes.new("GeometryNodeInstanceOnPoints")
    place.inputs["Pick Instance"].default_value = True
    links.new(source.outputs[0], scatter.inputs["Mesh"])
    links.new(scatter.outputs["Points"], place.inputs["Points"])
    links.new(library.outputs[0], place.inputs["Instance"])
    links.new(spin, place.inputs["Rotation"])
    links.new(size, place.inputs["Scale"])
    links.new(place.outputs["Instances"], sink.inputs[0])
    modifier = obj.modifiers.new("lawn_blades", "NODES")
    modifier.node_group = tree
    print("LAWN cells", len(patch), "tufts about", int(len(patch) * CELL * CELL * DENSITY))
    return obj
