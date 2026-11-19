"""Alder House: the buildings. Runs inside Blender.

Each building is one clapboard block on a stone foundation with a gable roof.
`ITEMS` lists what sits on each facade, in metres along the wall from its
left end as seen from outside.
"""
import math
import random

from mathutils import Vector

import kit
import materials as shaders
import plan
from kit import Frame, Mesh, facade

FOUND = 0.5  # top of the stone foundation
FFL = plan.FIRST_FLOOR
F1_SILL, F1_H = FFL + 0.78, 1.72
F2_FLOOR = FFL + 3.05
F2_SILL, F2_H = F2_FLOOR + 0.82, 1.5


def bounds(key):
    b = plan.BUILDINGS.get(key) or plan.NEIGHBOURS[key]
    return b["x"][0], b["x"][1], -b["z"][1], -b["z"][0], b


def win(u, sill=F1_SILL, w=1.02, h=F1_H, cols=3, rows=2, shutters=True, lit=0.0, split=True):
    return dict(kind="window", u=u, sill=sill, w=w, h=h, cols=cols, rows=rows, shutters=shutters, lit=lit, split=split)


def up(u, lit=0.0, w=1.02, shutters=True):
    return win(u, F2_SILL, w, F2_H, lit=lit, shutters=shutters)


# Facade contents. Sides: s faces the street, n the garden, e and w the ends.
ITEMS = {
    "main": {
        "s": [win(2.1, lit=0.9), win(5.1, lit=0.6), dict(kind="entry", u=8.4), win(11.7), win(14.7, lit=0.25),
              up(2.1), up(5.1, lit=0.0), up(8.4, lit=0.7), up(11.7), up(14.7, lit=0.5)],
        "n": [win(1.9, lit=0.5), dict(kind="french", u=5.2, lit=0.8), dict(kind="french", u=9.2, lit=0.3),
              win(12.6, w=1.9, cols=6, lit=0.9, shutters=False), win(15.2, w=0.9, shutters=False, lit=0.9),
              up(1.9), up(5.2, lit=0.4), up(8.4), up(11.6), up(14.9, lit=0.0)],
        "w": [up(2.3), up(8.5, lit=0.3),
              win(5.4, sill=8.05, w=0.8, h=1.0, cols=2, rows=2, shutters=False, split=False)],
        "e": [up(1.0, shutters=False), up(9.9, shutters=False),
              win(5.4, sill=8.05, w=0.8, h=1.0, cols=2, rows=2, shutters=False, split=False)],
    },
    "east_wing": {
        "s": [win(2.2, w=1.1, lit=0.35), win(5.6, w=1.1, lit=0.35)],
        "n": [win(1.4, lit=0.0, shutters=False)],
        "e": [win(1.5), dict(kind="service", u=6.4, lit=0.2)],
        "w": [],
    },
    "connector": {
        "s": [dict(kind="service", u=1.5, lit=0.5, hood=True), win(3.6, w=0.95, lit=0.5)],
        "n": [win(2.5, w=0.95, shutters=False)],
        "e": [],
        "w": [],
    },
    "garage": {
        "s": [dict(kind="garage", u=2.2), dict(kind="garage", u=5.9), dict(kind="garage", u=9.6)],
        "n": [win(3.0, shutters=False), win(8.8, shutters=False)],
        "w": [dict(kind="service", u=1.6), win(5.2, shutters=False),
              win(4.3, sill=4.55, w=0.9, h=1.25, cols=3, rows=2, shutters=False)],
        "e": [],
    },
    "pool_house": {
        "s": [win(1.2, w=0.9, shutters=False), win(4.8, w=0.9, shutters=False)],
        "n": [],
        "w": [dict(kind="french", u=2.4, lit=0.15)],
        "e": [],
    },
    "shed": {"s": [dict(kind="shed_door", u=1.8)], "n": [], "e": [], "w": [win(1.4, sill=1.1, w=0.7, h=0.8, cols=2, rows=2, shutters=False, split=False)]},
}

for _name, _lit in (("neighbour_a", (0.0, 0.5, 0.0, 0.7)), ("neighbour_b", (0.4, 0.0, 0.0, 0.0)), ("neighbour_c", (0.0, 0.0, 0.6, 0.0))):
    _w = plan.NEIGHBOURS[_name]["x"][1] - plan.NEIGHBOURS[_name]["x"][0]
    _front = [win(_w * 0.16, lit=_lit[0]), win(_w * 0.36, lit=_lit[1]), dict(kind="service", u=_w * 0.56, lit=0.3),
              win(_w * 0.78, lit=_lit[2])]
    if plan.NEIGHBOURS[_name]["storeys"] == 2:
        _front += [up(_w * 0.16, lit=_lit[3]), up(_w * 0.36), up(_w * 0.56), up(_w * 0.78, lit=_lit[1])]
    ITEMS[_name] = {"n": _front, "s": [], "e": [win(3.0)], "w": [win(3.0)]}

# Dormers: (centre x, faces -1 south or +1 north, lit)
DORMERS = {
    "main": dict(width=1.5, set_back=1.25, sill=0.2, wall=1.0, rise=0.62,
                 at=[(-5.3, -1, 0.0), (0.0, -1, 0.6), (5.3, -1, 0.0), (-3.6, 1, 0.3), (3.6, 1, 0.0)]),
    "garage": dict(width=1.4, set_back=1.0, sill=0.2, wall=0.92, rise=0.56,
                   at=[(-23.0, -1, 0.0), (-19.3, -1, 0.0), (-15.6, -1, 0.4)]),
    "east_wing": dict(width=1.4, set_back=1.0, sill=0.2, wall=0.92, rise=0.56,
                      at=[(10.5, -1, 0.5), (14.1, -1, 0.0), (12.3, 1, 0.0)]),
}

rng = random.Random(11)


def room(mesh, frame, opening, lit, length, library=None, seed=0, depth=2.4, pad=0.5):
    """A shallow room behind an opening so glass shows an interior, lit or dark.

    A lit room's back wall shows a furnished interior from a CC0 panorama.
    """
    u0, u1, z0, z1 = opening
    # Stay inside the building: a room may not reach past the wall's ends.
    a = max(u0 - pad, min(0.22, u0 - 0.02))
    b = min(u1 + pad, max(length - 0.22, u1 + 0.02))
    floor, ceil = min(z0 - 0.75, z0), z1 + 0.45
    wall_mat = "room_wall" if lit > 0.05 else "room_dark"
    n0, n1 = -0.15, -depth
    P = frame.at
    back = wall_mat
    if lit > 0.05 and library is not None:
        rooms = shaders.ROOMS_UP if z0 > F2_FLOOR - 0.3 else shaders.ROOMS_DOWN
        level = "bright" if lit > 0.55 else "tv" if 0.12 < lit < 0.2 else "dim"
        back = shaders.room_view(library, rooms[seed % len(rooms)], seed * 47 + (u0 + u1) * 9.0, level)
    mesh.face([P(a, n1, floor), P(b, n1, floor), P(b, n1, ceil), P(a, n1, ceil)], back, [(0, 0), (1, 0), (1, 1), (0, 1)])
    mesh.face([P(a, n0, floor), P(a, n1, floor), P(a, n1, ceil), P(a, n0, ceil)], wall_mat)
    mesh.face([P(b, n1, floor), P(b, n0, floor), P(b, n0, ceil), P(b, n1, ceil)], wall_mat)
    mesh.face([P(a, n0, floor), P(b, n0, floor), P(b, n1, floor), P(a, n1, floor)], "room_floor" if lit > 0.05 else "room_dark")
    mesh.face([P(a, n1, ceil), P(b, n1, ceil), P(b, n0, ceil), P(a, n0, ceil)], wall_mat)
    # Close the gap between the room and the wall around the opening.
    for q in ([P(a, n0, floor), P(u0, n0, floor), P(u0, n0, ceil), P(a, n0, ceil)],
              [P(u1, n0, floor), P(b, n0, floor), P(b, n0, ceil), P(u1, n0, ceil)],
              [P(u0, n0, z1), P(u1, n0, z1), P(u1, n0, ceil), P(u0, n0, ceil)],
              [P(u0, n0, floor), P(u1, n0, floor), P(u1, n0, z0), P(u0, n0, z0)]):
        mesh.face(q, "room_dark")
    if lit > 0.05:
        glow = "room_glow" if lit > 0.55 else "room_glow_dim"
        if 0.12 < lit < 0.2:
            glow = "room_glow_tv"
        c, d = (a + b) / 2, (n0 + n1) / 2
        s = 0.3 if lit > 0.55 else 0.2
        mesh.face([P(c - s, d - s, ceil - 0.02), P(c + s, d - s, ceil - 0.02), P(c + s, d + s, ceil - 0.02), P(c - s, d + s, ceil - 0.02)], glow)
    # Curtains drawn back at the sides, and sometimes a half-lowered blind.
    width = u1 - u0
    drape = width * rng.uniform(0.14, 0.26)
    for lo, hi in ((u0 - 0.04, u0 + drape), (u1 - drape, u1 + 0.04)):
        mesh.face([P(lo, -0.2, z0 - 0.05), P(hi, -0.2, z0 - 0.05), P(hi, -0.2, z1 + 0.1), P(lo, -0.2, z1 + 0.1)], "curtain")
    if rng.random() < 0.35:
        drop = (z1 - z0) * rng.uniform(0.25, 0.55)
        mesh.face([P(u0, -0.17, z1 - drop), P(u1, -0.17, z1 - drop), P(u1, -0.17, z1), P(u0, -0.17, z1)], "blind")


def entry(mesh, frame, centre):
    """The front door: six-panel leaf, sidelights, transom and a wide surround."""
    z0 = FFL
    door_w, door_h, side_w, post = 1.02, 2.2, 0.3, 0.1
    half = door_w / 2 + post + side_w
    top = z0 + door_h + 0.09 + 0.42
    opening = (centre - half, centre + half, z0, top)
    kit.panel_door(mesh, frame, (centre - door_w / 2, centre + door_w / 2), (z0, z0 + door_h))
    for sign in (-1, 1):
        inner = centre + sign * door_w / 2
        outer = inner + sign * post
        mesh.fbox(frame, (min(inner, outer), max(inner, outer)), (-0.1, 0.0), (z0, z0 + door_h), "trim")
        a, b = sorted((outer, outer + sign * side_w))
        mesh.fbox(frame, (a, b), (-0.09, -0.03), (z0, z0 + 0.7), "trim")
        mesh.fbox(frame, (a + 0.04, b - 0.04), (-0.03, -0.022), (z0 + 0.08, z0 + 0.62), "trim")
        kit.glazing(mesh, frame, (a, b), (z0 + 0.7, z0 + door_h), -0.04, 1, 4, stile=0.035, rail=0.04)
    mesh.fbox(frame, (centre - half, centre + half), (-0.1, 0.0), (z0 + door_h, z0 + door_h + 0.09), "trim")
    kit.glazing(mesh, frame, (centre - half, centre + half), (z0 + door_h + 0.09, top), -0.04, 5, 1, stile=0.04, rail=0.04)
    # Surround: broad pilasters carrying a deep head.
    for sign in (-1, 1):
        a, b = sorted((centre + sign * half, centre + sign * (half + 0.2)))
        mesh.fbox(frame, (a, b), (0, 0.05), (z0 - 0.05, top), "trim")
        mesh.fbox(frame, (a - 0.015, b + 0.015), (0, 0.065), (z0 - 0.05, z0 + 0.14), "trim")
    mesh.fbox(frame, (centre - half - 0.2, centre + half + 0.2), (0, 0.05), (top, top + 0.24), "trim")
    mesh.fbox(frame, (centre - half - 0.26, centre + half + 0.26), (0, 0.11), (top + 0.24, top + 0.3), "trim")
    mesh.fbox(frame, (centre - half, centre + half), (-0.14, 0.06), (z0 - 0.05, z0), "stone_cap")
    mesh.fbox(frame, (centre - 0.16, centre + 0.16), (0.05, 0.055), (top + 0.05, top + 0.19), "brass")
    return opening


def french(mesh, frame, centre, z0=FFL, width=1.68, height=2.24):
    """A pair of glazed doors."""
    u0, u1 = centre - width / 2, centre + width / 2
    kit.casing(mesh, frame, (u0, u1), (z0, z0 + height), sill=False, head=0.17)
    kit.glazing(mesh, frame, (u0, centre), (z0, z0 + height), -0.05, 2, 5, stile=0.085, rail=0.1, bottom_rail=0.24, thick=0.045)
    kit.glazing(mesh, frame, (centre, u1), (z0, z0 + height), -0.05, 2, 5, stile=0.085, rail=0.1, bottom_rail=0.24, thick=0.045)
    for du in (-0.06, 0.06):
        mesh.cylinder(frame.at(centre + du, -0.05, z0 + 1.0), frame.at(centre + du, 0.0, z0 + 1.0), 0.012, 0.012, "brass", 10)
        mesh.fbox(frame, (centre + du - 0.012, centre + du + 0.012), (0.0, 0.02), (z0 + 0.93, z0 + 1.07), "brass")
    mesh.fbox(frame, (u0, u1), (-0.12, 0.06), (z0 - 0.045, z0), "stone_cap")
    return (u0, u1, z0, z0 + height)


def service(mesh, frame, centre, z0=FFL, width=0.92, height=2.1, hood=False):
    """A half-glazed side door."""
    u0, u1 = centre - width / 2, centre + width / 2
    kit.casing(mesh, frame, (u0, u1), (z0, z0 + height), sill=False, head=0.13)
    kit.panel_door(mesh, frame, (u0, u1), (z0, z0 + height * 0.5), panels=((0.12, 0.9, 2),), knob=None)
    kit.glazing(mesh, frame, (u0, u1), (z0 + height * 0.5, z0 + height), -0.06, 3, 3, stile=0.11, rail=0.11, thick=0.045, mat="door")
    mesh.sphere(frame.at(u1 - 0.07, 0.0, z0 + 0.98), 0.03, "brass", 12, 8)
    mesh.fbox(frame, (u0, u1), (-0.12, 0.05), (z0 - 0.045, z0), "stone_cap")
    if hood:
        for sign in (-1, 1):
            edge = centre + sign * (width / 2 + 0.28)
            mesh.face([frame.at(edge, 0.0, z0 + height + 0.32), frame.at(edge, 0.85, z0 + height + 0.32),
                       frame.at(centre, 0.85, z0 + height + 0.72), frame.at(centre, 0.0, z0 + height + 0.72)][::sign], "roof")
            mesh.fbox(frame, (edge - 0.04, edge + 0.04), (0.0, 0.8), (z0 + height + 0.2, z0 + height + 0.3), "trim")
            for k in range(4):
                t0, t1 = k / 4, (k + 1) / 4
                mesh.fbox(frame, (edge - 0.03, edge + 0.03), (0.02 + 0.6 * t0, 0.02 + 0.6 * t1),
                          (z0 + height - 0.4 + 0.58 * t0, z0 + height - 0.33 + 0.58 * t1), "trim")
        mesh.face([frame.at(centre - width / 2 - 0.28, 0.85, z0 + height + 0.32), frame.at(centre + width / 2 + 0.28, 0.85, z0 + height + 0.32),
                   frame.at(centre, 0.85, z0 + height + 0.72)], "trim")
    return (u0, u1, z0, z0 + height)


def garage_door(mesh, frame, centre, z0=0.14, width=2.75, height=2.3):
    """A carriage-style overhead door: three panel rows under a row of lights."""
    u0, u1 = centre - width / 2, centre + width / 2
    kit.casing(mesh, frame, (u0, u1), (z0, z0 + height), sill=False, head=0.2, width=0.13)
    mesh.fbox(frame, (u0, u1), (-0.12, -0.075), (z0, z0 + height), "garage_door")
    rows, cols = 4, 4
    rh, cw = height / rows, width / cols
    for r in range(rows):
        for c in range(cols):
            a, b = u0 + c * cw + 0.07, u0 + (c + 1) * cw - 0.07
            lo, hi = z0 + r * rh + 0.07, z0 + (r + 1) * rh - 0.07
            if r == rows - 1:
                mesh.face([frame.at(a, -0.07, lo), frame.at(b, -0.07, lo), frame.at(b, -0.07, hi), frame.at(a, -0.07, hi)], "glass")
                mesh.fbox(frame, ((a + b) / 2 - 0.012, (a + b) / 2 + 0.012), (-0.075, -0.06), (lo, hi), "garage_door")
            else:
                mesh.fbox(frame, (a, b), (-0.075, -0.066), (lo, hi), "garage_door")
            for ea, eb in ((a - 0.07, a), (b, b + 0.07)):
                mesh.fbox(frame, (ea, eb), (-0.075, -0.05), (z0 + r * rh, z0 + (r + 1) * rh), "garage_door")
            mesh.fbox(frame, (a, b), (-0.075, -0.05), (lo - 0.07, lo), "garage_door")
            mesh.fbox(frame, (a, b), (-0.075, -0.05), (hi, hi + 0.07), "garage_door")
    for du in (-0.35, 0.35):
        mesh.fbox(frame, (centre + du - 0.09, centre + du + 0.09), (-0.05, -0.02), (z0 + 0.5, z0 + 0.53), "iron")
    return (u0, u1, z0, z0 + height)


def shed_door(mesh, frame, centre, z0=0.12, width=1.7, height=1.95):
    u0, u1 = centre - width / 2, centre + width / 2
    kit.casing(mesh, frame, (u0, u1), (z0, z0 + height), sill=False, head=0.1, width=0.09)
    for a, b in ((u0, centre - 0.005), (centre + 0.005, u1)):
        mesh.fbox(frame, (a, b), (-0.06, -0.02), (z0, z0 + height), "shutter")
        for lo, hi in ((0.02, 0.14), (0.86, 0.98)):
            mesh.fbox(frame, (a, b), (-0.02, 0.0), (z0 + lo * height, z0 + hi * height), "shutter")
    return (u0, u1, z0, z0 + height)


def block(collection, materials, key, lights):
    """Build one building: walls, openings, rooms, trim, roof, gutters, dormers."""
    x0, x1, y0, y1, b = bounds(key)
    eave, ridge = b["eave"], b["ridge"]
    axis = "x" if b["ridge_axis"] == "x" else "y"
    mesh = Mesh(key)
    frames = {"s": facade(x0, y0, x1, y0), "e": facade(x1, y0, x1, y1),
              "n": facade(x1, y1, x0, y1), "w": facade(x0, y1, x0, y0)}
    gable_sides = ("e", "w") if axis == "x" else ("n", "s")
    base = FOUND + 0.1 if key != "shed" else 0.12
    for side, (frame, length) in frames.items():
        openings, built = [], []
        for item in ITEMS[key][side]:
            kind, u = item["kind"], item["u"]
            if kind == "window":
                o = (u - item["w"] / 2, u + item["w"] / 2, item["sill"], item["sill"] + item["h"])
            elif kind == "entry":
                o = (u - 0.91, u + 0.91, FFL, FFL + 2.71)
            elif kind == "french":
                o = (u - 0.84, u + 0.84, FFL, FFL + 2.24)
            elif kind == "service":
                o = (u - 0.46, u + 0.46, FFL, FFL + 2.1)
            elif kind == "garage":
                o = (u - 1.375, u + 1.375, 0.14, 2.44)
            else:
                o = (u - 0.85, u + 0.85, 0.12, 2.07)
            openings.append(o)
            built.append((item, o))
        wall_base = min([base] + [o[2] for o in openings])
        kit.wall(mesh, frame, length, wall_base, eave, openings, "siding",
                 gable=(length / 2, ridge) if side in gable_sides else None)
        if key != "shed":
            mesh.fbox(frame, (-0.03, length + 0.03), (-0.2, 0.035), (-0.4, FOUND), "stone")
            for a, c in _spans(length, [o for o in openings if o[2] < FOUND + 0.2]):
                mesh.fbox(frame, (a, c), (0.0, 0.05), (FOUND, FOUND + 0.1), "trim")
        for a, c in ((-0.03, 0.105), (length - 0.105, length + 0.03)):
            mesh.fbox(frame, (a, c), (0.0, 0.033), (base, eave), "trim")
        if side not in gable_sides:
            mesh.fbox(frame, (0.0, length), (0.0, 0.028), (eave - 0.24, eave), "trim")
        for item, o in built:
            kind, u, lit = item["kind"], item["u"], item.get("lit", 0.0)
            if kind == "window":
                kit.window(mesh, frame, u, item["sill"], item["w"], item["h"], item["cols"], item["rows"],
                           item["shutters"], item["split"])
            elif kind == "entry":
                entry(mesh, frame, u)
                lit = 0.6
            elif kind == "french":
                french(mesh, frame, u)
            elif kind == "service":
                service(mesh, frame, u, hood=item.get("hood", False))
            elif kind == "garage":
                garage_door(mesh, frame, u)
            else:
                shed_door(mesh, frame, u)
            if kind in ("garage", "shed_door"):
                mesh.face([frame.at(o[0], -0.3, o[2]), frame.at(o[1], -0.3, o[2]), frame.at(o[1], -0.3, o[3]), frame.at(o[0], -0.3, o[3])], "room_dark")
            else:
                room(mesh, frame, o, lit, length, materials, sum(map(ord, key + side)) + int(u))
    height = kit.gable_roof(mesh, x0, x1, y0, y1, eave, ridge, axis,
                            eave_over=0.36 if key != "shed" else 0.2, rake_over=0.28 if key != "shed" else 0.16)
    pitch = (ridge - eave) / ((y1 - y0) / 2 if axis == "x" else (x1 - x0) / 2)
    if axis == "x" and key != "shed":
        over = 0.36
        for sign, y in ((-1, y0), (1, y1)):
            edge_y = y + sign * (over + 0.005)
            z = eave - over * pitch - 0.02
            kit.gutter(mesh, (x0 - 0.2, edge_y, z) if sign < 0 else (x1 + 0.2, edge_y, z),
                       (x1 + 0.2, edge_y, z) if sign < 0 else (x0 - 0.2, edge_y, z))
            for x in (x0 + 0.06, x1 - 0.06):
                mesh.cylinder((x, edge_y, z - 0.06), (x, y + sign * 0.07, z - 0.5), 0.036, 0.036, "gutter", 10)
                mesh.cylinder((x, y + sign * 0.07, z - 0.5), (x, y + sign * 0.07, 0.3), 0.036, 0.036, "gutter", 10)
                mesh.cylinder((x, y + sign * 0.07, 0.3), (x, y + sign * 0.3, 0.12), 0.036, 0.036, "gutter", 10)
    spec = DORMERS.get(key)
    if spec:
        for cx, facing, lit in spec["at"]:
            front_y = (y0 + spec["set_back"]) if facing < 0 else (y1 - spec["set_back"])
            base_z = height(cx, front_y)
            sill = base_z + spec["sill"]
            d_eave = sill + spec["wall"]
            frame, o = kit.dormer(mesh, cx, front_y, spec["width"], sill, d_eave + 0.16, d_eave + 0.16 + spec["rise"], height, facing)
            shade = "room_glow_dim" if lit > 0.05 else "blind"
            mesh.face([frame.at(o[0] - 0.05, -0.12, o[2] - 0.05), frame.at(o[1] + 0.05, -0.12, o[2] - 0.05),
                       frame.at(o[1] + 0.05, -0.12, o[3] + 0.05), frame.at(o[0] - 0.05, -0.12, o[3] + 0.05)],
                      "blind" if lit > 0.05 else "room_dark")
            if lit > 0.05:
                mesh.face([frame.at(o[0], -0.3, o[2]), frame.at(o[1], -0.3, o[2]), frame.at(o[1], -0.3, o[3]), frame.at(o[0], -0.3, o[3])], shade)
    obj = mesh.build(collection, materials)
    return obj, height, frames


def _spans(length, gaps):
    """Ranges of 0..length left after removing the given openings."""
    cuts = sorted((max(0.0, g[0] - 0.12), min(length, g[1] + 0.12)) for g in gaps)
    out, at = [], 0.0
    for a, b in cuts:
        if a > at:
            out.append((at, a))
        at = max(at, b)
    if at < length:
        out.append((at, length))
    return out


def portico(collection, materials, lights):
    """The front entrance: stone landing and steps, four columns, a pediment."""
    p = plan.PORTICO
    x0, x1 = p["x"]
    y0 = -p["z"][1]
    floor, top = p["floor"], p["eave"]
    mesh = Mesh("portico")
    mesh.box((x0, y0, -0.3), (x1, 0.0, floor - 0.06), "stone")
    mesh.box((x0 - 0.05, y0 - 0.05, floor - 0.06), (x1 + 0.05, 0.0, floor), "stone_cap")
    for i in range(3):
        z = floor - 0.19 * (i + 1)
        mesh.box((-1.75 - 0.0, y0 - 0.33 * (i + 1), -0.3), (1.75, y0 - 0.33 * i, z - 0.05), "stone")
        mesh.box((-1.8, y0 - 0.33 * (i + 1) - 0.03, z - 0.05), (1.8, y0 - 0.33 * i, z), "stone_cap")
    column_y = y0 + 0.28
    for x in (x0 + 0.3, -0.98, 0.98, x1 - 0.3):
        kit.column(mesh, x, column_y, floor, top - 0.42, 0.15)
    for x in (x0 + 0.3, x1 - 0.3):
        mesh.box((x - 0.17, -0.07, floor), (x + 0.17, 0.0, top - 0.42), "trim")
    # Entablature on three sides, then a low pediment.
    for lo, hi in (((x0, y0, top - 0.42), (x1, y0 + 0.5, top)), ((x0, y0, top - 0.42), (x0 + 0.5, 0.0, top)),
                   ((x1 - 0.5, y0, top - 0.42), (x1, 0.0, top))):
        mesh.box(lo, hi, "trim")
    mesh.box((x0 - 0.1, y0 - 0.1, top), (x1 + 0.1, 0.0, top + 0.09), "trim")
    mesh.face([(x0 + 0.5, y0 + 0.5, top - 0.41), (x1 - 0.5, y0 + 0.5, top - 0.41), (x1 - 0.5, 0.0, top - 0.41), (x0 + 0.5, 0.0, top - 0.41)][::-1], "trim")
    kit.gable_roof(mesh, x0 - 0.1, x1 + 0.1, y0 - 0.1, 0.4, top + 0.09, p["ridge"], "y", eave_over=0.1, rake_over=0.06, thick=0.1)
    mesh.face([(x0 - 0.1, y0 - 0.1, top + 0.09), (x1 + 0.1, y0 - 0.1, top + 0.09), (0.0, y0 - 0.1, p["ridge"])], "trim")
    # Hanging lantern under the portico.
    cx, cy, cz = 0.0, y0 + 1.35, top - 0.42
    mesh.cylinder((cx, cy, cz), (cx, cy, cz - 0.35), 0.008, 0.008, "iron", 8)
    for dx in (-0.09, 0.09):
        for dy in (-0.09, 0.09):
            mesh.box((cx + dx - 0.007, cy + dy - 0.007, cz - 0.72), (cx + dx + 0.007, cy + dy + 0.007, cz - 0.38), "iron")
    mesh.box((cx - 0.11, cy - 0.11, cz - 0.39), (cx + 0.11, cy + 0.11, cz - 0.35), "iron")
    mesh.box((cx - 0.1, cy - 0.1, cz - 0.74), (cx + 0.1, cy + 0.1, cz - 0.72), "iron")
    mesh.sphere((cx, cy, cz - 0.56), 0.035, "lamp_warm", 10, 6)
    lights.append(("portico pendant", (cx, cy, cz - 0.56), 2.6, "warm", 0.04))
    mesh.build(collection, materials)


def chimneys(collection, materials):
    mesh = Mesh("chimneys")
    x0, x1, y0, y1, b = bounds("main")
    mid = (y0 + y1) / 2
    for x in (x0 + 1.15, x1 - 1.15):
        kit.chimney(mesh, x, mid, 1.0, 1.5, b["ridge"] - 2.6, b["ridge"] + 1.5)
        mesh.box((x - 0.56, mid - 0.82, b["ridge"] - 1.0), (x + 0.56, mid + 0.82, b["ridge"] - 0.6), "gutter")
    # A fieldstone chimney on the east wing's gable end.
    ex0, ex1, ey0, ey1, eb = bounds("east_wing")
    cy = (ey0 + ey1) / 2
    mesh.box((ex1 - 0.05, cy - 0.95, -0.3), (ex1 + 0.62, cy + 0.95, 3.6), "stone")
    mesh.box((ex1 - 0.05, cy - 0.6, 3.6), (ex1 + 0.62, cy + 0.6, eb["ridge"] + 0.9), "stone")
    mesh.face([(ex1 + 0.62, cy - 0.95, 3.6), (ex1 + 0.62, cy - 0.6, 4.2), (ex1 - 0.05, cy - 0.6, 4.2), (ex1 - 0.05, cy - 0.95, 3.6)], "stone")
    mesh.face([(ex1 + 0.62, cy + 0.6, 4.2), (ex1 + 0.62, cy + 0.95, 3.6), (ex1 - 0.05, cy + 0.95, 3.6), (ex1 - 0.05, cy + 0.6, 4.2)], "stone")
    mesh.box((ex1 - 0.1, cy - 0.66, eb["ridge"] + 0.9), (ex1 + 0.68, cy + 0.66, eb["ridge"] + 0.98), "stone_cap")
    mesh.cylinder((ex1 + 0.28, cy, eb["ridge"] + 0.98), (ex1 + 0.28, cy, eb["ridge"] + 1.4), 0.13, 0.105, "clay", 14)
    mesh.build(collection, materials)


def sunroom(collection, materials, lights):
    """A glazed garden room: a low clapboard wall under tall divided lights."""
    x0, x1, y0, y1, b = bounds("sunroom")
    eave, ridge = b["eave"], b["ridge"]
    mesh = Mesh("sunroom")
    frames = {"e": facade(x1, y0, x1, y1), "n": facade(x1, y1, x0, y1), "w": facade(x0, y1, x0, y0)}
    knee, head = FFL + 0.5, eave - 0.28
    for side, (frame, length) in frames.items():
        kit.wall(mesh, frame, length, FOUND + 0.1, knee, [], "siding")
        mesh.fbox(frame, (-0.03, length + 0.03), (-0.2, 0.035), (-0.4, FOUND), "stone")
        mesh.fbox(frame, (0, length), (0.0, 0.05), (FOUND, FOUND + 0.1), "trim")
        mesh.fbox(frame, (-0.03, length + 0.03), (-0.12, 0.07), (knee, knee + 0.05), "trim")
        mesh.fbox(frame, (-0.03, length + 0.03), (-0.14, 0.03), (head, eave), "trim")
        bays = max(2, round(length / 1.25))
        step = length / bays
        door_bay = bays // 2 if side in ("w", "n") else None
        for i in range(bays + 1):
            u = i * step
            mesh.fbox(frame, (u - 0.06, u + 0.06), (-0.12, 0.03), (knee + 0.05, head), "trim")
        for i in range(bays):
            a, c = i * step + 0.06, (i + 1) * step - 0.06
            if i == door_bay:
                kit.glazing(mesh, frame, (a, c), (FFL, head - 0.5), -0.05, 2, 5, stile=0.08, rail=0.09, bottom_rail=0.22, thick=0.045)
                mesh.fbox(frame, (a, c), (-0.14, 0.05), (FFL - 0.05, FFL), "stone_cap")
                mesh.sphere(frame.at(c - 0.05, 0.0, FFL + 1.0), 0.028, "brass", 10, 6)
            else:
                kit.glazing(mesh, frame, (a, c), (knee + 0.05, head - 0.5), -0.05, 2, 3, stile=0.045, rail=0.05)
            mesh.fbox(frame, (a, c), (-0.1, 0.0), (head - 0.5, head - 0.44), "trim")
            kit.glazing(mesh, frame, (a, c), (head - 0.44, head), -0.05, 2, 1, stile=0.045, rail=0.045)
    kit.gable_roof(mesh, x0, x1, y0, y1, eave, ridge, "y", eave_over=0.3, rake_over=0.22, thick=0.12, mat="metal_roof")
    mesh.face([(x0, y1, eave), (x1, y1, eave), ((x0 + x1) / 2, y1, ridge)][::-1], "trim")
    # Interior: floor, a lit ceiling and the back wall.
    mesh.face([(x0, y0, FFL), (x1, y0, FFL), (x1, y1, FFL), (x0, y1, FFL)], "room_floor")
    mesh.face([(x0, y0, eave - 0.05), (x0, y1, eave - 0.05), (x1, y1, eave - 0.05), (x1, y0, eave - 0.05)], "room_wall")
    mesh.face([(x0, y0 + 0.02, FFL), (x0, y0 + 0.02, eave), (x1, y0 + 0.02, eave), (x1, y0 + 0.02, FFL)], "room_wall")
    lights.append(("sunroom lamp", ((x0 + x1) / 2 + 1.0, (y0 + y1) / 2, FFL + 1.5), 14.0, "warm", 0.12))
    mesh.build(collection, materials)


def cupola(collection, materials):
    """A louvred cupola with a copper cap on the garage ridge."""
    x0, x1, y0, y1, b = bounds("garage")
    cx, cy, z = (x0 + x1) / 2, (y0 + y1) / 2, b["ridge"]
    mesh = Mesh("cupola")
    s = 0.55
    mesh.box((cx - s - 0.08, cy - s - 0.08, z - 0.5), (cx + s + 0.08, cy + s + 0.08, z + 0.1), "trim")
    mesh.box((cx - s, cy - s, z + 0.1), (cx + s, cy + s, z + 1.05), "trim")
    for frame, length in (facade(cx - s, cy - s, cx + s, cy - s), facade(cx + s, cy - s, cx + s, cy + s),
                          facade(cx + s, cy + s, cx - s, cy + s), facade(cx - s, cy + s, cx - s, cy - s)):
        kit.shutter(mesh, frame, (0.14, length - 0.14), (z + 0.2, z + 0.95))
    mesh.box((cx - s - 0.12, cy - s - 0.12, z + 1.05), (cx + s + 0.12, cy + s + 0.12, z + 1.13), "trim")
    apex = (cx, cy, z + 1.75)
    ring = [(cx - s - 0.12, cy - s - 0.12, z + 1.13), (cx + s + 0.12, cy - s - 0.12, z + 1.13),
            (cx + s + 0.12, cy + s + 0.12, z + 1.13), (cx - s - 0.12, cy + s + 0.12, z + 1.13)]
    for i in range(4):
        mesh.face([ring[i], ring[(i + 1) % 4], apex], "copper")
    mesh.cylinder(apex, (cx, cy, z + 2.4), 0.012, 0.008, "iron", 8)
    mesh.sphere((cx, cy, z + 1.95), 0.06, "copper", 12, 8)
    mesh.box((cx - 0.28, cy - 0.004, z + 2.2), (cx + 0.28, cy + 0.004, z + 2.23), "iron")
    mesh.face([(cx + 0.28, cy, z + 2.31), (cx + 0.12, cy, z + 2.215), (cx + 0.28, cy, z + 2.12)], "iron")
    mesh.build(collection, materials)


def wall_lanterns(collection, materials, frames_by_block, lights):
    """Lanterns beside the doors and between the garage bays."""
    mesh = Mesh("lanterns")
    spots = [("main", "s", 6.95, 2.25, 1.0), ("main", "s", 9.85, 2.25, 1.0),
             ("main", "n", 3.95, 2.3, 0.9), ("main", "n", 7.2, 2.3, 0.9), ("main", "n", 10.45, 2.3, 0.9),
             ("garage", "s", 4.05, 2.45, 1.0), ("garage", "s", 7.75, 2.45, 1.0), ("garage", "s", 0.55, 2.45, 1.0),
             ("garage", "s", 11.25, 2.45, 1.0), ("connector", "s", 2.35, 2.2, 0.85),
             ("east_wing", "e", 5.6, 2.2, 0.85), ("garage", "w", 2.45, 2.2, 0.85), ("pool_house", "w", 0.9, 2.1, 0.85),
             ("pool_house", "w", 3.9, 2.1, 0.85)]
    for key, side, u, z, scale in spots:
        frame, _ = frames_by_block[key][side]
        lamp = kit.lantern(mesh, frame, u, z, scale)
        lights.append((f"lantern {key} {side} {u}", tuple(lamp), 1.8 * scale, "warm", 0.03))
    mesh.build(collection, materials)


def build(collection, materials):
    """Build every building. Returns roof height functions, facade frames and light specs."""
    lights, heights, frames = [], {}, {}
    for key in ("main", "east_wing", "connector", "garage", "pool_house", "shed", *plan.NEIGHBOURS):
        _, heights[key], frames[key] = block(collection, materials, key, lights)
    portico(collection, materials, lights)
    chimneys(collection, materials)
    sunroom(collection, materials, lights)
    cupola(collection, materials)
    wall_lanterns(collection, materials, frames, lights)
    return heights, frames, lights
