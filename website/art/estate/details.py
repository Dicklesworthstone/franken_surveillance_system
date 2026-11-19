"""Alder House: the small things that make a place look lived in. Runs inside Blender.

Camera posts, roof vents and skylights, a doorbell, door mats, a grill, pool
loungers and rails, a firewood stack, a basement hatch, window boxes and the
floodlight fixtures.
"""
import math
import random

from mathutils import Vector

import house
import kit
import plan
from kit import Mesh

rng = random.Random(41)


def camera_posts(mesh):
    """Posts for the cameras the plan mounts on one, and a lamp head where it says lamp post."""
    lamps = []
    for cam in plan.CAMERAS:
        mount = cam.get("mount", "")
        if "post" not in mount:
            continue
        x, up, z = cam["position"]
        y = -z
        lx, _, lz = cam["look_at"]
        back = Vector((lx - x, -(lz - z))).normalized() * -0.12
        px, py = x + back.x, y + back.y
        if "lamp" in mount:
            top = up + 0.55
            mesh.cylinder((px, py, 0.0), (px, py, 0.35), 0.075, 0.055, "iron", 14)
            mesh.cylinder((px, py, 0.35), (px, py, top), 0.04, 0.032, "iron", 12)
            mesh.box((px - 0.12, py - 0.12, top), (px + 0.12, py + 0.12, top + 0.02), "iron")
            for dx in (-0.1, 0.1):
                for dy in (-0.1, 0.1):
                    mesh.box((px + dx - 0.007, py + dy - 0.007, top + 0.02), (px + dx + 0.007, py + dy + 0.007, top + 0.36), "iron")
            for a, b in (((-0.1, -0.1), (0.1, -0.1)), ((0.1, -0.1), (0.1, 0.1)), ((0.1, 0.1), (-0.1, 0.1)), ((-0.1, 0.1), (-0.1, -0.1))):
                mesh.face([(px + a[0], py + a[1], top + 0.02), (px + b[0], py + b[1], top + 0.02),
                           (px + b[0], py + b[1], top + 0.36), (px + a[0], py + a[1], top + 0.36)], "lantern_glass")
            mesh.box((px - 0.14, py - 0.14, top + 0.36), (px + 0.14, py + 0.14, top + 0.375), "iron")
            apex = (px, py, top + 0.5)
            ring = [(px - 0.14, py - 0.14, top + 0.375), (px + 0.14, py - 0.14, top + 0.375),
                    (px + 0.14, py + 0.14, top + 0.375), (px - 0.14, py + 0.14, top + 0.375)]
            for i in range(4):
                mesh.face([ring[i], ring[(i + 1) % 4], apex], "iron")
            mesh.sphere((px, py, top + 0.18), 0.03, "lamp_warm", 10, 6)
            lamps.append((px, py, top + 0.18))
        else:
            height = up + 0.12
            mesh.cylinder((px, py, 0.0), (px, py, height), 0.035 if height < 1.6 else 0.045, 0.03, "iron", 12)
            mesh.box((px - 0.05, py - 0.05, height), (px + 0.05, py + 0.05, height + 0.02), "iron")
    return lamps


def roof_fittings(mesh, heights):
    main = heights["main"]
    for x, y in ((-2.2, 8.7), (4.4, 8.9), (-5.8, 8.0)):
        z = main(x, y)
        mesh.cylinder((x, y, z - 0.05), (x, y, z + 0.38), 0.04, 0.04, "plastic_dark", 10)
        mesh.cylinder((x, y, z - 0.02), (x, y, z + 0.03), 0.09, 0.05, "gutter", 12)
    # Two skylights on the connector's rear slope.
    conn = heights["connector"]
    x0, x1, y0, y1, _ = house.bounds("connector")
    for cx in (x0 + 1.5, x1 - 1.5):
        ya, yb = y1 - 2.3, y1 - 1.2
        for grow, lift, mat in ((0.07, 0.05, "iron"), (0.0, 0.075, "glass")):
            mesh.face([(cx - 0.42 - grow, yb + grow, conn(cx, yb + grow) + lift), (cx + 0.42 + grow, yb + grow, conn(cx, yb + grow) + lift),
                       (cx + 0.42 + grow, ya - grow, conn(cx, ya - grow) + lift), (cx - 0.42 - grow, ya - grow, conn(cx, ya - grow) + lift)][::-1], mat)


def entrance(mesh):
    """Doorbell camera, house number and mats."""
    z = plan.FIRST_FLOOR
    mesh.box((1.02, -0.075, z + 1.12), (1.07, -0.05, z + 1.26), "plastic_dark")
    mesh.cylinder((1.045, -0.075, z + 1.225), (1.045, -0.082, z + 1.225), 0.013, 0.013, "glass", 12)
    mesh.cylinder((1.045, -0.075, z + 1.155), (1.045, -0.08, z + 1.155), 0.014, 0.014, "lamp_cool", 12)
    floor = plan.PORTICO["floor"]
    mesh.box((-0.5, -0.82, floor), (0.5, -0.22, floor + 0.014), "rubber")
    t = plan.TERRACE["level"]
    for x in (3.2, -0.8):
        mesh.box((x - 0.55, 10.95, t), (x + 0.55, 11.5, t + 0.014), "rubber")


def grill(mesh):
    t = plan.TERRACE["level"]
    x, y = 8.6, 11.6
    for dx in (-0.5, 0.5):
        for dy in (-0.24, 0.24):
            mesh.box((x + dx - 0.02, y + dy - 0.02, t), (x + dx + 0.02, y + dy + 0.02, t + 0.62), "iron")
    mesh.box((x - 0.55, y - 0.28, t + 0.2), (x + 0.55, y + 0.28, t + 0.23), "iron")
    mesh.box((x - 0.55, y - 0.3, t + 0.62), (x + 0.55, y + 0.3, t + 0.9), "steel")
    mesh.cylinder((x - 0.52, y, t + 0.9), (x + 0.52, y, t + 0.9), 0.3, 0.3, "plastic_dark", 18)
    mesh.cylinder((x - 0.3, y - 0.34, t + 1.0), (x + 0.3, y - 0.34, t + 1.0), 0.014, 0.014, "steel", 8)
    for dx in (-0.88, 0.58):
        mesh.box((x + dx, y - 0.26, t + 0.84), (x + dx + 0.3, y + 0.26, t + 0.87), "steel")


def lounger(mesh, x, y, angle):
    """A teak chaise with a cushion, raised at the head end."""
    c, s = math.cos(angle), math.sin(angle)
    at = lambda u, v, z: (x + u * c - v * s, y + u * s + v * c, z)
    def slab(u0, u1, v0, v1, z0, z1, mat, z0b=None, z1b=None):
        z0b = z0 if z0b is None else z0b
        z1b = z1 if z1b is None else z1b
        low = [at(u0, v0, z0), at(u1, v0, z0), at(u1, v1, z0b), at(u0, v1, z0b)]
        high = [at(u0, v0, z1), at(u1, v0, z1), at(u1, v1, z1b), at(u0, v1, z1b)]
        mesh.face(high, mat)
        mesh.face(low[::-1], mat)
        for i in range(4):
            j = (i + 1) % 4
            mesh.face([low[i], low[j], high[j], high[i]], mat)
    for u in (-0.3, 0.3):
        for v in (-0.85, 0.2):
            slab(u - 0.025, u + 0.025, v - 0.025, v + 0.025, 0.04, 0.3, "wood_fence")
    slab(-0.33, 0.33, -0.95, 0.3, 0.3, 0.335, "wood_fence")
    slab(-0.33, 0.33, 0.3, 0.95, 0.3, 0.335, "wood_fence", 0.72, 0.755)
    slab(-0.3, 0.3, -0.93, 0.3, 0.335, 0.4, "cushion")
    slab(-0.3, 0.3, 0.3, 0.93, 0.335, 0.4, "cushion", 0.755, 0.82)


def poolside(mesh):
    p = plan.POOL
    x0, x1, y0, y1 = p["x"][0], p["x"][1], -p["z"][1], -p["z"][0]
    for i in range(4):
        lounger(mesh, x0 + 1.4 + i * 2.6, y0 - 1.55, math.pi)
    # Grab rails at the steps.
    for dx in (0.0, 0.55):
        x = x0 + 1.0 + dx
        mesh.cylinder((x, y1 + 0.2, 0.07), (x, y1 + 0.2, 0.92), 0.019, 0.019, "steel", 10)
        mesh.cylinder((x, y1 + 0.2, 0.92), (x, y1 - 0.4, 0.92), 0.019, 0.019, "steel", 10)
        mesh.cylinder((x, y1 - 0.4, 0.92), (x, y1 - 0.4, -0.5), 0.019, 0.019, "steel", 10)


def firewood(mesh):
    """A stacked cord of logs under a rack against the garage's north wall."""
    x0, x1, y0, y1, _ = house.bounds("garage")
    left, wall = x0 + 4.2, y1 + 0.08
    for end in (left - 0.06, left + 2.3):
        mesh.box((end, wall, 0.0), (end + 0.06, wall + 0.5, 1.25), "iron")
    mesh.box((left - 0.06, wall, 0.06), (left + 2.36, wall + 0.5, 0.1), "iron")
    z = 0.1
    row = 0
    while z < 1.05:
        x = left + (0.06 if row % 2 else 0.0)
        tallest = 0.0
        while x < left + 2.22:
            r = rng.uniform(0.055, 0.095)
            mesh.cylinder((x + r, wall + 0.03 + rng.uniform(0, 0.04), z + r), (x + r, wall + 0.45 + rng.uniform(-0.03, 0.03), z + r), r, r * rng.uniform(0.9, 1.0), "wood_fence", 9)
            x += 2 * r + 0.006
            tallest = max(tallest, 2 * r)
        z += tallest * 0.9
        row += 1


def hatch(mesh):
    """Sloped steel doors over the basement steps, behind the garage."""
    x0, x1, y0, y1, _ = house.bounds("garage")
    a, b, wall = x1 - 3.0, x1 - 1.5, y1
    mesh.box((a - 0.1, wall, -0.1), (a, wall + 1.6, 0.2), "concrete")
    mesh.box((b, wall, -0.1), (b + 0.1, wall + 1.6, 0.2), "concrete")
    mesh.box((a - 0.1, wall + 1.6, -0.1), (b + 0.1, wall + 1.7, 0.2), "concrete")
    mid = (a + b) / 2
    for lo, hi in ((a, mid - 0.01), (mid + 0.01, b)):
        mesh.face([(lo, wall + 1.62, 0.22), (hi, wall + 1.62, 0.22), (hi, wall + 0.02, 0.82), (lo, wall + 0.02, 0.82)], "shutter")
    for x in (a, b):
        mesh.face([(x, wall, 0.2), (x, wall + 1.6, 0.2), (x, wall, 0.82)], "shutter")
    mesh.box((mid - 0.12, wall + 0.9, 0.5), (mid + 0.12, wall + 0.93, 0.56), "iron")


def window_boxes(mesh, place, col):
    """Planted boxes under the east wing's front windows."""
    x0, x1, y0, y1, _ = house.bounds("east_wing")
    sill = house.F1_SILL
    for u in (2.2, 5.6):
        cx = x0 + u
        mesh.box((cx - 0.62, y0 - 0.25, sill - 0.36), (cx + 0.62, y0 - 0.045, sill - 0.15), "shutter")
        for bracket in (-0.45, 0.45):
            mesh.box((cx + bracket - 0.015, y0 - 0.2, sill - 0.5), (cx + bracket + 0.015, y0 - 0.02, sill - 0.36), "iron")
        for i in range(6):
            place(col, "shrub_01", cx - 0.5 + i * 0.2, y0 - 0.15, z=sill - 0.17, rot=rng.uniform(0, math.tau),
                  scale=rng.uniform(0.75, 1.0), pattern=r"^shrub_01_%s_LOD1$" % rng.choice("abcdef"))


def build(col, mats, heights, place, add_light, light_col, floods):
    mesh = Mesh("details")
    for lamp in camera_posts(mesh):
        add_light(light_col, "entry lamp post", lamp, 7.0, "warm", 0.035)
    roof_fittings(mesh, heights)
    entrance(mesh)
    grill(mesh)
    poolside(mesh)
    firewood(mesh)
    hatch(mesh)
    window_boxes(mesh, place, col)
    mesh.build(col, mats)
    for name, (location, target) in floods.items():
        heading = math.atan2(target[1] - location[1], target[0] - location[0])
        place(col, "security_light", location[0], location[1], z=location[2] + 0.1, rot=heading + math.pi / 2, ground=False, name="fixture_" + name)
