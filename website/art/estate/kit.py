"""Mesh construction kit for the Alder House builder. Runs inside Blender.

Everything is built in Blender's frame: +X east, +Y north, +Z up, metres.
The site plan's +z (south) is Blender's -Y.

A `Mesh` collects quads with one material name per face and UVs measured in
metres, so every texture tiles at real scale. `wall()` builds a facade with
window and door openings and real lapped clapboards. The part builders
(`window`, `door`, `lantern`, ...) take a `Frame`, which places a local
(along-wall, outward, up) coordinate system on a facade.
"""
import math

import bmesh
import bpy
from mathutils import Vector

CLAP = 0.108  # exposed clapboard height
LAP = 0.013  # how far a board's lower edge stands proud


class Mesh:
    """Accumulates faces, then becomes one Blender object."""

    def __init__(self, name):
        self.name = name
        self.verts = []
        self.faces = []  # (vertex indices, material name, uvs, smooth)
        self.materials = []

    def face(self, points, mat, uvs=None, smooth=False):
        base = len(self.verts)
        self.verts.extend(Vector(p) for p in points)
        if mat not in self.materials:
            self.materials.append(mat)
        if uvs is None:
            uvs = planar_uv(points)
        self.faces.append((list(range(base, base + len(points))), mat, uvs, smooth))

    def box(self, lo, hi, mat):
        """Axis-aligned box from two corners."""
        x0, y0, z0 = (min(a, b) for a, b in zip(lo, hi))
        x1, y1, z1 = (max(a, b) for a, b in zip(lo, hi))
        self.face([(x0, y0, z0), (x1, y0, z0), (x1, y0, z1), (x0, y0, z1)], mat)
        self.face([(x1, y1, z0), (x0, y1, z0), (x0, y1, z1), (x1, y1, z1)], mat)
        self.face([(x0, y1, z0), (x0, y0, z0), (x0, y0, z1), (x0, y1, z1)], mat)
        self.face([(x1, y0, z0), (x1, y1, z0), (x1, y1, z1), (x1, y0, z1)], mat)
        self.face([(x0, y0, z1), (x1, y0, z1), (x1, y1, z1), (x0, y1, z1)], mat)
        self.face([(x0, y1, z0), (x1, y1, z0), (x1, y0, z0), (x0, y0, z0)], mat)

    def fbox(self, frame, u, n, z, mat):
        """Box in a facade frame: u, n and z are (lo, hi) ranges."""
        corners = [frame.at(uu, nn, zz) for uu in u for nn in n for zz in z]
        c = lambda i, j, k: corners[i * 4 + j * 2 + k]
        quads = [
            [c(0, 1, 0), c(1, 1, 0), c(1, 1, 1), c(0, 1, 1)],  # outward face
            [c(1, 0, 0), c(0, 0, 0), c(0, 0, 1), c(1, 0, 1)],
            [c(0, 0, 0), c(0, 1, 0), c(0, 1, 1), c(0, 0, 1)],
            [c(1, 1, 0), c(1, 0, 0), c(1, 0, 1), c(1, 1, 1)],
            [c(0, 1, 1), c(1, 1, 1), c(1, 0, 1), c(0, 0, 1)],
            [c(0, 0, 0), c(1, 0, 0), c(1, 1, 0), c(0, 1, 0)],
        ]
        for q in quads:
            self.face(q, mat)

    def cylinder(self, base, top, r0, r1, mat, segments=20, caps=True, smooth=True):
        """Tapered cylinder between two points."""
        base, top = Vector(base), Vector(top)
        axis = (top - base).normalized()
        side = axis.orthogonal().normalized()
        other = axis.cross(side)
        ring = lambda centre, r: [centre + r * (math.cos(a) * side + math.sin(a) * other)
                                  for a in (2 * math.pi * i / segments for i in range(segments))]
        a, b = ring(base, r0), ring(top, r1)
        length = (top - base).length
        for i in range(segments):
            j = (i + 1) % segments
            u0, u1 = i / segments * 2 * math.pi * r0, (i + 1) / segments * 2 * math.pi * r0
            self.face([a[i], a[j], b[j], b[i]], mat, [(u0, 0), (u1, 0), (u1, length), (u0, length)], smooth)
        if caps:
            self.face(list(reversed(a)), mat)
            self.face(b, mat)

    def sphere(self, centre, radius, mat, segments=14, rings=8):
        centre = Vector(centre)
        point = lambda i, j: centre + radius * Vector((
            math.sin(math.pi * j / rings) * math.cos(2 * math.pi * i / segments),
            math.sin(math.pi * j / rings) * math.sin(2 * math.pi * i / segments),
            math.cos(math.pi * j / rings)))
        for j in range(rings):
            for i in range(segments):
                q = [point(i, j + 1), point(i + 1, j + 1), point(i + 1, j), point(i, j)]
                if j == 0:
                    q = q[:3]
                elif j == rings - 1:
                    q = [q[0], q[2], q[3]]
                self.face(q, mat, smooth=True)

    def extrude(self, profile, start, end, up, mat, closed=True):
        """Sweep a 2D profile of (out, up) pairs along a straight line.

        `up` is the profile's vertical axis; its horizontal axis is
        perpendicular to the line and to `up`.
        """
        start, end, up = Vector(start), Vector(end), Vector(up).normalized()
        along = (end - start).normalized()
        out = along.cross(up).normalized()
        a = [start + p[0] * out + p[1] * up for p in profile]
        b = [end + p[0] * out + p[1] * up for p in profile]
        count = len(profile)
        for i in range(count if closed else count - 1):
            j = (i + 1) % count
            self.face([a[i], a[j], b[j], b[i]], mat)
        if closed:
            self.face(list(reversed(a)), mat)
            self.face(b, mat)

    def build(self, collection, materials):
        mesh = bpy.data.meshes.new(self.name)
        bm = bmesh.new()
        uv_layer = bm.loops.layers.uv.new("UVMap")
        slots = {name: i for i, name in enumerate(self.materials)}
        verts = [bm.verts.new(v) for v in self.verts]
        for indices, mat, uvs, smooth in self.faces:
            try:
                face = bm.faces.new([verts[i] for i in indices])
            except ValueError:
                continue
            face.material_index = slots[mat]
            face.smooth = smooth
            for loop, uv in zip(face.loops, uvs):
                loop[uv_layer].uv = uv
        bmesh.ops.remove_doubles(bm, verts=bm.verts, dist=0.0004)
        bm.normal_update()
        bm.to_mesh(mesh)
        bm.free()
        for name in self.materials:
            mesh.materials.append(materials[name])
        obj = bpy.data.objects.new(self.name, mesh)
        collection.objects.link(obj)
        return obj


def planar_uv(points):
    """UVs in metres from the face's own plane, with v as close to up as it can be."""
    pts = [Vector(p) for p in points]
    normal = (pts[1] - pts[0]).cross(pts[-1] - pts[0])
    if normal.length < 1e-12:
        return [(0, 0)] * len(pts)
    normal.normalize()
    up = Vector((0, 0, 1))
    if abs(normal.z) > 0.95:
        u_axis, v_axis = Vector((1, 0, 0)), Vector((0, 1, 0))
    else:
        u_axis = up.cross(normal).normalized()
        v_axis = normal.cross(u_axis)
    return [(p.dot(u_axis), p.dot(v_axis)) for p in pts]


class Frame:
    """A facade coordinate system: u along the wall, n outward, z up."""

    def __init__(self, origin, u_dir, normal):
        self.origin = Vector(origin)
        self.u = Vector(u_dir).normalized()
        self.n = Vector(normal).normalized()

    def at(self, u, n, z):
        return self.origin + u * self.u + n * self.n + Vector((0, 0, z))

    def shifted(self, u=0.0, n=0.0, z=0.0):
        return Frame(self.at(u, n, z), self.u, self.n)


def facade(x0, y0, x1, y1):
    """Frame for a wall running from (x0, y0) to (x1, y1), outward to its right."""
    u = Vector((x1 - x0, y1 - y0, 0))
    length = u.length
    u.normalize()
    return Frame((x0, y0, 0), u, (u.y, -u.x, 0)), length


def clap_offset(z, base):
    """How far the clapboard face stands out at height z."""
    t = ((z - base) / CLAP) % 1.0
    return LAP * (1.0 - t)


def wall(mesh, frame, length, z0, z1, openings, mat, clapboard=True, gable=None, returns=0.14):
    """A facade with rectangular openings.

    openings: (u0, u1, z0, z1) holes. gable: (peak_u, peak_z) adds a triangular
    top above z1 whose slopes run from the wall ends up to the peak.
    """
    def band_lines(lo, hi):
        lines = {lo, hi}
        if clapboard:
            k = math.ceil((lo - z0) / CLAP - 1e-9)
            while z0 + k * CLAP < hi - 1e-6:
                if z0 + k * CLAP > lo + 1e-6:
                    lines.add(z0 + k * CLAP)
                k += 1
        for _, _, a, b in openings:
            for v in (a, b):
                if lo + 1e-6 < v < hi - 1e-6:
                    lines.add(v)
        return sorted(lines)

    def off(z, top):
        if not clapboard:
            return 0.0
        value = clap_offset(z, z0)
        # The top edge of a band belongs to the board below it.
        return 0.0 if top and value > LAP - 1e-6 else value

    def emit(u_a, u_b, z_a, z_b, ua_top=None, ub_top=None):
        ua_top = u_a if ua_top is None else ua_top
        ub_top = u_b if ub_top is None else ub_top
        pts = [frame.at(u_a, off(z_a, False), z_a), frame.at(u_b, off(z_a, False), z_a),
               frame.at(ub_top, off(z_b, True), z_b), frame.at(ua_top, off(z_b, True), z_b)]
        uvs = [(u_a, z_a), (u_b, z_a), (ub_top, z_b), (ua_top, z_b)]
        mesh.face(pts, mat, uvs)
        if clapboard and abs(clap_offset(z_a, z0) - LAP) < 1e-6:
            # The underside of the board, where it laps the one below.
            mesh.face([frame.at(u_a, 0, z_a), frame.at(u_b, 0, z_a),
                       frame.at(u_b, LAP, z_a), frame.at(u_a, LAP, z_a)], mat)

    inside = lambda u, z: any(a < u < b and c < z < d for a, b, c, d in openings)
    u_edges = sorted({0.0, length} | {v for o in openings for v in o[:2] if 0 < v < length})
    zs = band_lines(z0, z1)
    for z_a, z_b in zip(zs, zs[1:]):
        for u_a, u_b in zip(u_edges, u_edges[1:]):
            if not inside((u_a + u_b) / 2, (z_a + z_b) / 2):
                emit(u_a, u_b, z_a, z_b)
    if gable:
        peak_u, peak_z = gable
        left = lambda z: peak_u * (z - z1) / (peak_z - z1)
        right = lambda z: length - (length - peak_u) * (z - z1) / (peak_z - z1)
        zs = band_lines(z1, peak_z)
        for z_a, z_b in zip(zs, zs[1:]):
            inner = sorted({left(z_b), right(z_b)} | {v for o in openings for v in o[:2]
                                                      if left(z_b) < v < right(z_b)})
            if inner[0] >= inner[-1] - 1e-6:
                emit(left(z_a), right(z_a), z_a, z_b, peak_u, peak_u)
                continue
            emit(left(z_a), inner[0], z_a, z_b, left(z_b), inner[0])
            for u_a, u_b in zip(inner, inner[1:]):
                if not inside((u_a + u_b) / 2, (z_a + z_b) / 2):
                    emit(u_a, u_b, z_a, z_b)
            emit(inner[-1], right(z_a), z_a, z_b, inner[-1], right(z_b))
    for u_a, u_b, z_a, z_b in openings:
        # Reveals: the wall's thickness seen inside each opening.
        r = -returns
        mesh.face([frame.at(u_a, 0, z_a), frame.at(u_a, r, z_a), frame.at(u_a, r, z_b), frame.at(u_a, 0, z_b)], "trim")
        mesh.face([frame.at(u_b, r, z_a), frame.at(u_b, 0, z_a), frame.at(u_b, 0, z_b), frame.at(u_b, r, z_b)], "trim")
        mesh.face([frame.at(u_a, r, z_b), frame.at(u_b, r, z_b), frame.at(u_b, 0, z_b), frame.at(u_a, 0, z_b)], "trim")
        mesh.face([frame.at(u_a, 0, z_a), frame.at(u_b, 0, z_a), frame.at(u_b, r, z_a), frame.at(u_a, r, z_a)], "trim")


def glazing(mesh, frame, u, z, depth, cols, rows, stile=0.05, rail=0.05, bottom_rail=None, muntin=0.021,
            thick=0.036, mat="sash", glass="glass"):
    """One glazed sash or door leaf: frame, muntin grid and a pane of glass."""
    u0, u1 = u
    z0, z1 = z
    bottom_rail = rail if bottom_rail is None else bottom_rail
    n = (depth - thick, depth)
    mesh.fbox(frame, (u0, u0 + stile), n, (z0, z1), mat)
    mesh.fbox(frame, (u1 - stile, u1), n, (z0, z1), mat)
    mesh.fbox(frame, (u0 + stile, u1 - stile), n, (z0, z0 + bottom_rail), mat)
    mesh.fbox(frame, (u0 + stile, u1 - stile), n, (z1 - rail, z1), mat)
    gu0, gu1, gz0, gz1 = u0 + stile, u1 - stile, z0 + bottom_rail, z1 - rail
    bar = (depth - thick * 0.78, depth - thick * 0.12)
    for i in range(1, cols):
        c = gu0 + (gu1 - gu0) * i / cols
        mesh.fbox(frame, (c - muntin / 2, c + muntin / 2), bar, (gz0, gz1), mat)
    for j in range(1, rows):
        c = gz0 + (gz1 - gz0) * j / rows
        mesh.fbox(frame, (gu0, gu1), bar, (c - muntin / 2, c + muntin / 2), mat)
    mid = depth - thick / 2
    mesh.face([frame.at(gu0, mid, gz0), frame.at(gu1, mid, gz0), frame.at(gu1, mid, gz1), frame.at(gu0, mid, gz1)], glass)


def casing(mesh, frame, u, z, width=0.105, proud=0.03, sill=True, head=0.15, mat="trim"):
    """Flat casing with a projecting sill and a capped head."""
    u0, u1 = u
    z0, z1 = z
    mesh.fbox(frame, (u0 - width, u0), (0, proud), (z0, z1), mat)
    mesh.fbox(frame, (u1, u1 + width), (0, proud), (z0, z1), mat)
    mesh.fbox(frame, (u0 - width, u1 + width), (0, proud), (z1, z1 + head), mat)
    mesh.fbox(frame, (u0 - width - 0.03, u1 + width + 0.03), (0, proud + 0.045), (z1 + head, z1 + head + 0.035), mat)
    mesh.fbox(frame, (u0 - width - 0.015, u1 + width + 0.015), (0, proud + 0.02), (z1 + head - 0.03, z1 + head), mat)
    if sill:
        mesh.fbox(frame, (u0 - width - 0.03, u1 + width + 0.03), (-0.1, proud + 0.05), (z0 - 0.055, z0), mat)
        mesh.fbox(frame, (u0 - width, u1 + width), (0, proud - 0.008), (z0 - 0.15, z0 - 0.055), mat)


def shutter(mesh, frame, u, z, mat="shutter", louvres=True):
    """A louvred shutter standing just off the wall."""
    u0, u1 = u
    z0, z1 = z
    n = (LAP + 0.012, LAP + 0.045)
    stile, rail = 0.055, 0.07
    mesh.fbox(frame, (u0, u0 + stile), n, (z0, z1), mat)
    mesh.fbox(frame, (u1 - stile, u1), n, (z0, z1), mat)
    mid = (z0 + z1) / 2
    for a, b in ((z0, z0 + rail), (mid - rail / 2, mid + rail / 2), (z1 - rail, z1)):
        mesh.fbox(frame, (u0 + stile, u1 - stile), n, (a, b), mat)
    if not louvres:
        return
    for lo, hi in ((z0 + rail, mid - rail / 2), (mid + rail / 2, z1 - rail)):
        count = max(1, int((hi - lo) / 0.042))
        step = (hi - lo) / count
        for i in range(count):
            z_low = lo + i * step
            pts = [frame.at(u0 + stile, n[1] - 0.004, z_low), frame.at(u1 - stile, n[1] - 0.004, z_low),
                   frame.at(u1 - stile, n[0] + 0.004, z_low + step * 0.92), frame.at(u0 + stile, n[0] + 0.004, z_low + step * 0.92)]
            mesh.face(pts, mat)


def window(mesh, frame, centre, sill, width, height, cols=3, rows=2, shutters=True, split=True, head=0.15):
    """A double-hung window: casing, two sashes with divided lights, optional shutters."""
    u0, u1 = centre - width / 2, centre + width / 2
    casing(mesh, frame, (u0, u1), (sill, sill + height), head=head)
    if split:
        meet = sill + height / 2
        glazing(mesh, frame, (u0, u1), (meet - 0.02, sill + height), -0.035, cols, rows)
        glazing(mesh, frame, (u0, u1), (sill, meet + 0.02), -0.075, cols, rows, bottom_rail=0.075)
    else:
        glazing(mesh, frame, (u0, u1), (sill, sill + height), -0.05, cols, rows)
    if shutters:
        w = width / 2 + 0.02
        shutter(mesh, frame, (u0 - 0.115 - w, u0 - 0.115), (sill - 0.01, sill + height + 0.01))
        shutter(mesh, frame, (u1 + 0.115, u1 + 0.115 + w), (sill - 0.01, sill + height + 0.01))
    return (u0, u1, sill, sill + height)


def panel_door(mesh, frame, u, z, depth=-0.06, mat="door", panels=((0.5, 0.86, 2), (0.14, 0.46, 2), (0.9, 0.98, 2)),
               knob="brass", knob_side=1):
    """A panelled door leaf. panels: (bottom, top, count) as fractions of the leaf height."""
    u0, u1 = u
    z0, z1 = z
    thick = 0.045
    mesh.fbox(frame, (u0, u1), (depth - thick, depth - 0.012), (z0, z1), mat)
    stile, width, height = 0.115, u1 - u0, z1 - z0
    for a, b in ((u0, u0 + stile), (u1 - stile, u1)):
        mesh.fbox(frame, (a, b), (depth - 0.012, depth), (z0, z1), mat)
    edges = sorted({0.0, 1.0} | {v for p in panels for v in p[:2]})
    for lo, hi in zip(edges, edges[1:]):
        if not any(abs(p[0] - lo) < 1e-6 and abs(p[1] - hi) < 1e-6 for p in panels):
            mesh.fbox(frame, (u0 + stile, u1 - stile), (depth - 0.012, depth), (z0 + lo * height, z0 + hi * height), mat)
    for lo, hi, count in panels:
        inner = (width - 2 * stile - (count - 1) * stile * 0.8) / count
        for i in range(count):
            a = u0 + stile + i * (inner + stile * 0.8)
            if i:
                mesh.fbox(frame, (a - stile * 0.8, a), (depth - 0.012, depth), (z0 + lo * height, z0 + hi * height), mat)
            mesh.fbox(frame, (a + 0.03, a + inner - 0.03), (depth - 0.012, depth - 0.004),
                      (z0 + lo * height + 0.03, z0 + hi * height - 0.03), mat)
    if knob:
        ku = u1 - 0.075 if knob_side > 0 else u0 + 0.075
        mesh.cylinder(frame.at(ku, depth, z0 + 0.98), frame.at(ku, depth + 0.012, z0 + 0.98), 0.036, 0.036, knob, 16)
        mesh.cylinder(frame.at(ku, depth + 0.012, z0 + 0.98), frame.at(ku, depth + 0.055, z0 + 0.98), 0.012, 0.012, knob, 12)
        mesh.sphere(frame.at(ku, depth + 0.07, z0 + 0.98), 0.03, knob, 12, 8)


def lantern(mesh, frame, u, z, scale=1.0, mat="iron"):
    """A wall lantern. Returns where its lamp sits."""
    s = scale
    mesh.fbox(frame, (u - 0.06 * s, u + 0.06 * s), (0, 0.02), (z - 0.12 * s, z + 0.12 * s), mat)
    mesh.fbox(frame, (u - 0.015 * s, u + 0.015 * s), (0.02, 0.17 * s), (z + 0.05 * s, z + 0.075 * s), mat)
    c = 0.17 * s
    half, base, top = 0.085 * s, z - 0.2 * s, z + 0.06 * s
    for du in (-half, half):
        for dn in (-half, half):
            mesh.fbox(frame, (u + du - 0.007 * s, u + du + 0.007 * s), (c + dn - 0.007 * s, c + dn + 0.007 * s), (base, top), mat)
    mesh.fbox(frame, (u - half - 0.012 * s, u + half + 0.012 * s), (c - half - 0.012 * s, c + half + 0.012 * s), (base - 0.018 * s, base), mat)
    mesh.fbox(frame, (u - half - 0.03 * s, u + half + 0.03 * s), (c - half - 0.03 * s, c + half + 0.03 * s), (top, top + 0.014 * s), mat)
    apex = frame.at(u, c, top + 0.12 * s)
    ring = [frame.at(u + du, c + dn, top + 0.014 * s) for du, dn in
            ((-half - 0.03 * s, -half - 0.03 * s), (half + 0.03 * s, -half - 0.03 * s),
             (half + 0.03 * s, half + 0.03 * s), (-half - 0.03 * s, half + 0.03 * s))]
    for i in range(4):
        mesh.face([ring[i], ring[(i + 1) % 4], apex], mat)
    mesh.sphere(frame.at(u, c, top + 0.14 * s), 0.016 * s, mat, 8, 6)
    panes = [((-half, -half), (half, -half)), ((half, -half), (half, half)),
             ((half, half), (-half, half)), ((-half, half), (-half, -half))]
    for (a, b), (c2, d) in panes:
        mesh.face([frame.at(u + a, c + b, base), frame.at(u + c2, c + d, base),
                   frame.at(u + c2, c + d, top), frame.at(u + a, c + b, top)], "lantern_glass")
    lamp = frame.at(u, c, base + 0.09 * s)
    mesh.cylinder(frame.at(u, c, base), frame.at(u, c, base + 0.045 * s), 0.018 * s, 0.018 * s, mat, 8)
    mesh.sphere(lamp, 0.028 * s, "lamp_warm", 10, 6)
    return lamp


def gable_roof(mesh, x0, x1, y0, y1, eave, ridge, axis, eave_over=0.34, rake_over=0.26, thick=0.16,
               mat="roof", trim="trim"):
    """A gable roof with overhangs, fascia, rake boards, soffits and a ridge cap.

    axis "x": the ridge runs east-west and the slopes face north and south.
    Returns a function height(x, y) giving the roof surface height.
    """
    if axis == "x":
        along0, along1, span0, span1 = x0, x1, y0, y1
        point = lambda a, s, z: (a, s, z)
    else:
        along0, along1, span0, span1 = y0, y1, x0, x1
        point = lambda a, s, z: (s, a, z)
    mid = (span0 + span1) / 2
    half = (span1 - span0) / 2
    pitch = (ridge - eave) / half
    slope = math.hypot(1, pitch)
    a0, a1 = along0 - rake_over, along1 + rake_over
    low = eave - eave_over * pitch
    length = (half + eave_over) * slope
    for sign in (-1, 1):
        edge = mid + sign * (half + eave_over)
        top = [point(a0, edge, low), point(a1, edge, low), point(a1, mid, ridge), point(a0, mid, ridge)]
        uvs = [(a0, 0), (a1, 0), (a1, length), (a0, length)]
        if sign > 0:
            top, uvs = [top[1], top[0], top[3], top[2]], [uvs[1], uvs[0], uvs[3], uvs[2]]
        mesh.face(top, mat, uvs)
        under = [point(a0, edge, low - thick), point(a1, edge, low - thick),
                 point(a1, mid, ridge - thick), point(a0, mid, ridge - thick)]
        if sign < 0:
            under = list(reversed(under))
        mesh.face(under, trim)
        # Fascia along the eave and a rake board up each gable.
        fascia = [point(a0, edge, low - thick - 0.05), point(a1, edge, low - thick - 0.05), point(a1, edge, low), point(a0, edge, low)]
        mesh.face(fascia if sign < 0 else list(reversed(fascia)), trim)
        for a, flip in ((a0, sign < 0), (a1, sign > 0)):
            rake = [point(a, edge, low - thick - 0.05), point(a, edge, low), point(a, mid, ridge), point(a, mid, ridge - thick - 0.05)]
            mesh.face(list(reversed(rake)) if flip else rake, trim)
        # Soffit, closing the overhang back to the wall.
        wall_edge = mid + sign * half
        soffit = [point(a0, edge, low - thick - 0.05), point(a1, edge, low - thick - 0.05),
                  point(a1, wall_edge, low - thick - 0.05), point(a0, wall_edge, low - thick - 0.05)]
        mesh.face(soffit if sign > 0 else list(reversed(soffit)), trim)
    cap = 0.11
    for sign in (-1, 1):
        q = [point(a0, mid, ridge + 0.03), point(a1, mid, ridge + 0.03),
             point(a1, mid + sign * cap, ridge + 0.03 - cap * pitch), point(a0, mid + sign * cap, ridge + 0.03 - cap * pitch)]
        mesh.face(q if sign < 0 else list(reversed(q)), "ridge")

    def height(x, y):
        s = y if axis == "x" else x
        return ridge - abs(s - mid) * pitch

    return height


def gutter(mesh, start, end, drop_at=None, ground=0.0, mat="gutter"):
    """A half-round gutter along an eave, with an optional downspout at one end."""
    start, end = Vector(start), Vector(end)
    profile = [(0.0, 0.0)] + [(0.065 - 0.065 * math.cos(math.pi * i / 8), -0.065 * math.sin(math.pi * i / 8)) for i in range(9)]
    profile += [(0.13, 0.012), (0.118, 0.012)] + [(0.065 - 0.053 * math.cos(math.pi * i / 8), -0.053 * math.sin(math.pi * i / 8)) for i in range(8, -1, -1)]
    mesh.extrude(profile, start, end, (0, 0, 1), mat)
    if drop_at is not None:
        top = Vector(drop_at)
        mesh.cylinder(top, (top.x, top.y, ground + 0.25), 0.038, 0.038, mat, 10)


def dormer(mesh, cx, front_y, width, sill_z, eave_z, ridge_z, roof_height, facing=-1, lit=None):
    """A gable dormer on a roof slope that faces south (facing=-1) or north (+1).

    front_y is the plane of the dormer's face. roof_height(x, y) is the main
    roof surface. Returns the window rectangle in the dormer's facade frame.
    """
    half = width / 2
    step = 0.02 * facing
    probe = lambda target: next(front_y - facing * i * 0.01 for i in range(1, 800)
                                if roof_height(cx, front_y - facing * i * 0.01) >= target)
    back_eave, back_ridge = probe(eave_z), probe(ridge_z)
    if facing < 0:
        frame = Frame((cx - half, front_y, 0), (1, 0, 0), (0, -1, 0))
    else:
        frame = Frame((cx + half, front_y, 0), (-1, 0, 0), (0, 1, 0))
    base = roof_height(cx, front_y)
    win_w, win_h = width - 0.42, eave_z - sill_z - 0.16
    opening = (half - win_w / 2, half + win_w / 2, sill_z, sill_z + win_h)
    wall(mesh, frame, width, base - 0.05, eave_z, [opening], "siding", gable=(half, ridge_z))
    window(mesh, frame, half, sill_z, win_w, win_h, cols=2, rows=2, shutters=False, head=0.09)
    for sx in (-1, 1):
        x = cx + sx * half
        cheek = [(x, front_y, base - 0.05), (x, front_y, eave_z), (x, back_eave, eave_z)]
        mesh.face(cheek if sx * facing > 0 else list(reversed(cheek)), "siding")
        mesh.box((x - 0.045, front_y + 0.03 * facing, base - 0.05), (x + 0.045, front_y - 0.035 * facing, eave_z), "trim")
        over = 0.16
        pitch = (ridge_z - eave_z) / half
        lip = front_y + facing * 0.2
        q = [(cx + sx * (half + over), lip, eave_z - over * pitch), (cx, lip, ridge_z), (cx, back_ridge, ridge_z), (x, back_eave, eave_z)]
        mesh.face(q if sx * facing < 0 else list(reversed(q)), "roof",
                  [(0, 0), (0, math.hypot(half + over, ridge_z - eave_z + over * pitch)), (abs(back_ridge - lip), math.hypot(half, ridge_z - eave_z)), (abs(back_eave - lip), 0)])
        rake = [(cx + sx * (half + over), lip, eave_z - over * pitch - 0.1), (cx + sx * (half + over), lip, eave_z - over * pitch),
                (cx, lip, ridge_z), (cx, lip, ridge_z - 0.1)]
        mesh.face(rake if sx * facing > 0 else list(reversed(rake)), "trim")
    del step
    return frame, opening


def chimney(mesh, cx, cy, w, d, base_z, top_z, mat="brick"):
    """A brick chimney with a corbelled cap and two clay pots."""
    mesh.box((cx - w / 2, cy - d / 2, base_z), (cx + w / 2, cy + d / 2, top_z - 0.3), mat)
    for i, grow in enumerate((0.03, 0.06, 0.03)):
        z = top_z - 0.3 + i * 0.08
        mesh.box((cx - w / 2 - grow, cy - d / 2 - grow, z), (cx + w / 2 + grow, cy + d / 2 + grow, z + 0.08), mat)
    mesh.box((cx - w / 2 - 0.05, cy - d / 2 - 0.05, top_z - 0.06), (cx + w / 2 + 0.05, cy + d / 2 + 0.05, top_z), "stone_cap")
    for dy in (-d / 4, d / 4):
        mesh.cylinder((cx, cy + dy, top_z), (cx, cy + dy, top_z + 0.42), 0.13, 0.105, "clay", 14)


def column(mesh, x, y, base_z, top_z, radius=0.15, mat="trim"):
    """A Tuscan column with a plinth, a tapered shaft and a capital."""
    mesh.box((x - radius * 1.45, y - radius * 1.45, base_z), (x + radius * 1.45, y + radius * 1.45, base_z + 0.09), mat)
    mesh.cylinder((x, y, base_z + 0.09), (x, y, base_z + 0.17), radius * 1.3, radius * 1.18, mat, 24)
    mesh.cylinder((x, y, base_z + 0.17), (x, y, top_z - 0.2), radius, radius * 0.86, mat, 24, caps=False)
    mesh.cylinder((x, y, top_z - 0.2), (x, y, top_z - 0.11), radius * 0.9, radius * 1.22, mat, 24)
    mesh.box((x - radius * 1.4, y - radius * 1.4, top_z - 0.11), (x + radius * 1.4, y + radius * 1.4, top_z), mat)


def ribbon(mesh, centre_line, width, z, mat, thickness=0.0, subdivide=6):
    """A flat strip following a ground polyline given as (x, y) points."""
    pts = smooth_path(centre_line, subdivide)
    left, right, run = [], [], [0.0]
    for i, p in enumerate(pts):
        a, b = pts[max(i - 1, 0)], pts[min(i + 1, len(pts) - 1)]
        t = (Vector(b) - Vector(a)).normalized()
        side = Vector((-t.y, t.x))
        left.append(Vector(p) + side * width / 2)
        right.append(Vector(p) - side * width / 2)
        if i:
            run.append(run[-1] + (Vector(p) - Vector(pts[i - 1])).length)
    for i in range(len(pts) - 1):
        q = [(right[i].x, right[i].y, z), (right[i + 1].x, right[i + 1].y, z),
             (left[i + 1].x, left[i + 1].y, z), (left[i].x, left[i].y, z)]
        mesh.face(q, mat, [(0, run[i]), (0, run[i + 1]), (width, run[i + 1]), (width, run[i])])
    return left, right


def smooth_path(points, subdivide=6):
    """Catmull-Rom interpolation through 2D points."""
    pts = [Vector(p) for p in points]
    if len(pts) < 3:
        return [tuple(p) for p in pts]
    out = []
    for i in range(len(pts) - 1):
        p0, p1, p2, p3 = pts[max(i - 1, 0)], pts[i], pts[i + 1], pts[min(i + 2, len(pts) - 1)]
        for s in range(subdivide):
            t = s / subdivide
            out.append(tuple(0.5 * ((2 * p1) + (-p0 + p2) * t + (2 * p0 - 5 * p1 + 4 * p2 - p3) * t * t
                                    + (-p0 + 3 * p1 - 3 * p2 + p3) * t ** 3)))
    out.append(tuple(pts[-1]))
    return out


def polygon(mesh, ring, z, mat):
    """A flat polygon from a ground ring of (x, y) points, anticlockwise from above."""
    mesh.face([(x, y, z) for x, y in ring], mat, [(x, y) for x, y in ring])
