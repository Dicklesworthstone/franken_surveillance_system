"""Subdivide and shade the original raccoon mesh in bind space, preserving the authored skeletal animation.
Usage: python prepare-wildlife.py licensed-source.glb raccoon.glb (requires NumPy and Pillow)."""

import io
import json
import struct
import sys
from collections import defaultdict
from pathlib import Path

import numpy as np
from PIL import Image

src, dst = map(Path, sys.argv[-2:])
with src.open("rb") as input_file:
    input_file.read(12)
    n, _ = struct.unpack("<II", input_file.read(8))
    doc = json.loads(input_file.read(n))
    input_file.read(8)
    raw = bytearray(input_file.read())
types = {5126: "f", 5125: "I", 5123: "H", 5121: "B"}
dims = {"SCALAR": 1, "VEC2": 2, "VEC3": 3, "VEC4": 4}


def read(ix):
    a = doc["accessors"][ix]
    v = doc["bufferViews"][a["bufferView"]]
    fmt = "<" + dims[a["type"]] * types[a["componentType"]]
    return [
        struct.unpack_from(
            fmt,
            raw,
            v.get("byteOffset", 0)
            + a.get("byteOffset", 0)
            + k * v.get("byteStride", struct.calcsize(fmt)),
        )
        for k in range(a["count"])
    ]


def append(rows, channel_type, kind, normalized=False, bounds=False):
    while len(raw) % 4:
        raw.append(0)
    offset = len(raw)
    array = np.array(
        rows, dtype={5126: "<f4", 5125: "<u4", 5123: "<u2", 5121: "u1"}[kind]
    )
    raw.extend(array.tobytes())
    doc["bufferViews"].append(
        {"buffer": 0, "byteOffset": offset, "byteLength": len(raw) - offset}
    )
    a = {
        "bufferView": len(doc["bufferViews"]) - 1,
        "componentType": kind,
        "count": len(rows),
        "type": channel_type,
    }
    if normalized:
        a["normalized"] = True
    if bounds:
        a.update(min=array.min(axis=0).tolist(), max=array.max(axis=0).tolist())
    doc["accessors"].append(a)
    return len(doc["accessors"]) - 1


p = doc["meshes"][0]["primitives"][0]
a = p["attributes"]
tex = doc["bufferViews"][doc["images"][0]["bufferView"]]
palette = Image.open(
    io.BytesIO(raw[tex["byteOffset"] : tex["byteOffset"] + tex["byteLength"]])
).convert("RGB")
positions = []
weights = []
colour = []
hits = []
remap = []
index = {}
for xyz, js, ws, uv in zip(
    *[read(a[n]) for n in ["POSITION", "JOINTS_0", "WEIGHTS_0", "TEXCOORD_0"]]
):
    key = tuple(round(x, 4) for x in xyz)
    rgb = np.array(palette.getpixel((int(uv[0] * 4), int(uv[1] * 4))), dtype=float)
    if key not in index:
        i = index[key] = len(positions)
        positions.append(np.array(xyz))
        weights.append({j: w for j, w in zip(js, ws) if w > 0})
        colour.append(rgb)
        hits.append(1)
    else:
        i = index[key]
        colour[i] += rgb
        hits[i] += 1
    remap.append(i)
colour = [c / n for c, n in zip(colour, hits)]
indices = [remap[i[0]] for i in read(p["indices"])]
faces = [tuple(indices[i : i + 3]) for i in range(0, len(indices), 3)]


def blend(weights_a, weights_b):
    keys = weights_a.keys() | weights_b.keys()
    return {j: 0.5 * (weights_a.get(j, 0) + weights_b.get(j, 0)) for j in keys}


for level in range(3):
    edges = {}
    neighbors = defaultdict(set)
    opposites = defaultdict(list)
    for tri in faces:
        for aa, bb, cc in zip(tri, tri[1:] + tri[:1], tri[2:] + tri[:2]):
            edge = tuple(sorted((aa, bb)))
            neighbors[aa].add(bb)
            neighbors[bb].add(aa)
            opposites[edge].append(cc)
    old = positions
    positions = old[:]
    for i, adj in neighbors.items():
        # A modest first pass preserves ears and toes while rounding the triangular silhouette.
        n = len(adj)
        beta = (3 / 16 if n == 3 else 3 / (8 * n)) * (0.64 if level == 0 else 1)
        positions[i] = (1 - n * beta) * old[i] + beta * sum(old[j] for j in adj)
    for edge, op in opposites.items():
        aa, bb = edge
        edges[edge] = len(positions)
        mid = 0.5 * (old[aa] + old[bb])
        if len(op) == 2:
            mid = 0.375 * (old[aa] + old[bb]) + 0.125 * (old[op[0]] + old[op[1]])
        positions.append(mid)
        weights.append(blend(weights[aa], weights[bb]))
        colour.append(0.5 * (colour[aa] + colour[bb]))
    new = []
    for aa, bb, cc in faces:
        ab, bc, ca = [
            edges[tuple(sorted(pair))] for pair in [(aa, bb), (bb, cc), (cc, aa)]
        ]
        new.extend([(aa, ab, ca), (bb, bc, ab), (cc, ca, bc), (ab, bc, ca)])
    faces = new
xyz = np.array(positions)
tri = np.array(faces)
normal = np.zeros(xyz.shape)
cross = np.cross(xyz[tri[:, 1]] - xyz[tri[:, 0]], xyz[tri[:, 2]] - xyz[tri[:, 0]])
for j in range(3):
    np.add.at(normal, tri[:, j], cross)
normal /= np.maximum(1e-8, np.linalg.norm(normal, axis=1)[:, None])
x, y, z = xyz.T
palette = np.array(colour) / 255
# Disrupted fur values along the back and flanks. Keep the source's mask, pale brow, paws, and muzzle.
noise = (
    0.045 * np.sin(x * 3.08 + z * 0.76 + np.sin(y * 2.7))
    + 0.037 * np.sin(x * 5.6 - y * 3.87 + z * 0.16)
    + 0.022 * np.sin(x * 11.8 + z * 1.5)
)
colour = np.clip(
    palette * np.array([0.97, 0.927, 0.845]) + noise[:, None] + 0.012, 0, 1
)
ax = np.abs(x)


def ease(v):
    return np.clip(v, 0, 1) ** 2 * (3 - 2 * np.clip(v, 0, 1))


def paint(region, tint):
    global colour
    colour = (
        colour * (1 - region[:, None])
        + np.clip(np.array(tint) + noise[:, None] * 0.65, 0, 1) * region[:, None]
    )


# Six distinct tail bands, pale facial chevrons, dark tapered mask and charcoal paws.
tail = ease((-z - 28) / 5) * ease((8.5 - ax) / 2)
bar = ease((np.cos((z + 31) * 0.77) - 0.03) * 2.2)
paint(tail, (0.59, 0.55, 0.49))
paint(tail * bar, (0.15, 0.14, 0.132))
paint(tail * ease((-z - 65) / 2), (0.105, 0.10, 0.10))
face = ease((z - 27) / 4) * ease((47 - y) / 2) * ease((y - 34) / 2)
paint(face, (0.78, 0.743, 0.665))
mask = (
    face
    * ease((2.7 - np.abs(y - (43.25 - 0.25 * ax))) / 0.9)
    * ease((z - 27) / 3)
    * ease((1.25 - abs(z + (ax * 0.42) - 36) / 8) * 2)
    * ease((ax - 0.95) / 1.3)
)
paint(mask, (0.125, 0.116, 0.109))
nose = ease((z - 41.3) / 1.4) * ease((y - 36.4) / 0.65) * ease((40.2 - y) / 0.8)
eyes = (
    ease((1.3 - np.sqrt(((ax - 3.55) / 1.25) ** 2 + ((y - 42.85) / 0.98) ** 2)) * 3)
    * ease((z - 34.8) / 0.5)
    * ease((36.4 - z) / 0.4)
)
paint(np.maximum(nose, eyes), (0.055, 0.051, 0.047))
paint(ease((13 - y) / 9), (0.185, 0.168, 0.151))
colour = np.where(colour <= 0.04045, colour / 12.92, ((colour + 0.055) / 1.055) ** 2.4)
joints = []
values = []
for weights_for_vertex in weights:
    ordered = sorted(weights_for_vertex.items(), key=lambda item: -item[1])[:4]
    while len(ordered) < 4:
        ordered.append((0, 0))
    total = sum(w for _, w in ordered)
    joints.append([i for i, _ in ordered])
    values.append([w / total for _, w in ordered])
p["attributes"] = {
    "POSITION": append(xyz, "VEC3", 5126, bounds=True),
    "NORMAL": append(normal, "VEC3", 5126),
    "JOINTS_0": append(joints, "VEC4", 5123),
    "WEIGHTS_0": append(values, "VEC4", 5126),
}
# Packed RGB bytes must be aligned to four bytes per glTF vertex.
rgba = np.column_stack(
    [np.uint8(np.round(colour * 255)), np.full(len(colour), 255, dtype=np.uint8)]
)
p["attributes"]["COLOR_0"] = append(rgba, "VEC4", 5121, True)
p["indices"] = append(tri.reshape(-1, 1), "SCALAR", 5125)
doc["materials"][0] = {
    "name": "Brindled guard coat",
    "pbrMetallicRoughness": {"metallicFactor": 0, "roughnessFactor": 0.93},
}
while len(raw) % 4:
    raw.append(0)
doc["buffers"][0]["byteLength"] = len(raw)
js = json.dumps(doc, separators=(",", ":")).encode()
while len(js) % 4:
    js += b" "
dst.write_bytes(
    struct.pack("<4sII", b"glTF", 2, len(js) + len(raw) + 28)
    + struct.pack("<II", len(js), 0x4E4F534A)
    + js
    + struct.pack("<II", len(raw), 0x004E4942)
    + raw
)
