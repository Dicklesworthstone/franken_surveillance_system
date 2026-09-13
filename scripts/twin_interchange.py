#!/usr/bin/env python3
"""Separate authoring-side FSSTWIN1 encoder; no Blender or private skill dependency."""
from __future__ import annotations
import hashlib
import math
import os
from pathlib import Path
import struct

MAGIC = b"FSSTWIN1"
MAX_BYTES = 64 * 1024 * 1024
KINDS = ("unknown", "pedestrian_path", "grass", "stairs", "deck", "structure")


def require(condition, message):
    if not condition:
        raise ValueError(message)


def text(value, maximum):
    require(isinstance(value, str) and value.strip() == value and value,
            "nonempty, unpadded text required")
    require(not any(ord(c) < 32 or 127 <= ord(c) <= 159 for c in value), "control character")
    encoded = value.encode("utf-8")
    require(len(encoded) <= maximum, "text limit")
    return struct.pack("<H", len(encoded)) + encoded


def number(value):
    require(type(value) in (float, int) and math.isfinite(value), "finite number required")
    return struct.pack("<d", float(value) if value else 0.0)


def encode_twin(*, source_sha256, scope, epoch, scale, geometry_error,
                features, objects, vertices, triangles):
    """Triangles are (vertex0, vertex1, vertex2, object_id); coordinates stay Z-up."""
    require(isinstance(source_sha256, str) and len(source_sha256) == 64
            and all(c in "0123456789abcdef" for c in source_sha256), "source digest")
    source = bytes.fromhex(source_sha256)
    require(source != bytes(32), "zero source digest")
    require(isinstance(scale, dict), "scale object")
    tag = {"relative": 0, "estimated": 1, "measured_anchor": 2}.get(scale.get("status"))
    require(tag is not None, "scale status")
    if tag == 0:
        require(set(scale) == {"status"}, "relative scale cannot claim metric conversion")
        factor, scale_error = 0.0, -1.0
    else:
        require(set(scale) == {"status", "metres_per_unit", "error"}, "scale fields")
        factor, scale_error = scale["metres_per_unit"], scale["error"]
        number(factor)
        require(0 < factor <= 1e9, "scale factor")
        if scale_error is None:
            scale_error = -1.0
        else:
            number(scale_error)
            require(0 <= scale_error < factor, "scale error")
    error = -1.0 if geometry_error is None else geometry_error
    number(error)
    require(error == -1.0 or 0 <= error <= 1e12, "geometry error")
    require(1 <= len(features) <= 65536 and 1 <= len(objects) <= 65536
            and 1 <= len(vertices) <= 262144 and 1 <= len(triangles) <= 524288, "record count")
    feature_rows = sorted(features, key=lambda row: row["id"])
    object_rows = sorted(objects, key=lambda row: row["id"])
    fids = {row["id"]: i for i, row in enumerate(feature_rows)}
    oids = {row["id"]: i for i, row in enumerate(object_rows)}
    require(len(fids) == len(features) and len(oids) == len(objects), "duplicate identity")
    payload = bytearray(source + text(scope, 2048) + text(epoch, 128))
    payload += bytes([tag]) + number(factor) + number(scale_error) + number(error)
    payload += struct.pack("<IIII", len(features), len(objects), len(vertices), len(triangles))
    used_features, used_objects = set(), set()
    for row in feature_rows:
        require(set(row) == {"id", "surface"} and row["surface"] in KINDS, "feature fields")
        payload += text(row["id"], 256) + bytes([KINDS.index(row["surface"])])
    for row in object_rows:
        require(set(row) == {"id", "feature", "support", "opaque"}, "object fields")
        require(row["feature"] in fids, "object feature")
        require(type(row["support"]) is bool and type(row["opaque"]) is bool, "role booleans")
        used_features.add(row["feature"])
        payload += text(row["id"], 256) + struct.pack("<IBB", fids[row["feature"]], row["support"], row["opaque"])
    require(used_features == set(fids), "unused feature")
    for vertex in vertices:
        require(len(vertex) == 3, "vertex dimension")
        for x in vertex:
            require(type(x) in (int, float) and math.isfinite(x) and abs(x) <= 1e12, "vertex range")
            payload += number(x)
    for tri in triangles:
        require(len(tri) == 4 and tri[3] in oids, "triangle object")
        require(all(type(i) is int and 0 <= i < len(vertices) for i in tri[:3]), "triangle index")
        a, b, c = (vertices[i] for i in tri[:3])
        u, v = [b[i]-a[i] for i in range(3)], [c[i]-a[i] for i in range(3)]
        cross = [u[1]*v[2]-u[2]*v[1], u[2]*v[0]-u[0]*v[2], u[0]*v[1]-u[1]*v[0]]
        product = math.hypot(*u) * math.hypot(*v)
        require(product > 1e-24 and math.hypot(*cross) > 1e-12*product, "degenerate triangle")
        used_objects.add(tri[3])
        payload += struct.pack("<IIII", *tri[:3], oids[tri[3]])
    require(used_objects == set(oids), "unused object")
    require(len(payload) + 48 <= MAX_BYTES, "package byte limit")
    prefix = MAGIC + struct.pack("<Q", len(payload)) + payload
    return bytes(prefix) + hashlib.sha256(prefix).digest()


def publish_new(path, data):
    """Create-only publication: complete sibling temp, fsync, no-clobber link, cleanup.

    A successful write is local publication, not archive replication or qualification.
    Errors after link may leave a complete destination: inspect before retrying.
    """
    import tempfile
    path = Path(path)
    require(path.parent.is_dir(), "output parent missing")
    fd, temporary = tempfile.mkstemp(prefix=".fss-twin-", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.link(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        os.unlink(temporary)


def fixture():
    """Public synthetic geometry only; independently usable cross-language fixture."""
    return dict(source_sha256="01"*32, scope="synthetic/Z-up/frame=0", epoch="synthetic",
                scale={"status": "relative"}, geometry_error=None,
                features=[{"id": "walk", "surface": "pedestrian_path"}],
                objects=[{"id": "ground", "feature": "walk", "support": True, "opaque": True}],
                vertices=[[0., 0., 0.], [4., 0., 0.], [4., 4., 0.], [0., 4., 0.]],
                triangles=[[0, 1, 2, "ground"], [0, 2, 3, "ground"]])


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Write a create-only synthetic FSSTWIN1 fixture")
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    data = encode_twin(**fixture())
    publish_new(args.output, data)
    print(hashlib.sha256(data).hexdigest())
