#!/usr/bin/env python3
"""Owner-side camera interchange math; never imported by the FSS runtime.

Matrices are evaluated camera-to-world transforms in the same RH Z-up coordinates
as FSSTWIN1 geometry. Camera local axes are +X right, +Y up, -Z forward; FSS uses
+X right, +Y down, +Z forward and pixel-edge coordinates. Authored camera placement
does not establish measured calibration, source custody, or capture-clock accuracy.
"""
from __future__ import annotations

import json
import math

from twin_interchange import require, text

SCHEMA = "fss.scene_camera_rig.v1"
MAX_CAMERAS = 64
BINDING_FIELDS = {"camera", "calibration", "image_domain", "clock", "privacy_domain", "validity_ns"}
CAMERA_FIELDS = BINDING_FIELDS | {"source_object_id", "image_model", "world_to_camera", "intrinsics", "error", "status"}


def finite(value, limit=1e12):
    require(type(value) in (int, float) and math.isfinite(value) and abs(value) <= limit,
            "finite, bounded camera number required")
    return float(value) if value else 0.0


def positive_id(value):
    require(type(value) is int and 0 < value < 2**64, "camera binding needs a nonzero u64 identity")
    return value


def validate_binding(binding):
    require(isinstance(binding, dict) and set(binding) == BINDING_FIELDS, "camera binding fields")
    for key in BINDING_FIELDS - {"validity_ns"}:
        positive_id(binding[key])
    validity = binding["validity_ns"]
    require(isinstance(validity, (list, tuple)) and len(validity) == 2
            and all(type(v) is int and 0 <= v < 2**64 for v in validity)
            and validity[0] <= validity[1], "ordered capture-clock validity required")


def dot(a, b):
    return sum(x*y for x, y in zip(a, b))


def cross(a, b):
    return [a[1]*b[2]-a[2]*b[1], a[2]*b[0]-a[0]*b[2], a[0]*b[1]-a[1]*b[0]]


def unit(vector):
    length = math.hypot(*vector)
    require(length > 1e-12, "singular camera transform")
    return [v/length for v in vector]


def world_to_camera(camera_to_world):
    """Convert a proper row-major 4x4 Blender/OpenGL camera pose into FSS R,t.

    Explicitly refuse camera scale, reflection and shear. A 1e-6 tolerance admits
    Blender's float-matrix roundoff only; Gram-Schmidt then restores a proper
    rotation so the native reader's tighter rotation check can succeed.
    """
    require(len(camera_to_world) == 4 and all(len(r) == 4 for r in camera_to_world),
            "camera transform must be 4x4")
    m = [[finite(v) for v in row] for row in camera_to_world]
    require(all(abs(m[3][i] - (1.0 if i == 3 else 0.0)) <= 1e-12 for i in range(4)),
            "camera transform must be affine")
    columns = [[m[j][i] for j in range(3)] for i in range(3)]
    require(all(abs(math.hypot(*v)-1.0) <= 1e-6 for v in columns),
            "scaled camera transforms are unsupported; apply camera scale in the authoring scene")
    require(all(abs(dot(columns[i], columns[j])) <= 1e-6
                for i in range(3) for j in range(i)), "sheared camera transforms are unsupported")
    require(dot(cross(columns[0], columns[1]), columns[2]) > 0.0,
            "reflected camera transforms are unsupported")
    right = unit(columns[0])
    up = unit([columns[1][i] - dot(right, columns[1])*right[i] for i in range(3)])
    backward = cross(right, up)
    rotation = [right, [-v for v in up], [-v for v in backward]]
    center = [m[i][3] for i in range(3)]
    return {"rotation": [[finite(v) for v in row] for row in rotation],
            "translation": [finite(-dot(row, center)) for row in rotation]}


def validate_pose(pose):
    require(isinstance(pose, dict) and set(pose) == {"rotation", "translation"}, "camera pose fields")
    r, t = pose["rotation"], pose["translation"]
    require(len(r) == 3 and all(len(row) == 3 for row in r) and len(t) == 3, "camera pose dimensions")
    r = [[finite(v) for v in row] for row in r]
    t = [finite(v) for v in t]
    require(all(abs(dot(r[i], r[j])-(1.0 if i == j else 0.0)) <= 1e-8
                for i in range(3) for j in range(3))
            and abs(dot(cross(r[0], r[1]), r[2])-1.0) <= 1e-8,
            "camera pose requires a proper world-to-camera rotation")
    return {"rotation": r, "translation": t}


def validate_intrinsics(intrinsics):
    require(isinstance(intrinsics, dict)
            and set(intrinsics) == {"width", "height", "fx", "fy", "cx", "cy"}, "intrinsics fields")
    for key in ("width", "height"):
        require(type(intrinsics[key]) is int and 1 <= intrinsics[key] <= 65536, "camera image dimension")
    numbers = {key: finite(intrinsics[key], 1e9) for key in ("fx", "fy", "cx", "cy")}
    require(numbers["fx"] >= 1e-6 and numbers["fy"] >= 1e-6, "positive camera focal lengths required")
    return {"width": intrinsics["width"], "height": intrinsics["height"], **numbers}


def blender_intrinsics(*, width, height, lens_mm, sensor_width_mm, sensor_height_mm,
                       sensor_fit, pixel_aspect=(1.0, 1.0), shift=(0.0, 0.0)):
    """Perspective lens in a declared full, undistorted image mode.

    Uses Blender's sensor-size and view-plane conventions, including AUTO using
    sensor width even when a portrait image chooses vertical fit. Reference:
    blender v4.1.1 source/blender/blenkernel/intern/camera.cc,
    BKE_camera_sensor_size and BKE_camera_params_compute_viewplane. This original
    algebraic projection is tested against independently computed frame edges.
    """
    require(type(width) is int and type(height) is int and 1 <= width <= 65536
            and 1 <= height <= 65536, "camera image dimension")
    require(sensor_fit in ("AUTO", "HORIZONTAL", "VERTICAL"), "camera sensor fit")
    require(len(pixel_aspect) == 2 and len(shift) == 2, "camera aspect/shift dimensions")
    px, py = [finite(v, 1e6) for v in pixel_aspect]
    sx, sy = [finite(v, 1e6) for v in shift]
    lens, sensor_x, sensor_y = [finite(v, 1e9) for v in (lens_mm, sensor_width_mm, sensor_height_mm)]
    require(px > 0 and py > 0 and lens > 0 and sensor_x > 0 and sensor_y > 0,
            "positive camera lens, sensor size and pixel aspect required")
    ratio = py/px
    horizontal = sensor_fit == "HORIZONTAL" or (sensor_fit == "AUTO" and width*px >= height*py)
    view = float(width) if horizontal else height*ratio
    sensor = sensor_y if sensor_fit == "VERTICAL" else sensor_x
    fx = lens*view/sensor
    return validate_intrinsics({"width": width, "height": height, "fx": fx, "fy": fx/ratio,
                                "cx": width/2.0-sx*view, "cy": height/2.0+sy*view/ratio})


def camera_row(*, binding, source_object_id, matrix_world, intrinsics):
    """Construct an authored, unqualified camera row from explicit owner bindings."""
    validate_binding(binding)
    text(source_object_id, 256)
    return {**binding, "source_object_id": source_object_id, "image_model": "undistorted_pinhole",
            "world_to_camera": world_to_camera(matrix_world), "intrinsics": validate_intrinsics(intrinsics),
            "error": None, "status": "authored_nominal"}


def encode_rig(*, source_sha256, twin_sha256, geometry_basis, evaluation_scope, cameras):
    """Encode bounded control JSON. The native reader reconstructs typed geometry.

    Digests are lowercase hex without prefixes on input. This is not a durable
    calibration certificate and never changes the native twin binary format.
    """
    for digest in (source_sha256, twin_sha256):
        require(isinstance(digest, str) and len(digest) == 64 and digest != "00"*32
                and all(c in "0123456789abcdef" for c in digest), "camera rig digest")
    require(isinstance(geometry_basis, dict) and set(geometry_basis) == {"property", "revision"},
            "geometry basis fields")
    for v in geometry_basis.values():
        positive_id(v)
    text(evaluation_scope, 2048)
    require(isinstance(cameras, list) and 1 <= len(cameras) <= MAX_CAMERAS, "camera rig count")
    ids, objects, rows = set(), set(), []
    for camera in cameras:
        require(isinstance(camera, dict) and set(camera) == CAMERA_FIELDS, "camera row fields")
        validate_binding({k: camera[k] for k in BINDING_FIELDS})
        text(camera["source_object_id"], 256)
        require(camera["camera"] not in ids and camera["source_object_id"] not in objects, "duplicate camera binding")
        ids.add(camera["camera"])
        objects.add(camera["source_object_id"])
        require(camera["image_model"] == "undistorted_pinhole" and camera["error"] is None
                and camera["status"] == "authored_nominal", "authored camera model/status")
        rows.append({**camera, "world_to_camera": validate_pose(camera["world_to_camera"]),
                     "intrinsics": validate_intrinsics(camera["intrinsics"])})
    result = {"schema": SCHEMA, "source_scene_digest": "sha256:"+source_sha256,
              "twin_digest": "sha256:"+twin_sha256, "geometry_basis": geometry_basis,
              "coordinate_frame": "RH_Z_UP", "evaluation_scope": evaluation_scope,
              "cameras": sorted(rows, key=lambda row: row["camera"])}
    data = (json.dumps(result, sort_keys=True, ensure_ascii=False, allow_nan=False,
                       separators=(",", ":"))+"\n").encode("utf-8")
    require(len(data) <= 1024*1024, "camera rig byte bound")
    return data
