#!/usr/bin/env python3
"""Owner-run static glTF/GLB conversion to the native twin and camera rig.

This is an offline authoring tool, never an FSS runtime dependency. It imports
explicitly classified triangle geometry and bound perspective cameras, with no
network or external-URI reads. See docs/GLTF_SCENE_IMPORT.md for the supported
subset, scale declarations, and policy. glTF 2.0 reference:
https://registry.khronos.org/glTF/specs/2.0/glTF-2.0.html
"""
from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import json
import math
from pathlib import Path
import struct
import sys

from twin_interchange import KINDS, MAX_BYTES, encode_twin, publish_new, require, text

MAX_NODES = 8192
MAX_VERTICES = 262144
MAX_TRIANGLES = 524288
IDENTITY = [[float(i == j) for j in range(4)] for i in range(4)]
# One proper rotation applied to BOTH mesh vertices and camera-to-world matrices.
Y_UP_TO_Z_UP = [[1., 0., 0., 0.], [0., 0., -1., 0.],
                [0., 1., 0., 0.], [0., 0., 0., 1.]]


def natural(value, maximum, name, minimum=0):
    require(type(value) is int and minimum <= value <= maximum, name)
    return value


def finite(value, name, maximum=1e12):
    require(type(value) in (int, float) and math.isfinite(value)
            and abs(value) <= maximum, name)
    return float(value)


def vector(value, size, name):
    require(isinstance(value, list) and len(value) == size, name)
    return [finite(x, name) for x in value]


def row(values, index, name):
    require(isinstance(values, list), name)
    natural(index, len(values) - 1, name)
    value = values[index]
    require(isinstance(value, dict), name)
    return value


def strict_json(raw):
    require(len(raw) <= MAX_BYTES, "JSON input exceeds 64 MiB")
    # Check depth before the standard parser can recurse; braces in strings do
    # not count. The parser below still validates all syntax and Unicode.
    depth, quoted, escaped = 0, False, False
    for byte in raw:
        if quoted:
            if escaped:
                escaped = False
            elif byte == 92:
                escaped = True
            elif byte == 34:
                quoted = False
        elif byte == 34:
            quoted = True
        elif byte in (91, 123):
            depth += 1
            require(depth <= 64, "JSON nesting exceeds 64")
        elif byte in (93, 125):
            depth -= 1

    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, "duplicate JSON key")
            result[key] = value
        return result

    def constant(_):
        raise ValueError("nonfinite JSON number")

    value = json.loads(raw.decode("utf-8"), object_pairs_hook=pairs,
                       parse_constant=constant)
    require(isinstance(value, dict), "JSON root must be an object")
    return value


def unpack_source(raw):
    """Return JSON and the optional embedded BIN, with exact GLB bounds."""
    require(0 < len(raw) <= MAX_BYTES, "source size must be 1..64 MiB")
    if not raw.startswith(b"glTF"):
        return strict_json(raw), None
    require(len(raw) >= 20, "truncated GLB header")
    magic, version, length = struct.unpack_from("<4sII", raw)
    require(magic == b"glTF" and version == 2 and length == len(raw), "GLB header")
    offset, chunks = 12, []
    while offset < len(raw):
        require(offset + 8 <= len(raw), "truncated GLB chunk header")
        size, kind = struct.unpack_from("<II", raw, offset)
        offset += 8
        require(size % 4 == 0 and offset + size <= len(raw), "GLB chunk bounds")
        chunks.append((kind, raw[offset:offset + size]))
        require(len(chunks) <= 2, "only JSON and one BIN chunk are supported")
        offset += size
    require(chunks and chunks[0][0] == 0x4E4F534A, "GLB JSON must be first")
    require(len(chunks) == 1 or chunks[1][0] == 0x004E4942, "GLB BIN must be second")
    return strict_json(chunks[0][1]), chunks[1][1] if len(chunks) == 2 else None


def buffers(document, binary):
    declarations = document.get("buffers", [])
    require(isinstance(declarations, list) and len(declarations) <= 256, "buffer count")
    result, total, used_binary = [], 0, False
    for index, declaration in enumerate(declarations):
        require(isinstance(declaration, dict) and not declaration.get("extensions"),
                "unsupported buffer declaration")
        size = natural(declaration.get("byteLength"), MAX_BYTES, "buffer length", 1)
        uri = declaration.get("uri")
        if uri is None:
            require(index == 0 and binary is not None, "missing embedded buffer")
            require(size <= len(binary) <= size + 3 and not any(binary[size:]),
                    "GLB buffer length or padding")
            data, used_binary = binary[:size], True
        else:
            require(isinstance(uri, str), "buffer URI")
            prefixes = ("data:application/octet-stream;base64,",
                        "data:application/gltf-buffer;base64,")
            prefix = next((p for p in prefixes if uri.startswith(p)), None)
            require(prefix is not None,
                    "external buffer URIs are unsupported; export GLB or embedded glTF")
            encoded = uri[len(prefix):]
            require(len(encoded) <= 4 * ((size + 2) // 3), "base64 length")
            try:
                data = base64.b64decode(encoded, validate=True)
            except (ValueError, binascii.Error) as error:
                raise ValueError("invalid embedded base64") from error
            require(len(data) == size, "embedded buffer length")
        total += len(data)
        require(total <= MAX_BYTES, "total buffer bytes")
        result.append(data)
    require(binary is None or used_binary, "unreferenced GLB BIN chunk")
    return result


def multiply(left, right):
    out = [[sum(left[i][k] * right[k][j] for k in range(4))
            for j in range(4)] for i in range(4)]
    for values in out:
        for value in values:
            finite(value, "composed transform range")
    return out


def determinant(matrix):
    a, b, c = (values[:3] for values in matrix[:3])
    return (a[0] * (b[1] * c[2] - b[2] * c[1])
            - a[1] * (b[0] * c[2] - b[2] * c[0])
            + a[2] * (b[0] * c[1] - b[1] * c[0]))


def node_transform(node):
    require(not node.get("extensions"), "node extensions require evaluated export")
    if "matrix" in node:
        require(not {"translation", "rotation", "scale"}.intersection(node),
                "node cannot contain both matrix and TRS")
        values = vector(node["matrix"], 16, "node matrix")
        matrix = [[values[j * 4 + i] for j in range(4)] for i in range(4)]
    else:
        t = vector(node.get("translation", [0., 0., 0.]), 3, "translation")
        x, y, z, w = vector(node.get("rotation", [0., 0., 0., 1.]), 4, "quaternion")
        require(abs(x*x + y*y + z*z + w*w - 1.) <= 1e-6, "non-unit quaternion")
        # Normalize only floating-point serialization roundoff, not arbitrary data.
        norm = math.sqrt(x*x + y*y + z*z + w*w)
        x, y, z, w = (v / norm for v in (x, y, z, w))
        s = vector(node.get("scale", [1., 1., 1.]), 3, "scale")
        r = [[1-2*(y*y+z*z), 2*(x*y-z*w), 2*(x*z+y*w)],
             [2*(x*y+z*w), 1-2*(x*x+z*z), 2*(y*z-x*w)],
             [2*(x*z-y*w), 2*(y*z+x*w), 1-2*(x*x+y*y)]]
        matrix = [[r[i][j] * s[j] for j in range(3)] + [t[i]] for i in range(3)]
        matrix.append([0., 0., 0., 1.])
    require(matrix[3] == [0., 0., 0., 1.], "non-affine node transform")
    require(abs(determinant(matrix)) > 1e-12, "singular node transform")
    return matrix


def selected_nodes(document, scene_index):
    nodes = document.get("nodes", [])
    require(isinstance(nodes, list) and 0 < len(nodes) <= MAX_NODES, "node count")
    parents = [None] * len(nodes)
    for index, node in enumerate(nodes):
        require(isinstance(node, dict), "node object")
        children = node.get("children", [])
        require(isinstance(children, list) and len(children) <= MAX_NODES, "children")
        for child in children:
            natural(child, len(nodes)-1, "child index")
            require(parents[child] is None, "duplicate child or multiple node parents")
            parents[child] = index
    # Validate the complete forest even if a cyclic component is outside this scene.
    queue = [i for i, parent in enumerate(parents) if parent is None]
    visited = 0
    while queue:
        index = queue.pop()
        visited += 1
        queue.extend(nodes[index].get("children", []))
    require(visited == len(nodes), "cyclic node hierarchy")
    scene = row(document.get("scenes"), scene_index, "selected scene")
    roots = scene.get("nodes", [])
    require(isinstance(roots, list) and roots, "scene roots")
    for root in roots:
        natural(root, len(nodes)-1, "scene root index")
        require(parents[root] is None, "scene root has a parent")
    require(len(set(roots)) == len(roots), "duplicate scene root")
    stack = [(index, IDENTITY, 0) for index in reversed(roots)]
    result = []
    while stack:
        index, parent, depth = stack.pop()
        require(depth <= 128, "node depth exceeds 128")
        node = nodes[index]
        require("skin" not in node and not node.get("weights"),
                "skinned or morphed nodes require evaluated export")
        world = multiply(parent, node_transform(node))
        result.append((index, node, multiply(Y_UP_TO_Z_UP, world)))
        stack.extend((child, world, depth+1) for child in reversed(node.get("children", [])))
    return result


def accessor(document, loaded, index, positions):
    a = row(document.get("accessors"), index, "accessor index")
    require(not a.get("sparse") and not a.get("normalized") and not a.get("extensions"),
            "sparse, normalized or extended accessors require evaluated export")
    component = a.get("componentType")
    require(type(component) is int, "accessor component type")
    if positions:
        require(component == 5126 and a.get("type") == "VEC3", "POSITION must be FLOAT VEC3")
        fmt, alignment, size = "<fff", 4, 12
        count = natural(a.get("count"), MAX_VERTICES, "vertex count", 1)
    else:
        require(component in (5121, 5123, 5125) and a.get("type") == "SCALAR",
                "indices must be unsigned SCALAR")
        fmt, alignment = {5121: ("<B", 1), 5123: ("<H", 2), 5125: ("<I", 4)}[component]
        size = alignment
        count = natural(a.get("count"), MAX_TRIANGLES * 3, "index count", 1)
    view = row(document.get("bufferViews"), a.get("bufferView"), "buffer view")
    require(not view.get("extensions"), "extended buffer view")
    buffer_index = natural(view.get("buffer"), len(loaded)-1, "buffer index")
    data = loaded[buffer_index]
    start = natural(view.get("byteOffset", 0), len(data), "buffer view offset")
    length = natural(view.get("byteLength"), len(data)-start, "buffer view length", 1)
    offset = natural(a.get("byteOffset", 0), length, "accessor offset")
    stride = natural(view.get("byteStride", size), 252, "accessor stride", size)
    require(positions or "byteStride" not in view, "indices cannot be strided")
    require(stride % alignment == 0 and offset % alignment == 0
            and (start + offset) % alignment == 0,
            "misaligned accessor")
    if positions:
        require(offset % 4 == 0 and stride % 4 == 0, "misaligned vertex attribute")
    require(offset + stride * (count-1) + size <= length, "accessor exceeds buffer view")
    values = [struct.unpack_from(fmt, data, start + offset + i*stride) for i in range(count)]
    if positions:
        for value in values:
            for n in value:
                finite(n, "POSITION range")
        return values
    indices = [v[0] for v in values]
    require(all(index != (1 << (alignment * 8)) - 1 for index in indices),
            "primitive restart indices are invalid in glTF")
    return indices


def exclusion(spec):
    if spec.get("role") != "exclude":
        return False
    require(set(spec) == {"role", "reason"}, "exclusion fields")
    text(spec["reason"], 512)
    return True


def convert(raw, policy):
    """Build both outputs before publication; same input/policy yields same bytes."""
    from scene_camera_rig import camera_row, encode_rig

    fields = {"schema", "source_sha256", "scene", "epoch", "scale", "geometry_error",
              "geometry_basis", "objects", "cameras"}
    require(isinstance(policy, dict) and set(policy) == fields, "glTF policy fields")
    require(policy["schema"] == "fss.gltf-import-policy/1", "glTF policy schema")
    source_sha = hashlib.sha256(raw).hexdigest()
    require(policy["source_sha256"] == source_sha, "source digest mismatch")
    document, binary = unpack_source(raw)
    asset = document.get("asset")
    require(isinstance(asset, dict) and asset.get("version") == "2.0"
            and asset.get("minVersion", "2.0") == "2.0", "only glTF 2.0 is supported")
    require(not document.get("extensionsRequired"), "required glTF extension is unsupported")
    require(not document.get("animations"), "animated scenes require evaluated static export")
    loaded = buffers(document, binary)
    scene_index = natural(policy["scene"], MAX_NODES, "policy scene")
    selected = selected_nodes(document, scene_index)
    objects_policy, cameras_policy = policy["objects"], policy["cameras"]
    for mapping in (objects_policy, cameras_policy):
        require(isinstance(mapping, dict) and len(mapping) <= MAX_NODES, "policy node mapping")
        require(all(k.isascii() and k.isdigit() and str(int(k)) == k for k in mapping),
                "policy keys must be canonical node indices")
    features, objects, vertices, triangles, cameras = {}, [], [], [], []
    used_objects, used_cameras = set(), set()
    for node_index, node, matrix in selected:
        key = str(node_index)
        if "mesh" in node:
            spec = objects_policy.get(key)
            require(isinstance(spec, dict), "selected mesh node lacks explicit physical/exclude policy")
            used_objects.add(key)
            if not exclusion(spec):
                require(set(spec) == {"role", "id", "feature", "surface", "support", "opaque"}
                        and spec["role"] == "physical" and spec["surface"] in KINDS,
                        "physical object policy fields")
                text(spec["id"], 256)
                text(spec["feature"], 256)
                require(type(spec["support"]) is bool and type(spec["opaque"]) is bool,
                        "physical role booleans")
                old_surface = features.setdefault(spec["feature"], spec["surface"])
                require(old_surface == spec["surface"], "conflicting feature surface class")
                objects.append({k: spec[k] for k in ("id", "feature", "support", "opaque")})
                mesh = row(document.get("meshes"), node["mesh"], "mesh index")
                require(not mesh.get("weights") and not mesh.get("extensions"), "unsupported mesh")
                primitives = mesh.get("primitives")
                require(isinstance(primitives, list) and 0 < len(primitives) <= 4096, "mesh primitives")
                for primitive in primitives:
                    require(isinstance(primitive, dict) and primitive.get("mode", 4) == 4
                            and not primitive.get("targets") and not primitive.get("extensions"),
                            "only static uncompressed TRIANGLES are supported")
                    attrs = primitive.get("attributes")
                    require(isinstance(attrs, dict) and "POSITION" in attrs, "missing POSITION")
                    positions = accessor(document, loaded, attrs["POSITION"], True)
                    require(len(vertices) + len(positions) <= MAX_VERTICES, "evaluated vertex limit")
                    indices = (accessor(document, loaded, primitive["indices"], False)
                               if "indices" in primitive else list(range(len(positions))))
                    require(len(indices) % 3 == 0 and len(triangles) + len(indices)//3 <= MAX_TRIANGLES,
                            "triangle count")
                    require(all(0 <= i < len(positions) for i in indices), "primitive index range")
                    base = len(vertices)
                    for point in positions:
                        vertices.append([sum(matrix[i][j]*point[j] for j in range(3))
                                         + matrix[i][3] for i in range(3)])
                    reflected = determinant(matrix) < 0
                    for i in range(0, len(indices), 3):
                        a, b, c = (base + k for k in indices[i:i+3])
                        triangles.append([a, c, b, spec["id"]] if reflected
                                         else [a, b, c, spec["id"]])
        if "camera" in node:
            spec = cameras_policy.get(key)
            require(isinstance(spec, dict), "selected camera node lacks explicit binding/exclusion")
            used_cameras.add(key)
            if exclusion(spec):
                continue
            expected = {"camera", "calibration", "image_domain", "clock", "privacy_domain",
                        "validity_ns", "width", "height", "source_object_id"}
            require(set(spec) == expected, "camera binding fields")
            width = natural(spec["width"], 8192, "camera width", 1)
            height = natural(spec["height"], 8192, "camera height", 1)
            camera = row(document.get("cameras"), node["camera"], "camera index")
            require(camera.get("type") == "perspective" and not camera.get("extensions"),
                    "only perspective cameras are supported")
            p = camera.get("perspective")
            require(isinstance(p, dict) and not p.get("extensions"), "camera perspective")
            yfov = finite(p.get("yfov"), "vertical field of view")
            require(0 < yfov < math.pi, "vertical field of view range")
            near = finite(p.get("znear"), "near clipping plane")
            require(near > 0, "near clipping plane range")
            if "zfar" in p:
                require(finite(p["zfar"], "far clipping plane") > near, "far clipping plane range")
            aspect = finite(p.get("aspectRatio", width/height), "camera aspect ratio")
            require(aspect > 0, "camera aspect ratio range")
            fy = height / (2 * math.tan(yfov/2))
            intrinsics = {"width": width, "height": height, "fx": width/(2*aspect*math.tan(yfov/2)),
                          "fy": fy, "cx": width/2, "cy": height/2}
            binding = {k: spec[k] for k in expected - {"width", "height", "source_object_id"}}
            cameras.append(camera_row(binding=binding, source_object_id=spec["source_object_id"],
                                      matrix_world=matrix, intrinsics=intrinsics))
    require(used_objects == set(objects_policy) and used_cameras == set(cameras_policy),
            "policy references a node absent from the selected scene or of the wrong kind")
    require(cameras, "at least one explicitly bound camera is required")
    policy_sha = hashlib.sha256(json.dumps(policy, sort_keys=True, separators=(",", ":"),
                                          allow_nan=False).encode()).hexdigest()
    scope = f"glTF2/scene={scene_index}/static/RH_Y_UP-to-RH_Z_UP/policy_sha256={policy_sha}"
    twin = encode_twin(source_sha256=source_sha, scope=scope, epoch=policy["epoch"],
                       scale=policy["scale"], geometry_error=policy["geometry_error"],
                       features=[{"id": key, "surface": value} for key, value in features.items()],
                       objects=objects, vertices=vertices, triangles=triangles)
    rig = encode_rig(source_sha256=source_sha, twin_sha256=hashlib.sha256(twin).hexdigest(),
                     geometry_basis=policy["geometry_basis"], evaluation_scope=scope, cameras=cameras)
    return twin, rig


def read_bounded(path, limit):
    require(path.is_file() and not path.is_symlink(), "input must be a regular, non-symlink file")
    with path.open("rb") as stream:
        raw = stream.read(limit + 1)
    require(len(raw) <= limit, "input file exceeds byte bound")
    return raw


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path, help="self-contained .glb or embedded-buffer .gltf")
    parser.add_argument("--policy", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path, help="new FSSTWIN1 geometry file")
    parser.add_argument("--rig-output", required=True, type=Path, help="new camera-rig JSON file")
    args = parser.parse_args()
    try:
        require(args.output.resolve() != args.rig_output.resolve(), "outputs must be distinct")
        require(not args.output.exists() and not args.rig_output.exists(), "output already exists")
        raw = read_bounded(args.source, MAX_BYTES)
        policy = strict_json(read_bounded(args.policy, 4 * 1024 * 1024))
        twin, rig = convert(raw, policy)
        # The rig is the last published object and pins the complete twin child.
        publish_new(args.output, twin)
        publish_new(args.rig_output, rig)
        print(json.dumps({"twin_digest": "sha256:" + hashlib.sha256(twin).hexdigest(),
                          "camera_rig_digest": "sha256:" + hashlib.sha256(rig).hexdigest(),
                          "status": "authored_nominal"}, sort_keys=True))
    except (ValueError, TypeError, KeyError, OverflowError, OSError) as error:
        print(f"glTF import refused: {error}. A publication error may leave a complete twin; "
              "inspect outputs before retrying.", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
