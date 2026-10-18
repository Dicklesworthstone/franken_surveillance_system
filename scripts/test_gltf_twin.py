#!/usr/bin/env python3
"""Independent synthetic glTF authoring regressions; no native/field qualification."""
from __future__ import annotations

import base64
import copy
import hashlib
import json
import math
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest

import import_gltf_twin as importer


def fixture():
    """Asymmetry makes axis swaps, parent-order errors and reflection visible."""
    positions = [(1., 0., 0.), (0., 1., 0.), (0., 0., 1.)]
    binary = b"".join(struct.pack("<ffff", *point, 123.) for point in positions)
    binary += struct.pack("<HHH", 0, 1, 2)
    document = {
        "asset": {"version": "2.0"}, "scene": 0, "scenes": [{"nodes": [0]}],
        "nodes": [
            {"translation": [10, 20, 30],
             "rotation": [0, math.sqrt(.5), 0, math.sqrt(.5)], "children": [1, 2]},
            {"mesh": 0, "translation": [4, 5, 6], "scale": [-2, 3, 4]},
            {"camera": 0, "translation": [1, 2, 3]},
        ],
        "bufferViews": [
            {"buffer": 0, "byteOffset": 0, "byteLength": 48, "byteStride": 16},
            {"buffer": 0, "byteOffset": 48, "byteLength": 6},
        ],
        "accessors": [
            {"bufferView": 0, "componentType": 5126, "count": 3, "type": "VEC3"},
            {"bufferView": 1, "componentType": 5123, "count": 3, "type": "SCALAR"},
        ],
        "meshes": [{"primitives": [{"attributes": {"POSITION": 0}, "indices": 1}]}],
        "cameras": [{"type": "perspective", "perspective": {
            "yfov": math.pi / 2, "znear": .1, "aspectRatio": 2.}}],
    }
    policy = {
        "schema": "fss.gltf-import-policy/1", "source_sha256": "",
        "scene": 0, "epoch": "independent_synthetic_oracle",
        "scale": {"status": "relative"}, "geometry_error": None,
        "geometry_basis": {"property": 1, "revision": 2},
        "objects": {"1": {"role": "physical", "id": "triangle",
                          "feature": "surface", "surface": "structure",
                          "support": False, "opaque": True}},
        "cameras": {"2": {"camera": 1, "calibration": 2, "image_domain": 3,
                          "clock": 4, "privacy_domain": 5, "validity_ns": [0, 100],
                          "width": 800, "height": 600, "source_object_id": "camera"}},
    }
    return document, binary, policy


def source(document, binary, glb=False):
    document = copy.deepcopy(document)
    document["buffers"] = [{"byteLength": len(binary)}]
    if not glb:
        document["buffers"][0]["uri"] = (
            "data:application/octet-stream;base64," + base64.b64encode(binary).decode())
        return json.dumps(document, separators=(",", ":")).encode()
    body = json.dumps(document, separators=(",", ":")).encode()
    body += b" " * (-len(body) % 4)
    binary += b"\0" * (-len(binary) % 4)
    return (struct.pack("<4sII", b"glTF", 2, 28 + len(body) + len(binary))
            + struct.pack("<II", len(body), 0x4E4F534A) + body
            + struct.pack("<II", len(binary), 0x004E4942) + binary)


def pinned(policy, raw):
    policy = copy.deepcopy(policy)
    policy["source_sha256"] = hashlib.sha256(raw).hexdigest()
    return policy


def convert(document, binary, policy, glb=False):
    raw = source(document, binary, glb)
    twin, rig = importer.convert(raw, pinned(policy, raw))
    return twin, json.loads(rig), raw


def inspect_twin(blob):
    """Read the actual wire output independently of the authoring encoder."""
    if (blob[:8] != b"FSSTWIN1"
            or struct.unpack_from("<Q", blob, 8)[0] != len(blob) - 48
            or hashlib.sha256(blob[:-32]).digest() != blob[-32:]):
        raise AssertionError("invalid FSSTWIN1 framing or checksum")
    cursor = 48

    def unpack(fmt):
        nonlocal cursor
        value = struct.unpack_from(fmt, blob, cursor)
        cursor += struct.calcsize(fmt)
        return value

    def text():
        nonlocal cursor
        length, = unpack("<H")
        value = blob[cursor:cursor + length].decode()
        cursor += length
        return value

    scope, epoch = text(), text()
    scale = unpack("<Bddd")
    feature_count, object_count, vertex_count, triangle_count = unpack("<IIII")
    features = [(text(), unpack("<B")) for _ in range(feature_count)]
    objects = [(text(), unpack("<IBB")) for _ in range(object_count)]
    vertices = [unpack("<ddd") for _ in range(vertex_count)]
    triangles = [unpack("<IIII") for _ in range(triangle_count)]
    if cursor != len(blob) - 32:
        raise AssertionError("wire counts do not consume the payload")
    return {"source": blob[16:48].hex(), "scope": scope, "epoch": epoch,
            "scale": scale, "features": features, "objects": objects,
            "vertices": vertices, "triangles": triangles}


def set_path(value, path, replacement):
    for key in path[:-1]:
        value = value[key]
    value[path[-1]] = replacement


class GltfTwinTests(unittest.TestCase):
    def assert_vector(self, actual, expected):
        self.assertEqual(len(actual), len(expected))
        for a, b in zip(actual, expected):
            self.assertAlmostEqual(a, b, places=10)

    def assert_scene_oracle(self, twin, rig):
        scene = inspect_twin(twin)
        # Calculated from T(10,20,30) * Ry(90deg) * T(4,5,6) * S(-2,3,4),
        # then (x,y,z)_glTF -> (x,-z,y)_property. No importer math is reused.
        for actual, expected in zip(scene["vertices"],
                                    [(16, -28, 25), (16, -26, 28), (20, -26, 25)]):
            self.assert_vector(actual, expected)
        self.assertEqual(len(scene["vertices"]), 3)
        self.assertEqual(scene["triangles"], [(0, 2, 1, 0)])
        self.assertEqual(scene["objects"], [("triangle", (0, 0, 1))])
        camera, = rig["cameras"]
        pose = camera["world_to_camera"]
        for actual, expected in zip(pose["rotation"],
                                    [[0, 1, 0], [0, 0, -1], [-1, 0, 0]]):
            self.assert_vector(actual, expected)
        self.assert_vector(pose["translation"], [29, 22, 13])
        self.assertIsNone(camera["error"])
        self.assertEqual(camera["status"], "authored_nominal")
        # Camera-local (right=2, up=1, forward=5) is this independently
        # specified point after the parent and world-basis transforms.
        point = [8, -27, 23]
        xyz = [sum(row[i] * point[i] for i in range(3)) + pose["translation"][j]
               for j, row in enumerate(pose["rotation"])]
        self.assert_vector(xyz, [2, -1, 5])
        k = camera["intrinsics"]
        self.assert_vector([k["fx"], k["fy"], k["cx"], k["cy"]], [200, 300, 400, 300])
        self.assert_vector([k["fx"] * xyz[0] / xyz[2] + k["cx"],
                            k["fy"] * xyz[1] / xyz[2] + k["cy"]], [480, 240])

    def test_embedded_and_glb_preserve_independent_geometry_and_camera_oracle(self):
        document, binary, policy = fixture()
        a, arig, araw = convert(document, binary, policy)
        b, brig, braw = convert(document, binary, policy, glb=True)
        for twin, rig, raw in [(a, arig, araw), (b, brig, braw)]:
            self.assert_scene_oracle(twin, rig)
            self.assertEqual(rig["source_scene_digest"], "sha256:" + hashlib.sha256(raw).hexdigest())
            self.assertEqual(rig["twin_digest"], "sha256:" + hashlib.sha256(twin).hexdigest())
            self.assertEqual(rig["evaluation_scope"], inspect_twin(twin)["scope"])
        self.assertEqual(arig["cameras"], brig["cameras"])
        for key in ["features", "objects", "vertices", "triangles", "scale"]:
            self.assertEqual(inspect_twin(a)[key], inspect_twin(b)[key])
        self.assertNotEqual(a, b)  # Source identity distinguishes representations.
        self.assertEqual(importer.convert(araw, pinned(policy, araw)),
                         importer.convert(araw, pinned(policy, araw)))

    def test_column_major_parent_matrix_matches_independent_trs_oracle(self):
        document, binary, policy = fixture()
        # These are columns, not rows. Translation belongs in the last column.
        document["nodes"][0] = {
            "matrix": [0, 0, -1, 0, 0, 1, 0, 0, 1, 0, 0, 0, 10, 20, 30, 1],
            "children": [1, 2],
        }
        twin, rig, _ = convert(document, binary, policy)
        self.assert_scene_oracle(twin, rig)

    def test_unsigned_index_widths_and_nonindexed_triangles(self):
        for component, fmt in [(5121, "B"), (5123, "H"), (5125, "I"), (None, None)]:
            with self.subTest(component=component):
                document, binary, policy = fixture()
                if component is None:
                    del document["meshes"][0]["primitives"][0]["indices"]
                else:
                    indices = struct.pack("<" + fmt * 3, 0, 1, 2)
                    binary = binary[:48] + indices
                    document["accessors"][1]["componentType"] = component
                    document["bufferViews"][1]["byteLength"] = len(indices)
                self.assert_scene_oracle(*convert(document, binary, policy)[:2])

    def test_viewport_aspect_fallback_and_parent_camera_transform_refusals(self):
        document, binary, policy = fixture()
        del document["cameras"][0]["perspective"]["aspectRatio"]
        _, rig, _ = convert(document, binary, policy)
        k = rig["cameras"][0]["intrinsics"]
        self.assert_vector([k["fx"], k["fy"]], [300, 300])
        for scale in [[2, 2, 2], [-1, 1, 1], [0, 1, 1]]:
            with self.subTest(scale=scale):
                document, binary, policy = fixture()
                document["nodes"][0]["scale"] = scale
                with self.assertRaises(ValueError):
                    convert(document, binary, policy)
        for field, value in [("yfov", 0), ("yfov", math.pi), ("aspectRatio", 0),
                             ("znear", 0), ("zfar", .05)]:
            with self.subTest(field=field, value=value):
                document, binary, policy = fixture()
                document["cameras"][0]["perspective"][field] = value
                with self.assertRaises(ValueError):
                    convert(document, binary, policy)

    def test_source_hash_and_camera_mode_changes_bind_both_outputs(self):
        document, binary, policy = fixture()
        raw = source(document, binary)
        bound = pinned(policy, raw)
        with self.assertRaisesRegex(ValueError, "source digest mismatch"):
            importer.convert(raw + b" ", bound)
        a, arig = importer.convert(raw, bound)
        changed = copy.deepcopy(bound)
        changed["cameras"]["2"]["calibration"] += 1
        b, brig = importer.convert(raw, changed)
        self.assertNotEqual(a, b)
        self.assertNotEqual(arig, brig)
        self.assertNotEqual(inspect_twin(a)["scope"], inspect_twin(b)["scope"])
        self.assertEqual(inspect_twin(a)["vertices"], inspect_twin(b)["vertices"])

    def test_policy_requires_complete_selected_object_and_camera_bindings(self):
        for kind, replacement in [
                ("objects", {}), ("cameras", {}),
                ("objects", {"2": "wrong_node_kind"}),
                ("cameras", {"02": "noncanonical_index"})]:
            with self.subTest(kind=kind, replacement=replacement):
                document, binary, policy = fixture()
                policy[kind] = replacement
                with self.assertRaises(ValueError):
                    convert(document, binary, policy)
        document, binary, policy = fixture()
        policy["objects"]["999"] = copy.deepcopy(policy["objects"]["1"])
        with self.assertRaisesRegex(ValueError, "absent from the selected scene"):
            convert(document, binary, policy)

    def test_explicit_exclusions_do_not_turn_authoring_helpers_into_physical_geometry(self):
        document, binary, policy = fixture()
        document["nodes"][0]["children"].append(3)
        document["nodes"].append({"mesh": 0, "camera": 0, "translation": [100, 0, 0]})
        for key in ["objects", "cameras"]:
            policy[key]["3"] = {"role": "exclude", "reason": "authoring inspection helper"}
        self.assert_scene_oracle(*convert(document, binary, policy)[:2])
        policy["cameras"]["3"].pop("reason")
        with self.assertRaisesRegex(ValueError, "exclusion fields"):
            convert(document, binary, policy)

    def test_unsupported_or_unevaluated_geometry_is_refused(self):
        cases = [
            (("animations",), [{}]),
            (("extensionsRequired",), ["KHR_draco_mesh_compression"]),
            (("nodes", 1, "skin"), 0),
            (("nodes", 1, "extensions"), {"EXT_mesh_gpu_instancing": {}}),
            (("meshes", 0, "primitives", 0, "targets"), [{"POSITION": 0}]),
            (("meshes", 0, "primitives", 0, "mode"), 5),
            (("accessors", 0, "sparse"), {"count": 1}),
            (("accessors", 0, "normalized"), True),
            (("cameras", 0, "type"), "orthographic"),
        ]
        for path, value in cases:
            with self.subTest(path=path):
                document, binary, policy = fixture()
                set_path(document, path, value)
                with self.assertRaises(ValueError):
                    convert(document, binary, policy)

    def test_external_buffers_and_unreferenced_binary_are_never_loaded(self):
        document, binary, policy = fixture()
        document = json.loads(source(document, binary))
        for uri in ["geometry.bin", "../geometry.bin", "https://example.invalid/geometry.bin"]:
            with self.subTest(uri=uri):
                document["buffers"][0]["uri"] = uri
                raw = json.dumps(document).encode()
                with self.assertRaisesRegex(ValueError, "external buffer URIs are unsupported"):
                    importer.convert(raw, pinned(policy, raw))
        with self.assertRaisesRegex(ValueError, "unreferenced GLB BIN chunk"):
            importer.buffers({"buffers": []}, b"\0\0\0\0")

    def test_accessor_bounds_nonfinite_vertices_and_triangle_integrity(self):
        cases = [
            (("bufferViews", 0, "byteStride"), 8),
            (("bufferViews", 0, "byteStride"), 14),
            (("bufferViews", 0, "byteStride"), 256),
            (("bufferViews", 1, "byteLength"), 5),
            (("bufferViews", 1, "byteStride"), 2),
            (("accessors", 0, "count"), importer.MAX_VERTICES + 1),
            (("accessors", 0, "bufferView"), 99),
        ]
        for path, value in cases:
            with self.subTest(path=path, value=value):
                document, binary, policy = fixture()
                set_path(document, path, value)
                with self.assertRaises(ValueError):
                    convert(document, binary, policy)
        for name, change in [
                ("nonfinite", lambda b: struct.pack("<f", math.nan) + b[4:]),
                ("degenerate", lambda b: b[:48] + struct.pack("<HHH", 0, 0, 2)),
                ("out_of_range", lambda b: b[:48] + struct.pack("<HHH", 0, 1, 3))]:
            with self.subTest(name=name):
                document, binary, policy = fixture()
                with self.assertRaises(ValueError):
                    convert(document, change(binary), policy)

    def test_accessor_relative_offset_must_be_aligned_even_when_absolute_offset_is_aligned(self):
        document, binary, policy = fixture()
        # Absolute offset 49+1=50 is u16-aligned, but accessor offset 1 is not.
        # A reader checking only the absolute address would silently accept this.
        binary = binary[:48] + b"\0\0" + binary[48:]
        document["bufferViews"][1].update(byteOffset=49, byteLength=7)
        document["accessors"][1]["byteOffset"] = 1
        with self.assertRaisesRegex(ValueError, "misaligned accessor"):
            convert(document, binary, policy)

    def test_primitive_restart_sentinels_are_refused_at_every_index_width(self):
        for component, fmt, sentinel in [(5121, "B", 255), (5123, "H", 65535),
                                          (5125, "I", 4294967295)]:
            with self.subTest(component=component):
                raw = struct.pack("<" + fmt * 3, 0, 1, sentinel)
                document = {
                    "accessors": [{"bufferView": 0, "componentType": component,
                                   "count": 3, "type": "SCALAR"}],
                    "bufferViews": [{"buffer": 0, "byteLength": len(raw)}],
                }
                # Exercise the reader before mesh size checks can mask this guard.
                with self.assertRaisesRegex(ValueError, "primitive restart indices"):
                    importer.accessor(document, [raw], 0, False)

    def test_node_forest_cycles_multiple_parents_and_depth_bounds(self):
        for case in ["unselected_cycle", "multiple_parents", "nonroot_scene_root", "depth", "count"]:
            with self.subTest(case=case):
                document, binary, policy = fixture()
                if case == "unselected_cycle":
                    document["nodes"] += [{"children": [4]}, {"children": [3]}]
                elif case == "multiple_parents":
                    document["nodes"].append({"children": [1]})
                elif case == "nonroot_scene_root":
                    document["scenes"][0]["nodes"] = [1]
                elif case == "depth":
                    document["nodes"] = [{"children": [i + 1]} for i in range(130)] + [{}]
                else:
                    document["nodes"] = [{} for _ in range(importer.MAX_NODES + 1)]
                with self.assertRaises(ValueError):
                    convert(document, binary, policy)

    def test_glb_framing_truncation_and_padding_fail_closed(self):
        document, binary, policy = fixture()
        valid = source(document, binary, glb=True)
        wrong_version = bytearray(valid)
        struct.pack_into("<I", wrong_version, 4, 1)
        truncated = bytearray(valid[:-1])
        struct.pack_into("<I", truncated, 8, len(truncated))
        wrong_first_kind = bytearray(valid)
        struct.pack_into("<I", wrong_first_kind, 16, 0x004E4942)
        nonaligned_chunk = bytearray(valid)
        struct.pack_into("<I", nonaligned_chunk, 12, struct.unpack_from("<I", valid, 12)[0] - 1)
        extra_chunk = bytearray(valid + struct.pack("<II", 4, 1) + b"junk")
        struct.pack_into("<I", extra_chunk, 8, len(extra_chunk))
        cases = [valid[:11], valid[:-1], wrong_version, truncated, wrong_first_kind,
                 nonaligned_chunk, extra_chunk, valid[:-1] + b"\1"]
        for index, raw in enumerate(cases):
            with self.subTest(case=index):
                raw = bytes(raw)
                with self.assertRaises(ValueError):
                    importer.convert(raw, pinned(policy, raw))

    def test_json_duplicate_keys_depth_and_nonfinite_numbers_are_refused(self):
        for raw in [b'{"asset":{},"asset":{}}', b'{"x":NaN}', b'{"x":Infinity}',
                    b'{"x":"\xff"}', b'{"x":' + b'[' * 65 + b'0' + b']' * 65 + b'}']:
            with self.subTest(raw=raw[:40]):
                with self.assertRaises(ValueError):
                    importer.unpack_source(raw)

    def test_cli_publishes_the_pinned_pair_once_and_refuses_partial_overwrite(self):
        document, binary, policy = fixture()
        raw = source(document, binary, glb=True)
        policy = pinned(policy, raw)
        expected_twin, expected_rig = importer.convert(raw, policy)
        script = str(Path(importer.__file__).resolve())
        with tempfile.TemporaryDirectory() as directory:
            directory = Path(directory)
            source_path, policy_path = directory / "source.glb", directory / "policy.json"
            twin_path, rig_path = directory / "property.fsstwin", directory / "cameras.json"
            source_path.write_bytes(raw)
            policy_path.write_text(json.dumps(policy))

            def run(twin=twin_path, rig=rig_path):
                return subprocess.run(
                    [sys.executable, "-B", script, str(source_path), "--policy", str(policy_path),
                     "--output", str(twin), "--rig-output", str(rig)],
                    capture_output=True, text=True, timeout=10, check=False)

            result = run()
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(twin_path.read_bytes(), expected_twin)
            self.assertEqual(rig_path.read_bytes(), expected_rig)
            report = json.loads(result.stdout)
            self.assertEqual(report["twin_digest"], "sha256:" + hashlib.sha256(expected_twin).hexdigest())
            self.assertEqual(report["camera_rig_digest"], "sha256:" + hashlib.sha256(expected_rig).hexdigest())
            self.assertEqual(run().returncode, 2)
            second_twin = directory / "second.fsstwin"
            self.assertEqual(run(twin=second_twin).returncode, 2)
            self.assertFalse(second_twin.exists())
            self.assertEqual(twin_path.read_bytes(), expected_twin)
            self.assertEqual(rig_path.read_bytes(), expected_rig)
            new_rig = directory / "second.json"
            policy["source_sha256"] = "01" * 32
            policy_path.write_text(json.dumps(policy))
            self.assertEqual(run(twin=second_twin, rig=new_rig).returncode, 2)
            self.assertFalse(second_twin.exists())
            self.assertFalse(new_rig.exists())
            self.assertFalse(any(p.name.startswith(".fss-twin-") for p in directory.iterdir()))


if __name__ == "__main__":
    unittest.main()
