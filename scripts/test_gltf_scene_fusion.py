#!/usr/bin/env python3
"""Synthetic GLB -> authoring CLI -> native scene-fusion CLI regression.

Set FSS_SCENE_FUSE_BIN to an explicitly built native executable. Pixel observations
are calculated independently from glTF camera centers, not from the exported rig.
This checks the cross-language/coordinate boundary, not physical camera accuracy.
"""
import copy
import hashlib
import json
import math
import os
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest


SCRIPTS = Path(__file__).resolve().parent
CENTERS_GLTF = [[-2., 1., 5.], [2., 1., 5.], [0., 3., 5.]]
POSITION = [.3, 1., 1.2]  # RH Z-up property coordinates at REFERENCE.
VELOCITY = [.75, .25, .15]
REFERENCE = 1_500_000_000


def digest(raw):
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def label_digest(label):
    return digest(label.encode("utf-8"))


def synthetic_glb():
    # A physical ground triangle; all camera rays and reconstructed points lie above it.
    data = struct.pack("<9f3H", -10., 0., 10., 10., 0., 10., 0., 0., -10., 0, 1, 2)
    document = {
        "asset": {"version": "2.0", "generator": "FSS synthetic regression"},
        "scene": 0,
        "scenes": [{"nodes": [0, 1, 2, 3]}],
        "nodes": [{"mesh": 0}] + [
            {"camera": 0, "translation": center} for center in CENTERS_GLTF
        ],
        "cameras": [{"type": "perspective", "perspective": {
            "yfov": 2 * math.atan(.6), "aspectRatio": 4 / 3, "znear": .1,
        }}],
        "meshes": [{"primitives": [{"attributes": {"POSITION": 0}, "indices": 1}]}],
        "buffers": [{"byteLength": len(data)}],
        "bufferViews": [
            {"buffer": 0, "byteOffset": 0, "byteLength": 36},
            {"buffer": 0, "byteOffset": 36, "byteLength": 6},
        ],
        "accessors": [
            {"bufferView": 0, "componentType": 5126, "count": 3, "type": "VEC3",
             "min": [-10, 0, -10], "max": [10, 0, 10]},
            {"bufferView": 1, "componentType": 5123, "count": 3, "type": "SCALAR"},
        ],
    }
    encoded = json.dumps(document, sort_keys=True, separators=(",", ":")).encode()
    encoded += b" " * (-len(encoded) % 4)
    data += b"\0" * (-len(data) % 4)
    return (struct.pack("<4sII", b"glTF", 2, 28 + len(encoded) + len(data))
            + struct.pack("<II", len(encoded), 0x4e4f534a) + encoded
            + struct.pack("<II", len(data), 0x004e4942) + data)


def policy(raw):
    return {
        "schema": "fss.gltf-import-policy/1",
        "source_sha256": hashlib.sha256(raw).hexdigest(),
        "scene": 0, "epoch": "synthetic_scene_fusion",
        "scale": {"status": "relative"}, "geometry_error": None,
        "geometry_basis": {"property": 7, "revision": 2},
        "objects": {"0": {"role": "physical", "id": "ground", "feature": "ground",
                          "surface": "grass", "support": True, "opaque": True}},
        "cameras": {str(i): {
            "camera": i, "calibration": 1, "image_domain": 1, "clock": 11,
            "privacy_domain": 9, "validity_ns": [0, 2**64 - 1],
            "width": 640, "height": 480, "source_object_id": f"camera_{i}",
        } for i in range(1, 4)},
    }


def hypothesis(mode):
    if mode == "infer_linear":
        times = [1_000_000_000 + i * 200_000_000 for i in range(6)]
    elif mode == "linear":
        times = [1_000_000_000, 1_400_000_000, 1_800_000_000]
    else:
        times = [REFERENCE] * 3
    observations = []
    for index, when in enumerate(times):
        camera = index % 3
        dt = (when - REFERENCE) * 1e-9 if mode != "static" else 0.
        world = [p + v * dt for p, v in zip(POSITION, VELOCITY)]
        # Independent closed-form glTF projection: +Y up, camera looks along -Z.
        gltf = [world[0], world[2], -world[1]]
        center = CENTERS_GLTF[camera]
        depth = center[2] - gltf[2]
        pixel = [320 + 400 * (gltf[0] - center[0]) / depth,
                 240 - 400 * (gltf[1] - center[1]) / depth]
        observations.append({
            "source_digest": label_digest(f"synthetic_source_{camera}"),
            "evidence_digest": label_digest(f"synthetic_{mode}_{index}"),
            "camera": camera + 1, "track": 42, "exposure": index + 1,
            "image_domain": 1, "capture_ns": [str(when), str(when)],
            "pixel_min": list(pixel), "pixel_max": list(pixel),
            "visible_contact": True, "sigma_pixels": .5,
        })
    motion = {"kind": mode}
    if mode == "linear":
        motion.update(velocity_per_second=VELOCITY,
                      evidence=label_digest("synthetic_external_velocity"))
    elif mode == "infer_linear":
        motion["max_capture_uncertainty_ns"] = "0"
    return {
        "id": mode, "association_evidence": label_digest(f"synthetic_association_{mode}"),
        "motion": motion, "max_capture_span_ns": "1000000000",
        "observations": observations,
    }


class GltfNativeFusionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        binary = os.environ.get("FSS_SCENE_FUSE_BIN")
        if not binary:
            raise unittest.SkipTest("set FSS_SCENE_FUSE_BIN to the built native CLI")
        cls.binary = Path(binary).resolve(strict=True)
        if not cls.binary.is_file():
            raise ValueError("FSS_SCENE_FUSE_BIN must name an executable file")

    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="fss-gltf-native-")
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name)
        self.source = self.directory / "property.glb"
        self.policy = self.directory / "policy.json"
        self.twin = self.directory / "property.fsstwin"
        self.rig = self.directory / "property.cameras.json"
        self.query = self.directory / "observations.json"
        self.report = self.directory / "report.json"
        raw = synthetic_glb()
        self.source.write_bytes(raw)
        self.policy.write_text(json.dumps(policy(raw)), encoding="utf-8")
        imported = subprocess.run([
            sys.executable, str(SCRIPTS / "import_gltf_twin.py"), str(self.source),
            "--policy", str(self.policy), "--output", str(self.twin),
            "--rig-output", str(self.rig),
        ], capture_output=True, text=True, timeout=30)
        self.assertEqual(imported.returncode, 0, imported.stderr)
        receipt = json.loads(imported.stdout)
        self.assertEqual(receipt["twin_digest"], digest(self.twin.read_bytes()))
        self.assertEqual(receipt["camera_rig_digest"], digest(self.rig.read_bytes()))
        self.document = {
            "schema": "fss.scene_fusion_query.v1",
            "camera_rig_digest": digest(self.rig.read_bytes()),
            "privacy_domain": 9, "clock": 11,
            "clock_evidence": label_digest("synthetic_common_clock"),
            "reference_time_ns": str(REFERENCE),
            "hypotheses": [hypothesis(mode) for mode in ("static", "linear", "infer_linear")],
        }

    def run_fusion(self, document):
        self.query.write_text(json.dumps(document), encoding="utf-8")
        return subprocess.run([
            str(self.binary), "--twin", str(self.twin), "--rig", str(self.rig),
            "--observations", str(self.query), "--report-out", str(self.report),
        ], capture_output=True, text=True, timeout=30)

    def test_real_converter_and_native_cli_reconstruct_one_common_scene(self):
        completed = self.run_fusion(self.document)
        self.assertEqual(completed.returncode, 0, completed.stderr + completed.stdout)
        report = json.loads(self.report.read_bytes())["report"]
        self.assertEqual(json.loads(completed.stdout)["report"], report)
        self.assertEqual(report["counts"], {"total": 3, "solved": 3, "refused": 0})
        self.assertEqual(report["basis"]["source_scene_digest"], digest(self.source.read_bytes()))
        self.assertEqual(report["basis"]["twin_digest"], digest(self.twin.read_bytes()))
        self.assertEqual(report["basis"]["camera_rig_digest"], digest(self.rig.read_bytes()))
        self.assertEqual(report["basis"]["coordinate_frame"], "RH_Z_UP")
        self.assertEqual(report["basis"]["scale"]["kind"], "relative")
        self.assertTrue(all(c["status"] == "authored_nominal" for c in report["cameras"]))
        for result in report["hypotheses"]:
            with self.subTest(mode=result["id"]):
                self.assertEqual(result["knowledge"], "estimated")
                estimate = result["estimate"]
                self.assertEqual(estimate["reference_time_ns"], str(REFERENCE))
                for actual, expected in zip(estimate["position"], POSITION):
                    self.assertAlmostEqual(actual, expected, delta=1e-7)
                self.assertFalse(estimate["nominal_occlusion_conflict"])
                self.assertLess(estimate["rms_reprojection_pixels"], 1e-7)
                dimension = 6 if result["id"] == "infer_linear" else 3
                self.assertEqual(len(estimate["pixel_noise_covariance"]), dimension)
                self.assertEqual(len(estimate["views"]), len(result["observations"]))
                if result["id"] == "infer_linear":
                    for actual, expected in zip(estimate["velocity_per_second"], VELOCITY):
                        self.assertAlmostEqual(actual, expected, delta=1e-7)

    def test_changed_rig_file_cannot_silently_reuse_observation_pins(self):
        # Even a semantic-preserving file edit requires an updated explicit query pin.
        self.rig.write_bytes(self.rig.read_bytes() + b"\n")
        completed = self.run_fusion(self.document)
        self.assertEqual(completed.returncode, 2, completed.stderr)
        self.assertFalse(self.report.exists())
        self.assertIn("digest", completed.stderr)

    def test_geometric_refusal_survives_beside_other_imported_scene_features(self):
        query = copy.deepcopy(self.document)
        bad = next(h for h in query["hypotheses"] if h["id"] == "infer_linear")
        for key in ("pixel_min", "pixel_max"):
            bad["observations"][-1][key][0] += 100
        completed = self.run_fusion(query)
        self.assertEqual(completed.returncode, 3, completed.stderr + completed.stdout)
        report = json.loads(self.report.read_bytes())["report"]
        self.assertEqual(report["counts"], {"total": 3, "solved": 2, "refused": 1})
        bad_result = next(h for h in report["hypotheses"] if h["id"] == "infer_linear")
        self.assertEqual(bad_result["outcome"], "refused")
        self.assertEqual(len(bad_result["observations"]), 6)
        self.assertEqual(bad_result["estimate"]["state"], "unavailable")


if __name__ == "__main__":
    unittest.main()
