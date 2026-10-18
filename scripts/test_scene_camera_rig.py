#!/usr/bin/env python3
"""Camera convention, binding and mocked authoring tests; no real Blender claim."""
import copy
import hashlib
import json
import math
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest

from export_blender_twin import evaluation_scope, export_camera_rig, load_policy
from scene_camera_rig import blender_intrinsics, camera_row, encode_rig, world_to_camera
from twin_interchange import encode_twin, fixture


def binding(camera=1):
    return {"camera": camera, "calibration": 4, "image_domain": camera+10, "clock": 7,
            "privacy_domain": 9, "validity_ns": [0, 2**64-1]}


def intrinsic(**overrides):
    args = dict(width=1920, height=1080, lens_mm=50, sensor_width_mm=36,
                sensor_height_mm=24, sensor_fit="HORIZONTAL")
    args.update(overrides)
    return blender_intrinsics(**args)


IDENTITY = [[1., 0., 0., 0.], [0., 1., 0., 0.], [0., 0., 1., 0.], [0., 0., 0., 1.]]


class SceneCameraMathTests(unittest.TestCase):
    def test_independent_right_up_forward_axes_and_camera_center(self):
        matrix = copy.deepcopy(IDENTITY)
        matrix[0][3], matrix[1][3], matrix[2][3] = 2., -3., 7.
        pose = world_to_camera(matrix)
        self.assertEqual(pose, {"rotation": [[1., 0., 0.], [0., -1., 0.], [0., 0., -1.]],
                                "translation": [-2., -3., 7.]})
        def camera_point(point):
            return [sum(x*y for x, y in zip(row, point))+pose["translation"][i]
                    for i, row in enumerate(pose["rotation"])]
        self.assertEqual(camera_point([2, -3, 2]), [0, 0, 5])
        self.assertEqual(camera_point([3, -3, 2]), [1, 0, 5])
        self.assertEqual(camera_point([2, -2, 2]), [0, -1, 5])
        self.assertEqual(camera_point([2, -3, 9]), [0, 0, -2])

    def test_evaluated_parent_rotation_and_translation_not_object_origin(self):
        # Evaluated rotation: local right = world +Y, up = world +Z, backwards = world +X.
        # Its optical center is [4,5,6] in the property's frame, regardless of parent origin.
        matrix = [[0, 0, 1, 4], [1, 0, 0, 5], [0, 1, 0, 6], [0, 0, 0, 1]]
        pose = world_to_camera(matrix)
        self.assertEqual(pose["rotation"], [[0, 1, 0], [0, 0, -1], [-1, 0, 0]])
        self.assertEqual(pose["translation"], [-5, 6, 4])
        # Point [-6,7,9] is ten forward, two right, three up, independently of the converter.
        self.assertEqual([sum(a*b for a,b in zip(r, [-6,7,9]))+t
                          for r,t in zip(pose["rotation"], pose["translation"])], [2,-3,10])

    def test_scale_shear_reflection_nonfinite_and_projective_transforms_refused(self):
        for i,j,value in [(0,0,2), (0,1,.1), (0,0,-1), (1,1,0), (0,3,math.inf), (3,0,.01)]:
            matrix = copy.deepcopy(IDENTITY); matrix[i][j] = value
            with self.subTest(entry=(i,j,value)), self.assertRaises(ValueError):
                world_to_camera(matrix)

    def test_float_roundoff_is_orthonormalized_before_native_rotation_check(self):
        c = math.sqrt(.5)
        pose = world_to_camera([[c+1e-8,-c,0,0], [c,c,0,0], [0,0,1,0], [0,0,0,1]])
        r = pose["rotation"]
        for i in range(3):
            for j in range(3):
                self.assertAlmostEqual(sum(a*b for a,b in zip(r[i],r[j])), 1.0 if i==j else 0.0, places=14)

    def test_horizontal_vertical_and_auto_portrait_sensor_fit(self):
        horizontal = intrinsic()
        self.assertAlmostEqual(horizontal["fx"], 50*1920/36)
        self.assertAlmostEqual(horizontal["fy"], 50*1920/36)
        self.assertEqual([horizontal["cx"],horizontal["cy"]], [960,540])
        vertical = intrinsic(width=720,height=1280,sensor_fit="VERTICAL")
        auto = intrinsic(width=720,height=1280,sensor_fit="AUTO")
        self.assertAlmostEqual(vertical["fy"], 50*1280/24)
        self.assertAlmostEqual(auto["fy"], 50*1280/36)
        self.assertNotEqual(vertical["fy"], auto["fy"])

    def test_non_square_pixels_and_lens_shift_against_independent_frame_edges(self):
        k = intrinsic(width=800,height=600,lens_mm=40,sensor_width_mm=32,
                      pixel_aspect=[2,1],shift=[.1,-.2])
        self.assertEqual(k, {"width":800,"height":600,"fx":1000,"fy":2000,"cx":320,"cy":-20})
        # At unit depth the physical near-plane spans x=[-.32,.48], y(up)=[-.31,-.01].
        self.assertEqual(k["fx"]*(-.32)+k["cx"], 0)
        self.assertEqual(k["fx"]*.48+k["cx"], 800)
        self.assertEqual(k["fy"]*.01+k["cy"], 0)
        self.assertEqual(k["fy"]*.31+k["cy"], 600)

    def test_invalid_lens_modes_dimensions_and_aspect_refused(self):
        for override in ({"lens_mm":0}, {"sensor_fit":"PANORAMIC"}, {"pixel_aspect":[0,1]},
                         {"width":0}, {"height":True}, {"shift":[math.nan,0]}, {"sensor_height_mm":-1}):
            with self.subTest(override=override), self.assertRaises(ValueError):
                intrinsic(**override)

    def test_rig_canonical_camera_order_unknown_error_and_identity_pins(self):
        a = camera_row(binding=binding(1),source_object_id="camera-a",matrix_world=IDENTITY,intrinsics=intrinsic())
        b = camera_row(binding=binding(2),source_object_id="camera-b",matrix_world=IDENTITY,intrinsics=intrinsic())
        args = dict(source_sha256="01"*32,twin_sha256="02"*32,geometry_basis={"property":3,"revision":4},
                    evaluation_scope="synthetic/Z-up/frame=0")
        encoded = encode_rig(**args,cameras=[b,a])
        self.assertEqual(encoded, encode_rig(**args,cameras=[a,b]))
        rig = json.loads(encoded)
        self.assertEqual([row["camera"] for row in rig["cameras"]], [1,2])
        self.assertTrue(all(row["error"] is None and row["status"] == "authored_nominal" for row in rig["cameras"]))
        self.assertEqual(rig["source_scene_digest"],"sha256:"+"01"*32)
        self.assertEqual(rig["twin_digest"],"sha256:"+"02"*32)
        for bad in [dict(b,camera=1),dict(b,source_object_id="camera-a"),dict(b,error=0),dict(b,clock=0),
                    dict(b,validity_ns=[10,9]),dict(b,status="qualified")]:
            with self.assertRaises(ValueError): encode_rig(**args,cameras=[a,bad])


class BlenderCameraExportTests(unittest.TestCase):
    def setup_export(self, tmp):
        source = Path(tmp)/"synthetic.blend"
        source.write_bytes(b"synthetic mock; not a real Blender file")
        row = dict(binding(), image_size=[640,480],pixel_aspect=[1,1],image_model="undistorted_pinhole")
        policy = dict(schema="fss.blender-export-policy/2",source_sha256=hashlib.sha256(source.read_bytes()).hexdigest(),
                      scene="Scene",view_layer="ViewLayer",frame=1,epoch="synthetic",scale={"status":"relative"},
                      geometry_error=None,objects={},geometry_basis={"property":1,"revision":1},cameras={"authored-camera":row})
        camera = SimpleNamespace(type="PERSP",lens=50,sensor_width=36,sensor_height=24,sensor_fit="HORIZONTAL",shift_x=0,shift_y=0)
        obj = SimpleNamespace(type="CAMERA",original={"hhm_object_id":"authored-camera"},data=camera)
        instance = SimpleNamespace(object=obj,matrix_world=IDENTITY)
        graph = SimpleNamespace(object_instances=[instance])
        render = SimpleNamespace(use_border=False,use_crop_to_border=False)
        scene = SimpleNamespace(name="Scene",frame_current=1,render=render)
        window = SimpleNamespace(scene=scene,view_layer=SimpleNamespace(name="ViewLayer"))
        bpy = SimpleNamespace(data=SimpleNamespace(filepath=str(source)),context=SimpleNamespace(window=window),
                              context_placeholder=None)
        bpy.context.evaluated_depsgraph_get = lambda: graph
        geometry = fixture(); geometry["source_sha256"] = policy["source_sha256"]
        geometry["scope"] = evaluation_scope(policy, "03"*32)
        return bpy,policy,graph,encode_twin(**geometry)

    def test_selected_evaluated_camera_exports_bounded_rig_and_leaves_source_unchanged(self):
        with tempfile.TemporaryDirectory() as tmp:
            bpy,policy,graph,twin = self.setup_export(tmp)
            ignored = copy.deepcopy(graph.object_instances[0]); ignored.object.original["hhm_object_id"]="inspection-camera"
            graph.object_instances.append(ignored)
            before = Path(bpy.data.filepath).read_bytes()
            rig = json.loads(export_camera_rig(bpy,policy,"03"*32,twin))
            self.assertEqual(len(rig["cameras"]),1)
            self.assertEqual(rig["twin_digest"],"sha256:"+hashlib.sha256(twin).hexdigest())
            self.assertEqual(rig["evaluation_scope"],evaluation_scope(policy,"03"*32))
            self.assertEqual(rig["cameras"][0]["intrinsics"]["width"],640)
            self.assertEqual(Path(bpy.data.filepath).read_bytes(),before)

    def test_camera_instance_ambiguity_missing_camera_crop_and_lens_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            bpy,policy,graph,twin = self.setup_export(tmp)
            graph.object_instances *= 2
            with self.assertRaises(ValueError): export_camera_rig(bpy,policy,"03"*32,twin)
            graph.object_instances = []
            with self.assertRaises(ValueError): export_camera_rig(bpy,policy,"03"*32,twin)
            bpy,policy,graph,twin = self.setup_export(tmp)
            bpy.context.window.scene.render.use_border = True
            with self.assertRaises(ValueError): export_camera_rig(bpy,policy,"03"*32,twin)
            bpy.context.window.scene.render.use_border = False
            for kind in ("ORTHO","PANO","CUSTOM"):
                graph.object_instances[0].object.data.type = kind
                with self.assertRaises(ValueError): export_camera_rig(bpy,policy,"03"*32,twin)

    def test_old_geometry_policy_compatible_and_new_camera_policy_strict(self):
        with tempfile.TemporaryDirectory() as tmp:
            _,policy,_,_ = self.setup_export(tmp)
            path = Path(tmp)/"policy.json"
            path.write_text(json.dumps(policy))
            self.assertEqual(load_policy(path)[0],policy)
            bad = copy.deepcopy(policy); bad["cameras"]["authored-camera"]["image_model"]="raw_fisheye"
            path.write_text(json.dumps(bad))
            with self.assertRaises(ValueError): load_policy(path)
            policy["schema"]="fss.blender-export-policy/1"
            del policy["cameras"],policy["geometry_basis"]
            path.write_text(json.dumps(policy))
            self.assertEqual(load_policy(path)[0],policy)


if __name__ == "__main__":
    unittest.main()
