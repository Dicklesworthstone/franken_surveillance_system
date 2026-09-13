#!/usr/bin/env python3
"""Executable authoring-format tests. These do not substitute for Rust/Blender runs."""
import copy
import hashlib
import math
from pathlib import Path
import struct
import tempfile
import unittest
from twin_interchange import encode_twin, fixture, publish_new


class TwinFormatTests(unittest.TestCase):
    def test_binary_offsets_and_integrity(self):
        b = encode_twin(**fixture())
        self.assertEqual(b[:8], b"FSSTWIN1")
        self.assertEqual(struct.unpack_from("<Q", b, 8)[0], len(b)-48)
        self.assertEqual(b[16:48], bytes([1])*32)
        self.assertEqual(hashlib.sha256(b[:-32]).digest(), b[-32:])
        self.assertEqual(hashlib.sha256(b).hexdigest(), "1d997fa681292b2eac58f73be61ca31c76bbf1e15f3af46c2ddf033ad9782c24")
        self.assertEqual(struct.unpack_from("<IIII", b, len(b)-64), (0, 1, 2, 0))
        self.assertEqual(struct.unpack_from("<IIII", b, len(b)-48), (0, 2, 3, 0))

    def test_invalid_inputs(self):
        for field, bad in [("source_sha256", "00"*32), ("scope", "\nsecret"),
                           ("epoch", ""), ("geometry_error", float("nan")),
                           ("scale", {"status": "relative", "metres_per_unit": 1})]:
            with self.subTest(field=field):
                data = fixture(); data[field] = bad
                with self.assertRaises(ValueError): encode_twin(**data)
        mutations = [lambda x: x["vertices"][0].__setitem__(0, float("inf")),
                     lambda x: x["triangles"][0].__setitem__(0, 999),
                     lambda x: x["triangles"][0].__setitem__(1, 0),
                     lambda x: x["triangles"][0].__setitem__(3, "missing"),
                     lambda x: x["objects"][0].__setitem__("support", 1),
                     lambda x: x["objects"][0].__setitem__("feature", "missing"),
                     lambda x: x["features"].append(copy.deepcopy(x["features"][0]))]
        for i, mutate in enumerate(mutations):
            with self.subTest(mutation=i):
                data=fixture(); mutate(data)
                with self.assertRaises(ValueError): encode_twin(**data)

    def test_negative_zero_normalized(self):
        data=fixture(); data["vertices"][0][0]=-0.0
        self.assertEqual(encode_twin(**data), encode_twin(**fixture()))

    def test_scale_states(self):
        for status in ("estimated", "measured_anchor"):
            for error in (None, 0, .1):
                data=fixture(); data["scale"]={"status": status, "metres_per_unit": .5, "error": error}
                self.assertTrue(encode_twin(**data))
            for error in (-2, .5, math.inf, math.nan):
                data=fixture(); data["scale"]={"status": status, "metres_per_unit": .5, "error": error}
                with self.assertRaises(ValueError): encode_twin(**data)

    def test_identity_order_and_roles(self):
        data=fixture()
        data["features"].append({"id":"grass", "surface":"grass"})
        data["objects"].append({"id":"other", "feature":"grass", "support":True,"opaque":False})
        data["triangles"][1][3]="other"
        expected=encode_twin(**data)
        data["features"].reverse();data["objects"].reverse()
        self.assertEqual(encode_twin(**data), expected)
        data["objects"][0]["opaque"]=True
        self.assertNotEqual(encode_twin(**data), expected)

    def test_unused_geometry_identity_refused(self):
        data=fixture();data["objects"].append({"id":"unused","feature":"walk","support":True,"opaque":True})
        with self.assertRaises(ValueError): encode_twin(**data)

    def test_create_only_publication(self):
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/"property.fsstwin"; data=encode_twin(**fixture())
            publish_new(path,data)
            with self.assertRaises(FileExistsError): publish_new(path,b"different")
            self.assertEqual(path.read_bytes(),data)
            self.assertEqual(sorted(p.name for p in Path(tmp).iterdir()), [path.name])


if __name__ == "__main__": unittest.main()
