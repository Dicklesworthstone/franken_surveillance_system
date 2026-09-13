#!/usr/bin/env python3
"""Independent distorted-image fixture and localization oracle; never a Rust pass."""
import hashlib
import json
import math
from pathlib import Path
import sys
import unittest

import cv2
import numpy as np
from test_native_features_reference import texture, extract
from test_localization_matching_reference import independent

FIXTURE = Path(__file__).resolve().parents[1] / 'crates/fss-twin/tests/fixtures/brown_luma_96x96.gray'
COEFFICIENTS = np.array([-.1, .001, .001, -.001, .0001], dtype=np.float64)
K = np.array([[80.,0,47.5],[0,80.,47.5],[0,0,1.]], dtype=np.float64)


def generate():
    image = texture(96,96)
    raw_grid = np.array([[x,y] for y in range(96) for x in range(96)], dtype=np.float64).reshape(-1,1,2)
    inverse = cv2.undistortPoints(raw_grid, K, COEFFICIENTS, P=K).reshape(96,96,2)
    return cv2.remap(image, inverse[:,:,0].astype(np.float32), inverse[:,:,1].astype(np.float32),
                     cv2.INTER_LINEAR, borderMode=cv2.BORDER_CONSTANT).tobytes()


def rectify_oracle(raw):
    # Independent OpenCV projection; interpolation uses exact integer Q16/Q32 arithmetic.
    grid = np.array([[(x-47.5)/80,(y-47.5)/80,1.] for y in range(96) for x in range(96)], dtype=np.float64)
    sample = cv2.projectPoints(grid,np.zeros(3),np.zeros(3),K,COEFFICIENTS)[0].reshape(-1,2)
    out = bytearray(96*96)
    for idx,(x,y) in enumerate(sample):
        if not (0 <= x <= 95 and 0 <= y <= 95):
            raise AssertionError('fixture must not rely on invalid border content')
        xq,yq = math.floor(x*65536+.5),math.floor(y*65536+.5)
        x0,dx = divmod(xq,65536); y0,dy = divmod(yq,65536)
        x1,y1 = min(x0+1,95),min(y0+1,95)
        out[idx] = (raw[y0*96+x0]*(65536-dx)*(65536-dy) + raw[y0*96+x1]*dx*(65536-dy)
                    + raw[y1*96+x0]*(65536-dx)*dy + raw[y1*96+x1]*dx*dy + 2**31)//2**32
    return bytes(out)


def localization_oracle(corrected, side=96):
    reference = extract(texture(96,96))
    query = extract(np.frombuffer(corrected,dtype=np.uint8).reshape(side,side))
    matrix = [[sum((a^b).bit_count() for a,b in zip(q[2],r[2])) for r in reference] for q in query]
    matches = [(q,d[0]) for q,d in enumerate(independent(matrix,64,80)) if d[1] is None]
    if len(matches) < 8:
        raise AssertionError('fixture does not supply enough physical matches')
    for q,r in matches:
        if query[q][:2] != tuple(v-(96-side)//2 for v in reference[r][:2]):
            raise AssertionError('fixture contains an incorrect physical-feature match')
    world = np.array([[(x+.5-48)*(6+(i%7)*.5)/80, (y+.5-48)*(6+(i%7)*.5)/80,6+(i%7)*.5]
                      for i,(x,y,_) in enumerate(reference)])
    points = np.array([[query[q][0]+.5,query[q][1]+.5] for q,_ in matches])
    k = K.copy(); k[:2,2] = side/2
    ok,rv,tv = cv2.solvePnP(world[[r for _,r in matches]],points,k,None,flags=cv2.SOLVEPNP_EPNP)
    if not ok or np.linalg.norm(rv) > 1e-6 or np.linalg.norm(tv) > 1e-6:
        raise AssertionError('independent pose oracle disagrees with the identity control')
    return len(reference),len(query),len(matches)


class RectifiedLocalizationReference(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.raw = FIXTURE.read_bytes()
        cls.corrected = rectify_oracle(cls.raw)

    def test_committed_raw_fixture_is_independently_reproducible(self):
        self.assertEqual(len(self.raw),9216)
        self.assertEqual(self.raw,generate())
        self.assertNotEqual(self.raw,texture(96,96).tobytes())

    def test_rectified_pixels_have_an_independent_golden(self):
        self.assertEqual(hashlib.sha256(self.corrected).hexdigest(),CORRECTED_SHA256)
        self.assertNotEqual(self.raw,self.corrected)

    def test_crop_uses_the_target_not_the_source_intrinsics(self):
        image = np.frombuffer(self.corrected,dtype=np.uint8).reshape(96,96)
        _,_,matches = localization_oracle(image[8:88,8:88].copy().tobytes(),80)
        self.assertGreaterEqual(matches,16)

    def test_corrected_pixels_match_physical_landmarks_and_pose(self):
        reference,query,matches = localization_oracle(self.corrected)
        self.assertGreaterEqual(matches,16)
        print(json.dumps({'scope':'Python/OpenCV fixture only','reference_features':reference,
                          'query_features':query,'correct_physical_matches':matches,'rust_executed':False}))


CORRECTED_SHA256 = '7e31c6e153dded00386436ef3b1bdc98dba5a8dd9049c3fb65bb6ce68bd20e98'
if __name__ == '__main__':
    if sys.argv[1:] == ['--write-fixture']:
        FIXTURE.parent.mkdir(parents=True,exist_ok=True)
        raw = generate()
        with FIXTURE.open('xb') as stream:
            stream.write(raw)
        print(json.dumps({'opencv':cv2.__version__,'source_sha256':hashlib.sha256(raw).hexdigest(),
                          'corrected_sha256':hashlib.sha256(rectify_oracle(raw)).hexdigest()}))
    else:
        unittest.main()
