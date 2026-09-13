#!/usr/bin/env python3
"""Independent lens/sampling oracles; this does not execute the Rust implementation."""
import hashlib
import math
import random
import struct
import unittest
from fractions import Fraction

import cv2
import numpy as np

ONE = 65536
INVALID = 2**32-1


def project(kind, coefficients, x, y, k):
    obj = np.array([[[x, y, 1.0]]], dtype=np.float64)
    if kind == "fisheye":
        points, _ = cv2.fisheye.projectPoints(obj, np.zeros(3), np.zeros(3), k,
                                             np.array(coefficients, dtype=np.float64))
    else:
        points, _ = cv2.projectPoints(obj, np.zeros(3), np.zeros(3), k,
                                     np.array(coefficients, dtype=np.float64))
    return tuple(points.reshape(2)+0.5)


def direct(kind, coefficients, x, y, k):
    r2 = x*x+y*y
    if kind == "brown":
        k1, k2, p1, p2, k3 = coefficients
        f = 1+k1*r2+k2*r2*r2+k3*r2*r2*r2
        a, b = x*f+2*p1*x*y+p2*(r2+2*x*x), y*f+p1*(r2+2*y*y)+2*p2*x*y
    else:
        theta = math.atan(math.hypot(x,y))
        theta_d = theta*sum(c*theta**(2*j) for j,c in enumerate([1,*coefficients]))
        a,b = (0.,0.) if r2 == 0 else (x*theta_d/math.sqrt(r2),y*theta_d/math.sqrt(r2))
    return (k[0,0]*a+k[0,2]+0.5,k[1,1]*b+k[1,2]+0.5)


def q16_map(kind, coefficients, width, height, f, radius):
    k = np.array([[f,0,(width-1)/2],[0,f,(height-1)/2],[0,0,1]],dtype=np.float64)
    values=[]
    for y in range(height):
        for x in range(width):
            xn,yn=(x-(width-1)/2)/f,(y-(height-1)/2)/f
            if math.hypot(xn,yn)>radius:
                values.append((INVALID,INVALID));continue
            u,v=project(kind,coefficients,xn,yn,k)
            u-=0.5;v-=0.5
            if not (0<=u<=width-1 and 0<=v<=height-1):
                values.append((INVALID,INVALID));continue
            values.append((math.floor(u*ONE+0.5),math.floor(v*ONE+0.5)))
    return values


def bilinear_q16(values, dx, dy):
    weights=[(ONE-dx)*(ONE-dy),dx*(ONE-dy),(ONE-dx)*dy,dx*dy]
    return (sum(w*v for w,v in zip(weights,values))+2**31)//2**32


def golden():
    width,height,f=9,7,5.
    result={}
    for kind,c in [("brown",[.04,.002,.003,-.002,.0001]),("fisheye",[.01,-.0001,.00001,0.])]:
        table=q16_map(kind,c,width,height,f,2.)
        data=b''.join(struct.pack('<II',*q) for q in table)
        result[kind]=hashlib.sha256(data).hexdigest()
    return result


class RectificationReference(unittest.TestCase):
    def test_brown_projection_against_opencv(self):
        rng=random.Random(941)
        k=np.array([[835.,0,799.5],[0,814.,449.5],[0,0,1]])
        for _ in range(1000):
            x,y=rng.uniform(-1.2,1.2),rng.uniform(-1.2,1.2)
            c=[rng.uniform(-.03,.03) for _ in range(5)]
            actual=direct('brown',c,x,y,k)
            expected=project('brown',c,x,y,k)
            self.assertLess(max(abs(a-b) for a,b in zip(actual,expected)),1e-9)

    def test_fisheye_projection_against_opencv(self):
        rng=random.Random(442)
        k=np.array([[702.,0,959.5],[0,710.,539.5],[0,0,1]])
        for _ in range(1000):
            x,y=rng.uniform(-5,5),rng.uniform(-5,5)
            c=[rng.uniform(-.01,.01) for _ in range(4)]
            self.assertLess(max(abs(a-b) for a,b in zip(direct('fisheye',c,x,y,k),project('fisheye',c,x,y,k))),1e-9)

    def test_integer_bilinear_against_exact_rationals(self):
        rng=random.Random(113)
        for _ in range(2000):
            v=[rng.randrange(256) for _ in range(4)];dx,dy=rng.randrange(ONE),rng.randrange(ONE)
            a,b=Fraction(dx,ONE),Fraction(dy,ONE)
            exact=(1-a)*(1-b)*v[0]+a*(1-b)*v[1]+(1-a)*b*v[2]+a*b*v[3]
            self.assertEqual(bilinear_q16(v,dx,dy),math.floor(exact+Fraction(1,2)))

    def test_identity_grid_has_no_half_pixel_shift(self):
        k=np.array([[5.,0,4.],[0,5.,3.],[0,0,1]])
        for y in range(7):
            for x in range(9):
                u,v=project('brown',[0.]*5,(x-4)/5,(y-3)/5,k)
                self.assertAlmostEqual(u,x+.5,places=12);self.assertAlmostEqual(v,y+.5,places=12)

    def test_zero_fisheye_is_not_zero_brown(self):
        k=np.eye(3)
        self.assertNotEqual(project('fisheye',[0.]*4,1.,0.,k),project('brown',[0.]*5,1.,0.,k))

    def test_negative_radial_example_really_folds(self):
        self.assertGreater(1-3*.25,0)
        self.assertLess(1-3*1.,0)

    def test_positive_weight_mask_gate_is_noninterfering(self):
        for dx,dy in [(0,0),(1,1),(ONE//4,ONE//2),(ONE-1,ONE-1)]:
            weights=[(ONE-dx)*(ONE-dy),dx*(ONE-dy),(ONE-dx)*dy,dx*dy]
            for hidden in range(4):
                results=set()
                for value in range(256):
                    pixels=[15,67,198,230];pixels[hidden]=value
                    results.add(0 if weights[hidden] else bilinear_q16(pixels,dx,dy))
                self.assertEqual(len(results),1)

    def test_video_range_fixed_expansion(self):
        values=[min(219,max(0,v-16))*255 for v in [0,16,17,125,235,255]]
        self.assertEqual([(v+109)//219 for v in values],[0,0,1,127,255,255])

    def test_map_goldens_are_reproducible_and_distinct(self):
        first=golden();self.assertEqual(first,golden());self.assertNotEqual(first['brown'],first['fisheye'])


if __name__=='__main__':
    print('Oracle-only checks; Rust execution is separate. OpenCV:',cv2.__version__)
    print('Independent map goldens:',golden())
    unittest.main()
