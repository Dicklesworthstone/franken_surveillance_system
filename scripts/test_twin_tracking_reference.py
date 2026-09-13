#!/usr/bin/env python3
"""Independent arithmetic checks only; DOES NOT execute or qualify the Rust code."""
from fractions import Fraction
import math
import random
import unittest


def outward(lo,hi):
    return I(math.nextafter(lo,-math.inf),math.nextafter(hi,math.inf))


class I:
    def __init__(self,lo,hi=None):
        self.lo,self.hi=lo,lo if hi is None else hi
        assert math.isfinite(self.lo) and math.isfinite(self.hi) and self.lo<=self.hi
    def __add__(self,b):return outward(self.lo+b.lo,self.hi+b.hi)
    def __sub__(self,b):return outward(self.lo-b.hi,self.hi-b.lo)
    def __mul__(self,b):
        v=[a*c for a in (self.lo,self.hi) for c in (b.lo,b.hi)]
        return outward(min(v),max(v))
    def __truediv__(self,b):
        assert not b.lo<=0<=b.hi
        v=[a/c for a in (self.lo,self.hi) for c in (b.lo,b.hi)]
        return outward(min(v),max(v))
    def square(self):
        lo=0 if self.lo<=0<=self.hi else min(self.lo*self.lo,self.hi*self.hi)
        return I(0 if lo==0 else math.nextafter(lo,-math.inf),math.nextafter(max(self.lo*self.lo,self.hi*self.hi),math.inf))
    def root(self):return outward(math.sqrt(self.lo),math.sqrt(self.hi))
    def clip(self,b):
        lo,hi=max(self.lo,b.lo),min(self.hi,b.hi)
        return I(lo,hi) if lo<=hi else None
    def contains(self,x):return self.lo<=x<=self.hi


def around(x,e):return outward(x-e,x+e)
def dot(a,b):return (a[0]*b[0]+a[1]*b[1])+a[2]*b[2]
def sub(a,b):return [x-y for x,y in zip(a,b)]
def cross(a,b):return [a[1]*b[2]-a[2]*b[1],a[2]*b[0]-a[0]*b[2],a[0]*b[1]-a[1]*b[0]]


def projected_box(points):
    x=(I(449,451)-around(500,1))/around(500,10)
    y=(I(449,451)-around(500,1))/around(500,10)
    length=(x.square()+y.square()+I(1)).root()
    bearing=[x/length,y/length,I(1)/length]
    R=[[1,0,0],[0,-1,0],[0,0,-1]]
    direction=[dot([around(R[j][i],.005) for j in range(3)],bearing) for i in range(3)]
    origin=[around(x,.05) for x in (2,2,10)]
    vertices=[[around(x,.02) for x in p] for p in points]
    normal=cross(sub(vertices[1],vertices[0]),sub(vertices[2],vertices[0]))
    denominator=dot(normal,direction)
    distance=I(1e-4,1000)
    if not denominator.contains(0):distance=distance.clip(dot(normal,sub(vertices[0],origin))/denominator)
    if distance is None:return None
    boxes=[I(min(v[i].lo for v in vertices),max(v[i].hi for v in vertices)) for i in range(3)]
    for i in range(3):
        if not direction[i].contains(0):distance=distance.clip((boxes[i]-origin[i])/direction[i])
        if distance is None:return None
    position=[(origin[i]+distance*direction[i]).clip(boxes[i]) for i in range(3)]
    if any(p is None for p in position):return None
    for i in range(3):
        a,b=vertices[i],vertices[(i+1)%3]
        if dot(cross(sub(b,a),sub(position,a)),normal).hi<0:return None
    return position


class ReferenceTests(unittest.TestCase):
    def test_outward_arithmetic_against_exact_rationals(self):
        rng=random.Random(913)
        for _ in range(4000):
            a=I(*sorted([rng.uniform(-1e8,1e8),rng.uniform(-1e8,1e8)]))
            b=I(*sorted([rng.uniform(-1e8,1e8),rng.uniform(-1e8,1e8)]))
            for operation in (lambda x,y:x+y,lambda x,y:x-y,lambda x,y:x*y):
                result=operation(a,b)
                for x in (a.lo,a.hi):
                    for y in (b.lo,b.hi):
                        exact=operation(Fraction(x),Fraction(y))
                        self.assertLessEqual(Fraction(result.lo),exact)
                        self.assertGreaterEqual(Fraction(result.hi),exact)
            if not b.contains(0):
                result=a/b
                for x in (a.lo,a.hi):
                    for y in (b.lo,b.hi):self.assertTrue(Fraction(result.lo)<=Fraction(x)/Fraction(y)<=Fraction(result.hi))

    def test_perturbed_cameras_and_ground_contained(self):
        points=[[[0,0,0],[4,0,0],[4,4,0]],[[0,0,0],[4,4,0],[0,4,0]]]
        boxes=[b for p in points if (b:=projected_box(p)) is not None]
        rng=random.Random(914)
        for _ in range(10000):
            C=[base+rng.uniform(-.04,.04) for base in (2,2,10)]
            px,py=[rng.uniform(449,451) for _ in range(2)]
            fx,fy=[rng.uniform(490,510) for _ in range(2)]
            cx,cy=[rng.uniform(499,501) for _ in range(2)]
            bearing=[(px-cx)/fx,(py-cy)/fy,1]
            length=math.hypot(*bearing);bearing=[x/length for x in bearing]
            # Actual proper rotation, distinct from interval coefficient arithmetic.
            angle=rng.uniform(-.004,.004);co,s=math.cos(angle),math.sin(angle)
            D=[co*bearing[0]+s*bearing[2],-bearing[1],s*bearing[0]-co*bearing[2]]
            # Actual terrain differs from imported flat triangles.
            a,b=rng.uniform(-.001,.001),rng.uniform(-.001,.001);c=rng.uniform(-.005,.005)
            t=(c+a*C[0]+b*C[1]-C[2])/(D[2]-a*D[0]-b*D[1])
            point=[C[i]+t*D[i] for i in range(3)]
            self.assertTrue(any(all(box[i].contains(point[i]) for i in range(3)) for box in boxes))

    def test_interval_velocity_and_accelerated_propagation(self):
        rng=random.Random(915)
        position_a=I(.9,1.1);position_b=I(1.9,2.1);duration=I(.98,1.02)
        velocity=(position_b-position_a)/duration
        future=I(.99,1.01)
        acceleration=I(2)
        growth=((future.square()+future*duration)*acceleration*I(.5)).hi
        predicted=position_b+velocity*future+I(-growth,growth)
        for _ in range(10000):
            pa,pb=rng.uniform(.9,1.1),rng.uniform(1.9,2.1)
            dt=rng.uniform(.98,1.02);t=rng.uniform(.99,1.01)
            average=(pb-pa)/dt
            self.assertTrue(velocity.contains(average))
            past_acceleration=rng.uniform(-2,2);future_acceleration=rng.uniform(-2,2)
            endpoint=average+.5*past_acceleration*dt
            actual=pb+endpoint*t+.5*future_acceleration*t*t
            self.assertTrue(predicted.contains(actual))


if __name__=="__main__":unittest.main()
