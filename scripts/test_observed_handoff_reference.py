#!/usr/bin/env python3
"""Independent analytic controls for the observed-handoff Rust contract fixture.

This executes Python geometry/scheduling only. It does not execute or qualify Rust.
"""
import heapq
import json
import math
import unittest
from fractions import Fraction


def geometry():
    vertices = [(2*x, 2*y, 0) for y in range(3) for x in range(4)]
    faces, surfaces = [], []
    for y in range(2):
        for x in range(3):
            a = 4*y+x
            faces.extend([(a, a+1, a+5), (a, a+5, a+4)])
            surfaces.extend([2 if x == 2 else 0 if (x,y) == (1,0) else 1]*2)
    centers = [tuple(sum(vertices[v][k] for v in face)/3 for k in range(3)) for face in faces]
    graph = [[] for _ in faces]
    for i in range(len(faces)):
        for j in range(i):
            shared = sorted(set(faces[i]) & set(faces[j]))
            if len(shared) == 2:
                midpoint = tuple(sum(vertices[v][k] for v in shared)/2 for k in range(3))
                graph[i].append((j,midpoint)); graph[j].append((i,midpoint))
    return centers, surfaces, graph


def corridor(multiplier):
    centers, surfaces, graph = geometry()
    def divisor(i):
        return multiplier if surfaces[i] in (1,2) else 1
    start = (1.0,0.25,0.0)
    costs = [math.inf]*len(centers); parents = {}; closed = set()
    costs[0] = math.dist(start,centers[0])/divisor(0)
    queue = [(costs[0],0)]
    while queue:
        cost,i = heapq.heappop(queue)
        if i in closed:
            continue
        closed.add(i)
        if surfaces[i] == 2:
            route=[i]
            while route[-1]:
                route.append(parents[route[-1]][0])
            route.reverse()
            points=[start,centers[0]]
            for node in route[1:]:
                points.extend([parents[node][1],centers[node]])
            return route,points
        for j,midpoint in graph[i]:
            candidate=cost+math.dist(centers[i],midpoint)/divisor(i)+math.dist(midpoint,centers[j])/divisor(j)
            if j not in closed and candidate < costs[j]:
                costs[j]=candidate; parents[j]=(i,midpoint)
                heapq.heappush(queue,(candidate,j))
    raise AssertionError("fixture unexpectedly disconnected")


def position(points,speed,seconds):
    remaining=speed*seconds
    for a,b in zip(points,points[1:]):
        length=math.dist(a,b)
        if remaining <= length:
            return tuple(x+(y-x)*remaining/length for x,y in zip(a,b))
        remaining-=length
    return points[-1]


def observed(point):
    probes=[(-.1,-.1,.3),(.1,-.1,.3),(-.1,.1,1),(.1,.1,1)]
    pixels=[]
    for offset in probes:
        x,y,z=[point[k]+offset[k] for k in range(3)]
        # Independently written downward camera at (5,1,5), focal=200, center=50.
        u=50+200*(x-5)/(5-z); v=50+200*(1-y)/(5-z)
        if not (0 <= u < 100 and 0 <= v < 100):
            return False
        pixels.append((u,v))
    return all(max(p[k] for p in pixels)-min(p[k] for p in pixels) >= 1 for k in range(2))


class Reference(unittest.TestCase):
    def test_path_preference_selects_a_distinct_non_grass_corridor(self):
        neutral,_=corridor(1); preferred,_=corridor(8)
        _,surfaces,_=geometry()
        self.assertNotEqual(neutral,preferred)
        self.assertTrue(any(surfaces[i]==0 for i in neutral))
        self.assertFalse(any(surfaces[i]==0 for i in preferred))

    def test_observed_speed_changes_first_sample(self):
        _,points=corridor(1)
        times=[]
        for speed in (.3,.6):
            times.append(next(Fraction(k,10) for k in range(301) if observed(position(points,speed,k/10))))
        self.assertLess(times[1],times[0])
        self.assertEqual(times,[Fraction(64,5),Fraction(32,5)])

    def test_stopping_at_source_never_creates_a_second_camera_capture(self):
        self.assertFalse(observed((1,.25,0)))

    def test_analytic_source_pixel_inverse(self):
        for x in (.4,.7,1.0):
            u=100+10*(x-2); v=117.5
            self.assertAlmostEqual(2+(u-100)/10,x)
            self.assertAlmostEqual(2-(v-100)/10,.25)


if __name__ == '__main__':
    result=unittest.TextTestRunner().run(unittest.defaultTestLoader.loadTestsFromTestCase(Reference))
    print(json.dumps({'scope':'independent Python fixture geometry, not Rust execution',
                      'tests':result.testsRun,'passed':result.wasSuccessful()}))
    raise SystemExit(0 if result.wasSuccessful() else 1)
