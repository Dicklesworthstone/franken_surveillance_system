#!/usr/bin/env python3
"""Independent arithmetic/component oracle, never a substitute for native execution."""
import hashlib
import struct
import unittest
from collections import deque


def sha(b):
    return hashlib.sha256(b).digest()


def u64(n):
    return struct.pack('<Q', n)


def source(exposure, pixels, w, h):
    return (bytes([exposure])*32 + sha(bytes(pixels)) + bytes([7])*32 + bytes([9])*32
            + struct.pack('<IIQQQQ', w, h, 1, 2, exposure*10, exposure*10))


def oracle_labels(states, w, h):
    groups = [{i} for i, s in enumerate(states) if s >= 2]
    # Set merging is independent of the Rust flood fill and its queue ordering.
    for y in range(h):
        for x in range(w):
            i = y*w+x
            if states[i] < 2:
                continue
            for j in ([i+1] if x+1 < w else []) + ([i+w] if y+1 < h else []):
                if states[j] < 2:
                    continue
                a = next(g for g in groups if i in g)
                b = next(g for g in groups if j in g)
                if a is not b:
                    groups.remove(b)
                    a.update(b)
    labels = [0]*len(states)
    for group in groups:
        for i in group:
            labels[i] = min(group)+1
    return labels


def flood_labels(states, w, h):
    labels = [0]*len(states)
    for seed in range(len(states)):
        if states[seed] < 2 or labels[seed]:
            continue
        q = deque([seed])
        labels[seed] = seed+1
        while q:
            i = q.popleft()
            x, y = i % w, i // w
            adjacent = [yy*w+xx for xx, yy in ((x-1,y),(x+1,y),(x,y-1),(x,y+1))
                        if 0 <= xx < w and 0 <= yy < h]
            for j in adjacent:
                if states[j] >= 2 and not labels[j]:
                    labels[j] = seed+1
                    q.append(j)
    return labels


def state(lo, hi, value, known=True, permitted=True, threshold=10):
    if not known or not permitted:
        return 0
    return 2 if lo-value > threshold else 3 if value-hi > threshold else 1


def golden():
    w, h = 6, 5
    known = bytes([1])*30
    b = bytearray(b'fss/frozen-background/reference/1\0')
    b += bytes([6])*32 + u64(0) + u64(10000) + bytes([4]) + u64(3)
    for e, intensity in ((1,99),(2,100),(3,101)):
        b += source(e, [intensity]*30, w, h) + sha(known)
    b += sha(bytes([99])*30) + sha(bytes([101])*30) + sha(known)
    baseline = sha(b)
    pixels = [100]*30
    for i in (7,8,13): pixels[i] = 150
    for i in (22,28): pixels[i] = 30
    pixels[5] = 130
    states = [state(99,101,v) for v in pixels]
    labels = oracle_labels(states,w,h)
    r = (b'fss/foreground-regions/reference/1\0' + baseline + source(4,pixels,w,h) + sha(known)
         + bytes([10]) + u64(2) + u64(32) + u64(750) + sha(bytes(states))
         + sha(b''.join(struct.pack('<I', n) for n in labels)))
    return baseline.hex(), sha(r).hex(), labels


class ForegroundOracle(unittest.TestCase):
    def test_every_three_by_three_foreground_graph(self):
        for bits in range(512):
            states = [3 if bits & (1 << i) else 1 for i in range(9)]
            self.assertEqual(oracle_labels(states,3,3),flood_labels(states,3,3))

    def test_masked_components_cannot_bridge(self):
        s = [3,3,0,3,3]*3
        labels = oracle_labels(s,5,3)
        self.assertEqual(set(labels),{0,1,4})
        self.assertEqual(labels,[1,1,0,4,4]*3)

    def test_unknown_and_private_pixels_never_become_unchanged(self):
        for p in range(256):
            self.assertEqual(state(99,101,p,known=False),0)
            self.assertEqual(state(99,101,p,permitted=False),0)

    def test_integer_distance_and_no_unsigned_wrap(self):
        for lo in range(0,256,3):
            for hi in range(lo,min(256,lo+5)):
                for p in range(256):
                    actual = state(lo,hi,p)
                    distance = min(abs(p-v) for v in range(lo,hi+1))
                    self.assertEqual(actual >= 2,distance > 10)
        self.assertEqual([state(99,101,p) for p in [89,88,111,112]],[1,2,1,3])

    def test_static_foreground_stays_foreground(self):
        before = [state(99,101,p) for p in (100,150,30)]
        for _ in range(1000):
            self.assertEqual([state(99,101,p) for p in (100,150,30)],before)

    def test_independent_wire_and_component_golden(self):
        baseline, report, labels = golden()
        self.assertEqual(baseline,'e0b90edeef92b0c70bdf95843a8f07803a66afb3bcee665ac9e4fabec28e27a2')
        self.assertEqual(report,'3eda58e97b8b3a7e1bc339632f41ee7c7b70bbb01fac1952ba2634c54f266c7c')
        self.assertEqual([i for i,x in enumerate(labels) if x],[5,7,8,13,22,28])
        self.assertEqual([labels[i] for i in [5,7,8,13,22,28]],[6,8,8,8,23,23])

    def test_framewide_change_is_not_suppressed(self):
        states=[state(99,101,150)]*100
        self.assertEqual(sum(x >= 2 for x in states),100)
        self.assertEqual(len(set(oracle_labels(states,10,10))),1)


if __name__ == '__main__':
    unittest.main()
