#!/usr/bin/env python3
"""Native feature algorithm arithmetic/oracle checks; never a Rust pass receipt."""
import json
import math
import numpy as np
import cv2
from test_localization_matching_reference import independent

CIRCLE = [(0,-3),(1,-3),(2,-2),(3,-1),(3,0),(3,1),(2,2),(1,3),(0,3),(-1,3),(-2,2),(-3,1),(-3,0),(-3,-1),(-2,-2),(-1,-3)]


def texture(w, h):
    state = 1973
    values = []
    for _ in range(w*h):
        state = (state*1664525+1013904223) & 0xffffffff
        values.append(20 + ((state >> 16) % 180))
    return np.array(values, dtype=np.uint8).reshape(h, w)


def scores(image):
    image = image.astype(np.int16)
    h, w = image.shape
    deltas = np.stack([image[3+dy:h-3+dy,3+dx:w-3+dx]-image[3:h-3,3:w-3] for dx, dy in CIRCLE])
    response = np.zeros((h-6,w-6), dtype=np.int16)
    for start in range(16):
        run = deltas[[(start+k)%16 for k in range(9)]]
        response = np.maximum(response, np.maximum(np.min(run,axis=0), -np.max(run,axis=0)))
    result = np.zeros((h,w), dtype=np.uint8)
    result[3:-3,3:-3] = response
    return result


def round_away(x):
    return math.floor(x+0.5) if x >= 0 else math.ceil(x-0.5)


def describe(image, x, y):
    def mean(xx, yy):
        return int(image[yy-1:yy+2,xx-1:xx+2].sum())
    mx = my = 0
    for dy in range(-8,9):
        for dx in range(-8,9):
            if dx*dx+dy*dy <= 64:
                value = mean(x+dx,y+dy)
                mx += dx*value
                my += dy*value
    angle = math.atan2(my,mx)
    c, s = math.cos(angle), math.sin(angle)
    state, words = 731, [0]*4
    for bit in range(256):
        pair = []
        for _ in range(4):
            state = (state*1664525+1013904223) & 0xffffffff
            pair.append(state%21-10)
        values = [mean(x+round_away(c*dx-s*dy),y+round_away(s*dx+c*dy)) for dx,dy in [pair[:2],pair[2:]]]
        if values[0] < values[1]:
            words[bit//64] |= 1 << (bit%64)
    return tuple(words)


def extract(image, cap=200):
    h,w = image.shape
    response = scores(image)
    response[:16,:] = response[-16:,:] = response[:,:16] = response[:,-16:] = 0
    response[response<=20] = 0
    tiles = [[] for _ in range(64)]
    for y in range(16,h-16):
        for x in range(16,w-16):
            value = int(response[y,x]); idx = y*w+x
            if value == 0:
                continue
            if any(int(response[yy,xx])>value or (int(response[yy,xx])==value and yy*w+xx<idx)
                   for yy in range(y-1,y+2) for xx in range(x-1,x+2)):
                continue
            cell = tiles[(y*8//h)*8+x*8//w]
            cell.append((-value,idx));cell.sort();del cell[8:]
    selected = []
    for _,idx in sorted(item for cell in tiles for item in cell):
        y,x = divmod(idx,w)
        if any((x-xx)**2+(y-yy)**2<36 for xx,yy,_ in selected):
            continue
        selected.append((x,y,describe(image,x,y)))
        if len(selected)==cap:
            break
    return sorted(selected,key=lambda p:p[1]*w+p[0])


def main():
    comparisons = 0
    for seed in range(16):
        image = np.random.default_rng(seed).integers(0,256,(64,64),dtype=np.uint8)
        response = scores(image)
        for threshold in (1,20,80,200):
            engine = cv2.FastFeatureDetector_create(threshold=threshold,nonmaxSuppression=False,type=cv2.FAST_FEATURE_DETECTOR_TYPE_9_16)
            actual = {(int(k.pt[0]),int(k.pt[1])) for k in engine.detect(image)}
            expected = {(int(x),int(y)) for y,x in zip(*np.where(response>threshold))}
            assert actual == expected
            comparisons += 58*58
    image = texture(96,96)
    rotated = np.ascontiguousarray(np.rot90(image,-1))
    d = describe(image,31,25)
    assert d == describe(rotated,95-25,31)
    assert d == describe((image.astype(np.int16)+20).astype(np.uint8),31,25)
    reference,query = extract(image),extract(rotated)
    matrix = [[sum((a^b).bit_count() for a,b in zip(q[2],r[2])) for r in reference] for q in query]
    matches = [(qi,decision[0]) for qi,decision in enumerate(independent(matrix,0,80)) if decision[1] is None]
    world = np.array([[(x+.5-48)* (6+(i%7)*.5)/80,(y+.5-48)*(6+(i%7)*.5)/80,6+(i%7)*.5] for i,(x,y,_) in enumerate(reference)])
    assert len(matches) >= 8
    pts = np.array([[query[q][0]+.5,query[q][1]+.5] for q,_ in matches])
    for q,r in matches:
        assert query[q][:2] == (95-reference[r][1],reference[r][0])
    k=np.array([[80.,0,48.],[0,80.,48.],[0,0,1.]])
    ok,rv,tv=cv2.solvePnP(world[[r for _,r in matches]],pts,k,None,flags=cv2.SOLVEPNP_EPNP)
    assert ok
    rotation=cv2.Rodrigues(rv)[0]
    expected=np.array([[0.,-1.,0.],[1.,0.,0.],[0.,0.,1.]])
    assert np.linalg.norm(rotation-expected)<1e-8 and np.linalg.norm(tv)<1e-8
    print(json.dumps({'status':'PASS','scope':'Python feature arithmetic and OpenCV oracle only','opencv':cv2.__version__,
        'fast_pixel_decisions':comparisons,'descriptor_golden_words':d,'reference_features':len(reference),
        'query_features':len(query),'exact_rotated_matches':len(matches),'rust_executed':False}))


if __name__ == '__main__':
    main()
