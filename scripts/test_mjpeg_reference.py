#!/usr/bin/env python3
"""Laboratory checks only. Pillow/numpy never enter FSS production."""
import hashlib, io, math, struct, unittest
from pathlib import Path
import numpy as np
from PIL import Image

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / 'crates/fss-codec-mjpeg/tests/fixtures'
ZIG = [0,1,8,16,9,2,3,10,17,24,32,25,18,11,4,5,12,19,26,33,40,48,41,34,27,20,13,6,7,14,21,28,35,42,49,56,57,50,43,36,29,22,15,23,30,37,44,51,58,59,52,45,38,31,39,46,53,60,61,54,47,55,62,63]
BASIS = np.array([[(1 / math.sqrt(2) if u == 0 else 1) * math.cos((2*x+1)*u*math.pi/16) for x in range(8)] for u in range(8)])
Q14 = np.rint(BASIS * 16384).astype(np.int64)
ALGORITHM = b'fss/jpeg-luma/reference/1;SOF0;single-scan;strict-pad;no-default-tables;Q14-IDCT;floor-half-up;DC-2048:2047;raw-orientation'

def encode(mode, width, height, subsampling=0, restart=0):
    count = width * height * (1 if mode == 'L' else 3)
    pixels = bytes(((i*37 + (i//width)*17 + (i*i//31)) % 256) for i in range(count))
    image = Image.frombytes(mode, (width,height), pixels)
    out = io.BytesIO()
    image.save(out, format='JPEG', quality=81, optimize=True, subsampling=subsampling, restart_marker_blocks=restart)
    return out.getvalue()

def pillow_luma(encoded):
    image = Image.open(io.BytesIO(encoded))
    image.draft('L', image.size)
    image.load()
    if image.mode != 'L': raise AssertionError('oracle did not decode Y directly')
    return np.asarray(image)

def reference_decode(encoded):
    if encoded[:2] != b'\xff\xd8': raise ValueError('SOI')
    at = 2; q = {}; tables = {}; frame = None; interval = 0
    while at < len(encoded):
        if encoded[at] != 255: raise ValueError('marker')
        at += 1
        while encoded[at] == 255: at += 1
        marker = encoded[at]; at += 1
        if marker == 217: raise ValueError('missing scan')
        size, = struct.unpack_from('>H', encoded, at)
        data = encoded[at+2:at+size]; at += size
        if marker == 219:
            for start in range(0,len(data),65):
                descriptor = data[start]
                if descriptor > 3: raise ValueError('quantizer')
                matrix = np.zeros(64,dtype=np.int64)
                matrix[ZIG] = list(data[start+1:start+65]); q[descriptor] = matrix.reshape(8,8)
        elif marker == 196:
            index = 0
            while index < len(data):
                descriptor = data[index]; counts = data[index+1:index+17]; index += 17
                table = {}; code = 0
                for length, count in enumerate(counts,1):
                    for _ in range(count):
                        table[format(code,f'0{length}b')] = data[index]; index += 1; code += 1
                    code *= 2
                tables[descriptor] = table
        elif marker == 192:
            height,width = struct.unpack_from('>HH',data,1)
            comps = [(data[j],data[j+1]>>4,data[j+1]&15,data[j+2]) for j in range(6,len(data),3)]
            frame = (width,height,comps)
        elif marker == 221: interval, = struct.unpack('>H',data)
        elif marker == 218:
            scan = [(data[j],data[j+1]>>4,data[j+1]&15) for j in range(1,len(data)-3,2)]
            break
    width,height,comps = frame
    h,v = comps[0][1:3]; columns = (width+8*h-1)//(8*h); rows = (height+8*v-1)//(8*v)
    output = np.zeros((rows*v*8,columns*h*8),dtype=np.uint8)
    segments = []; restarts = []; current = bytearray()
    while at < len(encoded):
        b = encoded[at]; at += 1
        if b != 255: current.append(b); continue
        b = encoded[at]; at += 1
        if b == 0: current.append(255); continue
        segments.append(''.join(format(x,'08b') for x in current)); current.clear()
        if b == 217:
            if at != len(encoded): raise ValueError('trailer')
            break
        if not 208 <= b <= 215: raise ValueError('entropy marker')
        restarts.append(b-208)
    predictors = {c[0]:0 for c in comps}; segment = 0; offset = 0
    def bits(n):
        nonlocal offset
        result = segments[segment][offset:offset+n]
        if len(result) != n: raise ValueError('entropy end')
        offset += n
        return int(result or '0',2)
    def symbol(key):
        word = ''
        for _ in range(16):
            word += str(bits(1))
            if word in tables[key]: return tables[key][word]
        raise ValueError('code')
    def receive(n):
        a = bits(n)
        return a - (1<<n) + 1 if n and a < 1<<(n-1) else a
    def finish():
        if len(segments[segment])-offset > 7 or '0' in segments[segment][offset:]: raise ValueError('padding')
    blocks = 0
    for mcu in range(rows*columns):
        if mcu and interval and mcu%interval == 0:
            finish()
            if restarts[segment] != segment%8: raise ValueError('restart')
            segment += 1; offset = 0; predictors = dict.fromkeys(predictors,0)
        for cid,dc,ac in scan:
            comp = next(c for c in comps if c[0] == cid)
            for by in range(comp[2]):
                for bx in range(comp[1]):
                    coefficients = np.zeros(64,dtype=np.int64)
                    predictors[cid] += receive(symbol(dc)); coefficients[0] = predictors[cid]
                    k = 1
                    while k < 64:
                        s = symbol(16+ac); run, length = s>>4, s&15
                        if s == 0: break
                        if s == 240: k += 16; continue
                        k += run
                        if k >= 64: raise ValueError('run')
                        coefficients[ZIG[k]] = receive(length); k += 1
                    coefficients = coefficients.reshape(8,8)*q[comp[3]]; blocks += 1
                    if cid != comps[0][0]: continue
                    fixed = np.clip(((Q14.T @ coefficients @ Q14)+(1<<29))//(1<<30)+128,0,255).astype(np.uint8)
                    real = np.clip(np.floor((BASIS.T @ coefficients @ BASIS)/4+128.5),0,255)
                    if np.max(abs(fixed.astype(int)-real)) > 1: raise AssertionError('fixed inverse transform')
                    y,x = (mcu//columns*v+by)*8,(mcu%columns*h+bx)*8
                    output[y:y+8,x:x+8] = fixed
    finish()
    if segment != len(segments)-1: raise ValueError('unused entropy')
    return output[:height,:width], blocks, len(restarts)

class ReferenceTests(unittest.TestCase):
    def test_standard_encoded_images_and_odd_edges(self):
        cases = 0
        for mode in ['L','RGB']:
            for shape in [(1,1),(7,9),(17,13),(32,25),(48,33)]:
                for sub in ([0] if mode == 'L' else [0,1,2]):
                    for interval in [0,1,3]:
                        encoded = encode(mode,*shape,sub,interval)
                        result,_,_ = reference_decode(encoded)
                        error = np.abs(result.astype(int)-pillow_luma(encoded).astype(int))
                        self.assertLessEqual(int(error.max()),1)
                        cases += 1
        self.assertEqual(cases,60)
    def test_committed_oracle_fixtures(self):
        for p in FIXTURES.glob('*.jpg'):
            encoded = p.read_bytes(); image = pillow_luma(encoded)
            self.assertEqual(image.tobytes(),p.with_suffix('.gray').read_bytes())
            result,_,_ = reference_decode(encoded)
            self.assertLessEqual(int(np.max(abs(result.astype(int)-image.astype(int)))),1)
    def test_transform_fingerprint(self):
        digest = hashlib.sha256(ALGORITHM+b''.join(struct.pack('<i',int(x)) for x in Q14.flat)).hexdigest()
        self.assertEqual(digest,'588e556273a96bd86576c60858f7a277eb0974a1ef56165e916c773350868461')
    def test_transform_bound(self):
        generator = np.random.default_rng(8271)
        for _ in range(2000):
            c = generator.integers(-2048*255,2048*255,size=(8,8),dtype=np.int64)
            a = Q14.T @ c @ Q14
            self.assertLess(int(np.max(np.abs(a))),1<<54)
    def test_restart_count(self):
        result,blocks,restarts = reference_decode(encode('RGB',48,33,2,1))
        self.assertEqual((blocks,restarts),(54,8))
        self.assertEqual(result.shape,(33,48))

if __name__ == '__main__': unittest.main()
