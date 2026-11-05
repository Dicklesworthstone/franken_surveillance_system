import sys
sys.path.insert(0, '/Users/jemanuel/projects/franken_surveillance_system/tools')
import tapo_lzma2 as T

class DictOut(bytearray):
    def __getitem__(self, i):
        if isinstance(i, int) and i < 0 and i < -len(self):
            return 0
        return super().__getitem__(i)

blob = open('/Users/jemanuel/fss-exploit/c460_113.bin.dec','rb').read()
body = blob[0x70284+6:0x70284+6+61439]
want = bytes.fromhex('b00000ea14f09fe5')

def run(mask, n=8):
    dec = T.LZMA(3,0,2,1<<22)
    out = DictOut(); dec.out = out
    rc = T.RC(body)
    prev = 0
    for pos in range(n):
        pos_state = len(out) & 3
        if (mask >> pos) & 1:
            if rc.bit(dec.is_match, (dec.state << 2) + pos_state) != 0:
                return None, bytes(out)
        b = dec._lit(rc, pos_state, prev)
        out.append(b); prev = b; dec.state = 0
    return sum(1 for a, b in zip(bytes(out), want) if a == b), bytes(out)

best = []
for mask in range(256):
    score, head = run(mask)
    if score:
        best.append((score, mask, head.hex()))
best.sort(reverse=True)
for s, m, h in best[:5]:
    print('score=%d/%d mask=%s head=%s' % (s, len(want), format(m, '08b'), h))
