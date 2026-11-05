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
for st0 in range(12):
    dec = T.LZMA(3,0,2,1<<22)
    out = DictOut(); dec.out = out
    rc = T.RC(body)
    dec.state = st0
    prev = 0
    try:
        while len(out) < 8:
            pos_state = len(out) & 3
            if rc.bit(dec.is_match, (dec.state << 2) + pos_state) == 0:
                b = dec._lit(rc, pos_state, prev)
                out.append(b); prev = b
                dec.state = 0 if dec.state < 4 else (dec.state-3 if dec.state < 10 else dec.state-6)
                continue
            break
        print('state0=%d: %s' % (st0, bytes(out[:8]).hex()))
    except Exception:
        print('state0=%d: err %s' % (st0, bytes(out[:4]).hex()))
