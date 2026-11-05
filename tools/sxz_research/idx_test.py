import sys
sys.path.insert(0, '/Users/jemanuel/projects/franken_surveillance_system/tools')
import tapo_lzma2 as T

blob = open('/Users/jemanuel/fss-exploit/c460_113.bin.dec','rb').read()
body = blob[0x70284+6:0x70284+6+61439]

class DictOut(bytearray):
    def __getitem__(self, i):
        if isinstance(i, int) and i < 0 and i < -len(self):
            return 0
        return super().__getitem__(i)

def run(pb, variant):
    dec = T.LZMA(3,0,2,1<<22)
    out = DictOut(); dec.out = out
    rc = T.RC(body)
    prev = 0
    pmask = (1 << pb) - 1
    try:
        while len(out) < 64:
            if variant == 'std':
                idx = (dec.state << pb) + (len(out) & pmask)
            elif variant == 'prevpos':
                idx = (dec.state << pb) + ((len(out) - 1) & pmask)
            elif variant == 'nopos':
                idx = dec.state
            if rc.bit(dec.is_match, idx) == 0:
                b = dec._lit(rc, len(out) & pmask, prev)
                out.append(b); prev = b
                dec.state = 0 if dec.state < 4 else (dec.state-3 if dec.state < 10 else dec.state-6)
                continue
            if rc.bit(dec.is_rep, dec.state) == 1:
                if rc.bit(dec.is_rep_g0, dec.state) == 0:
                    if rc.bit(dec.is_rep0_long, (dec.state << pb) + (len(out) & pmask)) == 0:
                        out.append(out[-dec.rep[0]-1]); prev = out[-1]
                        dec.state = 9 if dec.state < 7 else 11
                        continue
                    ln = dec.rep_len.decode(rc, len(out) & pmask)
                else:
                    if rc.bit(dec.is_rep_g1, dec.state) == 0:
                        d0 = dec.rep[1]
                    else:
                        if rc.bit(dec.is_rep_g2, dec.state) == 0:
                            d0 = dec.rep[2]
                        else:
                            d0 = dec.rep[3]; dec.rep[3] = dec.rep[2]
                        dec.rep[2] = dec.rep[1]
                    dec.rep[1] = dec.rep[0]; dec.rep[0] = d0
                    ln = dec.rep_len.decode(rc, len(out) & pmask)
                dec.state = 8 if dec.state < 7 else 11
                for _ in range(ln+2):
                    out.append(out[-dec.rep[0]-1])
                prev = out[-1]
            else:
                dec.rep[3], dec.rep[2], dec.rep[1] = dec.rep[2], dec.rep[1], dec.rep[0]
                ln = dec.len_coder.decode(rc, len(out) & pmask)
                dec.state = 7 if dec.state < 7 else 10
                dec.rep[0] = dec._dist(rc, ln)
                for _ in range(ln+2):
                    out.append(out[-dec.rep[0]-1])
                prev = out[-1]
    except Exception as e:
        return bytes(out[:16]).hex() + ' [stopped %s @%d]' % (type(e).__name__, len(out))
    return bytes(out[:16]).hex()

for variant in ('std', 'prevpos', 'nopos'):
    print(variant, run(2, variant))
