import sys
sys.path.insert(0, '/Users/jemanuel/projects/franken_surveillance_system/tools')
import tapo_lzma2 as T

blob = open('/Users/jemanuel/fss-exploit/c460_113.bin.dec','rb').read()
body = blob[0x70284+6:0x70284+6+61439]

def run(style):
    dec = T.LZMA(3,0,2,1<<22)
    out = bytearray(); dec.out = out
    rc = T.RC(body)
    prev = 0
    trace = []
    orig_bit = T.RC.bit
    def logging_bit(self, probs, idx):
        p = probs[idx]
        r = orig_bit(self, probs, idx)
        trace.append((idx, p, r))
        return r
    T.RC.bit = logging_bit
    if style == 'while':
        while len(out) < 4:
            pos_state = len(out) & 3
            if rc.bit(dec.is_match, (dec.state << 2) + pos_state) == 0:
                b = dec._lit(rc, pos_state, prev)
                out.append(b); prev = b
                dec.state = 0 if dec.state < 4 else (dec.state-3 if dec.state < 10 else dec.state-6)
                continue
            break
    else:
        for pos in range(2):
            pos_state = len(out) & 3
            rc.bit(dec.is_match, (dec.state << 2) + pos_state)
            b = dec._lit(rc, pos_state, prev)
            out.append(b); prev = b; dec.state = 0
        b = dec._lit(rc, 2, prev)
        out.append(b); prev = b
    T.RC.bit = orig_bit
    return bytes(out[:4]).hex(), trace

h1, t1 = run('while')
h2, t2 = run('for')
print('while:', h1)
print('for  :', h2)
# diff the traces up to the point they agree in length
for i, (a, b) in enumerate(zip(t1, t2)):
    if a != b:
        print('FIRST DIVERGENCE at decision %d: while(idx=%d,p=%d,r=%d) for(idx=%d,p=%d,r=%d)' % (i, a[0], a[1], a[2], b[0], b[1], b[2]))
        print('  context before:', t1[max(0,i-3):i])
        break
else:
    print('traces identical for %d decisions' % min(len(t1), len(t2)))
