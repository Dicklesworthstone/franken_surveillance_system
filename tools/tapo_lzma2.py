#!/usr/bin/env python3
"""Minimal LZMA1/LZMA2 raw decoder that tolerates lc+lp > 4.

liblzma (and therefore xz, 7z and Python's lzma) rejects the SigmaStar encoder's
props 0xef = lc 5 / lp 1 / pb 5, because LZMA2 requires lc+lp <= 4. The hardware
decoder does not care. This implements the range coder directly so the C460
ramdisk can be unpacked.
"""
import sys

K_TOP = 1 << 24
PROB_INIT = 1024
MOVE = 5


class RC:
    def __init__(self, data):
        self.d = data
        self.i = 0
        self.range = 0xFFFFFFFF
        self.code = 0
        for _ in range(5):
            self.code = ((self.code << 8) | self._byte()) & 0xFFFFFFFF
        self.code &= 0xFFFFFFFF

    def _byte(self):
        b = self.d[self.i] if self.i < len(self.d) else 0
        self.i += 1
        return b

    def _norm(self):
        if self.range < K_TOP:
            self.range = (self.range << 8) & 0xFFFFFFFF
            self.code = ((self.code << 8) | self._byte()) & 0xFFFFFFFF

    def bit(self, probs, idx):
        p = probs[idx]
        bound = (self.range >> 11) * p
        if self.code < bound:
            self.range = bound
            probs[idx] = p + ((2048 - p) >> MOVE)
            r = 0
        else:
            self.range -= bound
            self.code -= bound
            probs[idx] = p - (p >> MOVE)
            r = 1
        self._norm()
        return r

    def direct(self, n):
        # fixed-probability bits: `code` in the LOWER half of the range is bit 0.
        # The xz reference (rc.direct_bits / RangeCoder) shifts range by 1, then
        # `code -= range; if code < 0: code += range; bit = 0 else bit = 1` —
        # negative means the value sits below the midpoint, i.e. bit 0. The old
        # code emitted 1 there, inverting every direct bit and desyncing the
        # distance decode at slots >= 14 (the "slot 40 vs 9" symptom).
        r = 0
        for _ in range(n):
            self.range >>= 1
            self.code -= self.range
            if self.code < 0:
                self.code = (self.code + self.range) & 0xFFFFFFFF
                r <<= 1
            else:
                r = (r << 1) | 1
            self._norm()
        return r


class Len:
    def __init__(self):
        self.choice = [PROB_INIT] * 2
        self.low = [[PROB_INIT] * 8 for _ in range(16)]
        self.mid = [[PROB_INIT] * 8 for _ in range(16)]
        self.high = [PROB_INIT] * 256

    def decode(self, rc, pos_state):
        if rc.bit(self.choice, 0) == 0:
            return self._tree(rc, self.low[pos_state], 3)
        if rc.bit(self.choice, 1) == 0:
            return 8 + self._tree(rc, self.mid[pos_state], 3)
        return 16 + self._tree(rc, self.high, 8)

    @staticmethod
    def _tree(rc, probs, nbits):
        m = 1
        for _ in range(nbits):
            m = (m << 1) | rc.bit(probs, m)
        return m - (1 << nbits)


class LZMA:
    def __init__(self, lc, lp, pb, dict_size):
        self.lc, self.lp, self.pb = lc, lp, pb
        self.dict_size = dict_size
        self.state = 0
        self.rep = [0, 0, 0, 0]
        self.is_match = [PROB_INIT] * (12 << pb)
        self.is_rep = [PROB_INIT] * 12
        self.is_rep_g0 = [PROB_INIT] * 12
        self.is_rep_g1 = [PROB_INIT] * 12
        self.is_rep_g2 = [PROB_INIT] * 12
        self.is_rep0_long = [PROB_INIT] * (12 << pb)
        self.literal = [PROB_INIT] * (0x300 << (lc + lp))
        self.pos_slot = [[PROB_INIT] * 64 for _ in range(4)]
        self.pos_spec = [PROB_INIT] * 115
        self.align = [PROB_INIT] * 16
        self.len_coder = Len()
        self.rep_len = Len()

    def _lit(self, rc, pos_state, prev):
        pos = len(self.out)
        base = 0x300 * (((pos & ((1 << self.lp) - 1)) << self.lc) + (prev >> (8 - self.lc)))
        probs = self.literal
        sym = 1
        if self.state >= 7:
            match_byte = self.out[-self.rep[0] - 1]
            while sym < 0x100:
                match_bit = (match_byte >> 7) & 1
                match_byte = (match_byte << 1) & 0xFF
                b = rc.bit(probs, base + ((1 + match_bit) << 8) + sym)
                sym = (sym << 1) | b
                if match_bit != b:
                    break
        while sym < 0x100:
            sym = (sym << 1) | rc.bit(probs, base + sym)
        return sym & 0xFF

    def _dist(self, rc, length):
        slot = Len._tree(rc, self.pos_slot[min(length, 3)], 6)
        if slot < 4:
            return slot
        nd = (slot >> 1) - 1
        dist = (2 | (slot & 1)) << nd
        if slot < 14:
            # spec: BitTreeReverseDecode(PosDecoders + dist - posSlot, nd)
            # — REVERSE bit order, prob table indexed at (dist - slot) + m
            m = 1
            sym = 0
            base = dist - slot
            for i in range(nd):
                b = rc.bit(self.pos_spec, base + m)
                m = (m << 1) | b
                sym |= b << i
            return dist + sym
        dist += rc.direct(nd - 4) << 4
        # spec: AlignDecoder.ReverseDecode — REVERSE bit order
        m = 1
        sym = 0
        for i in range(4):
            b = rc.bit(self.align, m)
            m = (m << 1) | b
            sym |= b << i
        return dist + sym

    def decode(self, data, out_size, out):
        rc = RC(data)
        self.out = out
        prev = self.out[-1] if self.out else 0
        start = len(self.out)
        while len(self.out) - start < out_size:
            pos_state = len(self.out) & ((1 << self.pb) - 1)
            if rc.bit(self.is_match, (self.state << self.pb) + pos_state) == 0:
                b = self._lit(rc, pos_state, prev)
                self.out.append(b)
                prev = b
                self.state = 0 if self.state < 4 else (self.state - 3 if self.state < 10 else self.state - 6)
                continue
            if rc.bit(self.is_rep, self.state) == 1:
                if rc.bit(self.is_rep_g0, self.state) == 0:
                    if rc.bit(self.is_rep0_long, (self.state << self.pb) + pos_state) == 0:
                        self.state = 9 if self.state < 7 else 11
                        self.out.append(self.out[-self.rep[0] - 1])
                        prev = self.out[-1]
                        continue
                else:
                    if rc.bit(self.is_rep_g1, self.state) == 0:
                        d = self.rep[1]
                    else:
                        if rc.bit(self.is_rep_g2, self.state) == 0:
                            d = self.rep[2]
                        else:
                            d = self.rep[3]
                            self.rep[3] = self.rep[2]
                        self.rep[2] = self.rep[1]
                    self.rep[1] = self.rep[0]
                    self.rep[0] = d
                ln = self.rep_len.decode(rc, pos_state)
                self.state = 8 if self.state < 7 else 11
            else:
                self.rep[3], self.rep[2], self.rep[1] = self.rep[2], self.rep[1], self.rep[0]
                ln = self.len_coder.decode(rc, pos_state)
                self.state = 7 if self.state < 7 else 10
                self.rep[0] = self._dist(rc, ln)
            length = ln + 2
            for _ in range(length):
                self.out.append(self.out[-self.rep[0] - 1])
            prev = self.out[-1]
        return bytes(self.out[start:start + out_size])


def lzma2(data, out_size):
    """Drive LZMA2 chunk framing; only LZMA chunks are handled."""
    i = 0
    out = bytearray()
    dec = None
    while i < len(data) and len(out) < out_size:
        ctrl = data[i]
        i += 1
        if ctrl == 0x00:
            break
        if ctrl in (0x01, 0x02):
            n = int.from_bytes(data[i:i + 2], "big") + 1
            i += 2
            out += data[i:i + n]
            i += n
            continue
        if ctrl < 0x80:
            raise ValueError("bad control %#x" % ctrl)
        # LZMA2 chunk header order is control | usize-1 (2B BE) | csize-1 (2B BE)
        # | props (1B) — props comes AFTER the compressed size (doc tapo.md C3
        # correction); reading it earlier shifts every later field.
        usize = ((ctrl & 0x1F) << 16) + int.from_bytes(data[i:i + 2], "big") + 1
        i += 2
        csize = int.from_bytes(data[i:i + 2], "big") + 1
        i += 2
        props = data[i]
        i += 1
        lc = props % 9
        lp = (props // 9) % 5
        pb = props // 45
        if dec is None:
            dec = LZMA(lc, lp, pb, 1 << 24)
        if ctrl >= 0xC0:
            dec.state = 0
            dec.rep = [0, 0, 0, 0]
        # dec.decode appends into `out` and returns the appended slice; do NOT
        # `out +=` that return again — every chunk was being doubled.
        dec.decode(data[i:i + csize], usize, out)
        i += csize
    return bytes(out)


if __name__ == "__main__":
    src, off, size, dst = sys.argv[1], int(sys.argv[2], 0), int(sys.argv[3], 0), sys.argv[4]
    blob = open(src, "rb").read()[off:]
    out = lzma2(blob, size) if size else lzma2(blob, 1 << 26)
    open(dst, "wb").write(out)
    print("wrote", len(out))
