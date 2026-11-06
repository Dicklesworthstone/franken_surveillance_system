#!/usr/bin/env python3
"""Offline synthetic H.264 fixture; no production decoder or encoder is used.

Assemble one 48x32 High-profile I picture with six single-macroblock slices.
Each slice has one luma DC coefficient using a prefix 15, 16 or 17 escape,
with both signs. QP 0 and a scaling-list weight of 1 keep the reconstructed
extended-escape samples away from clipping. Expected pixels/hashes must be
obtained independently; this script only writes the syntax described in
ITU-T H.264 (08/2024), clauses 7.3.2.1.1, 7.3.3, 7.3.5 and 9.2.2.
"""

from pathlib import Path


class Bits:
    def __init__(self):
        self.bits = ""

    def u(self, width, value):
        assert 0 <= value < (1 << width)
        self.bits += f"{value:0{width}b}"
        return self

    def ue(self, value):
        code = value + 1
        width = code.bit_length()
        self.bits += "0" * (width - 1) + f"{code:b}"
        return self

    def se(self, value):
        return self.ue(2 * value - 1 if value > 0 else -2 * value)

    def nal(self, header):
        bits = self.bits + "1"  # rbsp_stop_one_bit
        bits += "0" * (-len(bits) % 8)
        raw = bytes(int(bits[i:i + 8], 2) for i in range(0, len(bits), 8))
        ebsp = bytearray()
        zeros = 0
        for byte in raw:
            if zeros == 2 and byte <= 3:
                ebsp.append(3)
                zeros = 0
            ebsp.append(byte)
            zeros = zeros + 1 if byte == 0 else 0
        return b"\x00\x00\x00\x01" + bytes([header]) + ebsp


def sps():
    w = Bits().u(8, 100).u(8, 0).u(8, 30).ue(0)
    w.ue(1).ue(0).ue(0).u(1, 0).u(1, 1)  # 8-bit 4:2:0, scaling lists
    for index in range(8):
        w.u(1, int(index == 0))
        if index == 0:
            w.se(-7)  # first scaling weight: 8 - 7 = 1
            for _ in range(15):
                w.se(0)  # remaining intra-luma 4x4 weights stay 1
    w.ue(0).ue(2).ue(1).u(1, 0).ue(2).ue(1)  # frame_num 4, POC 2, 3x2 MBs
    w.u(1, 1).u(1, 1).u(1, 0).u(1, 0)  # progressive, inference, no crop/VUI
    return w.nal(0x67)


def pps():
    w = Bits().ue(0).ue(0).u(1, 0).u(1, 0).ue(0)
    w.ue(0).ue(0).u(1, 0).u(2, 0)
    w.se(-26).se(0).se(0)  # initial QP=0, default chroma offset
    w.u(1, 1).u(1, 0).u(1, 0)  # deblocking control, no constrained intra/redundancy
    return w.nal(0x68)


def slice_nal(address, prefix, suffix):
    w = Bits().ue(address).ue(7).ue(0).u(4, 0).ue(0)
    w.u(1, 0).u(1, 0).se(0).ue(1)  # IDR marking, QP delta 0, no deblocking
    w.ue(3).ue(0).se(0)  # I_16x16 DC, no AC/chroma residual, chroma DC prediction
    w.u(6, 0b000101)  # nC=0: TotalCoeff=1, TrailingOnes=0
    w.u(prefix, 0).u(1, 1).u(prefix - 3, suffix)
    w.u(1, 1)  # TotalCoeff=1, total_zeros=0
    return w.nal(0x65)


if __name__ == "__main__":
    stream = sps() + pps()
    for address, (prefix, suffix) in enumerate(
        [(15, 0), (15, 1), (16, 0), (16, 1), (17, 0), (17, 1)]
    ):
        stream += slice_nal(address, prefix, suffix)
    path = Path(__file__).with_name("h_cavlc_level_escape.h264")
    path.write_bytes(stream)
    print(f"{path.name}: {len(stream)} bytes")
