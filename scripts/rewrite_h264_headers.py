#!/usr/bin/env python3
"""Header-only rewrites of libx264 Constrained-Baseline Annex-B streams.

libx264 cannot emit two syntax paths the decoder must support, so this
script derives them from existing fixture streams by rewriting parameter
set / slice header fields bit-exactly and copying all macroblock data
verbatim (ITU-T H.264 7.3.2.1.1 and 7.3.3):

  --deblock-idc2  every slice gets disable_deblocking_filter_idc = 2
                  (filter everything except slice edges), keeping its
                  alpha/beta offsets;
  --poc-type0     SPS pic_order_cnt_type 2 -> 0 with an 8-bit
                  pic_order_cnt_lsb, and every slice carries
                  pic_order_cnt_lsb = 2 * (pictures since the last IDR).

Pixels for the rewritten streams still come only from the FFmpeg oracle.
Supports exactly the syntax libx264 Baseline emits (profile 66, one PPS,
deblocking_filter_control_present_flag = 1, no reordering / MMCO) and
fails loudly on anything else.

Usage: rewrite_h264_headers.py (--deblock-idc2 | --poc-type0) IN OUT
"""
import sys


class Reader:
    def __init__(self, data):
        self.data = data
        self.pos = 0

    def u(self, n):
        value = 0
        for _ in range(n):
            byte = self.data[self.pos >> 3]
            value = (value << 1) | ((byte >> (7 - (self.pos & 7))) & 1)
            self.pos += 1
        return value

    def ue(self):
        zeros = 0
        while self.u(1) == 0:
            zeros += 1
        return (1 << zeros) - 1 + self.u(zeros)

    def se(self):
        k = self.ue()
        return (k + 1) // 2 if k % 2 else -(k // 2)

    def rest_bits(self):
        """Remaining payload bits up to (excluding) the rbsp stop bit."""
        total = len(self.data) * 8
        last = total - 1
        while ((self.data[last >> 3] >> (7 - (last & 7))) & 1) == 0:
            last -= 1
        bits = []
        while self.pos < last:
            bits.append(self.u(1))
        return bits


class Writer:
    def __init__(self):
        self.bits = []

    def u(self, n, value):
        for shift in range(n - 1, -1, -1):
            self.bits.append((value >> shift) & 1)

    def ue(self, value):
        code = value + 1
        length = code.bit_length()
        self.u(length - 1, 0)
        self.u(length, code)

    def se(self, value):
        self.ue(2 * value - 1 if value > 0 else -2 * value)

    def finish(self, tail):
        bits = self.bits + tail + [1]
        while len(bits) % 8:
            bits.append(0)
        return bytes(
            sum(bit << (7 - i) for i, bit in enumerate(bits[k:k + 8]))
            for k in range(0, len(bits), 8)
        )


def unescape(ebsp):
    out = bytearray()
    zeros = 0
    i = 0
    while i < len(ebsp):
        byte = ebsp[i]
        if zeros == 2 and byte == 3:
            zeros = 0
            i += 1
            continue
        out.append(byte)
        zeros = zeros + 1 if byte == 0 else 0
        i += 1
    return bytes(out)


def escape(rbsp):
    out = bytearray()
    zeros = 0
    for byte in rbsp:
        if zeros == 2 and byte <= 3:
            out.append(3)
            zeros = 0
        out.append(byte)
        zeros = zeros + 1 if byte == 0 else 0
    return bytes(out)


def split_annex_b(stream):
    starts = []
    i = 0
    while i + 2 < len(stream):
        if stream[i] == 0 and stream[i + 1] == 0 and stream[i + 2] == 1:
            starts.append(i + 3)
            i += 3
        else:
            i += 1
    units = []
    for index, start in enumerate(starts):
        end = starts[index + 1] - 3 if index + 1 < len(starts) else len(stream)
        unit = stream[start:end]
        while unit and unit[-1] == 0:
            unit = unit[:-1]
        if unit:
            units.append(unit)
    return units


def main():
    mode, source, target = sys.argv[1], sys.argv[2], sys.argv[3]
    if mode not in ("--deblock-idc2", "--poc-type0"):
        sys.exit("unknown mode " + mode)
    stream = open(source, "rb").read()
    out = bytearray()
    log2_max_frame_num = None
    poc_type = None
    picture_since_idr = -1
    for nal in split_annex_b(stream):
        header = nal[0]
        nal_type = header & 31
        ref_idc = (header >> 5) & 3
        rbsp = unescape(nal[1:])
        r = Reader(rbsp)
        w = Writer()
        if nal_type == 7:
            profile = r.u(8)
            if profile != 66:
                sys.exit("only profile 66 streams are supported")
            w.u(8, profile)
            w.u(8, r.u(8))
            w.u(8, r.u(8))
            w.ue(r.ue())  # sps id
            log2_max_frame_num = r.ue() + 4
            w.ue(log2_max_frame_num - 4)
            poc_type = r.ue()
            if poc_type != 2:
                sys.exit("expected pic_order_cnt_type 2 from libx264")
            if mode == "--poc-type0":
                w.ue(0)
                w.ue(8 - 4)  # log2_max_pic_order_cnt_lsb = 8
            else:
                w.ue(2)
            body = w.finish(r.rest_bits())
        elif nal_type in (1, 5):
            idr = nal_type == 5
            first_mb = r.ue()
            slice_type = r.ue()
            pps_id = r.ue()
            frame_num = r.u(log2_max_frame_num)
            w.ue(first_mb)
            w.ue(slice_type)
            w.ue(pps_id)
            w.u(log2_max_frame_num, frame_num)
            if idr:
                w.ue(r.ue())  # idr_pic_id
            if first_mb == 0:
                picture_since_idr = 0 if idr else picture_since_idr + 1
            if mode == "--poc-type0":
                w.u(8, (2 * picture_since_idr) % 256)
                body = w.finish(r.rest_bits())
            else:
                if slice_type % 5 == 0:
                    override = r.u(1)
                    w.u(1, override)
                    if override:
                        w.ue(r.ue())
                    if r.u(1):
                        sys.exit("ref_pic_list_modification not supported")
                    w.u(1, 0)
                elif slice_type % 5 != 2:
                    sys.exit("only I and P slices are supported")
                if ref_idc:
                    if idr:
                        w.u(2, r.u(2))
                    else:
                        if r.u(1):
                            sys.exit("adaptive marking not supported")
                        w.u(1, 0)
                w.se(r.se())  # slice_qp_delta
                idc = r.ue()
                alpha, beta = (r.se(), r.se()) if idc != 1 else (0, 0)
                w.ue(2)
                w.se(alpha)
                w.se(beta)
                body = w.finish(r.rest_bits())
        else:
            body = rbsp
        out += b"\x00\x00\x00\x01" + bytes([header]) + escape(body)
    open(target, "wb").write(bytes(out))


if __name__ == "__main__":
    main()
