#!/usr/bin/env python3
"""Rewrite a libx265 P-only stream so its oldest references are long-term pictures.

Laboratory fixture tool for fss-codec-h265 long-term reference support (clauses 7.4.7.1,
8.3.2, 8.3.4). No available encoder emits long-term reference pictures, which consumer
"smart codec" cameras use, so this tool converts an encoded stream instead:

* the SPS is re-emitted with ``long_term_ref_pics_present_flag = 1`` and
  ``num_long_term_ref_pics_sps = 0`` (every other bit is copied verbatim);
* every P-slice header replaces its short-term RPS with an explicit RPS that keeps all but the
  oldest used reference short-term and signals the oldest one as a long-term picture by its
  ``poc_lsb_lt`` (optionally with ``delta_poc_msb_present_flag`` and a zero MSB cycle, which
  exercises the full-POC matching path); the rest of the slice header and the slice data are
  copied verbatim (the slice data starts byte-aligned, so CABAC data is untouched).

Long-term entries follow the short-term entries in RefPicListTemp0, so list order is
preserved. With one reference the rewritten stream decodes to exactly the original pictures;
with two, the long-term motion-vector rules of clause 8.5.3.2 change predictors, so the
oracle is FFmpeg's decode of the *rewritten* stream. Requirements on the input (checked):
one slice per picture, no B slices, no temporal MVP, no weighted prediction, no tiles, no
lists modification, a short clip (picture order counts below MaxPicOrderCntLsb / 2).

Usage: generate_h265_ltr_fixture.py <input.h265> <output.h265> [--msb-on-odd]
"""

import sys


class BitReader:
    def __init__(self, data: bytes):
        self.data = data
        self.pos = 0

    def bit(self) -> int:
        byte = self.data[self.pos >> 3]
        value = (byte >> (7 - (self.pos & 7))) & 1
        self.pos += 1
        return value

    def bits(self, n: int) -> int:
        value = 0
        for _ in range(n):
            value = (value << 1) | self.bit()
        return value

    def ue(self) -> int:
        zeros = 0
        while self.bit() == 0:
            zeros += 1
        return (1 << zeros) - 1 + self.bits(zeros)

    def se(self) -> int:
        k = self.ue()
        return (k + 1) // 2 if k & 1 else -(k // 2)


class BitWriter:
    def __init__(self):
        self.out = []

    def bit(self, value: int):
        self.out.append(value & 1)

    def bits(self, value: int, n: int):
        for shift in range(n - 1, -1, -1):
            self.bit((value >> shift) & 1)

    def ue(self, value: int):
        value += 1
        length = value.bit_length()
        self.bits(0, length - 1)
        self.bits(value, length)

    def raw(self, bits):
        self.out.extend(bits)


def bit_list(data: bytes, start: int, end: int):
    return [(data[i >> 3] >> (7 - (i & 7))) & 1 for i in range(start, end)]


def to_bytes(bits) -> bytes:
    out = bytearray()
    for i in range(0, len(bits), 8):
        chunk = bits[i:i + 8] + [0] * (8 - len(bits[i:i + 8]))
        value = 0
        for b in chunk:
            value = (value << 1) | b
        out.append(value)
    return bytes(out)


def rbsp_from_ebsp(ebsp: bytes) -> bytes:
    out = bytearray()
    zeros = 0
    for byte in ebsp:
        if zeros >= 2 and byte == 3:
            zeros = 0
            continue
        out.append(byte)
        zeros = zeros + 1 if byte == 0 else 0
    return bytes(out)


def ebsp_from_rbsp(rbsp: bytes) -> bytes:
    out = bytearray()
    zeros = 0
    for byte in rbsp:
        if zeros >= 2 and byte <= 3:
            out.append(3)
            zeros = 0
        out.append(byte)
        zeros = zeros + 1 if byte == 0 else 0
    return bytes(out)


def split_annexb(stream: bytes):
    nals, i, n = [], 0, len(stream)
    starts = []
    while i + 3 <= n:
        if stream[i:i + 3] == b"\x00\x00\x01":
            starts.append(i + 3)
            i += 3
        else:
            i += 1
    for k, start in enumerate(starts):
        end = starts[k + 1] - 3 if k + 1 < len(starts) else n
        while end > start and stream[end - 1] == 0:
            end -= 1
        nals.append(stream[start:end])
    return nals


def skip_profile_tier_level(r: BitReader, max_sub_layers_minus1: int):
    r.bits(2 + 1 + 5 + 32 + 4 + 43 + 1 + 8)
    present = []
    for _ in range(max_sub_layers_minus1):
        present.append((r.bit(), r.bit()))
    if max_sub_layers_minus1 > 0:
        for _ in range(max_sub_layers_minus1, 8):
            r.bits(2)
    for profile, level in present:
        if profile:
            r.bits(88)
        if level:
            r.bits(8)


def parse_st_rps(r: BitReader, idx: int, previous: list):
    """Returns (negative deltas, used flags, positive deltas, used flags)."""
    inter = r.bit() if idx != 0 else 0
    if inter:
        delta_idx = 1  # only in slice headers would delta_idx_minus1 be coded
        if idx == len(previous):
            delta_idx = r.ue() + 1
        sign = r.bit()
        abs_delta = r.ue() + 1
        delta_rps = (1 - 2 * sign) * abs_delta
        ref = previous[idx - delta_idx]
        ref_deltas = ref[0] + ref[2]
        used_by, use_delta = [], []
        for _ in range(len(ref_deltas) + 1):
            used = r.bit()
            use = 1 if used else r.bit()
            used_by.append(used)
            use_delta.append(use)
        # Clause 7.4.8 derivation.
        neg, neg_used, pos, pos_used = [], [], [], []
        s0, s1 = ref[0], ref[2]
        u0, u1 = ref[1], ref[3]
        nn, np_ = len(s0), len(s1)
        for j in range(np_ - 1, -1, -1):
            d = s1[j] + delta_rps
            if d < 0 and use_delta[nn + j]:
                neg.append(d)
                neg_used.append(used_by[nn + j])
        if delta_rps < 0 and use_delta[nn + np_]:
            neg.append(delta_rps)
            neg_used.append(used_by[nn + np_])
        for j in range(nn):
            d = s0[j] + delta_rps
            if d < 0 and use_delta[j]:
                neg.append(d)
                neg_used.append(used_by[j])
        for j in range(nn - 1, -1, -1):
            d = s0[j] + delta_rps
            if d > 0 and use_delta[j]:
                pos.append(d)
                pos_used.append(used_by[j])
        if delta_rps > 0 and use_delta[nn + np_]:
            pos.append(delta_rps)
            pos_used.append(used_by[nn + np_])
        for j in range(np_):
            d = s1[j] + delta_rps
            if d > 0 and use_delta[nn + j]:
                pos.append(d)
                pos_used.append(used_by[nn + j])
        return neg, neg_used, pos, pos_used
    num_negative, num_positive = r.ue(), r.ue()
    neg, neg_used, pos, pos_used = [], [], [], []
    value = 0
    for _ in range(num_negative):
        value -= r.ue() + 1
        neg.append(value)
        neg_used.append(r.bit())
    value = 0
    for _ in range(num_positive):
        value += r.ue() + 1
        pos.append(value)
        pos_used.append(r.bit())
    return neg, neg_used, pos, pos_used


def parse_sps(rbsp: bytes):
    r = BitReader(rbsp)
    r.bits(16)  # NAL header
    r.bits(4)
    max_sub_layers_minus1 = r.bits(3)
    r.bit()
    skip_profile_tier_level(r, max_sub_layers_minus1)
    r.ue()
    chroma = r.ue()
    if chroma == 3:
        r.bit()
    r.ue()
    r.ue()
    if r.bit():
        for _ in range(4):
            r.ue()
    r.ue()
    r.ue()
    log2_max_poc_lsb = r.ue() + 4
    ordering = r.bit()
    for _ in range(0 if ordering else max_sub_layers_minus1, max_sub_layers_minus1 + 1):
        r.ue()
        r.ue()
        r.ue()
    for _ in range(6):
        r.ue()
    if r.bit():  # scaling_list_enabled
        if r.bit():
            raise SystemExit("SPS scaling list data is not supported by this tool")
    r.bit()  # amp
    sao = r.bit()
    if r.bit():  # pcm
        raise SystemExit("PCM is not supported by this tool")
    count = r.ue()
    st_rps = []
    for i in range(count):
        st_rps.append(parse_st_rps(r, i, st_rps))
    flag_position = r.pos
    if r.bit():
        raise SystemExit("the input already signals long-term references")
    temporal_mvp = r.bit()
    return {
        "log2_max_poc_lsb": log2_max_poc_lsb,
        "sao": sao,
        "st_rps": st_rps,
        "flag_position": flag_position,
        "temporal_mvp": temporal_mvp,
        "chroma": chroma,
    }


def rewrite_sps(rbsp: bytes, info) -> bytes:
    stop = len(rbsp) * 8 - 1
    while not (rbsp[stop >> 3] >> (7 - (stop & 7))) & 1:
        stop -= 1
    position = info["flag_position"]
    bits = bit_list(rbsp, 0, position)
    bits += [1, 1]  # long_term_ref_pics_present_flag = 1; num_long_term_ref_pics_sps = ue(0)
    bits += bit_list(rbsp, position + 1, stop)
    bits.append(1)
    return to_bytes(bits)


IRAP = range(16, 24)


def rewrite_slice(rbsp: bytes, nal_type: int, sps, pps, poc_state, msb_on_odd: bool):
    r = BitReader(rbsp)
    r.bits(16)
    first = r.bit()
    if not first:
        raise SystemExit("one slice per picture is required")
    if nal_type in IRAP:
        r.bit()
    r.ue()
    r.bits(pps["extra_bits"])
    slice_type = r.ue()
    if pps["output_flag"]:
        r.bit()
    if nal_type in (19, 20):  # IDR: no RPS
        poc_state["count"] += 1
        return rbsp, False
    poc_lsb = r.bits(sps["log2_max_poc_lsb"])
    start = r.pos
    from_sps = r.bit()
    if from_sps:
        count = len(sps["st_rps"])
        bits = (count - 1).bit_length() if count > 1 else 0
        rps = sps["st_rps"][r.bits(bits)]
    else:
        rps = parse_st_rps(r, len(sps["st_rps"]), sps["st_rps"])
    if sps["temporal_mvp"]:
        raise SystemExit("temporal MVP must be disabled in the SPS")
    end = r.pos
    if slice_type == 0:
        raise SystemExit("B slices are not supported by this tool")
    if slice_type == 2:  # I slice: keep its RPS
        return rbsp, False
    neg, neg_used, pos, pos_used = rps
    if pos or not neg or not all(neg_used):
        raise SystemExit(f"unexpected RPS for a P picture: {rps}")
    if pps["weighted_pred"]:
        raise SystemExit("weighted prediction must be disabled")
    if poc_lsb >= (1 << sps["log2_max_poc_lsb"]) // 2:
        raise SystemExit("the clip is too long for unambiguous long-term LSB matching")
    oldest = neg[-1]
    keep = neg[:-1]
    w = BitWriter()
    w.bit(0)  # short_term_ref_pic_set_sps_flag
    if len(sps["st_rps"]) != 0:
        w.bit(0)  # inter_ref_pic_set_prediction_flag
    w.ue(len(keep))
    w.ue(0)
    previous = 0
    for delta in keep:
        w.ue(previous - delta - 1)
        w.bit(1)
        previous = delta
    w.ue(1)  # num_long_term_pics (num_long_term_sps absent: none in the SPS)
    w.bits(poc_lsb + oldest, sps["log2_max_poc_lsb"])
    w.bit(1)  # used_by_curr_pic_lt_flag
    use_msb = msb_on_odd and poc_lsb % 2 == 1
    w.bit(1 if use_msb else 0)
    if use_msb:
        w.ue(0)  # delta_poc_msb_cycle_lt: same MSB cycle
    # The header remainder after the RPS is copied verbatim up to its byte_alignment();
    # the byte-aligned slice data follows unchanged.
    data_start = header_end(rbsp, end, slice_type, sps, pps)
    remainder = bit_list(rbsp, end, data_start_alignment_bit(rbsp, data_start))
    bits = bit_list(rbsp, 0, start) + w.out + remainder
    bits.append(1)  # byte_alignment(): alignment_bit_equal_to_one
    while len(bits) % 8:
        bits.append(0)
    return to_bytes(bits) + rbsp[data_start // 8:], True


def header_end(rbsp: bytes, end: int, slice_type: int, sps, pps) -> int:
    """Parses the slice header remainder after the RPS; returns the bit position where the
    slice data starts (after byte_alignment())."""
    r = BitReader(rbsp)
    r.pos = end
    if sps["sao"]:
        r.bit()
        if sps["chroma"] != 0:
            r.bit()
    if slice_type in (0, 1):
        if r.bit():  # num_ref_idx_active_override_flag
            r.ue()
            if slice_type == 0:
                r.ue()
        if pps.get("cabac_init_present"):
            r.bit()
        r.ue()  # five_minus_max_num_merge_cand
    return HeaderTail(rbsp, r.pos, sps, pps).end()


class HeaderTail:
    """slice_qp_delta onwards; needs PPS flags parsed in full."""

    def __init__(self, rbsp, pos, sps, pps):
        self.rbsp, self.pos, self.sps, self.pps = rbsp, pos, sps, pps

    def end(self) -> int:
        r = BitReader(self.rbsp)
        r.pos = self.pos
        p = self.pps
        r.se()  # slice_qp_delta
        if p["slice_chroma_qp_offsets_present"]:
            r.se()
            r.se()
        deblocking_disabled = p["pps_deblocking_disabled"]
        if p["deblocking_override_enabled"]:
            if r.bit():
                deblocking_disabled = r.bit()
                if not deblocking_disabled:
                    r.se()
                    r.se()
        if p["loop_filter_across_slices"] and (self.sps["sao"] or not deblocking_disabled):
            r.bit()
        if p["entropy_sync"]:
            count = r.ue()
            if count:
                length = r.ue() + 1
                r.bits(length * count)
        if p["slice_header_extension"]:
            length = r.ue()
            r.bits(8 * length)
        # byte_alignment(): one '1' then zeros to the boundary.
        if r.bit() != 1:
            raise SystemExit("slice header alignment bit is not 1")
        while r.pos % 8:
            if r.bit() != 0:
                raise SystemExit("slice header alignment zero bit is not 0")
        return r.pos


def data_start_alignment_bit(rbsp: bytes, data_start: int) -> int:
    """Position of the alignment '1' bit that precedes `data_start`."""
    position = data_start - 1
    while not (rbsp[position >> 3] >> (7 - (position & 7))) & 1:
        position -= 1
    return position


def parse_pps_full(rbsp: bytes):
    r = BitReader(rbsp)
    r.bits(16)
    r.ue()
    r.ue()
    dependent = r.bit()
    output_flag = r.bit()
    extra_bits = r.bits(3)
    r.bit()
    cabac_init_present = r.bit()
    r.ue()
    r.ue()
    r.se()
    r.bit()
    r.bit()
    if r.bit():
        r.ue()
    r.se()
    r.se()
    chroma_offsets = r.bit()
    weighted_pred = r.bit()
    r.bit()  # weighted_bipred
    r.bit()  # transquant_bypass
    tiles = r.bit()
    entropy_sync = r.bit()
    if tiles:
        raise SystemExit("tiles are not supported by this tool")
    loop_filter_across_slices = r.bit()
    override_enabled, pps_disabled = 0, 0
    if r.bit():
        override_enabled = r.bit()
        pps_disabled = r.bit()
        if not pps_disabled:
            r.se()
            r.se()
    if r.bit():  # pps_scaling_list_data_present
        raise SystemExit("PPS scaling lists are not supported by this tool")
    lists_modification = r.bit()
    r.ue()  # log2_parallel_merge_level_minus2
    extension = r.bit()
    return {
        "dependent": dependent,
        "output_flag": output_flag,
        "extra_bits": extra_bits,
        "cabac_init_present": cabac_init_present,
        "slice_chroma_qp_offsets_present": chroma_offsets,
        "weighted_pred": weighted_pred,
        "entropy_sync": entropy_sync,
        "loop_filter_across_slices": loop_filter_across_slices,
        "deblocking_override_enabled": override_enabled,
        "pps_deblocking_disabled": pps_disabled,
        "lists_modification": lists_modification,
        "slice_header_extension": extension,
    }


def main():
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    msb_on_odd = "--msb-on-odd" in sys.argv
    if len(args) != 2:
        raise SystemExit(__doc__)
    stream = open(args[0], "rb").read()
    out = bytearray()
    sps = pps = None
    poc_state = {"count": 0}
    rewritten = 0
    for nal in split_annexb(stream):
        nal_type = (nal[0] >> 1) & 0x3F
        rbsp = rbsp_from_ebsp(nal)
        if nal_type == 33:
            sps = parse_sps(rbsp)
            rbsp = rewrite_sps(rbsp, sps)
        elif nal_type == 34:
            pps = parse_pps_full(rbsp)
            if pps["lists_modification"]:
                raise SystemExit("lists modification must be disabled")
        elif nal_type < 32:
            rbsp, changed = rewrite_slice(rbsp, nal_type, sps, pps, poc_state, msb_on_odd)
            rewritten += int(changed)
        out += b"\x00\x00\x00\x01" + ebsp_from_rbsp(rbsp)
    if rewritten == 0:
        raise SystemExit("no P slice was rewritten")
    open(args[1], "wb").write(bytes(out))
    print(f"rewrote {rewritten} P slices to long-term references -> {args[1]}")


if __name__ == "__main__":
    main()
