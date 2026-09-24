#!/usr/bin/env python3
"""Hand-assembled H.265 Main streams exercising PCM coding units.

libx265 never emits pcm_flag, so these tiny streams are written bit by bit
from the syntax tables of ITU-T H.265 (7.3.2.2 VPS, 7.3.2.2 SPS, 7.3.2.3
PPS, 7.3.6 slice segment header, 7.3.8 slice segment data), with a small
CABAC encoder (clause 9.3.5: EncodeDecision / EncodeBypass /
EncodeTerminate / EncodeFlush) for the slice data. The expected pixels come
from the sealed FFmpeg oracle (see tests/fixtures/decode/README.md), not
from the Rust decoder; the Rust test additionally checks the PCM samples
against the pattern below, which is independent of any decoder.

Picture: 32x16 luma, CTB 16x16, minimum CB 8x8, one IDR I slice, QP 26.
PCM: 5-bit luma, 6-bit chroma, 8x8..16x16 coding blocks.
  CTU 0: one 16x16 PCM coding unit (k = 0).
  CTU 1: split into four 8x8 coding units:
    (16, 0) PCM (k = 1)
    (24, 0) intra 2Nx2N, mpm_idx 0, chroma DM, no residual
    (16, 8) intra 2Nx2N, rem_intra_luma_pred_mode 10, no residual
    (24, 8) intra 2Nx2N, mpm_idx 1, no residual
The CABAC context tables are read from the decoder crate's generated
cabac_tables.rs (itself generated from FFmpeg's transcription); a wrong
table would make the oracle decode disagree with the PCM pattern test.

Usage: generate_h265_pcm_fixture.py <output-dir>
Writes pcm_mixed_nodeblock.h265 (deblocking disabled in the PPS),
pcm_mixed_deblock.h265 (deblocking on, pcm_loop_filter_disabled_flag 1:
PCM samples are never filtered) and pcm_mixed_deblock_lf.h265 (deblocking
on, pcm_loop_filter_disabled_flag 0: PCM edges are filtered).
"""
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
TABLES = os.path.join(HERE, "..", "crates", "fss-codec-h265", "src", "cabac_tables.rs")
PCM_BITS_Y, PCM_BITS_C = 5, 6
SLICE_QP = 26


def pcm_luma(k, x, y):
    return (x * 7 + y * 13 + k * 50) & ((1 << PCM_BITS_Y) - 1)


def pcm_chroma(k, c, x, y):
    return (x * 11 + y * 5 + k * 30 + c * 17) & ((1 << PCM_BITS_C) - 1)


class Bits:
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

    def align_zero(self):
        while len(self.bits) % 8:
            self.bits.append(0)

    def trailing(self):
        self.bits.append(1)
        self.align_zero()

    def bytes(self):
        assert len(self.bits) % 8 == 0
        return bytes(
            int("".join(str(b) for b in self.bits[i:i + 8]), 2)
            for i in range(0, len(self.bits), 8)
        )


def load_tables():
    text = open(TABLES).read()
    consts = {m.group(1): int(m.group(2))
              for m in re.finditer(r"pub const (\w+): usize = (\d+);", text)}

    def array(name):
        m = re.search(name + r"[^=]*=\s*\[(.*?)\n\];", text, re.S)
        return [int(v) for v in re.findall(r"\d+", m.group(1))]

    init = array("INIT_VALUES")
    count = consts["CTX_COUNT"]
    range_lps = array("RANGE_TAB_LPS")
    return (consts, init[:count], [range_lps[i * 4:(i + 1) * 4] for i in range(64)],
            array("TRANS_IDX_LPS"), array("TRANS_IDX_MPS"))


CONSTS, INIT_I, RANGE_LPS, TRANS_LPS, TRANS_MPS = load_tables()


class Context:
    def __init__(self, init_value):
        m = (init_value >> 4) * 5 - 45
        n = ((init_value & 15) << 3) - 16
        pre = max(1, min(126, ((m * SLICE_QP) >> 4) + n))
        self.mps = 1 if pre > 63 else 0
        self.state = pre - 64 if self.mps else 63 - pre


class Encoder:
    """Clause 9.3.5 arithmetic encoder writing into a Bits sink."""

    def __init__(self, sink):
        self.sink = sink
        self.contexts = [Context(v) for v in INIT_I]
        self.init_engine()

    def init_engine(self):
        self.low, self.range, self.outstanding, self.first = 0, 510, 0, True

    def put_bit(self, bit):
        if self.first:
            self.first = False
        else:
            self.sink.bits.append(bit)
        while self.outstanding:
            self.sink.bits.append(1 - bit)
            self.outstanding -= 1

    def renorm(self):
        while self.range < 256:
            if self.low < 256:
                self.put_bit(0)
            elif self.low >= 512:
                self.low -= 512
                self.put_bit(1)
            else:
                self.low -= 256
                self.outstanding += 1
            self.range <<= 1
            self.low <<= 1

    def decision(self, name, inc, value):
        ctx = self.contexts[CONSTS[name] + inc]
        lps = RANGE_LPS[ctx.state][(self.range >> 6) & 3]
        self.range -= lps
        if value != ctx.mps:
            self.low += self.range
            self.range = lps
            if ctx.state == 0:
                ctx.mps = 1 - ctx.mps
            ctx.state = TRANS_LPS[ctx.state]
        else:
            ctx.state = TRANS_MPS[ctx.state]
        self.renorm()

    def bypass(self, value):
        self.low <<= 1
        if value:
            self.low += self.range
        if self.low >= 1024:
            self.put_bit(1)
            self.low -= 1024
        elif self.low < 512:
            self.put_bit(0)
        else:
            self.low -= 512
            self.outstanding += 1

    def terminate(self, value):
        self.range -= 2
        if value:
            self.low += self.range
            self.flush()
        else:
            self.renorm()

    def flush(self):
        self.range = 2
        self.renorm()
        self.put_bit((self.low >> 9) & 1)
        self.sink.u(2, ((self.low >> 7) & 3) | 1)


def profile_tier_level(b):
    b.u(2, 0)            # general_profile_space
    b.u(1, 0)            # general_tier_flag
    b.u(5, 1)            # general_profile_idc: Main
    b.u(32, 0x60000000)  # compatibility flags 1 (Main) and 2 (Main 10)
    b.u(1, 1)            # progressive_source
    b.u(1, 0)            # interlaced_source
    b.u(1, 0)            # non_packed_constraint
    b.u(1, 1)            # frame_only_constraint
    b.u(43, 0)
    b.u(1, 0)
    b.u(8, 30)           # general_level_idc (level 1)


def nal(unit_type, payload):
    header = bytes([unit_type << 1, 1])
    out = bytearray()
    zeros = 0
    for byte in header + payload:
        if zeros >= 2 and byte <= 3 and len(out) >= 2:
            out.append(3)
            zeros = 0
        out.append(byte)
        zeros = zeros + 1 if byte == 0 else 0
    return b"\x00\x00\x00\x01" + bytes(out)


def vps():
    b = Bits()
    b.u(4, 0)        # vps_video_parameter_set_id
    b.u(1, 1)        # vps_base_layer_internal_flag
    b.u(1, 1)        # vps_base_layer_available_flag
    b.u(6, 0)        # vps_max_layers_minus1
    b.u(3, 0)        # vps_max_sub_layers_minus1
    b.u(1, 1)        # vps_temporal_id_nesting_flag
    b.u(16, 0xFFFF)  # vps_reserved_0xffff_16bits
    profile_tier_level(b)
    b.u(1, 1)        # vps_sub_layer_ordering_info_present_flag
    b.ue(0)          # vps_max_dec_pic_buffering_minus1
    b.ue(0)          # vps_max_num_reorder_pics
    b.ue(0)          # vps_max_latency_increase_plus1
    b.u(6, 0)        # vps_max_layer_id
    b.ue(0)          # vps_num_layer_sets_minus1
    b.u(1, 0)        # vps_timing_info_present_flag
    b.u(1, 0)        # vps_extension_flag
    b.trailing()
    return nal(32, b.bytes())


def sps(pcm_loop_filter_disabled):
    b = Bits()
    b.u(4, 0)        # sps_video_parameter_set_id
    b.u(3, 0)        # sps_max_sub_layers_minus1
    b.u(1, 1)        # sps_temporal_id_nesting_flag
    profile_tier_level(b)
    b.ue(0)          # sps_seq_parameter_set_id
    b.ue(1)          # chroma_format_idc 4:2:0
    b.ue(32)         # pic_width_in_luma_samples
    b.ue(16)         # pic_height_in_luma_samples
    b.u(1, 0)        # conformance_window_flag
    b.ue(0)          # bit_depth_luma_minus8
    b.ue(0)          # bit_depth_chroma_minus8
    b.ue(4)          # log2_max_pic_order_cnt_lsb_minus4
    b.u(1, 1)        # sps_sub_layer_ordering_info_present_flag
    b.ue(0)          # sps_max_dec_pic_buffering_minus1
    b.ue(0)          # sps_max_num_reorder_pics
    b.ue(0)          # sps_max_latency_increase_plus1
    b.ue(0)          # log2_min_luma_coding_block_size_minus3 (8)
    b.ue(1)          # log2_diff_max_min_luma_coding_block_size (CTB 16)
    b.ue(0)          # log2_min_luma_transform_block_size_minus2 (4)
    b.ue(2)          # log2_diff_max_min_luma_transform_block_size (16)
    b.ue(0)          # max_transform_hierarchy_depth_inter
    b.ue(0)          # max_transform_hierarchy_depth_intra
    b.u(1, 0)        # scaling_list_enabled_flag
    b.u(1, 0)        # amp_enabled_flag
    b.u(1, 0)        # sample_adaptive_offset_enabled_flag
    b.u(1, 1)        # pcm_enabled_flag
    b.u(4, PCM_BITS_Y - 1)
    b.u(4, PCM_BITS_C - 1)
    b.ue(0)          # log2_min_pcm_luma_coding_block_size_minus3 (8)
    b.ue(1)          # log2_diff_max_min_pcm_luma_coding_block_size (16)
    b.u(1, 1 if pcm_loop_filter_disabled else 0)  # pcm_loop_filter_disabled_flag
    b.ue(0)          # num_short_term_ref_pic_sets
    b.u(1, 0)        # long_term_ref_pics_present_flag
    b.u(1, 0)        # sps_temporal_mvp_enabled_flag
    b.u(1, 0)        # strong_intra_smoothing_enabled_flag
    b.u(1, 0)        # vui_parameters_present_flag
    b.u(1, 0)        # sps_extension_present_flag
    b.trailing()
    return nal(33, b.bytes())


def pps(deblocking_disabled):
    b = Bits()
    b.ue(0)          # pps_pic_parameter_set_id
    b.ue(0)          # pps_seq_parameter_set_id
    b.u(1, 0)        # dependent_slice_segments_enabled_flag
    b.u(1, 0)        # output_flag_present_flag
    b.u(3, 0)        # num_extra_slice_header_bits
    b.u(1, 0)        # sign_data_hiding_enabled_flag
    b.u(1, 0)        # cabac_init_present_flag
    b.ue(0)          # num_ref_idx_l0_default_active_minus1
    b.ue(0)          # num_ref_idx_l1_default_active_minus1
    b.se(0)          # init_qp_minus26
    b.u(1, 0)        # constrained_intra_pred_flag
    b.u(1, 0)        # transform_skip_enabled_flag
    b.u(1, 0)        # cu_qp_delta_enabled_flag
    b.se(0)          # pps_cb_qp_offset
    b.se(0)          # pps_cr_qp_offset
    b.u(1, 0)        # pps_slice_chroma_qp_offsets_present_flag
    b.u(1, 0)        # weighted_pred_flag
    b.u(1, 0)        # weighted_bipred_flag
    b.u(1, 0)        # transquant_bypass_enabled_flag
    b.u(1, 0)        # tiles_enabled_flag
    b.u(1, 0)        # entropy_coding_sync_enabled_flag
    b.u(1, 0)        # pps_loop_filter_across_slices_enabled_flag
    b.u(1, 1)        # deblocking_filter_control_present_flag
    b.u(1, 0)        # deblocking_filter_override_enabled_flag
    b.u(1, 1 if deblocking_disabled else 0)
    if not deblocking_disabled:
        b.se(0)      # pps_beta_offset_div2
        b.se(0)      # pps_tc_offset_div2
    b.u(1, 0)        # pps_scaling_list_data_present_flag
    b.u(1, 0)        # lists_modification_present_flag
    b.ue(0)          # log2_parallel_merge_level_minus2
    b.u(1, 0)        # slice_segment_header_extension_present_flag
    b.u(1, 0)        # pps_extension_present_flag
    b.trailing()
    return nal(34, b.bytes())


def pcm_samples(b, k, size):
    for y in range(size):
        for x in range(size):
            b.u(PCM_BITS_Y, pcm_luma(k, x, y))
    for c in range(2):
        for y in range(size // 2):
            for x in range(size // 2):
                b.u(PCM_BITS_C, pcm_chroma(k, c, x, y))


def slice_nal():
    b = Bits()
    b.u(1, 1)        # first_slice_segment_in_pic_flag
    b.u(1, 0)        # no_output_of_prior_pics_flag
    b.ue(0)          # slice_pic_parameter_set_id
    b.ue(2)          # slice_type I
    b.se(0)          # slice_qp_delta
    b.u(1, 1)        # byte_alignment(): alignment_bit_equal_to_one
    b.align_zero()
    enc = Encoder(b)

    def pcm_cu(k, size):
        enc.terminate(1)          # pcm_flag
        b.align_zero()            # pcm_alignment_zero_bit
        pcm_samples(b, k, size)
        enc.init_engine()         # clause 9.3.2.5 after pcm_sample()

    def intra_cu(prev_flag, value):
        enc.decision("PART_MODE", 0, 1)  # PART_2Nx2N
        enc.terminate(0)                 # pcm_flag
        enc.decision("PREV_INTRA_LUMA_PRED_FLAG", 0, prev_flag)
        if prev_flag:
            for i in range(value):       # mpm_idx, truncated unary
                enc.bypass(1)
            if value < 2:
                enc.bypass(0)
        else:
            for shift in range(4, -1, -1):
                enc.bypass((value >> shift) & 1)
        enc.decision("INTRA_CHROMA_PRED_MODE", 0, 0)  # mode 4 (DM)
        enc.decision("CBF_CB_CR", 0, 0)
        enc.decision("CBF_CB_CR", 0, 0)
        enc.decision("CBF_LUMA", 1, 0)

    # CTU 0: no split, one 16x16 PCM coding unit.
    enc.decision("SPLIT_CODING_UNIT_FLAG", 0, 0)
    pcm_cu(0, 16)
    enc.terminate(0)                     # end_of_slice_segment_flag
    # CTU 1: split (left CTU at depth 0 is not deeper -> ctxInc 0).
    enc.decision("SPLIT_CODING_UNIT_FLAG", 0, 1)
    enc.decision("PART_MODE", 0, 1)
    pcm_cu(1, 8)
    intra_cu(1, 0)
    intra_cu(0, 10)
    intra_cu(1, 1)
    enc.terminate(1)                     # end_of_slice_segment_flag
    b.align_zero()                       # the flush wrote the stop bit
    return nal(19, b.bytes())


def main():
    out = sys.argv[1]
    variants = (
        ("pcm_mixed_nodeblock", True, True),
        ("pcm_mixed_deblock", False, True),
        ("pcm_mixed_deblock_lf", False, False),
    )
    for name, deblocking_disabled, pcm_lf_disabled in variants:
        stream = vps() + sps(pcm_lf_disabled) + pps(deblocking_disabled) + slice_nal()
        with open(os.path.join(out, name + ".h265"), "wb") as f:
            f.write(stream)
        print(f"wrote {name}.h265 ({len(stream)} bytes)")


if __name__ == "__main__":
    main()
