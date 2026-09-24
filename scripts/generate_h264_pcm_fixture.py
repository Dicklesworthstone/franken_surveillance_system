#!/usr/bin/env python3
"""Hand-assembled Constrained-Baseline H.264 streams exercising I_PCM.

libx264 never emits I_PCM, so these two tiny streams are written bit by bit
from the syntax tables of ITU-T H.264 (7.3.2.1.1 SPS, 7.3.2.2 PPS, 7.3.3
slice header, 7.3.5 macroblock layer). The expected pixels come from the
sealed FFmpeg oracle (see tests/fixtures/decode/README.md), not from the
Rust decoder; the Rust test additionally checks the PCM samples against the
pattern below, which is independent of any decoder.

Picture: 48x32 (3x2 macroblocks), one IDR I slice, POC type 2.
  MB0 (0,0) I_PCM   MB1 (1,0) I_16x16 DC   MB2 (2,0) I_PCM
  MB3 (0,1) I_16x16 DC   MB4 (1,1) I_PCM   MB5 (2,1) I_16x16 DC
The I_16x16 macroblocks carry no AC/chroma residual; their DC
coeff_token is coded with nC = 16 (PCM neighbours count as 16), which uses
the 6-bit fixed-length code "000011" for TotalCoeff = 0.

Usage: generate_h264_pcm_fixture.py <output-dir>
Writes pcm_mixed.h264 (deblocking on, QP 36) and pcm_mixed_nodeblock.h264.
"""
import os
import sys

PCM_MBS = (0, 2, 4)
WIDTH_MBS, HEIGHT_MBS = 3, 2


def pcm_luma(mb, x, y):
    return (x * 7 + y * 13 + mb * 50) & 255


def pcm_chroma(mb, component, x, y):
    return (x * 11 + y * 5 + mb * 30 + component * 90) & 255


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
        out = bytearray()
        for i in range(0, len(self.bits), 8):
            byte = 0
            for bit in self.bits[i:i + 8]:
                byte = (byte << 1) | bit
            out.append(byte)
        return bytes(out)


def ebsp(rbsp):
    out = bytearray()
    zeros = 0
    for byte in rbsp:
        if zeros == 2 and byte <= 3:
            out.append(3)
            zeros = 0
        out.append(byte)
        zeros = zeros + 1 if byte == 0 else 0
    return bytes(out)


def nal(header, bits):
    return b"\x00\x00\x00\x01" + bytes([header]) + ebsp(bits.bytes())


def sps():
    b = Bits()
    b.u(8, 66)  # profile_idc: Baseline
    b.u(8, 0xC0)  # constraint_set0/1 (Constrained Baseline)
    b.u(8, 30)  # level_idc
    b.ue(0)  # seq_parameter_set_id
    b.ue(0)  # log2_max_frame_num_minus4
    b.ue(2)  # pic_order_cnt_type
    b.ue(1)  # max_num_ref_frames
    b.u(1, 0)  # gaps_in_frame_num_value_allowed_flag
    b.ue(WIDTH_MBS - 1)
    b.ue(HEIGHT_MBS - 1)
    b.u(1, 1)  # frame_mbs_only_flag
    b.u(1, 1)  # direct_8x8_inference_flag
    b.u(1, 0)  # frame_cropping_flag
    b.u(1, 0)  # vui_parameters_present_flag
    b.trailing()
    return nal(0x67, b)


def pps(qp):
    b = Bits()
    b.ue(0)  # pic_parameter_set_id
    b.ue(0)  # seq_parameter_set_id
    b.u(1, 0)  # entropy_coding_mode_flag (CAVLC)
    b.u(1, 0)  # bottom_field_pic_order_in_frame_present_flag
    b.ue(0)  # num_slice_groups_minus1
    b.ue(0)  # num_ref_idx_l0_default_active_minus1
    b.ue(0)  # num_ref_idx_l1_default_active_minus1
    b.u(1, 0)  # weighted_pred_flag
    b.u(2, 0)  # weighted_bipred_idc
    b.se(qp - 26)  # pic_init_qp_minus26
    b.se(0)  # pic_init_qs_minus26
    b.se(0)  # chroma_qp_index_offset
    b.u(1, 1)  # deblocking_filter_control_present_flag
    b.u(1, 0)  # constrained_intra_pred_flag
    b.u(1, 0)  # redundant_pic_cnt_present_flag
    b.trailing()
    return nal(0x68, b)


def idr_slice(disable_deblocking):
    b = Bits()
    b.ue(0)  # first_mb_in_slice
    b.ue(7)  # slice_type: I (all slices of the picture)
    b.ue(0)  # pic_parameter_set_id
    b.u(4, 0)  # frame_num (log2_max_frame_num = 4)
    b.ue(0)  # idr_pic_id
    b.u(1, 0)  # no_output_of_prior_pics_flag
    b.u(1, 0)  # long_term_reference_flag
    b.se(0)  # slice_qp_delta
    b.ue(1 if disable_deblocking else 0)  # disable_deblocking_filter_idc
    if not disable_deblocking:
        b.se(0)  # slice_alpha_c0_offset_div2
        b.se(0)  # slice_beta_offset_div2
    for mb in range(WIDTH_MBS * HEIGHT_MBS):
        if mb in PCM_MBS:
            b.ue(25)  # mb_type I_PCM
            b.align_zero()  # pcm_alignment_zero_bit
            for y in range(16):
                for x in range(16):
                    b.u(8, pcm_luma(mb, x, y))
            for component in range(2):
                for y in range(8):
                    for x in range(8):
                        b.u(8, pcm_chroma(mb, component, x, y))
        else:
            # I_16x16_2_0_0: DC prediction, no chroma/AC coded blocks.
            b.ue(3)
            b.ue(0)  # intra_chroma_pred_mode: DC
            b.se(0)  # mb_qp_delta
            b.u(6, 0b000011)  # Intra16x16DCLevel coeff_token, nC >= 8: TotalCoeff 0
    b.trailing()
    return nal(0x65, b)


def main():
    out = sys.argv[1]
    os.makedirs(out, exist_ok=True)
    for name, disable in (("pcm_mixed", False), ("pcm_mixed_nodeblock", True)):
        with open(os.path.join(out, name + ".h264"), "wb") as handle:
            handle.write(sps() + pps(36) + idr_slice(disable))


if __name__ == "__main__":
    main()
