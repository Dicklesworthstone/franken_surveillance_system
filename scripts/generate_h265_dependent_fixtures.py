#!/usr/bin/env python3
"""Author real Main-profile dependent slice-segment CABAC fixtures, offline only.

Uses the repository's small arithmetic encoder, not a header rewrite of independent
libx265 slices. CABAC contexts continue across dependent segments, while the
arithmetic engine restarts. WPP synchronizes from CTU 1 of the previous row.
The bounded pictures use PCM seeds and intra blocks with a single DC coefficient.
Expected pixels are decoded by FFmpeg, never by the Rust implementation.

Usage: python3 scripts/generate_h265_dependent_fixtures.py OUTPUT_DIR
"""

import argparse
import copy
import hashlib
import re
import subprocess
import tempfile
from dataclasses import dataclass, replace
from pathlib import Path

import generate_h265_pcm_fixture as pcm


@dataclass(frozen=True)
class Config:
    columns: int
    rows: int
    wpp: bool = False
    cu_qp: bool = False
    deblock: bool = False
    pcm_filter_disabled: bool = True
    dpb_pictures: int = 1


INIT_VALUES = [int(value) for value in re.findall(r"\d+", re.search(
    r"INIT_VALUES[^=]*=\s*\[(.*?)\n\];", Path(pcm.TABLES).read_text(), re.S).group(1))]
assert len(INIT_VALUES) == 3 * pcm.CONSTS["CTX_COUNT"]


class Encoder(pcm.Encoder):
    def __init__(self, sink, contexts=None, qp=26, init_type=0):
        super().__init__(sink)
        if contexts is not None:
            self.contexts = copy.deepcopy(contexts)
        else:
            count = pcm.CONSTS["CTX_COUNT"]
            initial_values = INIT_VALUES[init_type * count:(init_type + 1) * count]
            for context, initial in zip(self.contexts, initial_values):
                m = (initial >> 4) * 5 - 45
                n = ((initial & 15) << 3) - 16
                pre = max(1, min(126, ((m * qp) >> 4) + n))
                context.mps = int(pre > 63)
                context.state = pre - 64 if context.mps else 63 - pre


def vps(config):
    b = pcm.Bits()
    b.u(4, 0)
    b.u(1, 1)
    b.u(1, 1)
    b.u(6, 0)
    b.u(3, 0)
    b.u(1, 1)
    b.u(16, 0xFFFF)
    pcm.profile_tier_level(b)
    b.u(1, 1)
    b.ue(config.dpb_pictures - 1)
    b.ue(0)
    b.ue(0)
    b.u(6, 0)
    b.ue(0)
    b.u(1, 0)
    b.u(1, 0)
    b.trailing()
    return pcm.nal(32, b.bytes())


def sps(config):
    b = pcm.Bits()
    b.u(4, 0)                  # sps_video_parameter_set_id
    b.u(3, 0)                  # sps_max_sub_layers_minus1
    b.u(1, 1)
    pcm.profile_tier_level(b)
    b.ue(0)                    # sps_seq_parameter_set_id
    b.ue(1)                    # 4:2:0
    b.ue(16 * config.columns)
    b.ue(16 * config.rows)
    b.u(1, 0)                  # no cropping
    b.ue(0)                    # 8-bit luma/chroma
    b.ue(0)
    b.ue(4)                    # 8-bit POC LSB
    b.u(1, 1)                  # ordering_info_present
    b.ue(config.dpb_pictures - 1)
    b.ue(0)                    # no reorder
    b.ue(0)
    b.ue(0)                    # minimum coding block 8x8
    b.ue(1)                    # CTB 16x16
    b.ue(0)                    # minimum transform 4x4
    b.ue(2)                    # maximum transform 16x16
    b.ue(0)                    # transform hierarchy depth inter/intra
    b.ue(0)
    b.u(1, 0)                  # no scaling list
    b.u(1, 0)                  # no AMP
    b.u(1, 0)                  # no SAO
    b.u(1, 1)                  # PCM enabled
    b.u(4, pcm.PCM_BITS_Y - 1)
    b.u(4, pcm.PCM_BITS_C - 1)
    b.ue(0)                    # PCM 8x8..16x16
    b.ue(1)
    b.u(1, int(config.pcm_filter_disabled))
    b.ue(0)                    # no SPS short-term reference sets
    b.u(1, 0)                  # no long-term references
    b.u(1, 0)                  # no temporal MVP
    b.u(1, 0)                  # no strong intra smoothing
    b.u(1, 0)                  # no VUI
    b.u(1, 0)                  # no extensions
    b.trailing()
    return pcm.nal(33, b.bytes())


def pps(config):
    b = pcm.Bits()
    b.ue(0)                    # PPS 0, SPS 0
    b.ue(0)
    b.u(1, 1)                  # dependent_slice_segments_enabled_flag
    b.u(1, 0)                  # output_flag_present
    b.u(3, 0)
    b.u(1, 0)                  # no sign data hiding
    b.u(1, 0)                  # no cabac_init flag
    b.ue(0)
    b.ue(0)
    b.se(0)                    # initial QP 26
    b.u(1, 0)                  # unconstrained intra
    b.u(1, 0)                  # no transform skip
    b.u(1, int(config.cu_qp))
    if config.cu_qp:
        b.ue(0)                # one quantization group per CTU
    b.se(0)
    b.se(0)
    b.u(1, 0)                  # no slice chroma QP offsets
    b.u(1, 0)                  # no weighted prediction
    b.u(1, 0)
    b.u(1, 0)                  # no transquant bypass
    b.u(1, 0)                  # no tiles
    b.u(1, int(config.wpp))
    b.u(1, 0)                  # do not filter across independent slices
    b.u(1, 1)                  # deblocking control present
    b.u(1, 0)                  # no slice override
    b.u(1, int(not config.deblock))
    if config.deblock:
        b.se(0)
        b.se(0)
    b.u(1, 0)                  # no PPS scaling lists
    b.u(1, 0)                  # no list modification
    b.ue(0)
    b.u(1, 0)                  # no slice header extension
    b.u(1, 0)                  # no PPS extension
    b.trailing()
    return pcm.nal(34, b.bytes())


def segment_header(config, address, dependent, qp, nal_type, slice_type, poc_lsb):
    b = pcm.Bits()
    b.u(1, int(address == 0))
    if 16 <= nal_type <= 23:
        b.u(1, 0)              # IRAP: no_output_of_prior_pics_flag
    b.ue(0)                    # PPS 0
    if address:
        b.u(1, int(dependent))
        b.u((config.columns * config.rows - 1).bit_length(), address)
    else:
        assert not dependent
    if not dependent:
        b.ue(slice_type)
        if nal_type not in (19, 20):
            b.u(8, poc_lsb)
            b.u(1, 0)          # explicit short-term reference set
            b.ue(1)            # one negative reference
            b.ue(0)            # no positive references
            b.ue(0)            # previous POC (delta_poc_s0_minus1 = 0)
            b.u(1, 1)          # used_by_curr_pic_s0_flag
        if slice_type == 1:
            b.u(1, 0)          # default one active L0 reference
            b.ue(4)            # exactly one merge candidate
        b.se(qp - 26)
    if config.wpp:
        # Each authored segment remains inside a CTU row: no entry points.
        b.ue(0)
    b.u(1, 1)                  # byte_alignment()
    b.align_zero()
    return b


def qp_delta(enc, delta):
    assert -4 <= delta <= 4
    magnitude = abs(delta)
    for index in range(magnitude):
        enc.decision("CU_QP_DELTA", int(index > 0), 1)
    enc.decision("CU_QP_DELTA", int(magnitude > 0), 0)
    if magnitude:
        enc.bypass(int(delta < 0))


def dc_coefficient(enc, level):
    # A 16x16 luma block with only (0,0) significant: the position is
    # inferred, with no significant-group/position bins or hidden sign.
    assert 1 <= level <= 32
    enc.decision("LAST_SIGNIFICANT_COEFF_X_PREFIX", 6, 0)
    enc.decision("LAST_SIGNIFICANT_COEFF_Y_PREFIX", 6, 0)
    enc.decision("COEFF_ABS_LEVEL_GREATER1_FLAG", 1, int(level > 1))
    if level > 1:
        enc.decision("COEFF_ABS_LEVEL_GREATER2_FLAG", 0, int(level > 2))
    enc.bypass(0)              # positive coefficient
    if level > 2:
        value = level - 3
        if value < 3:
            prefix, suffix, bits = value, 0, 0
        else:
            bits = (value - 2).bit_length() - 1
            prefix, suffix = 3 + bits, value - (1 << bits) - 2
        for _ in range(prefix):
            enc.bypass(1)
        enc.bypass(0)
        for shift in range(bits - 1, -1, -1):
            enc.bypass((suffix >> shift) & 1)


def ctu(enc, kind, cu_qp, skip_context=0):
    enc.decision("SPLIT_CODING_UNIT_FLAG", 0, 0)
    if kind[0] == "skip":
        enc.decision("SKIP_FLAG", skip_context, 1)
        # A single merge candidate: no merge_idx. Zero-motion prediction
        # comes from the prior picture or the preceding same-slice CTU.
        return
    if kind[0] == "pcm":
        enc.terminate(1)
        enc.sink.align_zero()
        pcm.pcm_samples(enc.sink, kind[1], 16)
        enc.init_engine()
        return
    _, mode, delta, level = kind
    enc.terminate(0)           # not PCM
    enc.decision("PREV_INTRA_LUMA_PRED_FLAG", 0, 1)
    for _ in range(mode):
        enc.bypass(1)
    if mode < 2:
        enc.bypass(0)
    enc.decision("INTRA_CHROMA_PRED_MODE", 0, 0)  # derived luma mode
    enc.decision("CBF_CB_CR", 0, 0)
    enc.decision("CBF_CB_CR", 0, 0)
    enc.decision("CBF_LUMA", 1, int(level > 0))
    if level:
        if cu_qp:
            qp_delta(enc, delta)
        else:
            assert delta == 0
        dc_coefficient(enc, level)


def picture(config, kinds, segments, nal_type=19, slice_type=2, poc_lsb=0,
            include_parameters=True):
    """segments = (end-exclusive CTU address, dependent flag, independent QP)."""
    assert len(kinds) == config.columns * config.rows
    result = vps(config) + sps(config) + pps(config) if include_parameters else b""
    contexts, wpp_saved, start = None, None, 0
    slice_start, slice_qp = 0, 26
    for end, dependent, qp in segments:
        assert start < end <= len(kinds)
        if config.wpp:
            assert start // config.columns == (end - 1) // config.columns
        if not dependent:
            contexts, wpp_saved = None, None
            slice_start, slice_qp = start, qp
        if config.wpp and start % config.columns == 0:
            row = start // config.columns
            above_right = start + 1 - config.columns
            contexts = (wpp_saved[1] if wpp_saved is not None
                        and wpp_saved[0] + 1 == row
                        and above_right >= slice_start else None)
        b = segment_header(config, start, dependent, slice_qp, nal_type, slice_type, poc_lsb)
        enc = Encoder(b, contexts, slice_qp, 0 if slice_type == 2 else 1)
        for address in range(start, end):
            left_skip = (address % config.columns > 0 and address - 1 >= slice_start
                         and kinds[address - 1][0] == "skip")
            above_skip = (address - config.columns >= slice_start
                          and kinds[address - config.columns][0] == "skip")
            ctu(enc, kinds[address], config.cu_qp, int(left_skip) + int(above_skip))
            enc.terminate(int(address + 1 == end))
            if config.wpp and address % config.columns == 1:
                wpp_saved = (address // config.columns, copy.deepcopy(enc.contexts))
        b.align_zero()
        result += pcm.nal(nal_type, b.bytes())
        contexts = copy.deepcopy(enc.contexts)
        start = end
    assert start == len(kinds)
    return result


def decode_oracle(path, config, frames=1):
    command = ["ffmpeg", "-hide_banner", "-loglevel", "error", "-nostdin",
               "-xerror", "-err_detect", "explode", "-threads", "1", "-f", "hevc",
               "-i", str(path), "-pix_fmt", "yuv420p", "-f", "rawvideo", "pipe:1"]
    completed = subprocess.run(command, check=True, capture_output=True, timeout=30)
    expected = frames * config.columns * 16 * config.rows * 16 * 3 // 2
    if completed.stderr or len(completed.stdout) != expected:
        raise RuntimeError(f"oracle decode failed for {path}: {completed.stderr!r}; bytes={len(completed.stdout)}")
    return completed.stdout


def coalesce(config, segments):
    """Remove dependent cuts without crossing WPP row substream boundaries."""
    combined, starts = [], []
    start = 0
    for end, dependent, qp in segments:
        if dependent and combined and (not config.wpp
                or starts[-1] // config.columns == (end - 1) // config.columns):
            combined[-1] = (end, combined[-1][1], combined[-1][2])
        else:
            combined.append((end, dependent, qp))
            starts.append(start)
        start = end
    return combined


def verify_pixels(raw, config, kinds):
    # The first PCM block is a direct independent mathematical expectation.
    # It is protected from filters; no decoder can supply these expected samples.
    if kinds[0][0] != "pcm":
        return
    width, height = 16 * config.columns, 16 * config.rows
    k = kinds[0][1]
    for y in range(16):
        for x in range(16):
            assert raw[y * width + x] == pcm.pcm_luma(k, x, y) << (8 - pcm.PCM_BITS_Y)
    for c in range(2):
        base = width * height + c * width * height // 4
        for y in range(8):
            for x in range(8):
                assert raw[base + y * (width // 2) + x] == pcm.pcm_chroma(k, c, x, y) << (8 - pcm.PCM_BITS_C)


def cases():
    residual = [("intra", 0, 4, 16), ("intra", 1, 0, 8),
                ("intra", 0, 0, 16), ("intra", 1, 0, 8)]
    wavefront = [("pcm", 0), ("intra", 0, 4, 16), ("intra", 2, -2, 8),
                 ("intra", 1, 0, 16), ("intra", 0, 3, 8), ("intra", 2, 0, 4)]
    return [
        ("dependent_midrow", Config(2, 1),
         [("pcm", 0), ("intra", 0, 0, 0)], [(1, False, 26), (2, True, 26)]),
        ("dependent_context_chain", Config(4, 1),
         [("pcm", 0), ("intra", 0, 0, 8), ("intra", 1, 0, 3), ("intra", 2, 0, 8)],
         [(1, False, 26), (3, True, 26), (4, True, 26)]),
        ("dependent_qp_carry", Config(3, 1, cu_qp=True),
         [("intra", 0, 4, 16), ("intra", 0, 0, 16), ("intra", 0, 0, 16)],
         [(1, False, 26), (2, True, 26), (3, True, 26)]),
        ("dependent_independent_reset", Config(4, 1, cu_qp=True), residual,
         [(1, False, 26), (2, True, 26), (3, False, 20), (4, True, 20)]),
        ("dependent_deblock", Config(4, 1, cu_qp=True, deblock=True), residual,
         [(2, False, 26), (4, True, 26)]),
        ("dependent_wpp_before_save", Config(3, 2, wpp=True, cu_qp=True), wavefront,
         [(1, False, 26), (3, True, 26), (6, True, 26)]),
        ("dependent_wpp_after_save", Config(3, 2, wpp=True, cu_qp=True), wavefront,
         [(2, False, 26), (3, True, 26), (6, True, 26)]),
        ("dependent_wpp_midrow", Config(3, 2, wpp=True, cu_qp=True), wavefront,
         [(3, False, 26), (4, True, 26), (6, True, 26)]),
        ("dependent_wpp_one_column", Config(1, 3, wpp=True, cu_qp=True),
         [("intra", 0, 4, 16), ("intra", 1, 0, 8), ("intra", 0, -2, 16)],
         [(1, False, 26), (2, True, 26), (3, True, 26)]),
    ]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    version = subprocess.run(["ffmpeg", "-version"], check=True, capture_output=True, timeout=10).stdout.decode().splitlines()[0]
    for name, config, kinds, segments in cases():
        stream = picture(config, kinds, segments)
        path = args.output / f"{name}.h265"
        path.write_bytes(stream)
        raw = decode_oracle(path, config)
        verify_pixels(raw, config, kinds)
        # Removing dependent segment boundaries must preserve every output
        # sample. Independent boundaries and WPP row starts remain in place.
        with tempfile.TemporaryDirectory(prefix="fss-hevc-dependent-oracle-") as temporary:
            joined = Path(temporary) / "coalesced.h265"
            joined.write_bytes(picture(config, kinds, coalesce(config, segments)))
            assert raw == decode_oracle(joined, config), f"segment boundary changed pixels: {name}"
            if config.deblock:
                unfiltered = replace(config, deblock=False)
                joined.write_bytes(picture(unfiltered, kinds, segments))
                plain = decode_oracle(joined, unfiltered)
                boundary = segments[0][0] * 16
                width = config.columns * 16
                assert any(raw[y * width + x] != plain[y * width + x]
                           for y in range(config.rows * 16)
                           for x in range(boundary - 4, boundary + 4)), \
                    "filter fixture must visibly filter the dependent boundary"
        digest = hashlib.sha256(raw).hexdigest()
        (args.output / f"{name}.sha256").write_text(f"# {name}; oracle: {version}\n0 {len(raw)} {digest}\n")
        print(f"{name}: {len(stream)} encoded bytes, {len(raw)} I420 bytes, {digest}")
    # An IDR PCM seed followed by a P skip/merge picture: dependent P headers
    # inherit the RPS/list fields and the CABAC P initialization, and neighboring
    # skip flags remain available across the two dependent boundaries.
    name, config = "dependent_p_skip", Config(3, 1, dpb_pictures=2)
    seed_kinds = [("pcm", 0), ("pcm", 1), ("pcm", 2)]
    seed = picture(config, seed_kinds, [(3, False, 26)])
    p_segments = [(1, False, 26), (2, True, 26), (3, True, 26)]
    p_kinds = [("skip",)] * 3
    predicted = picture(config, p_kinds, p_segments, 1, 1, 1, False)
    path = args.output / f"{name}.h265"
    path.write_bytes(seed + predicted)
    raw = decode_oracle(path, config, frames=2)
    frame_size = len(raw) // 2
    verify_pixels(raw[:frame_size], config, seed_kinds)
    assert raw[:frame_size] == raw[frame_size:], "zero-motion P prediction changed the PCM seed"
    with tempfile.TemporaryDirectory(prefix="fss-hevc-dependent-oracle-") as temporary:
        joined = Path(temporary) / "coalesced.h265"
        joined.write_bytes(seed + picture(config, p_kinds, coalesce(config, p_segments), 1, 1, 1, False))
        assert raw == decode_oracle(joined, config, frames=2)
    digest = hashlib.sha256(raw[:frame_size]).hexdigest()
    (args.output / f"{name}.sha256").write_text(
        f"# {name}; oracle: {version}\n0 {frame_size} {digest}\n1 {frame_size} {digest}\n")
    print(f"{name}: {len(seed + predicted)} encoded bytes, 2 x {frame_size} I420 bytes, {digest}")


if __name__ == "__main__":
    main()
