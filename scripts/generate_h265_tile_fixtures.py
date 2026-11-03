#!/usr/bin/env python3
"""Author bounded Main-profile tile streams; FFmpeg alone supplies pixel oracles.

Offline laboratory use only. The caller authorizes reading the local CABAC tables,
writing OUTPUT_DIR and invoking the installed FFmpeg with a 30-second deadline.
No foreign executable or encoder runs in production or in Rust tests.
"""

import argparse
import copy
import hashlib
import subprocess
from dataclasses import dataclass, replace
from pathlib import Path

import generate_h265_dependent_fixtures as dep
import generate_h265_pcm_fixture as pcm


@dataclass(frozen=True)
class Config:
    widths: tuple
    heights: tuple
    uniform: bool = True
    cu_qp: bool = True
    deblock: bool = False
    across_tiles: bool = False
    dpb_pictures: int = 2
    sao: str = ""
    pcm_filter_disabled: bool = True
    trim_right: int = 0
    trim_bottom: int = 0

    @property
    def width(self):
        return self.columns * 16 - self.trim_right

    @property
    def height(self):
        return self.rows * 16 - self.trim_bottom

    @property
    def columns(self):
        return sum(self.widths)

    @property
    def rows(self):
        return sum(self.heights)

    @property
    def base(self):
        return dep.Config(self.columns, self.rows, cu_qp=self.cu_qp,
                          deblock=self.deblock, dpb_pictures=self.dpb_pictures,
                          pcm_filter_disabled=self.pcm_filter_disabled)

    def tiles(self):
        y = 0
        for height in self.heights:
            x = 0
            for width in self.widths:
                yield [cy * self.columns + cx for cy in range(y, y + height)
                       for cx in range(x, x + width)]
                x += width
            y += height


def level4(b):
    # Same Main profile as the existing authoring helper, level 4 rather than
    # level 1: Annex A permits up to five tile rows/columns at this level.
    b.u(2, 0)
    b.u(1, 0)
    b.u(5, 1)
    b.u(32, 0x60000000)
    b.u(1, 1)
    b.u(1, 0)
    b.u(1, 0)
    b.u(1, 1)
    b.u(44, 0)
    b.u(8, 120)


def pps(config):
    b = pcm.Bits()
    b.ue(0)
    b.ue(0)
    b.u(1, 1)                 # dependent segments enabled
    b.u(1, 0)
    b.u(3, 0)
    b.u(1, 0)                 # no sign hiding
    b.u(1, 0)
    b.ue(0)
    b.ue(0)
    b.se(0)
    b.u(1, 0)
    b.u(1, 0)
    b.u(1, int(config.cu_qp))
    if config.cu_qp:
        b.ue(0)
    b.se(0)
    b.se(0)
    b.u(1, 0)
    b.u(1, 0)
    b.u(1, 0)
    b.u(1, 0)
    b.u(1, 1)                 # tiles enabled
    b.u(1, 0)                 # WPP forbidden with tiles in Main
    b.ue(len(config.widths) - 1)
    b.ue(len(config.heights) - 1)
    b.u(1, int(config.uniform))
    if not config.uniform:
        for width in config.widths[:-1]:
            b.ue(width - 1)
        for height in config.heights[:-1]:
            b.ue(height - 1)
    b.u(1, int(config.across_tiles))
    b.u(1, 0)                 # no filtering across independent slices
    b.u(1, 1)                 # deblocking control
    b.u(1, 0)
    b.u(1, int(not config.deblock))
    if config.deblock:
        b.se(0)
        b.se(0)
    b.u(1, 0)
    b.u(1, 0)
    b.ue(0)
    b.u(1, 0)
    b.u(1, 0)
    b.trailing()
    return pcm.nal(34, b.bytes())


def sps(config):
    b = pcm.Bits()
    b.u(4, 0)
    b.u(3, 0)
    b.u(1, 1)
    level4(b)
    b.ue(0)
    b.ue(1)
    b.ue(config.width)
    b.ue(config.height)
    b.u(1, 0)
    b.ue(0)
    b.ue(0)
    b.ue(4)
    b.u(1, 1)
    b.ue(config.dpb_pictures - 1)
    b.ue(0)
    b.ue(0)
    b.ue(0)
    b.ue(1)
    b.ue(0)
    b.ue(2)
    b.ue(0)
    b.ue(0)
    b.u(1, 0)
    b.u(1, 0)
    b.u(1, int(bool(config.sao)))
    b.u(1, 1)
    b.u(4, pcm.PCM_BITS_Y - 1)
    b.u(4, pcm.PCM_BITS_C - 1)
    b.ue(0)
    b.ue(1)
    b.u(1, int(config.pcm_filter_disabled))
    b.ue(0)
    b.u(1, 0)
    b.u(1, 0)
    b.u(1, 0)
    b.u(1, 0)
    b.u(1, 0)
    b.trailing()
    return pcm.nal(33, b.bytes())


def escaped(payload):
    return pcm.nal(1, payload)[6:]


def header(config, address, dependent, qp, nal_type, slice_type, poc, subsets):
    b = pcm.Bits()
    b.u(1, int(address == 0))
    if 16 <= nal_type <= 23:
        b.u(1, 0)
    b.ue(0)
    if address:
        b.u(1, int(dependent))
        b.u((config.columns * config.rows - 1).bit_length(), address)
    if not dependent:
        b.ue(slice_type)
        if nal_type not in (19, 20):
            b.u(8, poc)
            b.u(1, 0)
            b.ue(1)
            b.ue(0)
            b.ue(0)
            b.u(1, 1)
        if config.sao:
            b.u(1, 1)
            b.u(1, 1)
        if slice_type == 1:
            b.u(1, 0)
            b.ue(4)            # one merge candidate
        b.se(qp - 26)
    b.ue(len(subsets) - 1)
    if len(subsets) > 1:
        sizes = [len(escaped(data)) for data in subsets[:-1]]
        bits = max(1, max(size - 1 for size in sizes).bit_length())
        b.ue(bits - 1)
        for size in sizes:
            b.u(bits, size - 1)
    b.u(1, 1)
    b.align_zero()
    return b.bytes()


def sao(enc, kind, left, above):
    if left:
        enc.decision("SAO_MERGE_FLAG", 0, 0)
    if above:
        enc.decision("SAO_MERGE_FLAG", 0, 0)
    edge = kind != "band"
    for component in range(3):
        if component < 2:
            enc.decision("SAO_TYPE_IDX", 0, 1)
            enc.bypass(int(edge))
        for magnitude in (2, 1, 1, 2):
            for _ in range(magnitude):
                enc.bypass(1)
            enc.bypass(0)
        if edge:
            if component < 2:
                index = {"horizontal": 0, "vertical": 1, "diagonal": 2}[kind]
                enc.bypass(index >> 1)
                enc.bypass(index & 1)
        else:
            for sign in (0, 1, 0, 1):
                enc.bypass(sign)
            for shift in range(4, -1, -1):
                enc.bypass((16 >> shift) & 1)


def ctu(enc, kind, cu_qp, skip_context):
    if kind[0] not in ("mv", "zero_pcm"):
        dep.ctu(enc, kind, cu_qp, skip_context)
        return
    enc.decision("SPLIT_CODING_UNIT_FLAG", 0, 0)
    if kind[0] == "zero_pcm":
        enc.terminate(1)
        enc.sink.align_zero()
        enc.sink.u(256 * pcm.PCM_BITS_Y + 128 * pcm.PCM_BITS_C, 0)
        enc.init_engine()
        return
    enc.decision("SKIP_FLAG", skip_context, 0)
    enc.decision("PRED_MODE_FLAG", 0, 0)
    enc.decision("PART_MODE", 0, 1)
    enc.decision("MERGE_FLAG", 0, 0)
    vector = kind[1:]
    for value in vector:
        enc.decision("ABS_MVD_GREATER0_FLAG", 0, int(value != 0))
    for value in vector:
        if value:
            enc.decision("ABS_MVD_GREATER1_FLAG", 1, int(abs(value) > 1))
    for value in vector:
        if not value:
            continue
        if abs(value) > 1:
            remaining, bits = abs(value) - 2, 1
            while remaining >= 1 << bits:
                enc.bypass(1)
                remaining -= 1 << bits
                bits += 1
            enc.bypass(0)
            for shift in range(bits - 1, -1, -1):
                enc.bypass((remaining >> shift) & 1)
        enc.bypass(int(value < 0))
    enc.decision("MVP_LX_FLAG", 0, 0)
    enc.decision("NO_RESIDUAL_DATA_FLAG", 0, 0)


def partial_ctu(enc, config, address):
    # The partially occupied 16x16 CTU has inferred split_flag=1; only
    # in-picture 8x8 CUs follow, with intra part_mode and PCM samples.
    x0, y0 = (address % config.columns) * 16, (address // config.columns) * 16
    for index, (dx, dy) in enumerate(((0, 0), (8, 0), (0, 8), (8, 8))):
        if x0 + dx >= config.width or y0 + dy >= config.height:
            continue
        enc.decision("PART_MODE", 0, 1)
        enc.terminate(1)
        enc.sink.align_zero()
        pcm.pcm_samples(enc.sink, address + index, 8)
        enc.init_engine()


def picture(config, kinds, segments=None, nal_type=19, slice_type=2, poc=0,
            parameters=True):
    tiles = list(config.tiles())
    order = [address for tile in tiles for address in tile]
    tile_of = {address: index for index, tile in enumerate(tiles) for address in tile}
    tile_starts = {tile[0] for tile in tiles}
    segments = segments or [(len(order), False, 26)]
    contexts, start, slice_start, slice_qp = None, 0, 0, 26
    result = dep.vps(config.base) + sps(config) + pps(config) if parameters else b""
    for end, dependent, qp in segments:
        assert start < end <= len(order)
        if not dependent:
            contexts, slice_start, slice_qp = None, start, qp
        subsets = []
        at = start
        while at < end:
            first = order[at]
            if first in tile_starts:
                contexts = None
            b = pcm.Bits()
            enc = dep.Encoder(b, contexts, slice_qp, 0 if slice_type == 2 else 1)
            while True:
                address = order[at]
                tile_id = tile_of[address]
                decoded = set(order[slice_start:at])
                left = (address % config.columns > 0 and address - 1 in decoded
                        and tile_of[address - 1] == tile_id)
                above = (address - config.columns in decoded
                         and tile_of[address - config.columns] == tile_id)
                skip_context = int(left and kinds[address - 1][0] == "skip") + int(
                    above and kinds[address - config.columns][0] == "skip")
                if config.sao:
                    sao(enc, config.sao, left, above)
                if (address % config.columns + 1) * 16 > config.width or (address // config.columns + 1) * 16 > config.height:
                    assert slice_type == 2
                    partial_ctu(enc, config, address)
                else:
                    ctu(enc, kinds[address], config.cu_qp, skip_context)
                at += 1
                last = at == end
                enc.terminate(int(last))
                if last or order[at] in tile_starts:
                    if not last:
                        enc.terminate(1)  # end_of_subset_one_bit
                    b.align_zero()
                    subsets.append(b.bytes())
                    contexts = copy.deepcopy(enc.contexts)
                    break
        result += pcm.nal(nal_type, header(config, order[start], dependent, slice_qp,
                                          nal_type, slice_type, poc, subsets) + b"".join(subsets))
        start = end
    assert start == len(order)
    return result


def residual_kinds(config):
    kinds = [("intra", address % 3, 0, 4 + address % 20)
             for address in range(config.columns * config.rows)]
    for tile_id, tile in enumerate(config.tiles()):
        kinds[tile[0]] = ("intra", 0, 4 if tile_id % 2 == 0 else -2, 16)
    return kinds


def decode_oracle(path, config, frames=1):
    command = ["ffmpeg", "-hide_banner", "-loglevel", "error", "-nostdin", "-xerror",
               "-err_detect", "explode", "-threads", "1", "-f", "hevc", "-i", str(path),
               "-pix_fmt", "yuv420p", "-f", "rawvideo", "pipe:1"]
    completed = subprocess.run(command, check=True, capture_output=True, timeout=30)
    if completed.stderr or len(completed.stdout) != frames * config.width * config.height * 3 // 2:
        raise RuntimeError(f"oracle decode failed for {path}: {completed.stderr!r}")
    return completed.stdout


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    pcm.profile_tier_level = level4
    version = subprocess.run(["ffmpeg", "-version"], check=True, capture_output=True,
                             timeout=10).stdout.decode().splitlines()[0]
    def retain(name, config, stream, frames=1):
        path = args.output / f"{name}.h265"
        path.write_bytes(stream)
        raw = decode_oracle(path, config, frames)
        frame_size = len(raw) // frames
        rows = [f"{index} {frame_size} {hashlib.sha256(raw[index * frame_size:(index + 1) * frame_size]).hexdigest()}"
                for index in range(frames)]
        path.with_suffix(".sha256").write_text(f"# {name}; oracle: {version}\n" + "\n".join(rows) + "\n")
        print(f"{name}: {len(stream)} encoded bytes, {frames} x {frame_size} I420 bytes")
        return raw

    config = Config((16, 16), (4,))
    kinds = residual_kinds(config)
    first = picture(config, kinds)
    predicted = picture(config, [("skip",)] * (config.columns * config.rows),
                        nal_type=1, slice_type=1, poc=1, parameters=False)
    raw = retain("tiles_uniform_p", config, first + predicted, 2)
    assert raw[:len(raw) // 2] == raw[len(raw) // 2:]

    kinds[0] = ("zero_pcm",)
    encoded = picture(config, kinds)
    assert encoded.count(b"\x00\x00\x03") > 20
    zero = retain("tiles_emulation", config, encoded)
    assert all(zero[y * config.columns * 16 + x] == 0 for y in range(16) for x in range(16))

    for name, cfg in [("tiles_grid", Config((16, 16), (4, 4))),
                      ("tiles_explicit", Config((16, 20), (4, 6), uniform=False))]:
        values = residual_kinds(cfg)
        whole = retain(name, cfg, picture(cfg, values))
        # Each dependent segment stays in one tile or contains complete tiles
        # (6.3.1), while their logical slice spans the complete tile grid.
        first_size = len(next(cfg.tiles()))
        first_row = cfg.columns * cfg.heights[0]
        segments = [(first_size - 1, False, 26), (first_size, True, 26),
                    (first_size + 1, True, 26), (first_row, True, 26),
                    (cfg.columns * cfg.rows, True, 26)]
        cut = retain(name + "_dependent", cfg, picture(cfg, values, segments))
        assert cut == whole, "dependent boundaries must preserve all samples"
        if name == "tiles_grid":
            # FFmpeg accepts this syntactically decodable stream, but a segment
            # straddles two partial tiles. Retain it only as a normative refusal
            # fixture; independent pixel success does not prove conformance.
            invalid = args.output / "tiles_invalid_partial_segment.h265"
            invalid.write_bytes(picture(cfg, values, [(first_size - 1, False, 26),
                (first_size + 1, True, 26), (cfg.columns * cfg.rows, True, 26)]))
            assert decode_oracle(invalid, cfg) == whole

    partial = Config((16, 16), (4, 4), trim_right=8, trim_bottom=8)
    raw = retain("tiles_partial_ctbs", partial, picture(partial, residual_kinds(partial)))
    # Direct PCM expectation at the bottom-right 8x8 CU, independent of any decoder.
    address = partial.columns * partial.rows - 1
    for y in range(8):
        for x in range(8):
            assert raw[(partial.height - 8 + y) * partial.width + partial.width - 8 + x] == pcm.pcm_luma(address, x, y) << (8 - pcm.PCM_BITS_Y)

    segments = [(31, False, 26), (64, True, 26), (80, False, 20), (128, True, 20)]
    retain("tiles_independent", config, picture(config, residual_kinds(config), segments))

    # Nonzero explicit motion at each tile origin, then merge propagation. The
    # second tile must not inherit the first tile's spatial MVP or merge field.
    predicted_kinds = [("skip",)] * (config.columns * config.rows)
    for tile_id, tile in enumerate(config.tiles()):
        predicted_kinds[tile[0]] = ("mv", 4 if tile_id == 0 else -4, 0)
    predicted = picture(config, predicted_kinds, nal_type=1, slice_type=1, poc=1,
                        parameters=False)
    raw = retain("tiles_motion", config, first + predicted, 2)
    size, width = len(raw) // 2, config.columns * 16
    for tile_id, tile in enumerate(config.tiles()):
        dx = 1 if tile_id == 0 else -1
        for address in tile:
            x0, y0 = (address % config.columns) * 16, (address // config.columns) * 16
            for y in range(y0, y0 + 16):
                for x in range(x0, x0 + 16):
                    assert raw[size + y * width + x] == raw[y * width + min(width - 1, max(0, x + dx))]

    for filter_kind in ("deblock", "horizontal", "vertical", "diagonal", "band"):
        cfg = Config((16, 16), (4, 4), deblock=filter_kind == "deblock",
                     sao="" if filter_kind == "deblock" else filter_kind)
        values = residual_kinds(cfg)
        restricted = retain(f"tiles_{filter_kind}_closed", cfg, picture(cfg, values))
        enabled = replace(cfg, across_tiles=True)
        across = retain(f"tiles_{filter_kind}_across", enabled, picture(enabled, values))
        if filter_kind != "band":
            assert restricted != across, f"{filter_kind} fixture must visibly exercise tile boundaries"
        else:
            assert restricted == across, "band offset has no neighbor boundary dependence"


if __name__ == "__main__":
    main()
