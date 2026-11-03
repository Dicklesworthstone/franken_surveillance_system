#!/usr/bin/env python3
"""Derive three POC-type-1 fixtures from the committed libx264 CAVLC corpus.

Laboratory fixture authoring only; never imported by production or Rust tests.
H.264 clauses 7.3.2.1.1, 7.3.3 and 8.2.1.2 define the rewritten syntax.
The three specific seeds below have no I_PCM macroblocks or MMCO 5. Every
macroblock data bit is copied, and the original picture order is reproduced.
Do not use this as a general AVC stream converter: CABAC alignment, PCM
alignment, field coding, scaling matrices and arbitrary PPS changes are not
implemented. Unexpected admitted seed syntax refuses.

Run scripts/generate_h264_decode_fixtures.sh to regenerate the corpus and its
independent FFmpeg frame hashes; this script alone rewrites only the bitstreams.
Usage: python3 scripts/rewrite_h264_poc1_fixtures.py [fixture-directory]
"""

from pathlib import Path
import sys

from rewrite_h264_headers import Reader, Writer, escape, split_annex_b, unescape


SEEDS = (
    ("ip_100x60_crop", "ip_100x60_poc1_cycle", "cycle"),
    ("ip_qcif_slices3", "ip_qcif_slices3_poc1_deltas", "deltas"),
    ("m_b_cavlc", "m_b_cavlc_poc1", "deltas"),
)


def rewrite(stream, mode):
    if len(stream) > 2 * 1024 * 1024:
        raise ValueError("fixture byte bound exceeded")
    frame_bits = old_poc_type = lsb_bits = None
    have_pps = False
    previous_frame = frame_offset = previous_lsb = previous_msb = 0
    picture_poc = None
    output = bytearray()
    for nal in split_annex_b(stream):
        if len(nal) > 65536:
            raise ValueError("fixture NAL bound exceeded")
        kind = nal[0] & 31
        reference = (nal[0] >> 5) != 0
        rbsp = unescape(nal[1:])
        reader, writer = Reader(rbsp), Writer()
        if kind == 7:
            profile = reader.u(8)
            if profile not in (66, 77):
                raise ValueError("expected Baseline/Main seed without chroma extension")
            writer.u(8, profile)
            writer.u(8, reader.u(8))
            writer.u(8, reader.u(8))
            sps_id = reader.ue()
            if sps_id != 0:
                raise ValueError("unexpected SPS identity")
            writer.ue(sps_id)
            frame_bits = reader.ue() + 4
            if not 4 <= frame_bits <= 16:
                raise ValueError("invalid frame_num width")
            writer.ue(frame_bits - 4)
            old_poc_type = reader.ue()
            if old_poc_type == 0:
                lsb_bits = reader.ue() + 4
                if not 4 <= lsb_bits <= 16:
                    raise ValueError("invalid original POC width")
            elif old_poc_type != 2:
                raise ValueError("expected original POC type0 or2")
            if mode == "cycle" and old_poc_type != 2:
                raise ValueError("implicit cycle rewrite requires POC type2 seed")
            writer.ue(1)
            writer.u(1, int(mode == "cycle"))
            writer.se(-1)  # applies to non-reference pictures even with an empty cycle
            writer.se(0 if mode == "cycle" else 2)
            writer.ue(1 if mode == "cycle" else 0)
            if mode == "cycle":
                writer.se(2)
            body = writer.finish(reader.rest_bits())
        elif kind == 8:
            pps_id, sps_id = reader.ue(), reader.ue()
            entropy, bottom = reader.u(1), reader.u(1)
            if (pps_id, sps_id, entropy, bottom) != (0, 0, 0, 0):
                raise ValueError("expected one CAVLC PPS without original bottom delta")
            writer.ue(pps_id)
            writer.ue(sps_id)
            writer.u(1, 0)
            writer.u(1, int(mode != "cycle"))
            body = writer.finish(reader.rest_bits())
            have_pps = True
        elif kind in (1, 5):
            if frame_bits is None or not have_pps:
                raise ValueError("missing parameter sets")
            first_mb, slice_type, pps_id = reader.ue(), reader.ue(), reader.ue()
            if slice_type % 5 not in (0, 1, 2) or pps_id != 0:
                raise ValueError("unexpected slice syntax")
            frame_num = reader.u(frame_bits)
            writer.ue(first_mb)
            writer.ue(slice_type)
            writer.ue(pps_id)
            writer.u(frame_bits, frame_num)
            idr = kind == 5
            if idr:
                writer.ue(reader.ue())
            original_lsb = reader.u(lsb_bits) if old_poc_type == 0 else None
            if first_mb == 0:
                if idr:
                    previous_frame = frame_offset = previous_lsb = previous_msb = 0
                elif previous_frame > frame_num:
                    frame_offset += 1 << frame_bits
                if old_poc_type == 0:
                    limit = 1 << lsb_bits
                    msb = previous_msb
                    if original_lsb < previous_lsb and previous_lsb - original_lsb >= limit // 2:
                        msb += limit
                    elif original_lsb > previous_lsb and original_lsb - previous_lsb > limit // 2:
                        msb -= limit
                    picture_poc = msb + original_lsb
                    if reference:
                        previous_msb, previous_lsb = msb, original_lsb
                else:
                    picture_poc = 2 * (frame_offset + frame_num) - int(not reference)
                previous_frame = frame_num
            if picture_poc is None:
                raise ValueError("slice before first picture")
            if mode != "cycle":
                writer.se(picture_poc + int(not reference))
                writer.se(-2)  # cancels the positive SPS bottom-field offset exactly
            body = writer.finish(reader.rest_bits())
        else:
            body = rbsp
        output += b"\x00\x00\x00\x01" + nal[:1] + escape(body)
    return bytes(output)


def main():
    if len(sys.argv) > 2:
        raise SystemExit(__doc__)
    directory = Path(sys.argv[1]) if len(sys.argv) == 2 else Path(
        "crates/fss-codec-h264/tests/fixtures/decode"
    )
    for source, target, mode in SEEDS:
        (directory / (target + ".h264")).write_bytes(
            rewrite((directory / (source + ".h264")).read_bytes(), mode)
        )


if __name__ == "__main__":
    main()
