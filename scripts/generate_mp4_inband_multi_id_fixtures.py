#!/usr/bin/env python3
"""Generate independent MP4 oracles for a later sample's entry-only PPS.

Run with FFmpeg 6.1.1 (libx264) and Python 3.  This deliberately does not change
the main in-band fixture generator or its manifest.  Both MP4s are decoded with
``-xerror -err_detect explode``; any decoder diagnostic fails generation.

AVC combines an IDR encoded with PPS 0 and later P pictures encoded with PPS 1.
Both PPSs refer to the same SPS 0, and both are present only in avcC.  Identical
constant-QP source encodes must have identical decoded pixels before combining.

HEVC uses the independently authored PCM/skip CABAC fixture generator.  The IDR
carries PPS 0 in-band; the following three-segment P picture refers to PPS 1,
which exists only in hvcC.  New slice headers are aligned before CABAC encoding;
no compressed slice payload is shifted or patched.  Its unchanged mathematical
PCM seed and the strict external decoder supply independent pixel expectations.
"""

import hashlib
import json
import re
import subprocess

import generate_h265_dependent_fixtures as hevc
import generate_mp4_inband_fixtures as mp4


def digest(data):
    return hashlib.sha256(data).hexdigest()


def bits(data):
    return [(value >> shift) & 1 for value in data for shift in range(7, -1, -1)]


def rbsp(escaped):
    result = bytearray()
    zeros = 0
    for index, value in enumerate(escaped):
        if zeros >= 2 and value == 3:
            assert index + 1 < len(escaped) and escaped[index + 1] <= 3
            zeros = 0
            continue
        result.append(value)
        zeros = zeros + 1 if value == 0 else 0
    return bytes(result)


def escape(raw):
    result = bytearray()
    zeros = 0
    for value in raw:
        if zeros >= 2 and value <= 3:
            result.append(3)
            zeros = 0
        result.append(value)
        zeros = zeros + 1 if value == 0 else 0
    return bytes(result)


def read_ue(values, at):
    start = at
    while values[at] == 0:
        at += 1
    width = at - start
    number = 1
    for value in values[at + 1:at + 1 + width]:
        number = number * 2 + value
    return number - 1, at + width + 1


def ue(value):
    code = value + 1
    width = code.bit_length()
    return [0] * (width - 1) + [(code >> shift) & 1 for shift in range(width - 1, -1, -1)]


def replace_parameter_ue(nal, header_size, offset, previous, replacement):
    """Change one parameter-set ID and regenerate rbsp_trailing_bits padding."""
    values = bits(rbsp(nal[header_size:]))
    old, end = read_ue(values, offset)
    assert old == previous
    stop = len(values) - 1 - values[::-1].index(1)
    rewritten = hevc.pcm.Bits()
    rewritten.bits = values[:offset] + ue(replacement) + values[end:stop + 1]
    rewritten.align_zero()
    return nal[:header_size] + escape(rewritten.bytes())


def annex_nals(data):
    result = re.split(b"\x00\x00(?:\x00)?\x01", data)
    assert not result[0]
    assert all(result[1:])
    return result[1:]


def annex(parameters, groups):
    return b"".join(b"\0\0\0\1" + nal for _, nal in parameters) + b"".join(
        b"\0\0\0\1" + nal for group in groups for nal in group
    )


def frame_hashes(raw, dimensions, count):
    width, height = dimensions
    size = width * height * 3 // 2
    assert len(raw) == size * count
    return [digest(raw[at:at + size]) for at in range(0, len(raw), size)]


def require_decode_failure(data, format_name):
    try:
        mp4.decode(data, format_name)
    except (subprocess.CalledProcessError, RuntimeError):
        return
    raise AssertionError("entry-only PPS removal unexpectedly remained decodable")


def avc_encode(parameter_id):
    dimensions = (64, 48)
    encoded = mp4.run([
        "ffmpeg", "-hide_banner", "-loglevel", "error", "-nostdin", "-f", "lavfi", "-i",
        "testsrc2=size=64x48:rate=10", "-frames:v", "4", "-an", "-pix_fmt", "yuv420p",
        "-c:v", "libx264", "-profile:v", "high", "-qp", "26", "-x264-params",
        "threads=1:lookahead_threads=1:keyint=4:min-keyint=4:scenecut=0:bframes=0:"
        f"ref=2:aud=1:repeat-headers=1:slices=1:sps-id={parameter_id}",
        "-movflags", "empty_moov+frag_keyframe+default_base_moof",
        "-video_track_timescale", "90000", "-f", "mp4", "pipe:1",
    ])
    config = mp4.configuration(encoded, b"avcC")
    parameters = mp4.arrays("avc", config)
    packets = json.loads(mp4.run([
        "ffprobe", "-v", "error", "-show_packets", "-show_entries",
        "packet=pos,size,dts,pts,duration,flags", "-of", "json", "pipe:0",
    ], encoded))["packets"]
    groups, timing = [], []
    first_dts = int(packets[0]["dts"])
    for packet in packets:
        at, size = int(packet["pos"]), int(packet["size"])
        groups.append([nal for nal in mp4.nals(encoded[at:at + size])
                       if mp4.kind("avc", nal) not in (6, 7, 8)])
        timing.append((int(packet["dts"]) - first_dts, int(packet["pts"]) - first_dts,
                       int(packet.get("duration", 9000)), "K" in packet["flags"]))
    assert len(groups) == 4
    hashes = frame_hashes(mp4.decode(encoded, "mp4"), dimensions, 4)
    return config, parameters, groups, timing, hashes


def write_fixture(name, codec, config, entry_parameters, groups, dimensions, timing, hashes,
                  indispensable_pps, provenance):
    """Require the whole MP4 and its actual sample NALs to match the same oracle."""
    parameter_types = {7, 8} if codec == "avc" else {32, 33, 34}
    record = mp4.config_record(codec, config, entry_parameters, parameter_types, 4)
    entry = "avc3" if codec == "avc" else "hev1"
    samples = [b"".join(len(nal).to_bytes(4, "big") + nal for nal in group) for group in groups]
    data = mp4.movie(entry, record, dimensions, samples, timing)
    count = len(groups)
    assert frame_hashes(mp4.decode(data, "mp4"), dimensions, count) == hashes
    format_name = "h264" if codec == "avc" else "hevc"
    assert frame_hashes(mp4.decode(annex(entry_parameters, groups), format_name),
                        dimensions, count) == hashes
    frames = json.loads(mp4.run([
        "ffprobe", "-v", "error", "-err_detect", "explode", "-threads", "1", "-show_frames",
        "-show_entries", "frame=width,height", "-of", "json", "pipe:0",
    ], data))["frames"]
    assert [(frame["width"], frame["height"]) for frame in frames] == [dimensions] * count

    # This is a behavioral oracle: simply retaining the first picture's tuple
    # cannot decode the later picture.  The missing PPS is not repeated in-band.
    remaining = [(tag, nal) for tag, nal in entry_parameters if nal != indispensable_pps]
    assert len(remaining) + 1 == len(entry_parameters)
    bad_record = mp4.config_record(codec, config, remaining, parameter_types, 4)
    require_decode_failure(mp4.movie(entry, bad_record, dimensions, samples, timing), "mp4")
    require_decode_failure(annex(remaining, groups), format_name)

    mp4.OUT.mkdir(parents=True, exist_ok=True)
    (mp4.OUT / f"{name}.mp4").write_bytes(data)
    width, height = dimensions
    oracle = [f"source {digest(data)}"]
    oracle += [f"frame {width} {height} {value}" for value in hashes]
    oracle += [f"sample {d} {p} {duration} {int(sync)}" for d, p, duration, sync in timing]
    oracle += [f"range 0 {count}"]
    (mp4.OUT / f"{name}.oracle").write_text("\n".join(oracle) + "\n")
    return {
        "name": name, "entry": entry, "nal_length_bytes": 4, "fragmented": True,
        "sha256": digest(data), "bytes": len(data), "dimensions": list(dimensions),
        "frames": hashes, "samples": count, "entry_only_pps_removal_rejected": True,
        **provenance,
    }


def avc_fixture():
    first = avc_encode(0)
    other = avc_encode(1)
    config, parameters, original, timing, hashes = first
    assert timing == other[3] and hashes == other[4]
    sps0, pps0 = (next(nal for tag, nal in parameters if tag == kind) for kind in (7, 8))
    sps1, pps1 = (next(nal for tag, nal in other[1] if tag == kind) for kind in (7, 8))
    assert replace_parameter_ue(sps1, 1, 24, 1, 0) == sps0
    pps_id, offset = read_ue(bits(rbsp(pps1[1:])), 0)
    assert pps_id == 1
    pps1 = replace_parameter_ue(pps1, 1, offset, 1, 0)
    # Apart from the PPS identifier, every decoded parameter is identical.
    assert replace_parameter_ue(pps1, 1, 0, 1, 0) == pps0
    groups = original[:1] + other[2][1:]
    for index, group in enumerate(groups):
        assert all(mp4.kind("avc", nal) not in (7, 8) for nal in group)
        slices = [nal for nal in group if mp4.kind("avc", nal) in (1, 5)]
        assert len(slices) == 1
        values = bits(rbsp(slices[0][1:]))
        _, at = read_ue(values, 0)  # first_mb_in_slice
        _, at = read_ue(values, at)  # slice_type
        pps_id, _ = read_ue(values, at)
        assert pps_id == int(index != 0)
    return write_fixture(
        "avc3_later_pps_entry", "avc", config, [(7, sps0), (8, pps0), (8, pps1)],
        groups, (64, 48), timing, hashes, pps1,
        {"entry_ids": {"sps": [0], "pps": [0, 1]}, "sample_pps_ids": [0, 1, 1, 1],
         "inband_parameter_ids": [], "pixel_oracle": "two constant-QP libx264 encodes; exact equal pixels"},
    )


def hevc_fixture():
    config = hevc.Config(3, 1, dpb_pictures=2)
    kinds = [("pcm", 0), ("pcm", 1), ("pcm", 2)]
    seed = hevc.picture(config, kinds, [(3, False, 26)])
    segments = [(1, False, 26), (2, True, 26), (3, True, 26)]
    skip_kinds = [("skip",)] * 3
    original_p = hevc.picture(config, skip_kinds, segments, 1, 1, 1, False)
    original_pixels = mp4.decode(seed + original_p, "hevc")
    hevc.verify_pixels(original_pixels, config, kinds)
    hashes = frame_hashes(original_pixels, (48, 16), 2)
    assert hashes == ["085802419bab58efe28d6d166d9ebc51097e216cbcf140254972c950c2c58135"] * 2

    original_header = hevc.segment_header

    def pps1_header(cfg, address, dependent, qp, nal_type, slice_type, poc_lsb):
        result = original_header(cfg, address, dependent, qp, nal_type, slice_type, poc_lsb)
        assert nal_type == 1
        old, end = read_ue(result.bits, 1)
        assert old == 0
        alignment = len(result.bits) - 1 - result.bits[::-1].index(1)
        result.bits = result.bits[:1] + ue(1) + result.bits[end:alignment + 1]
        result.align_zero()
        return result

    # Override the header writer only while authoring the new entropy stream;
    # the imported generator and its fixture files remain untouched.
    hevc.segment_header = pps1_header
    try:
        predicted = hevc.picture(config, skip_kinds, segments, 1, 1, 1, False)
    finally:
        hevc.segment_header = original_header

    seed_nals = annex_nals(seed)
    parameters = [(mp4.kind("hevc", nal), nal) for nal in seed_nals
                  if 32 <= mp4.kind("hevc", nal) <= 34]
    pps0 = next(nal for tag, nal in parameters if tag == 34)
    pps1 = replace_parameter_ue(pps0, 2, 0, 0, 1)
    assert replace_parameter_ue(pps1, 2, 0, 1, 0) == pps0
    entry = [(tag, nal) for tag, nal in parameters if tag != 34] + [(34, pps1)]
    # The initial IDR's PPS is deliberately absent from hvcC.  This requires the
    # in-band bootstrap path; later P slices then need the OTHER, entry-only PPS.
    groups = [[pps0] + [nal for nal in seed_nals if mp4.kind("hevc", nal) < 32],
              annex_nals(predicted)]
    assert len(groups[0]) == 2 and len(groups[1]) == 3
    for nal in groups[1]:
        assert mp4.kind("hevc", nal) == 1
        pps_id, _ = read_ue(bits(rbsp(nal[2:])), 1)
        assert pps_id == 1

    profile = hevc.pcm.Bits()
    hevc.pcm.profile_tier_level(profile)
    assert len(profile.bytes()) == 12
    record_header = (b"\x01" + profile.bytes() + b"\xf0\x00\xfc\xfd\xf8\xf8"
                     + b"\x00\x00\x0f\x00")
    assert len(record_header) == 23
    return write_fixture(
        "hev1_later_pps_entry", "hevc", record_header, entry, groups, (48, 16),
        [(0, 0, 9000, True), (9000, 9000, 9000, False)], hashes, pps1,
        {"entry_ids": {"vps": [0], "sps": [0], "pps": [1]}, "sample_pps_ids": [0, 1],
         "inband_parameter_ids": [{"sample": 0, "pps": 0}],
         "pixel_oracle": "mathematical PCM seed and inherited-reference P-skip; strict FFmpeg"},
    )


def main():
    version = mp4.run(["ffmpeg", "-version"]).decode().splitlines()[0]
    rows = [avc_fixture(), hevc_fixture()]
    metadata = {"generator": "scripts/generate_mp4_inband_multi_id_fixtures.py",
                "oracle": version, "fixtures": rows}
    (mp4.OUT / "multi_id_manifest.json").write_text(json.dumps(metadata, indent=2) + "\n")
    for row in rows:
        print(f"{row['name']}: {row['bytes']} bytes, {row['samples']} samples, {row['sha256']}")


if __name__ == "__main__":
    main()
