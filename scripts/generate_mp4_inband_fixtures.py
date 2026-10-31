#!/usr/bin/env python3
"""Offline avc3/hev1 configuration-change oracles. Never used by production or Rust tests.

Original testsrc2 pixels are encoded by FFmpeg/libx264/libx265. A small independent BMFF
writer changes only parameter carriage and sample tables. FFmpeg verifies the resulting
sample-entry types, frames, dimensions and selected random-access pixel hashes. No camera
footage, network source, foreign runtime dependency or decoder-generated expected value.
"""
import hashlib
import json
from pathlib import Path
import struct
import subprocess

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "crates/fss-container/tests/fixtures/inband"


def run(command, data=None):
    result = subprocess.run(command, input=data, capture_output=True, timeout=40, check=True)
    if result.stderr:
        raise RuntimeError(result.stderr.decode(errors="replace"))
    return result.stdout


def u16(value):
    return struct.pack(">H", value)


def u32(value):
    return struct.pack(">I", value)


def box(kind, data):
    return u32(len(data) + 8) + kind.encode("ascii") + data


def full(kind, flags, data):
    return box(kind, u32(flags) + data)


def matrix():
    return b"".join(map(u32, [65536, 0, 0, 0, 65536, 0, 0, 0, 1073741824]))


def kind(codec, nal):
    return nal[0] & 31 if codec == "avc" else (nal[0] >> 1) & 63


def configuration(data, wanted, start=0, end=None):
    end = len(data) if end is None else end
    while start < end:
        size = int.from_bytes(data[start:start + 4], "big")
        tag = data[start + 4:start + 8]
        assert size >= 8 and start + size <= end
        if tag == wanted:
            return data[start + 8:start + size]
        skip = {b"moov": 0, b"trak": 0, b"mdia": 0, b"minf": 0, b"stbl": 0,
                b"stsd": 8, b"avc1": 78, b"avc3": 78, b"hvc1": 78, b"hev1": 78}
        if tag in skip:
            value = configuration(data, wanted, start + 8 + skip[tag], start + size)
            if value is not None:
                return value
        start += size
    return None


def arrays(codec, config):
    result = []
    if codec == "avc":
        at = 6
        for tag, count in [(7, config[5] & 31), (8, None)]:
            if count is None:
                count, at = config[at], at + 1
            for _ in range(count):
                size = int.from_bytes(config[at:at + 2], "big")
                at += 2
                result.append((tag, config[at:at + size]))
                at += size
    else:
        at = 23
        for _ in range(config[22]):
            tag = config[at] & 63
            count = int.from_bytes(config[at + 1:at + 3], "big")
            at += 3
            for _ in range(count):
                size = int.from_bytes(config[at:at + 2], "big")
                at += 2
                if 32 <= tag <= 34:
                    result.append((tag, config[at:at + size]))
                at += size
    return result


def config_record(codec, original, parameters, keep, length):
    if codec == "avc":
        sps = [nal for tag, nal in parameters if tag == 7 and tag in keep]
        pps = [nal for tag, nal in parameters if tag == 8 and tag in keep]
        record = original[:4] + bytes([0xfc | (length - 1), 0xe0 | len(sps)])
        record += b"".join(u16(len(nal)) + nal for nal in sps)
        record += bytes([len(pps)]) + b"".join(u16(len(nal)) + nal for nal in pps)
        if original[1] == 100:
            record += bytes([0xfd, 0xf8, 0xf8, 0])
        return record
    groups = []
    for tag in (32, 33, 34):
        selected = [nal for current, nal in parameters if current == tag and tag in keep]
        if selected:
            # array_completeness=0: in-band parameter definitions are explicitly permitted.
            groups.append(bytes([tag]) + u16(len(selected))
                          + b"".join(u16(len(nal)) + nal for nal in selected))
    return original[:21] + bytes([(original[21] & 0xfc) | (length - 1), len(groups)]) + b"".join(groups)


def nals(data, length=4):
    result, at = [], 0
    while at < len(data):
        size = int.from_bytes(data[at:at + length], "big")
        at += length
        assert 0 < size <= len(data) - at
        result.append(data[at:at + size])
        at += size
    assert at == len(data)
    return result


def encode(codec, dimensions, bframes=0, solid=False, slices=1):
    width, height = dimensions
    source = f"color=c=0x347abe:size={width}x{height}:rate=10" if solid else f"testsrc2=size={width}x{height}:rate=10"
    options = (["-c:v", "libx264", "-profile:v", "high", "-x264-params",
                f"threads=1:lookahead_threads=1:keyint=4:min-keyint=4:scenecut=0:bframes={bframes}:ref=2:aud=1:repeat-headers=1:slices={slices}"]
               if codec == "avc" else ["-c:v", "libx265", "-profile:v", "main", "-x265-params",
                f"log-level=error:pools=none:frame-threads=1:wpp=0:keyint=4:min-keyint=4:scenecut=0:bframes={bframes}:ref=2:aud=1:repeat-headers=1"])
    encoded = run(["ffmpeg", "-hide_banner", "-loglevel", "error", "-nostdin", "-f", "lavfi", "-i", source,
                   "-frames:v", "4", "-an", "-pix_fmt", "yuv420p", *options,
                   "-movflags", "empty_moov+frag_keyframe+default_base_moof", "-video_track_timescale", "90000", "-f", "mp4", "pipe:1"])
    config = configuration(encoded, b"avcC" if codec == "avc" else b"hvcC")
    parameters = arrays(codec, config)
    packet_json = run(["ffprobe", "-v", "error", "-show_packets", "-show_entries",
                       "packet=pos,size,dts,pts,duration,flags", "-of", "json", "pipe:0"], encoded)
    packets = json.loads(packet_json)["packets"]
    groups, times = [], []
    first_dts = int(packets[0]["dts"])
    for packet in packets:
        at, size = int(packet["pos"]), int(packet["size"])
        group = [nal for nal in nals(encoded[at:at + size])
                 if kind(codec, nal) not in ({7, 8, 6} if codec == "avc" else {32, 33, 34, 39, 40})]
        if "K" in packet["flags"]:
            group = [nal for _, nal in parameters] + group
        groups.append(group)
        times.append((int(packet["dts"]) - first_dts, int(packet["pts"]) - first_dts,
                      int(packet.get("duration", 9000)), "K" in packet["flags"]))
    pixels = decode(encoded, "mp4")
    frame_size = width * height * 3 // 2
    assert len(pixels) == frame_size * 4
    hashes = [hashlib.sha256(pixels[i:i + frame_size]).hexdigest() for i in range(0, len(pixels), frame_size)]
    return {"codec": codec, "dimensions": dimensions, "config": config,
            "parameters": parameters, "groups": groups, "times": times, "hashes": hashes}


def decode(data, format_name):
    return run(["ffmpeg", "-hide_banner", "-loglevel", "error", "-nostdin", "-xerror",
                "-err_detect", "explode", "-threads", "1", "-f", format_name, "-i", "pipe:0",
                "-map", "0:v:0", "-an", "-pix_fmt", "yuv420p", "-fps_mode", "passthrough",
                "-f", "rawvideo", "pipe:1"], data)


def movie(entry, config, dimensions, samples, timing, fragmented=True):
    width, height = dimensions
    duration = timing[-1][0] + timing[-1][2]
    ftyp = box("ftyp", b"isom" + u32(0) + b"isomiso6mp41")
    mvhd = full("mvhd", 0, bytes(8) + u32(90000) + u32(duration) + u32(65536)
                + u16(256) + bytes(10) + matrix() + bytes(24) + u32(2))
    tkhd = full("tkhd", 7, bytes(8) + u32(1) + u32(0) + u32(duration) + bytes(16)
                + matrix() + u32(width << 16) + u32(height << 16))
    mdhd = full("mdhd", 0, bytes(8) + u32(90000) + u32(duration) + u16(0x55c4) + u16(0))
    hdlr = full("hdlr", 0, u32(0) + b"vide" + bytes(12) + b"FSS inband fixture\0")
    visual = bytes(6) + u16(1) + bytes(16) + u16(width) + u16(height)
    visual += u32(0x00480000) * 2 + bytes(4) + u16(1) + bytes(32) + u16(24) + u16(65535)
    sample_entry = box(entry, visual + box("avcC" if entry.startswith("avc") else "hvcC", config))

    def moov(offset):
        stbl = full("stsd", 0, u32(1) + sample_entry)
        if fragmented:
            stbl += full("stts", 0, u32(0)) + full("stsc", 0, u32(0))
            stbl += full("stsz", 0, bytes(8)) + full("stco", 0, u32(0))
        else:
            stbl += full("stts", 0, u32(len(timing)) + b"".join(u32(1) + u32(t[2]) for t in timing))
            stbl += full("ctts", 0x1000000, u32(len(timing)) + b"".join(u32(1) + struct.pack(">i", t[1] - t[0]) for t in timing))
            stbl += full("stsc", 0, u32(1) + u32(1) + u32(len(samples)) + u32(1))
            stbl += full("stsz", 0, u32(0) + u32(len(samples)) + b"".join(u32(len(s)) for s in samples))
            stbl += full("stco", 0, u32(1) + u32(offset))
            keys = [i + 1 for i, t in enumerate(timing) if t[3]]
            stbl += full("stss", 0, u32(len(keys)) + b"".join(map(u32, keys)))
        dinf = box("dinf", full("dref", 0, u32(1) + full("url ", 1, b"")))
        minf = box("minf", full("vmhd", 1, bytes(8)) + dinf + box("stbl", stbl))
        mdia = box("mdia", mdhd + hdlr + minf)
        mvex = box("mvex", full("trex", 0, u32(1) + u32(1) + bytes(12))) if fragmented else b""
        return box("moov", mvhd + box("trak", tkhd + mdia) + mvex)

    initial = ftyp + moov(0)
    if not fragmented:
        return ftyp + moov(len(initial) + 8) + box("mdat", b"".join(samples))
    # Independent fragments at each random-access point; all sample data is original NAL data.
    result = initial
    keys = [i for i, t in enumerate(timing) if t[3]] + [len(samples)]
    assert keys[0] == 0
    for sequence, (first, end) in enumerate(zip(keys, keys[1:]), 1):
        selected = samples[first:end]
        entries = b"".join(u32(t[2]) + u32(len(s)) + u32(0x02000000 if t[3] else 0x01010000)
                           + struct.pack(">i", t[1] - t[0]) for s, t in zip(selected, timing[first:end]))
        offset = 96 + 16 * len(selected)
        traf = full("tfhd", 0x20000, u32(1)) + full("tfdt", 0x1000000, struct.pack(">Q", timing[first][0]))
        traf += full("trun", 0x1000f01, u32(len(selected)) + u32(offset) + entries)
        moof = box("moof", full("mfhd", 0, u32(sequence)) + box("traf", traf))
        assert len(moof) + 8 == offset
        result += moof + box("mdat", b"".join(selected))
    return result


def make(name, clips, carriage="empty", length=4, fragmented=True):
    codec = clips[0]["codec"]
    entry = "avc3" if codec == "avc" else "hev1"
    all_kinds = {7, 8} if codec == "avc" else {32, 33, 34}
    keep = set() if carriage == "empty" else ({7} if codec == "avc" else {32}) if carriage == "partial" else all_kinds
    config = config_record(codec, clips[0]["config"], clips[0]["parameters"], keep, length)
    groups, timing, expected, ranges = [], [], [], []
    for clip_index, clip in enumerate(clips):
        first = len(groups)
        base = first * 9000
        for group_index, group in enumerate(clip["groups"]):
            # Exercise genuine hybrid and out-of-band bootstrap, not redundant copies that
            # would happen to decode even if the sample-entry parameters were ignored.
            groups.append([nal for nal in group if not (
                clip_index == 0 and group_index == 0 and kind(codec, nal) in keep
            )])
        timing.extend((d + base, p + base, duration, sync) for d, p, duration, sync in clip["times"])
        expected.extend({"dimensions": list(clip["dimensions"]), "i420_sha256": value} for value in clip["hashes"])
        ranges.append({"first": first, "count": len(clip["groups"]), "dimensions": list(clip["dimensions"]), "hashes": clip["hashes"]})
    samples = [b"".join(len(nal).to_bytes(length, "big") + nal for nal in group) for group in groups]
    dimensions = tuple(max(clip["dimensions"][axis] for clip in clips) for axis in (0, 1))
    data = movie(entry, config, dimensions, samples, timing, fragmented)
    frames = json.loads(run(["ffprobe", "-v", "error", "-err_detect", "explode", "-threads", "1", "-show_frames",
                             "-show_entries", "frame=width,height", "-of", "json", "pipe:0"], data))["frames"]
    assert [[f["width"], f["height"]] for f in frames] == [e["dimensions"] for e in expected]
    # Independently decode every selected random-access section from its actual NAL sample
    # bytes, using the matching configuration. This avoids implicit FFmpeg output resizing
    # when an entire recording changes dimensions between GOPs.
    for section in ranges:
        first, count = section["first"], section["count"]
        annex = b"".join(b"\0\0\0\1" + nal for _, nal in arrays(codec, config))
        annex += b"".join(b"\0\0\0\1" + nal for sample in samples[first:first + count] for nal in nals(sample, length))
        pixels = decode(annex, "h264" if codec == "avc" else "hevc")
        width, height = section["dimensions"]
        size = width * height * 3 // 2
        actual = [hashlib.sha256(pixels[i:i + size]).hexdigest() for i in range(0, len(pixels), size)]
        assert actual == section["hashes"], name
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / f"{name}.mp4").write_bytes(data)
    oracle = [f"source {hashlib.sha256(data).hexdigest()}"]
    oracle += [f"frame {f['dimensions'][0]} {f['dimensions'][1]} {f['i420_sha256']}" for f in expected]
    oracle += [f"sample {d} {p} {duration} {int(sync)}" for d, p, duration, sync in timing]
    oracle += [f"range {r['first']} {r['count']}" for r in ranges]
    (OUT / f"{name}.oracle").write_text("\n".join(oracle) + "\n")
    return {"name": name, "entry": entry, "carriage": carriage, "nal_length_bytes": length,
            "fragmented": fragmented, "sha256": hashlib.sha256(data).hexdigest(),
            "samples": [{"dts": t[0], "pts": t[1], "duration": t[2], "sync": t[3]} for t in timing],
            "frames": expected, "ranges": ranges}


def main():
    avc0, avc1 = encode("avc", (64, 48)), encode("avc", (96, 64))
    hevc0, hevc1 = encode("hevc", (64, 48)), encode("hevc", (96, 64))
    rows = []
    for codec, first, second in [("avc3", avc0, avc1), ("hev1", hevc0, hevc1)]:
        for carriage in ("empty", "partial", "full"):
            rows.append(make(f"{codec}_{carriage}_change", [first, second], carriage))
        rows.append(make(f"{codec}_indexed_change", [first, second], "empty", fragmented=False))
        rows.append(make(f"{codec}_length2", [first], "empty", length=2))
    rows.append(make("avc3_length1", [encode("avc", (16, 16), solid=True)], length=1))
    rows.append(make("avc3_multislice", [encode("avc", (64, 64), slices=2)]))
    rows.append(make("avc3_bframes", [encode("avc", (64, 48), bframes=2)]))
    rows.append(make("hev1_bframes", [encode("hevc", (64, 48), bframes=2)]))
    version = run(["ffmpeg", "-version"]).decode().splitlines()[0]
    (OUT / "manifest.json").write_text(json.dumps({"oracle": version, "fixtures": rows}, indent=2) + "\n")
    print(f"Verified {len(rows)} original synthetic in-band fixtures with {version}")


if __name__ == "__main__":
    main()
