"""Independent laboratory MP4 layout oracle; never imported by production Rust.

Only the two named synthetic, single-slice fixtures are supported. This is not a
media importer. --regenerate explicitly records golden init/header bytes; normal
runs compare them and decode using a laboratory FFmpeg, without editing fixtures.
"""
from pathlib import Path
import argparse
import hashlib
import json
import re
import struct
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
AVC = ROOT / "crates/fss-packet/tests/fixtures/avc"
GOLD = ROOT / "crates/fss-container/tests/fixtures"

def u32(n): return struct.pack(">I", n)
def u16(n): return struct.pack(">H", n)
def box(tag, data): return u32(len(data) + 8) + tag.encode("ascii") + data
def full(tag, vf, data): return box(tag, u32(vf) + data)
def matrix(): return b"".join(map(u32, [65536, 0, 0, 0, 65536, 0, 0, 0, 1073741824]))

def initialization(sps, pps, width, height, scale):
    ftyp = box("ftyp", b"iso6" + u32(1) + b"iso6avc1mp41")
    mvhd = full("mvhd", 0, bytes(8) + u32(scale) + u32(0) + u32(65536) + u16(256)
                + bytes(10) + matrix() + bytes(24) + u32(2))
    tkhd = full("tkhd", 7, bytes(8) + u32(1) + bytes(24) + matrix() + u32(width << 16) + u32(height << 16))
    mdhd = full("mdhd", 0, bytes(8) + u32(scale) + u32(0) + u16(0x55c4) + u16(0))
    hdlr = full("hdlr", 0, u32(0) + b"vide" + bytes(12) + b"FSS video\0")
    vmhd = full("vmhd", 1, bytes(8))
    dinf = box("dinf", full("dref", 0, u32(1) + full("url ", 1, b"")))
    config = bytes([1, sps[1], sps[2], sps[3], 255, 225]) + u16(len(sps)) + sps + bytes([1]) + u16(len(pps)) + pps
    if sps[1] == 100: config += bytes([253, 248, 248, 0])
    visual = bytes(6) + u16(1) + bytes(16) + u16(width) + u16(height)
    visual += u32(0x00480000) * 2 + u32(0) + u16(1) + bytes(32) + u16(24) + u16(65535)
    stbl = full("stsd", 0, u32(1) + box("avc1", visual + box("avcC", config)))
    stbl += full("stts", 0, u32(0)) + full("stsc", 0, u32(0))
    stbl += full("stsz", 0, bytes(8)) + full("stco", 0, u32(0))
    mdia = box("mdia", mdhd + hdlr + box("minf", vmhd + dinf + box("stbl", stbl)))
    mvex = box("mvex", full("trex", 0, u32(1) + u32(1) + bytes(12)))
    return ftyp + box("moov", mvhd + box("trak", tkhd + mdia) + mvex)

def fragment(groups, pts, sequence=1, start=0):
    samples = [b"".join(u32(len(n)) + n for n in group if n[0] & 31 not in (7, 8)) for group in groups]
    media_offset = 96 + 16 * len(samples)
    entries = b""
    for index, (group, data, pt) in enumerate(zip(groups, samples, pts, strict=True)):
        flags = 0x02000000 if any(n[0] & 31 == 5 for n in group) else 0x01010000
        entries += u32(3600) + u32(len(data)) + u32(flags) + struct.pack(">i", pt - start - index * 3600)
    traf = full("tfhd", 0x20000, u32(1)) + full("tfdt", 0x1000000, struct.pack(">Q", start))
    traf += full("trun", 0x1000f01, u32(len(samples)) + u32(media_offset) + entries)
    moof = box("moof", full("mfhd", 0, u32(sequence)) + box("traf", traf))
    assert len(moof) + 8 == media_offset
    data = moof + box("mdat", b"".join(samples))
    return data, data[:media_offset]

def frame_hashes(path):
    data = subprocess.check_output(["ffmpeg", "-v", "error", "-i", str(path), "-an", "-f", "framemd5", "-"], timeout=20, text=True)
    return [line.rsplit(",", 1)[1].strip() for line in data.splitlines() if line and not line.startswith("#")]

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--regenerate", action="store_true")
    args = parser.parse_args()
    results = []
    for name, dimensions, pts in [("baseline", (160, 128), [0, 3600, 7200, 10800]),
                                   ("high_cropped", (64, 36), [0, 10800, 3600, 7200, 18000, 14400])]:
        source = AVC / (name + ".264")
        nals = [n.rstrip(b"\0") for n in re.split(b"\x00\x00\x00?\x01", source.read_bytes()) if n]
        groups, pending = [], []
        for nal in nals:
            pending.append(nal)
            if nal[0] & 31 in (1, 5): groups.append(pending); pending = []
        assert not pending and len(groups) == len(pts)
        init = initialization(nals[0], nals[1], *dimensions, 90000)
        media, prefix = fragment(groups, pts)
        GOLD.mkdir(parents=True, exist_ok=True)
        for suffix, data in [("init", init), ("prefix", prefix)]:
            path = GOLD / (name + "_" + suffix + ".bin")
            if args.regenerate: path.write_bytes(data)
            else: assert path.read_bytes() == data, path
        with tempfile.TemporaryDirectory(prefix="fss-mp4-oracle-") as tmp:
            path = Path(tmp) / (name + ".mp4")
            path.write_bytes(init + media)
            probe = json.loads(subprocess.check_output(["ffprobe", "-v", "error", "-count_frames",
                "-show_entries", "stream=width,height,nb_read_frames", "-of", "json", str(path)], timeout=10))["streams"][0]
            assert (probe["width"], probe["height"]) == dimensions
            assert int(probe["nb_read_frames"]) == len(groups)
            frames = frame_hashes(path)
            assert frames == frame_hashes(source), "container changed decoded pixels"
            packets = json.loads(subprocess.check_output(["ffprobe", "-v", "error", "-show_packets",
                "-show_entries", "packet=pts,dts", "-of", "json", str(path)], timeout=10))["packets"]
            # Raw version-one trun offsets are authoritative. FFmpeg 7.1's mov
            # demuxer adds -min(CTS, 0) to all PTS when offsets are negative.
            # Record that laboratory divergence rather than rewriting wire time.
            offsets = [pt - i * 3600 for i, pt in enumerate(pts)]
            oracle_shift = max(0, -min(offsets))
            assert [p["pts"] for p in packets] == [pt + oracle_shift for pt in pts]
            table = prefix[88:88 + 16 * len(groups)]
            assert [struct.unpack_from(">i", table, i * 16 + 12)[0] for i in range(len(groups))] == offsets
            assert [p["dts"] for p in packets] == [i * 3600 for i in range(len(groups))]
        results.append(dict(fixture=name, frames=len(frames), dimensions=dimensions,
                            init_sha256=hashlib.sha256(init).hexdigest(), prefix_sha256=hashlib.sha256(prefix).hexdigest(),
                            mp4_sha256=hashlib.sha256(init + media).hexdigest(), decoded_frame_md5=frames,
                            wire_pts=pts, ffprobe_pts=[p["pts"] for p in packets], ffprobe_pts_shift=oracle_shift))
    report = dict(schema="fss.mp4.layout_oracle.v1", rust_executed=False,
                  ffmpeg_version=subprocess.check_output(["ffmpeg", "-version"], text=True).splitlines()[0], fixtures=results)
    if args.regenerate: (GOLD / "expected.json").write_text(json.dumps(report, indent=2) + "\n")
    else:
        expected = json.loads((GOLD / "expected.json").read_text())
        assert json.loads(json.dumps(report["fixtures"])) == expected["fixtures"]
    print(json.dumps(report, indent=2))

if __name__ == "__main__": main()
