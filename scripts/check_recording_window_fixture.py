#!/usr/bin/env python3
"""Independent reference bytes for the recording-window contract, laboratory only.

Build one IDR window from retained synthetic AVC, independently encode its packet
pack/index/manifest and MP4 boxes, then compare decoded pixels with the source.
This never runs or qualifies Rust. Its hashes are pinned in the Rust golden test.
"""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import re
import struct
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
SOURCE_BLOB = '5d584a10e60d6e0ecdb89bfa2be742088021a45e'

def u16(n): return struct.pack('>H', n)
def u32(n): return struct.pack('>I', n)
def u64(n): return struct.pack('>Q', n)
def text(s):
    b = s.encode('utf-8')
    return u64(len(b)) + b

def digest(b): return b'\x01' + hashlib.sha256(b).digest()
def span(a, b): return u64(a) + u64(b)
def box(kind, data): return u32(len(data) + 8) + kind + data
def full(kind, flags, data): return box(kind, u32(flags) + data)
def matrix(): return struct.pack('>9I', 65536, 0, 0, 0, 65536, 0, 0, 0, 1073741824)

def init_segment(sps, pps):
    width, height = 160, 128  # Pinned input; independently checked with FFprobe below.
    avcc = bytes([1, sps[1], sps[2], sps[3], 255, 225]) + u16(len(sps)) + sps + b'\x01' + u16(len(pps)) + pps
    visual = (bytes(6) + u16(1) + bytes(16) + u16(width) + u16(height) + u32(72 << 16) * 2
              + bytes(4) + u16(1) + bytes(32) + u16(24) + u16(65535) + box(b'avcC', avcc))
    tables = full(b'stsd', 0, u32(1) + box(b'avc1', visual))
    tables += full(b'stts', 0, bytes(4)) + full(b'stsc', 0, bytes(4))
    tables += full(b'stsz', 0, bytes(8)) + full(b'stco', 0, bytes(4))
    dinf = box(b'dinf', full(b'dref', 0, u32(1) + full(b'url ', 1, b'')))
    minf = box(b'minf', full(b'vmhd', 1, bytes(8)) + dinf + box(b'stbl', tables))
    mdhd = full(b'mdhd', 0, bytes(8) + u32(90000) + bytes(4) + u16(0x55c4) + bytes(2))
    hdlr = full(b'hdlr', 0, bytes(4) + b'vide' + bytes(12) + b'FSS video\0')
    mdia = box(b'mdia', mdhd + hdlr + minf)
    tkhd = full(b'tkhd', 7, bytes(8) + u32(1) + bytes(24) + matrix() + u32(width << 16) + u32(height << 16))
    mvhd = full(b'mvhd', 0, bytes(8) + u32(90000) + bytes(4) + u32(65536) + u16(256)
                + bytes(10) + matrix() + bytes(24) + u32(2))
    mvex = box(b'mvex', full(b'trex', 0, u32(1) + u32(1) + bytes(12)))
    return box(b'ftyp', b'iso6' + u32(1) + b'iso6avc1mp41') + box(b'moov', mvhd + box(b'trak', tkhd + mdia) + mvex)

def build(nals, fragmented):
    initialization = init_segment(nals[0], nals[1])
    sps_at = initialization.index(nals[0]); pps_at = initialization.index(nals[1])
    sps_span = span(sps_at, sps_at + len(nals[0])); pps_span = span(pps_at, pps_at + len(nals[1]))
    media_payload = b''.join(u32(len(nal)) + nal for nal in nals if nal[0] & 31 not in (7, 8))
    trun = full(b'trun', 0x01000f01, u32(1) + u32(112) + struct.pack('>IIIi', 3600, len(media_payload), 0x02000000, 0))
    traf = box(b'traf', full(b'tfhd', 0x20000, u32(1)) + full(b'tfdt', 0x01000000, u64(0)) + trun)
    media = box(b'moof', full(b'mfhd', 0, u32(1)) + traf) + box(b'mdat', media_payload)
    assert media[108:112] == b'mdat' and len(media) == 112 + len(media_payload)
    packets = []; maps = []; sequence = 1; cursor = 112
    for ordinal, nal in enumerate(nals):
        is_vcl = nal[0] & 31 in (1, 5)
        if is_vcl and fragmented:
            third = (len(nal) - 1) // 3
            bodies = [nal[1:1 + third], nal[1 + third:1 + 2 * third], nal[1 + 2 * third:]]
            payloads = [bytes([(nal[0] & 96) | 28, (nal[0] & 31) | flag]) + b for flag, b in zip([128, 0, 64], bodies)]
        else:
            payloads = [nal]
        sources = []; reconstructed = b'' if len(payloads) == 1 else nal[:1]
        for i, payload in enumerate(payloads):
            marker = is_vcl and i == len(payloads) - 1
            wire = bytes([128, 96 | (128 if marker else 0)]) + u16(sequence) + u32(90000) + u32(7) + payload
            packets.append((sequence, sequence, wire))
            if len(payloads) == 1:
                sources.append(u64(sequence) + span(12, len(wire)) + span(0, len(nal)) + b'\0')
                reconstructed = payload
            else:
                begin = len(reconstructed); reconstructed += payload[2:]
                sources.append(u64(sequence) + span(14, len(wire)) + span(begin, len(reconstructed)) + b'\1' + span(12, 14))
            sequence += 1
        assert reconstructed == nal
        if nal[0] & 31 == 7: target = b'\0' + sps_span
        elif nal[0] & 31 == 8: target = b'\0' + pps_span
        else:
            target = b'\1' + span(cursor + 4, cursor + 4 + len(nal)); cursor += 4 + len(nal)
        maps.append(u64(0) + u64(ordinal) + target + u64(len(sources)) + b''.join(sources))
    assert cursor == len(media)
    source = text('fss.recording_window.source.v1') + u64(len(packets))
    source += b''.join(u64(seq) + u64(now) + u64(len(wire)) + wire for seq, now, wire in packets)
    index = text('fss.recording_window.index.v1') + text('sensor-fixture') + text('stream-fixture')
    index += u64(1) + digest(b'owner-authority-anchor') + digest(b'host-clock-epoch') + u32(7) + u32(96) + u32(90000)
    index += digest(source) + digest(initialization) + digest(media) + sps_span + pps_span
    # One sample: explicit DTS/PTS/duration/RTP time/IDR; boundary 3 = sender RTP marker.
    index += u64(1) + span(112, len(media)) + u64(0) + u64(0) + u32(3600) + u32(90000) + b'\1' + u64(3) + span(0, len(maps))
    index += u64(len(maps)) + b''.join(maps)
    children = sorted(digest(b) for b in [source, initialization, media, index])
    manifest = text('fss.object_manifest.v1') + text('avc_recording_window_v1') + u64(4) + b''.join(children) + b'\1' + digest(index)
    objects = dict(source=source, initialization=initialization, media=media, index=index, manifest=manifest)
    return objects, len(packets)

def call(*args):
    return subprocess.run(args, check=True, capture_output=True, text=True, timeout=20).stdout

def pixels(path):
    output = call('ffmpeg', '-v', 'error', '-i', str(path), '-map', '0:v:0', '-frames:v', '1', '-f', 'framemd5', '-')
    return [line.rsplit(',', 1)[1].strip() for line in output.splitlines() if line and not line.startswith('#')]

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--fixture', type=Path, default=ROOT / 'crates/fss-packet/tests/fixtures/avc/baseline.264')
    args = parser.parse_args()
    data = args.fixture.read_bytes()
    assert hashlib.sha1(b'blob ' + str(len(data)).encode() + b'\0' + data).hexdigest() == SOURCE_BLOB
    positions = list(re.finditer(b'\x00\x00(?:\x00)?\x01', data)); nals = []
    for i, m in enumerate(positions):
        nal = data[m.end():positions[i + 1].start() if i + 1 < len(positions) else len(data)].rstrip(b'\0')
        nals.append(nal)
        if nal[0] & 31 in (1, 5): break
    assert [n[0] & 31 for n in nals] == [7, 8, 6, 5]
    report = dict(schema='fss.recording_window.lab_oracle.v1', source_blob=SOURCE_BLOB,
                  rust_executed=False, filesystem_publication_executed=False, fixtures=[])
    original_pixels = pixels(args.fixture)
    assert len(original_pixels) == 1
    with tempfile.TemporaryDirectory(prefix='fss-recording-window-oracle-') as tmp:
        for fragmented in [False, True]:
            name = 'fu_a' if fragmented else 'single_nal'
            objects, count = build(nals, fragmented)
            movie = Path(tmp) / (name + '.mp4')
            movie.write_bytes(objects['initialization'] + objects['media'])
            assert pixels(movie) == original_pixels
            probe = json.loads(call('ffprobe', '-v', 'error', '-show_streams', '-show_packets', '-select_streams', 'v:0', '-of', 'json', str(movie)))
            s = probe['streams'][0]; p = probe['packets']; assert len(p) == 1
            assert (s['width'], s['height'], s['time_base']) == (160, 128, '1/90000')
            assert (int(p[0]['dts']), int(p[0]['pts']), int(p[0]['duration'])) == (0, 0, 3600)
            assert 'K' in p[0]['flags']
            report['fixtures'].append(dict(name=name, packets=count, nals=len(nals), samples=1,
                object_sha256={k: hashlib.sha256(v).hexdigest() for k,v in objects.items()},
                object_bytes={k:len(v) for k,v in objects.items()}, pixel_hash=original_pixels[0],
                pixel_hash_equal=True, timing_equal=True))
    print(json.dumps(report, indent=2))

if __name__ == '__main__': main()
