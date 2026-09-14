#!/usr/bin/env python3
"""Independent whole-buffer and incremental structural controls, NOT Rust execution."""
import hashlib
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / 'crates/fss-codec-mjpeg/tests/fixtures'

def whole_frame_end(data, start):
    if data[start:start+2] != b'\xff\xd8':
        raise ValueError('SOI')
    offset, scanned = start+2, False
    while True:
        if offset >= len(data) or data[offset] != 255:
            raise ValueError('marker')
        while offset < len(data) and data[offset] == 255:
            offset += 1
        if offset >= len(data):
            raise ValueError('truncated marker')
        code = data[offset]
        offset += 1
        if code in (0, 216) or 208 <= code <= 215:
            raise ValueError('unexpected marker')
        if code == 217:
            if not scanned:
                raise ValueError('scan absent')
            return offset
        if code == 1:
            continue
        if code < 192:
            raise ValueError('unsupported marker')
        if offset+2 > len(data):
            raise ValueError('length absent')
        length = int.from_bytes(data[offset:offset+2], 'big')
        if length < 2 or offset+length > len(data):
            raise ValueError('length')
        offset += length
        if code != 218:
            continue
        scanned = True
        while True:
            marker_start = data.find(b'\xff', offset)
            if marker_start < 0 or marker_start+1 == len(data):
                raise ValueError('entropy truncated')
            after = marker_start+1
            while after < len(data) and data[after] == 255:
                after += 1
            if after == len(data):
                raise ValueError('entropy marker truncated')
            code = data[after]
            if code == 0:
                if after != marker_start+1:
                    raise ValueError('filled stuffing')
                offset = after+1
            elif 208 <= code <= 215:
                offset = after+1
            else:
                offset = marker_start
                break

def ranges(data):
    output, offset = [], 0
    while offset < len(data):
        end = whole_frame_end(data, offset)
        output.append((offset, end))
        offset = end
    return output

class IncrementalControl:
    def __init__(self):
        self.state = 'start'
        self.offset = self.begin = 0
        self.buffer = bytearray()
        self.marker = self.remaining = self.high = 0
        self.scanned = self.fill = False
    def marker_code(self, code):
        if code in (0, 216) or 208 <= code <= 215:
            raise ValueError('marker')
        if code == 217:
            if not self.scanned:
                raise ValueError('scan')
            return True
        if code == 1:
            self.state = 'prefix'
        elif code < 192:
            raise ValueError('reserved')
        else:
            self.marker, self.state = code, 'length_high'
        return False
    def push(self, data):
        for index, value in enumerate(data):
            self.buffer.append(value)
            self.offset += 1
            complete = False
            if self.state == 'start':
                if value != 255: raise ValueError('start')
                self.state = 'soi'
            elif self.state == 'soi':
                if value != 216: raise ValueError('soi')
                self.state = 'prefix'
            elif self.state == 'prefix':
                if value != 255: raise ValueError('prefix')
                self.state = 'code'
            elif self.state == 'code':
                if value != 255: complete = self.marker_code(value)
            elif self.state == 'length_high':
                self.high, self.state = value, 'length_low'
            elif self.state == 'length_low':
                self.remaining = self.high*256+value-2
                if self.remaining < 0: raise ValueError('length')
                if self.remaining:
                    self.state = 'payload'
                elif self.marker == 218:
                    self.scanned, self.state = True, 'entropy'
                else:
                    self.state = 'prefix'
            elif self.state == 'payload':
                self.remaining -= 1
                if self.remaining == 0:
                    if self.marker == 218: self.scanned, self.state = True, 'entropy'
                    else: self.state = 'prefix'
            elif self.state == 'entropy':
                if value == 255: self.fill, self.state = False, 'entropy_code'
            elif self.state == 'entropy_code':
                if value == 255: self.fill = True
                elif value == 0:
                    if self.fill: raise ValueError('fill')
                    self.state = 'entropy'
                elif 208 <= value <= 215: self.state = 'entropy'
                else: complete = self.marker_code(value)
            if complete:
                result = (self.begin, self.offset, bytes(self.buffer))
                self.buffer.clear()
                self.begin, self.state, self.scanned = self.offset, 'start', False
                return index+1, result
        return len(data), None
    def finish(self):
        if self.state != 'start' or self.buffer:
            raise ValueError('truncated')

def feed(chunks):
    stream, frames = IncrementalControl(), []
    for chunk in chunks:
        while chunk:
            used, frame = stream.push(chunk)
            if used <= 0: raise AssertionError('no progress')
            chunk = chunk[used:]
            if frame is not None: frames.append(frame)
    stream.finish()
    return frames

def add_metadata(data):
    payload = b'not boundaries:\xff\xd9\xff\xd8\xff\xda\xff\x00'
    return data[:2]+b'\xff\xe1'+(len(payload)+2).to_bytes(2, 'big')+payload+data[2:]

class FramingTests(unittest.TestCase):
    def setUp(self):
        self.gray = (FIXTURES/'gray.jpg').read_bytes()
        self.color = (FIXTURES/'y420_restart.jpg').read_bytes()
    def test_every_split_against_independent_whole_buffer_ranges(self):
        data = add_metadata(self.gray)+self.color+self.gray
        expected = [(a,b,data[a:b]) for a,b in ranges(data)]
        for split in range(len(data)+1):
            self.assertEqual(feed([data[:split],data[split:]]), expected)
    def test_many_chunk_sizes_and_exact_source_hashes(self):
        data = self.gray+self.color+self.gray
        expected = [(a,b,data[a:b]) for a,b in ranges(data)]
        for size in range(1,65):
            result = feed([data[i:i+size] for i in range(0,len(data),size)])
            self.assertEqual(result, expected)
            self.assertEqual([hashlib.sha256(row[2]).digest() for row in result],
                [hashlib.sha256(frame).digest() for frame in (self.gray,self.color,self.gray)])
    def test_all_truncated_prefixes_are_incomplete(self):
        for end in range(1,len(self.gray)):
            with self.assertRaises(ValueError): feed([self.gray[:end]])
    def test_metadata_markers_are_not_frame_boundaries(self):
        data = add_metadata(self.gray)
        self.assertGreater(data.count(b'\xff\xd9'),1)
        self.assertEqual(ranges(data),[(0,len(data))])
        self.assertEqual(feed([bytes([b]) for b in data]),[(0,len(data),data)])
    def test_malformed_prefixes_do_not_resynchronize(self):
        bad = [b'\x00',b'\xff\xd8\xff\xd9',b'\xff\xd8\xff\xdb\x00\x01',
            b'\xff\xd8\xff\xda\x00\x02\xff\xff\x00',b'\xff\xd8\xff\xd8',
            b'\xff\xd8\xff\xd0',b'\xff\xd8\xff\x00',b'\xff\xd8\xff\x02']
        for prefix in bad:
            with self.assertRaises(ValueError): ranges(prefix+self.gray)
            with self.assertRaises(ValueError): feed([prefix+self.gray])
    def test_bad_suffix_preserves_only_the_previously_completed_frame(self):
        stream = IncrementalControl()
        consumed, framed = stream.push(self.gray+b'\x00'+self.gray)
        self.assertEqual(consumed,len(self.gray))
        self.assertEqual(framed,(0,len(self.gray),self.gray))
        with self.assertRaises(ValueError): stream.push(b'\x00'+self.gray)
    def test_multiple_scans_and_restart_markers_are_structural_only(self):
        data=b'\xff\xd8\xff\xda\x00\x02\x11\xff\x00\xff\xd0\x33\xff\xda\x00\x02\x22\xff\xd9'
        self.assertEqual(ranges(data),[(0,len(data))])
        self.assertEqual(feed([bytes([b]) for b in data]),[(0,len(data),data)])
    def test_empty_source_is_distinct_from_an_incomplete_marker(self):
        self.assertEqual(feed([b'']),[])
        with self.assertRaises(ValueError): feed([b'\xff'])

if __name__ == '__main__': unittest.main()
