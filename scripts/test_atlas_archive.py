#!/usr/bin/env python3
"""Independent FSATLAS1 golden/layout checks; does not execute the Rust decoder."""
import hashlib
import struct
import unittest


def digest(data):
    return hashlib.sha256(data).digest()


def fixture():
    pack = struct.pack
    text = lambda value: pack('<H', len(value)) + value
    b = bytes([1]) * 32 + text(b'test/Z-up') + text(b'synthetic')
    b += b'\0' + pack('<dddIIII', 0., -1., -1., 1, 1, 4, 2)
    b += text(b'walk') + b'\1' + text(b'ground') + pack('<IBB', 0, 1, 1)
    b += b''.join(pack('<ddd', *p) for p in [(0., 0., 0.), (4., 0., 0.), (4., 4., 0.), (0., 4., 0.)])
    b += pack('<IIIIIIII', 0, 1, 2, 0, 0, 2, 3, 0)
    twin = b'FSSTWIN1' + pack('<Q', len(b)) + b
    twin += digest(twin)
    points = [(3, 103, (0., 1., 2.), 8, None), (9, 109, (1., 2., 3.), 9, (0., .2, .3))]
    features = [(7, (23.25, 24.5), 0), (8, (80.5, 40.25), 2**64-1)]
    semantic = b'fss/localization-atlas/reference/1\0' + digest(twin) + bytes([5])*32 + pack('<Q', 2)
    payload = b''
    for identity, group, xyz, evidence, error in points:
        common = pack('<ddd', *xyz) + bytes([evidence])*32 + bytes([error is not None])
        if error is not None:
            common += pack('<ddd', *error)
        semantic += pack('<QQQ', identity, group, 0) + common
        payload += pack('<QQI', identity, group, 0) + common
    image_hashes = bytes([2])*32 + bytes([3])*32 + bytes([4])*32
    semantic += pack('<QQ', 1, 6) + image_hashes + pack('<QQQ', 128, 96, 2)
    payload += pack('<Q', 6) + image_hashes + pack('<II', 128, 96) + bytes([10])*32 + bytes([11])*32 + pack('<I', 2)
    for identity, pixel, word in features:
        feature = pack('<QddQQQQ', identity, *pixel, *([word]*4))
        payload += feature
        semantic += feature
    binding = pack('<QQQQQQ', 3, 6, 7, 9, 6, 8)
    semantic += pack('<Q', 2) + binding
    payload = digest(twin) + bytes([5])*32 + digest(semantic) + bytes([12])*32 + pack('<III', 2, 1, 2) + payload + binding
    archive = b'FSATLAS1' + pack('<Q', len(payload)) + payload
    archive += digest(archive)
    return archive, digest(twin), digest(semantic)


def inspect(data):
    if not 188 <= len(data) <= 8*1024*1024 or data[:8] != b'FSATLAS1':
        raise ValueError('header')
    if struct.unpack_from('<Q', data, 8)[0] != len(data)-48 or digest(data[:-32]) != data[-32:]:
        raise ValueError('length or checksum')
    points, refs, bindings = struct.unpack_from('<III', data, 144)
    if not 1 <= points <= 4096 or not 1 <= refs <= 64 or not 1 <= bindings <= 32768:
        raise ValueError('limits')
    offset = 156
    point_ids = set()
    for _ in range(points):
        identity, group, feature = struct.unpack_from('<QQI', data, offset)
        if identity in point_ids or not identity or not group:
            raise ValueError('point')
        point_ids.add(identity)
        tag = data[offset+76]
        if tag not in (0, 1):
            raise ValueError('error')
        offset += 77 + 24*tag
    feature_ids = set()
    for _ in range(refs):
        identity = struct.unpack_from('<Q', data, offset)[0]
        count = struct.unpack_from('<I', data, offset+176)[0]
        if not identity or not 1 <= count <= 512:
            raise ValueError('view')
        offset += 180
        for _ in range(count):
            feature_ids.add((identity, struct.unpack_from('<Q', data, offset)[0]))
            offset += 56
    for _ in range(bindings):
        point, ref, feature = struct.unpack_from('<QQQ', data, offset)
        if point not in point_ids or (ref, feature) not in feature_ids:
            raise ValueError('binding')
        offset += 24
    if offset != len(data)-32:
        raise ValueError('trailing')
    return points, refs, bindings


class ArchiveChecks(unittest.TestCase):
    def test_golden(self):
        data, twin, semantic = fixture()
        self.assertEqual(inspect(data), (2, 1, 2))
        self.assertEqual(len(data), 706)
        self.assertEqual(data[16:48], twin)
        self.assertEqual(data[80:112], semantic)

    def test_every_truncation(self):
        data = fixture()[0]
        for end in range(len(data)):
            with self.assertRaises((ValueError, struct.error, IndexError)):
                inspect(data[:end])

    def test_every_bit_mutation(self):
        data = fixture()[0]
        for offset in range(len(data)):
            for bit in range(8):
                changed = bytearray(data)
                changed[offset] ^= 1 << bit
                with self.assertRaises((ValueError, struct.error, IndexError)):
                    inspect(changed)

    def test_resealed_count_and_reference_errors(self):
        data = fixture()[0]
        for offset, value in [(144, 4097), (148, 65), (152, 32769), (len(data)-48, 999)]:
            changed = bytearray(data)
            struct.pack_into('<I', changed, offset, value)
            changed[-32:] = digest(changed[:-32])
            with self.assertRaises((ValueError, struct.error, IndexError)):
                inspect(changed)


if __name__ == '__main__':
    data, twin, semantic = fixture()
    print('whole_sha256=' + digest(data).hex(), 'twin=' + twin.hex(), 'semantic=' + semantic.hex())
    unittest.main()
