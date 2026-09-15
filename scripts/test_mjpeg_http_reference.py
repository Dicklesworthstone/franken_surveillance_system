#!/usr/bin/env python3
"""Independent HTTP framing/source-map controls. This does not execute Rust."""
import hashlib
import http.client
import io
import random
import re
import unittest

class Socket:
    def __init__(self, data): self.data = data
    def makefile(self, *args, **kwargs): return io.BytesIO(self.data)

def packet(body, coding, sizes=()):
    header = b'HTTP/1.1 200 OK\r\nContent-Type: multipart/x-mixed-replace; boundary=frame\r\n'
    if coding == 'length': return header + f'Content-Length: {len(body)}\r\n\r\n'.encode() + body
    if coding == 'eof': return header + b'\r\n' + body
    wire = bytearray(header + b'Transfer-Encoding: chunked\r\nTrailer: X-Checksum\r\n\r\n')
    pos = 0
    for n in sizes:
        block = body[pos:pos+n]
        if not block: break
        wire.extend(f'{len(block):x};tag="literal;value"\r\n'.encode() + block + b'\r\n')
        pos += len(block)
    if pos != len(body): raise ValueError('chunk recipe incomplete')
    wire.extend(b'0\r\nX-Checksum: uninterpreted\r\n\r\n')
    return bytes(wire)

def mapped_entity(wire):
    end = wire.index(b'\r\n\r\n') + 4
    header = wire[:end].lower()
    data, maps = bytearray(), []
    if b'transfer-encoding: chunked' not in header:
        length = re.search(rb'content-length: ([0-9]+)\r\n', header)
        count = int(length[1]) if length else len(wire)-end
        if end+count != len(wire): raise ValueError('length or trailing bytes')
        return wire[end:], [(end,len(wire),0,count)] if count else []
    at = end
    while True:
        e = wire.index(b'\r\n', at)
        size = int(wire[at:e].split(b';',1)[0],16)
        at = e+2
        if not size:
            if wire[at:at+2] == b'\r\n': tail = at+2
            else: tail = wire.index(b'\r\n\r\n',at)+4
            if tail != len(wire): raise ValueError('trailing bytes')
            return bytes(data), maps
        if at+size+2 > len(wire) or wire[at+size:at+size+2] != b'\r\n': raise ValueError('truncated chunk')
        start = len(data)
        data.extend(wire[at:at+size]); maps.append((at,at+size,start,len(data))); at += size+2

def standard_entity(wire):
    response = http.client.HTTPResponse(Socket(wire))
    response.begin()
    return response.read()

class HttpReference(unittest.TestCase):
    def test_all_modes_match_standard_client_with_binary_entities(self):
        rng=random.Random(981)
        for n in range(1,257):
            body=rng.randbytes(n)
            for coding in ['length','chunked','eof']:
                wire=packet(body,coding,[1]*n)
                actual,maps=mapped_entity(wire)
                self.assertEqual(actual,standard_entity(wire)); self.assertEqual(actual,body)
                for a,b,c,d in maps: self.assertEqual(wire[a:b],body[c:d])
    def test_header_bound_identity_golden(self):
        head=packet(b'abc','length')[:-3]
        root=hashlib.sha256(b'fss/http-mjpeg-entity/ref/1\0'+bytes([9])*32+(4).to_bytes(8,'little')+hashlib.sha256(head).digest()).hexdigest()
        self.assertEqual(len(b'fss/http-mjpeg-entity/ref/1\0'),28)
        self.assertEqual(root,'a6b6286b519c5c47cace4e089bbbd2076c8bcea304d8685bbc5bb1c3b54c6040')
    def test_one_byte_chunks_preserve_all_ranges_without_headers(self):
        body=b'\xff\xd8metadata\x00\r\n0\r\n\r\n\xff\xd9'
        wire=packet(body,'chunked',[1]*len(body)); decoded,maps=mapped_entity(wire)
        self.assertEqual(decoded,body); self.assertEqual(len(maps),len(body))
        self.assertTrue(all(b-a==d-c==1 for a,b,c,d in maps))
        self.assertTrue(all(maps[i-1][1]<maps[i][0] for i in range(1,len(maps))))
    def test_random_chunk_boundaries_reassemble_exactly(self):
        rng=random.Random(118)
        for _ in range(300):
            body=rng.randbytes(rng.randrange(1,2048)); sizes=[]; left=len(body)
            while left: n=min(left,rng.randrange(1,128)); sizes.append(n); left-=n
            wire=packet(body,'chunked',sizes); decoded,maps=mapped_entity(wire)
            self.assertEqual(decoded,standard_entity(wire)); self.assertEqual(decoded,body)
            self.assertEqual(b''.join(wire[a:b] for a,b,_,_ in maps),body)
    def test_all_truncations_of_explicit_framing_refuse(self):
        for coding in ['length','chunked']:
            wire=packet(b'payload','chunked' if coding=='chunked' else 'length',[2,3,2])
            for n in range(len(wire)):
                with self.assertRaises((ValueError,IndexError)): mapped_entity(wire[:n])
    def test_chunk_headers_and_terminators_are_not_image_bytes(self):
        wire=packet(b'ABCD','chunked',[2,2]); decoded,maps=mapped_entity(wire)
        covered=set(i for a,b,_,_ in maps for i in range(a,b))
        self.assertEqual(decoded,b'ABCD'); self.assertEqual(len(covered),4)
        self.assertGreater(len(wire)-len(covered),100)
    def test_close_delimited_loss_is_not_observable_from_http_alone(self):
        wire=packet(b'image-prefix-and-tail','eof')
        self.assertEqual(standard_entity(wire[:-4]),b'image-prefix-and-')
        self.assertNotEqual(standard_entity(wire[:-4]),standard_entity(wire))
    def test_parser_harness_source_has_no_runtime_or_network_fallback(self):
        from pathlib import Path
        root=Path(__file__).resolve().parents[1]/'crates/fss-codec-mjpeg/src/http.rs'
        text=root.read_text()
        for forbidden in ['TcpStream','std::process','tokio::','unsafe {']: self.assertNotIn(forbidden,text)

if __name__=='__main__': unittest.main(verbosity=2)
