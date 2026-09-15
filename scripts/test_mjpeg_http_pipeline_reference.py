#!/usr/bin/env python3
"""Independent wire/MIME/source-map checks; does not execute native Rust."""
import email.parser
import email.policy
import hashlib
import io
import random
import unittest
from pathlib import Path
from test_mjpeg_http_reference import packet, mapped_entity, standard_entity

FIXTURE = Path(__file__).resolve().parents[1] / 'crates/fss-codec-mjpeg/tests/fixtures/gray.jpg'
JPEG = FIXTURE.read_bytes()

def entity(count=2, final_crlf=True):
    body = bytearray(b'--frame\r\n')
    ranges = []
    for i in range(count):
        body.extend(b'Content-Type: image/jpeg\r\n\r\n')
        ranges.append((len(body), len(body)+len(JPEG)))
        body.extend(JPEG)
        body.extend(b'\r\n--frame--' if i+1 == count else b'\r\n--frame\r\n')
    if final_crlf: body.extend(b'\r\n')
    return bytes(body), ranges

def jpeg_spans(ranges, maps):
    return [[(a+max(c,start)-c, a+min(d,end)-c, max(c,start)-start, min(d,end)-start)
             for a,b,c,d in maps if max(c,start)<min(d,end)] for start,end in ranges]

class PipelineReference(unittest.TestCase):
    def test_standard_http_mime_and_encoded_image_compose(self):
        from PIL import Image
        body, ranges = entity()
        for mode in ['length','eof','chunked']:
            wire=packet(body,mode,[1]*len(body))
            raw, maps=mapped_entity(wire)
            self.assertEqual(raw,standard_entity(wire))
            message=email.parser.BytesParser(policy=email.policy.default).parsebytes(
                b'Content-Type: multipart/x-mixed-replace; boundary=frame\r\n\r\n'+raw)
            payloads=[part.get_payload(decode=True) for part in message.iter_parts()]
            self.assertEqual(payloads,[JPEG,JPEG])
            for payload in payloads:
                image=Image.open(io.BytesIO(payload)); image.load(); self.assertEqual(image.size,(17,13))
            for spans in jpeg_spans(ranges,maps):
                rebuilt=b''.join(wire[a:b] for a,b,_,_ in spans)
                self.assertEqual(rebuilt,JPEG)
    def test_random_chunkings_agree_with_bytewise_origin_oracle(self):
        rng=random.Random(9071); body,ranges=entity(3)
        for _ in range(300):
            sizes=[];left=len(body)
            while left:
                n=min(left,rng.randrange(1,512)); sizes.append(n); left-=n
            wire=packet(body,'chunked',sizes); _,maps=mapped_entity(wire)
            origin={c+j:a+j for a,b,c,d in maps for j in range(d-c)}
            for (start,end),spans in zip(ranges,jpeg_spans(ranges,maps)):
                actual=[i for a,b,_,_ in spans for i in range(a,b)]
                self.assertEqual(actual,[origin[i] for i in range(start,end)])
                self.assertEqual(bytes(wire[i] for i in actual),JPEG)
    def test_final_delimiter_without_crlf_remains_parseable(self):
        body,ranges=entity(1,False); wire=packet(body,'length'); actual,maps=mapped_entity(wire)
        self.assertTrue(actual.endswith(b'--frame--'))
        spans=jpeg_spans(ranges,maps)[0]
        self.assertEqual(b''.join(wire[a:b] for a,b,_,_ in spans),JPEG)
    def test_payload_mapping_excludes_all_http_and_mime_headers(self):
        body,ranges=entity();wire=packet(body,'chunked',[1]*len(body));_,maps=mapped_entity(wire)
        for spans in jpeg_spans(ranges,maps):
            self.assertEqual(len(spans),len(JPEG))
            self.assertEqual(sum(b-a for a,b,_,_ in spans),len(JPEG))
            self.assertEqual(spans[0][2],0);self.assertEqual(spans[-1][3],len(JPEG))
    def test_http_success_does_not_imply_mime_completion(self):
        body,_=entity();wire=packet(body[:-8],'length')
        self.assertEqual(standard_entity(wire),body[:-8]);self.assertFalse(standard_entity(wire).endswith(b'--frame--\r\n'))
    def test_fixture_identity_is_original_compressed_bytes(self):
        self.assertEqual(hashlib.sha256(JPEG).hexdigest(),'db60dfc4ac098088fc15bde677ae01c6b39a1683ef7b0493ceb9402a3c46d476')

if __name__=='__main__': unittest.main(verbosity=2)
