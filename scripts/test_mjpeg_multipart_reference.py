#!/usr/bin/env python3
"""Independent MIME framing controls; these never claim native Rust execution."""
import hashlib, re, unittest
from email import policy
from email.parser import BytesFeedParser, BytesParser
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
JPEG=(ROOT/'crates/fss-codec-mjpeg/tests/fixtures/gray.jpg').read_bytes()
TYPE=b'multipart/x-mixed-replace; boundary="camera:7"'
BOUNDARY=b'camera:7'

def entity(images, lengths=True, eof_line=False):
    out=bytearray(b'--camera:7\r\n')
    for i,image in enumerate(images):
        out.extend(b'Content-Type: image/jpeg\r\nX-Timestamp: not-a-clock\r\n')
        if lengths: out.extend(f'Content-Length: {len(image)}\r\n'.encode())
        out.extend(b'\r\n'+image+b'\r\n--camera:7')
        if i+1==len(images): out.extend(b'--')
        out.extend(b'\r\n')
    return bytes(out[:-2] if eof_line else out)

def oracle(data,chunks=None):
    header=b'MIME-Version: 1.0\r\nContent-Type: '+TYPE+b'\r\n\r\n'
    p=BytesFeedParser(policy=policy.default)
    p.feed(header)
    for chunk in chunks or [data]:p.feed(chunk)
    m=p.close()
    if m.defects:raise ValueError(m.defects)
    return [part.get_payload(decode=True) for part in m.iter_parts()]

def scan(data,eof=False):
    token=b'--'+BOUNDARY
    boundary=re.compile(rb'(?:\A|\r\n)'+re.escape(token)+rb'(--)?([ \t]{0,64})(\r\n|\Z)')
    first=boundary.search(data)
    if first is None:return [],False
    if first.group(1):raise ValueError('initial boundary')
    if first.group(3)!=b'\r\n':return [],False
    at=first.end();parts=[]
    while True:
        end=data.find(b'\r\n\r\n',at)
        if end<0:return parts,False
        headers=data[at:end+4]
        h=BytesParser(policy=policy.default).parsebytes(headers)
        names=[k.lower() for k,v in h.raw_items()]
        if len(names)!=len(set(names)) or h.get_content_type()!='image/jpeg':raise ValueError('header identity/type')
        if h.get('Content-Encoding') or h.get('Transfer-Encoding') or h.get('Content-Transfer-Encoding','binary').lower()!='binary':raise ValueError('encoding')
        start=end+4
        following=boundary.search(data,start)
        if following is None:return parts,False
        if following.group(3)==b'' and (not eof or not following.group(1)):return parts,False
        image=data[start:following.start()]
        if len(image)<4 or image[:2]!=b'\xff\xd8' or image[-2:]!=b'\xff\xd9':raise ValueError('jpeg envelope')
        declared=h.get('Content-Length')
        if declared is not None and (not declared.isdigit() or int(declared)!=len(image)):raise ValueError('length')
        parts.append((start,following.start(),image))
        if following.group(1):return parts,True
        at=following.end()

class MultipartReference(unittest.TestCase):
    def test_length_present_absent_and_eof_delimiter_against_standard_mime(self):
        for lengths in [False,True]:
            for ending in [False,True]:
                data=entity([JPEG,JPEG],lengths,ending)
                parts,complete=scan(data,True)
                self.assertTrue(complete);self.assertEqual([p[2] for p in parts],oracle(data));self.assertEqual(len(parts),2)
    def test_every_fragment_split_against_independent_feed_parser(self):
        data=entity([JPEG,JPEG])
        for cut in range(len(data)+1):
            self.assertEqual(oracle(data,[data[:cut],data[cut:]]),[JPEG,JPEG])
            first,done=scan(data[:cut],False)
            self.assertLessEqual(len(first),2)
            for a,b,part in first:self.assertEqual(data[a:b],part)
    def test_all_premature_ends_are_not_complete(self):
        data=entity([JPEG],False)
        for end in range(len(data)-2):self.assertFalse(scan(data[:end],True)[1])
        self.assertTrue(scan(data[:-2],True)[1]);self.assertFalse(scan(data[:-2],False)[1])
    def test_marker_like_metadata_does_not_split_mime_parts(self):
        meta=b'before\xff\xd9\r\n--other-boundary\r\n\xff\xd8'
        image=JPEG[:2]+b'\xff\xe1'+(len(meta)+2).to_bytes(2,'big')+meta+JPEG[2:]
        data=entity([image,JPEG],False)
        parts,complete=scan(data,True)
        self.assertTrue(complete);self.assertEqual([p[2] for p in parts],oracle(data))
    def test_range_fixture(self):
        data=entity([JPEG,JPEG],True);parts,complete=scan(data,True)
        self.assertTrue(complete)
        for start,end,image in parts:
            self.assertEqual(data[start:end],JPEG)
            self.assertEqual(hashlib.sha256(image).hexdigest(),'db60dfc4ac098088fc15bde677ae01c6b39a1683ef7b0493ceb9402a3c46d476')
        self.assertEqual([(p[0],p[1]) for p in parts],[(87,438),(527,878)])
    def test_wrong_lengths_duplicates_and_representation_are_rejected(self):
        data=entity([JPEG],True)
        for replacement in [b'Content-Length: 4',b'Content-Length: -1',b'Content-Length: 351\r\ncontent-length: 351']:
            with self.assertRaises(ValueError):scan(data.replace(b'Content-Length: 351',replacement),True)
        with self.assertRaises(ValueError):scan(data.replace(b'image/jpeg',b'text/plain'),True)
        with self.assertRaises(ValueError):scan(data.replace(b'X-Timestamp:',b'Content-Encoding:'),True)
    def test_completed_prefix_survives_without_false_final_completion(self):
        data=entity([JPEG,JPEG],False)
        prefix=data[:-12]
        parts,complete=scan(prefix,True)
        self.assertEqual(len(parts),1);self.assertFalse(complete)
    def test_preamble_epilogue_and_transport_padding(self):
        data=b'preamble\r\n'+entity([JPEG],False)[:-2]+b' \t\r\nepilogue'
        parts,complete=scan(data,True)
        self.assertTrue(complete);self.assertEqual([p[2] for p in parts],oracle(data))

if __name__=='__main__':unittest.main()
