#!/usr/bin/env python3
"""Execute actual Rust HTTP/MIME/JPEG replay or explicitly report NOT_RUN."""
import hashlib
import re
import shutil
import subprocess
import tempfile
from pathlib import Path
from test_mjpeg_http_reference import packet
from test_mjpeg_http_pipeline_reference import entity, JPEG

ROOT=Path(__file__).resolve().parents[1]
def run(path,wire,split):
    path.write_bytes(wire)
    return subprocess.run(['cargo','run','--quiet','--locked','--offline','-p','fss-codec-mjpeg','--example','decode_http','--',str(path),hashlib.sha256(wire).hexdigest(),'grayscale',str(split)],cwd=ROOT,text=True,capture_output=True,timeout=180)
def check(text,wire,expected):
    frames=re.findall(r'^frame=(\d+) encoded=([0-9a-f]{64}) luma=([0-9a-f]{64}) width=17 height=13 spans=(\d+)$',text,re.M)
    assert len(frames)==expected,text
    maps=re.findall(r'^map frame=(\d+) jpeg_start=(\d+) jpeg_end=(\d+) wire_start=(\d+) wire_end=(\d+)$',text,re.M)
    for ordinal,encoded,luma,count in frames:
        spans=[tuple(map(int,row[1:])) for row in maps if row[0]==ordinal]
        assert len(spans)==int(count)
        assert spans[0][0]==0 and spans[-1][1]==len(JPEG)
        assert all(spans[i-1][1]==spans[i][0] for i in range(1,len(spans)))
        assert b''.join(wire[a:b] for _,_,a,b in spans)==JPEG
        assert encoded==hashlib.sha256(JPEG).hexdigest()
        assert luma=='5875da5ed7274432c2e42d253dae128c4a7d4be02f9122f72f3688a0a0b86f1d'
    assert f'complete frames={expected} ' in text
    return [(a,b,c) for a,b,c,_ in frames]
def main():
    if shutil.which('cargo') is None:
        print('NOT_RUN: Cargo is unavailable; no native HTTP/MIME/JPEG result produced.');return 3
    with tempfile.TemporaryDirectory(prefix='fss-http-native-') as temp:
        path=Path(temp)/'response.http';body,_=entity(2)
        for mode in ['length','eof','chunked']:
            sizes=[min(37,len(body)-i) for i in range(0,len(body),37)]
            wire=packet(body,mode,sizes);outputs=[]
            for split in [1,29,65536]:
                result=run(path,wire,split);assert result.returncode==0,result.stderr
                outputs.append(check(result.stdout,wire,2))
            assert outputs[0]==outputs[1]==outputs[2]
        wire=packet(body,'chunked',[len(body)])[:-1]
        result=run(path,wire,17);assert result.returncode!=0;assert 'complete frames=' not in result.stdout
        bad=bytearray(body);pos=bad.index(JPEG);sof=bad.index(b'\xff\xc0',pos);bad[sof+4]=16
        result=run(path,packet(bytes(bad),'length'),17);assert result.returncode!=0;assert 'complete frames=' not in result.stdout
    print('PASS: actual native HTTP/MIME/JPEG replay, source mappings and failure completion.');return 0
if __name__=='__main__': raise SystemExit(main())
