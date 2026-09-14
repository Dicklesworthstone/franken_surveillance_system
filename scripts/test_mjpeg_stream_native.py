#!/usr/bin/env python3
"""Run the real Rust stream example. Missing Cargo is NOT_RUN, never an oracle pass."""
import hashlib
import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

def main():
    if shutil.which('cargo') is None:
        print('NOT_RUN: Cargo unavailable; Rust MJPEG framing/decoding was not executed.',file=sys.stderr)
        return 3
    from test_mjpeg_reference import reference_decode
    from test_mjpeg_stream_reference import add_metadata
    command=['cargo','run','--locked','--offline','--quiet','-p','fss-codec-mjpeg','--example','decode_stream','--']
    fixtures=ROOT/'crates/fss-codec-mjpeg/tests/fixtures'
    frames=[add_metadata((fixtures/'gray.jpg').read_bytes()),(fixtures/'background.jpg').read_bytes(),(fixtures/'gray.jpg').read_bytes()]
    expected=[]
    offset=0
    for ordinal,frame in enumerate(frames,1):
        luma,_,_=reference_decode(frame)
        expected.append(dict(kind='frame',ordinal=ordinal,start=offset,end=offset+len(frame),
            width=17,height=13,encoded_sha256=hashlib.sha256(frame).hexdigest(),luma_sha256=hashlib.sha256(luma.tobytes()).hexdigest()))
        offset+=len(frame)
    with tempfile.TemporaryDirectory() as directory:
        path=Path(directory)/'capture.mjpeg'
        payload=b''.join(frames)
        path.write_bytes(payload)
        arguments=command+[str(path),hashlib.sha256(payload).hexdigest(),'grayscale']
        first=subprocess.run(arguments,cwd=ROOT,capture_output=True,check=True)
        second=subprocess.run(arguments,cwd=ROOT,capture_output=True,check=True)
        if first.stdout!=second.stdout: raise AssertionError('nondeterministic native transcript')
        rows=[json.loads(line) for line in first.stdout.splitlines()]
        if rows[:-1]!=expected or rows[-1].get('kind')!='complete' or rows[-1].get('frames')!=3 or rows[-1].get('bytes')!=len(payload):
            raise AssertionError('incorrect native frame ranges/pixels/completion')
        for tail in [frames[1][:-1],b'\x00'+frames[1],b'\xff\xd8\xff\xda\x00\x02\xff\xd9']:
            damaged=frames[0]+tail
            path.write_bytes(damaged)
            result=subprocess.run(command+[str(path),hashlib.sha256(damaged).hexdigest(),'grayscale'],cwd=ROOT,capture_output=True)
            rows=[json.loads(line) for line in result.stdout.splitlines()]
            if result.returncode==0 or rows!=expected[:1]: raise AssertionError('invalid suffix produced a false complete or additional frame')
        result=subprocess.run(command+[str(path),'1'*64,'grayscale'],cwd=ROOT,capture_output=True)
        if result.returncode==0 or result.stdout: raise AssertionError('source mismatch produced output')
    print('PASS: native concatenated-JPEG framing/decoding, byte ranges, repeated output and three failure suffixes.')
    return 0

if __name__ == '__main__': sys.exit(main())
