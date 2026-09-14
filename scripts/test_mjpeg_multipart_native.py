#!/usr/bin/env python3
"""Execute the actual Rust multipart decoder. No compiler means NOT_RUN, not PASS."""
import hashlib, json, shutil, subprocess, sys, tempfile
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]

def verify(rows, expected, size):
    if not rows or rows[:-1]!=expected or rows[-1].get('kind')!='complete' or rows[-1].get('frames')!=len(expected) or rows[-1].get('bytes')!=size:
        raise AssertionError('native MIME ranges, pixels or completion differ')

def main():
    if shutil.which('cargo') is None:
        print('NOT_RUN: Cargo unavailable; native multipart JPEG pipeline not executed.',file=sys.stderr)
        return 3
    from test_mjpeg_multipart_reference import entity, scan, TYPE, JPEG
    from test_mjpeg_reference import reference_decode
    luma,_,_=reference_decode(JPEG)
    luma_hash=hashlib.sha256(luma.tobytes()).hexdigest()
    command=['cargo','run','--locked','--offline','--quiet','-p','fss-codec-mjpeg','--example','decode_multipart','--']
    with tempfile.TemporaryDirectory() as directory:
        path=Path(directory)/'entity.bin'
        def run(data, expected_hash=None):
            path.write_bytes(data)
            return subprocess.run(command+[str(path),expected_hash or hashlib.sha256(data).hexdigest(),TYPE.decode(),'grayscale'],cwd=ROOT,capture_output=True)
        for lengths in [False,True]:
            for eof_line in [False,True]:
                data=entity([JPEG,JPEG],lengths,eof_line)
                parts,complete=scan(data,True)
                if not complete:raise AssertionError('invalid independent fixture')
                expected=[dict(kind='frame',ordinal=i,start=a,end=b,width=17,height=13,encoded_sha256=hashlib.sha256(j).hexdigest(),luma_sha256=luma_hash) for i,(a,b,j) in enumerate(parts,1)]
                first=run(data);second=run(data)
                if first.returncode or second.returncode or first.stdout!=second.stdout:
                    raise AssertionError(('native MIME execution failed',first.stderr,second.stderr))
                rows=[json.loads(line) for line in first.stdout.splitlines()]
                verify(rows,expected,len(data))
                if rows[-1].get('preamble_bytes')!=0 or rows[-1].get('epilogue_bytes')!=0:raise AssertionError('invented wrapper bytes')
        data=entity([JPEG,JPEG],True)
        damaged_cases=[data[:-12],data[:-2]+b'x',data.replace(b'Content-Length: 351',b'Content-Length: 350',1)]
        for damaged in damaged_cases:
            result=run(damaged)
            rows=[json.loads(line) for line in result.stdout.splitlines()]
            if result.returncode==0 or any(r.get('kind')=='complete' for r in rows):raise AssertionError('bad MIME suffix completed')
        mismatch=run(data,'1'*64)
        if mismatch.returncode==0 or mismatch.stdout:raise AssertionError('source mismatch exposed output')
    print('PASS: actual native MIME framing, JPEG decoding, range/pixel goldens, repeats and failure cases.')
    return 0
if __name__=='__main__':sys.exit(main())
