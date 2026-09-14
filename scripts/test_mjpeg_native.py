#!/usr/bin/env python3
import hashlib
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

def main():
    if shutil.which('cargo') is None:
        print('NOT_RUN: Cargo is unavailable; native JPEG decoding was not executed.', file=sys.stderr)
        return 3
    command = ['cargo','run','--locked','--offline','--quiet','-p','fss-codec-mjpeg','--example','decode_frame','--']
    fixtures = sorted((ROOT/'crates/fss-codec-mjpeg/tests/fixtures').glob('*.jpg'))
    if len(fixtures) != 5:
        raise RuntimeError('incomplete committed fixture set')
    for p in fixtures:
        encoded = p.read_bytes(); digest = hashlib.sha256(encoded).hexdigest()
        color = 'grayscale' if p.stem in ('gray','background') else 'ycbcr'
        args = command+[str(p),digest,color,'--raw']
        first = subprocess.run(args,cwd=ROOT,capture_output=True,check=True)
        second = subprocess.run(args,cwd=ROOT,capture_output=True,check=True)
        oracle = p.with_suffix('.gray').read_bytes()
        if first.stdout != second.stdout or len(first.stdout) != len(oracle):
            raise AssertionError('nondeterministic or wrong-size native output')
        if any(abs(a-b)>1 for a,b in zip(first.stdout,oracle)):
            raise AssertionError(f'native JPEG Y differs from independent oracle: {p.name}')
    with tempfile.TemporaryDirectory() as directory:
        encoded = fixtures[0].read_bytes()+b'\x00'
        path = Path(directory)/'corrupt.jpg'; path.write_bytes(encoded)
        digest = hashlib.sha256(encoded).hexdigest()
        result = subprocess.run(command+[str(path),digest,'grayscale','--raw'],cwd=ROOT,capture_output=True)
        if result.returncode == 0 or result.stdout:
            raise AssertionError('corrupt suffix published a decoded prefix')
    print('PASS: native decoder repeated on five encoded fixtures; corrupt suffix produced no partial output.')
    return 0

if __name__ == '__main__': sys.exit(main())
