#!/usr/bin/env python3
"""Execute the real Rust file harness; missing Cargo is NOT_RUN, never a pass."""
import hashlib
import json
import pathlib
import shutil
import subprocess
import tempfile
import sys


def digest(b):
    return hashlib.sha256(b).hexdigest()


def exercise(cargo):
    root = pathlib.Path(__file__).resolve().parents[1]
    with tempfile.TemporaryDirectory(prefix='fss-foreground-') as temporary:
        folder = pathlib.Path(temporary)
        lines = ['FSS_FOREGROUND_FRAMES_1', 'width=6', 'height=5', 'camera=1', 'clock=2',
                 'calibration='+'09'*32, 'image_domain='+'07'*32, 'valid_from=0', 'valid_until=10000',
                 'selection_evidence='+'06'*32, 'maximum_spread=4', 'minimum_change=10',
                 'minimum_area=2', 'maximum_regions=32', 'widespread_per_mille=750', 'work_units=10000000']
        pixels = bytearray([100]*30)
        for i in [7, 8, 13]: pixels[i] = 150
        for i in [22, 28]: pixels[i] = 30
        pixels[5] = 130
        for exposure in range(1, 7):
            data = bytes([98+exposure])*30 if exposure <= 3 else bytes(pixels)
            mask = bytes([0 if exposure == 6 else 1])*30
            image_name, mask_name = f'frame-{exposure}.gray', f'mask-{exposure}.bin'
            (folder/image_name).write_bytes(data)
            (folder/mask_name).write_bytes(mask)
            role = 'reference' if exposure <= 3 else 'query'
            lines.append(f'{role} {bytes([exposure]*32).hex()} {exposure*10} {exposure*10} '
                         f'{image_name} {digest(data)} {mask_name} {digest(mask)}')
        manifest = folder/'frames.txt'
        manifest.write_text('\n'.join(lines)+'\n')
        cmd = [cargo, 'run', '--locked', '--offline', '--quiet', '-p', 'fss-twin',
               '--example', 'foreground_frames', '--', str(manifest)]
        result = subprocess.run(cmd, cwd=root, capture_output=True, text=True, timeout=240)
        if result.returncode:
            raise AssertionError('native replay did not run successfully:\n'+result.stderr)
        rows = [json.loads(line) for line in result.stdout.splitlines()]
        if len(rows) != 4 or rows[-1].get('kind') != 'complete' or rows[-1].get('frames') != 3:
            raise AssertionError('replay lacks complete exact frame coverage')
        first, second, third = rows[:3]
        expected_regions = [
            {'id':8, 'area':3, 'min':[1,1], 'max':[3,3], 'unknown_boundary':False, 'image_edge':False},
            {'id':23, 'area':2, 'min':[4,3], 'max':[5,5], 'unknown_boundary':False, 'image_edge':True}]
        assert first['report'] == '3eda58e97b8b3a7e1bc339632f41ee7c7b70bbb01fac1952ba2634c54f266c7c'
        assert first['regions'] == expected_regions
        assert first['changed'] == second['changed'] == 6
        assert first['small_components'] == first['small_pixels'] == 1
        assert first['comparable'] == second['comparable'] == 30
        assert second['regions'] == first['regions']
        assert first['exposure'] == '04'*32 and second['exposure'] == '05'*32
        assert third['assessment'] == 'NoComparablePixels' and third['comparable'] == 0
        assert third['changed'] == 0 and third['regions'] == []
        again = subprocess.run(cmd, cwd=root, capture_output=True, text=True, timeout=240)
        assert again.returncode == 0 and again.stdout == result.stdout
        (folder/'mask-6.bin').write_bytes(bytes([1])*30)
        failed = subprocess.run(cmd, cwd=root, capture_output=True, text=True, timeout=240)
        assert failed.returncode != 0
        assert not any(json.loads(line).get('kind') == 'complete' for line in failed.stdout.splitlines())
    return {'status':'PASS', 'native_frames':3, 'exact_replay':True, 'bad_suffix_refused':True}


if __name__ == '__main__':
    cargo = shutil.which('cargo')
    if not cargo:
        print(json.dumps({'status':'NOT_RUN', 'reason':'Cargo is unavailable; no Rust output was substituted'}))
        sys.exit(3)
    try:
        print(json.dumps(exercise(cargo)))
    except Exception as error:
        print(json.dumps({'status':'FAIL', 'reason':str(error)}))
        sys.exit(1)
