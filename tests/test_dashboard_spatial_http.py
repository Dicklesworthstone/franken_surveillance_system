#!/usr/bin/env python3
"""Native import -> spatial snapshot -> authorized preview; no replacement server or camera mock."""
import argparse
import base64
import contextlib
import hashlib
import json
from pathlib import Path
import re
import subprocess
import tempfile
import time
from test_dashboard_http import request

JPEG = '/9j/4AAQSkZJRgABAQAAAQABAAD/2wBDAAgGBgcGBQgHBwcJCQgKDBQNDAsLDBkSEw8UHRofHh0aHBwgJC4nICIsIxwcKDcpLDAxNDQ0Hyc5PTgyPC4zNDL/2wBDAQkJCQwLDBgNDRgyIRwhMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjL/wAARCAAIAAgDASIAAhEBAxEB/8QAHwAAAQUBAQEBAQEAAAAAAAAAAAECAwQFBgcICQoL/8QAtRAAAgEDAwIEAwUFBAQAAAF9AQIDAAQRBRIhMUEGE1FhByJxFDKBkaEII0KxwRVS0fAkM2JyggkKFhcYGRolJicoKSo0NTY3ODk6Q0RFRkdISUpTVFVWV1hZWmNkZWZnaGlqc3R1dnd4eXqDhIWGh4iJipKTlJWWl5iZmqKjpKWmp6ipqrKztLW2t7i5usLDxMXGx8jJytLT1NXW19jZ2uHi4+Tl5ufo6erx8vP09fb3+Pn6/8QAHwEAAwEBAQEBAQEBAQAAAAAAAAECAwQFBgcICQoL/8QAtREAAgECBAQDBAcFBAQAAQJ3AAECAxEEBSExBhJBUQdhcRMiMoEIFEKRobHBCSMzUvAVYnLRChYkNOEl8RcYGRomJygpKjU2Nzg5OkNERUZHSElKU1RVVldYWVpjZGVmZ2hpanN0dXZ3eHl6goOEhYaHiImKkpOUlZaXmJmaoqOkpaanqKmqsrO0tba3uLm6wsPExcbHyMnK0tPU1dbX2Nna4uPk5ebn6Onq8vP09fb3+Pn6/9oADAMBAAIRAxEAPwCpRRRUHEf/2Q=='
PNG = 'iVBORw0KGgoAAAANSUhEUgAAAAgAAAAICAIAAABLbSncAAAAFElEQVR4nGNMaChgwAaYsIoOWgkACucBYBJwRygAAAAASUVORK5CYII='
SITE='site:spatial-http'
HEADERS={'X-FSS-Read':'1','Sec-Fetch-Site':'same-origin'}

def digest(b): return 'sha256:'+hashlib.sha256(b).hexdigest()
def run_ok(args):
    result = subprocess.run([str(a) for a in args],capture_output=True,timeout=15)
    if result.returncode:
        # Preserve bounded native diagnostics so a fixture failure is diagnosable.
        raise AssertionError(f'native fixture command failed ({result.returncode}): '
                             + result.stderr[:4096].decode('utf8',errors='replace'))
    return result.stdout

@contextlib.contextmanager
def serving(binary,common,scene,frames):
    with tempfile.TemporaryFile() as log:
        args=[str(binary),*map(str,common),'--scene',str(scene),'--port','0','--serve-seconds','60']
        if frames: args+=['--allow-local-frames','yes']
        child=subprocess.Popen(args,stdout=subprocess.DEVNULL,stderr=log)
        try:
            deadline=time.monotonic()+15
            while time.monotonic()<deadline:
                log.seek(0);text=log.read(16384).decode('utf8',errors='replace')
                found=re.search(r'http://127\.0\.0\.1:(\d+)',text)
                if found:
                    yield int(found.group(1))
                    return
                if child.poll() is not None:raise AssertionError(text)
                time.sleep(.02)
            raise AssertionError('Native listener did not start')
        finally:
            if child.poll() is None:
                child.terminate()
                try:child.wait(timeout=3)
                except subprocess.TimeoutExpired:child.kill();child.wait(timeout=3)

def run(binary,importer):
    with tempfile.TemporaryDirectory(prefix='fss-spatial-http-') as temporary:
        base=Path(temporary);root=base/'deployment';source=base/'source.jpg';source.write_bytes(base64.b64decode(JPEG))
        preview=base/'private-preview.png';preview.write_bytes(base64.b64decode(PNG))
        import_args=[importer,'import','--root',root,'--site',SITE,'--input',source,'--sensor','sensor:front','--stream','stream:front','--media-format','mjpeg','--receive-time-ns','1000000']
        run_ok(import_args)
        common=['--root',root,'--site',SITE,'--allow-local-metadata','yes']
        meta=json.loads(run_ok([binary,*common,'--snapshot']))
        assert len(meta['imports'])==1 and meta['demo'] is False
        scene=dict(format='fss.operator_scene.v1',site=SITE,frame='frame:fixture:z-up',scale={'kind':'estimated','metresPerUnit':1,'error':None},ledgerRoot=meta['ledgerRoot'],mesh=dict(vertices=[[0,0,0],[1,0,0],[0,1,0]],triangles=[[0,1,2,0]],materials=[dict(name='Ground',role='terrain',color=[.2,.3,.4])]),sensors=[dict(id='sensor:front',label='Front',kind='camera',status='available',knowledge='observed',basis='Fixture only; not a field calibration',position=[3,5,2],pose={'rotation':[[1,0,0],[0,0,-1],[0,1,0]],'translation':[-3,2,-5]},intrinsics={'width':800,'height':600,'fx':400,'fy':300,'cx':310,'cy':260,'imageDomain':'undistorted_pinhole'},frame={'file':preview.name,'digest':digest(preview.read_bytes()),'sourceDigest':meta['imports'][0],'capturedAtUnixMs':'1789398500000','privacy':'operator-approved-redacted-preview'},reading=None)],placements=[])
        path=base/'scene.json'
        def write_scene():path.write_text(json.dumps(scene),encoding='utf8')
        def frame_path():return '/api/frame/0/'+digest(path.read_bytes()).split(':')[1]
        write_scene()
        before={p.relative_to(root):p.read_bytes() for p in root.rglob('*') if p.is_file()}
        with serving(binary,common,path,True) as port:
            for asset in ['/','/spatial','/sensors','/evidence','/spatial.js','/view3d.js','/spatial-model.js','/spatial.css','/demo-scene.js']:
                assert request(port,asset)[0]==200,asset
            code,_,body=request(port,'/api/spatial',headers=HEADERS);assert code==200
            composite=json.loads(body);assert composite['framesAuthorized'] is True
            assert composite['scene']['sensors'][0]['pose']==scene['sensors'][0]['pose']
            assert 'private-preview.png' not in body.decode()
            code,mime,image=request(port,frame_path(),headers=HEADERS)
            assert code==200 and mime=='image/png' and image==preview.read_bytes()
            assert request(port,frame_path())[0]==403
            assert request(port,'/api/frame/0/'+'0'*64,headers=HEADERS)[0]==503
            original=preview.read_bytes();preview.write_bytes(original+b'changed')
            assert request(port,frame_path(),headers=HEADERS)[0]==503
            preview.write_bytes(original)
            assert request(port,frame_path(),headers=HEADERS)[0]==200
            assert before=={p.relative_to(root):p.read_bytes() for p in root.rglob('*') if p.is_file()}
            # Advance authority with a genuinely different recording/stream. Re-importing the
            # same source under a different receive time conflicts with immutable source facts;
            # the test must not depend on weakening that native protection.
            successor=base/'successor.mjpeg'
            successor.write_bytes(source.read_bytes()*2)
            changed=import_args.copy()
            changed[changed.index('--input')+1]=successor
            changed[changed.index('--stream')+1]='stream:front:successor'
            changed[-1]='2000000'
            run_ok(changed)
            assert request(port,frame_path(),headers=HEADERS)[0]==503
            advanced=json.loads(run_ok([binary,*common,'--snapshot']))
            assert advanced['ledgerRoot']!=meta['ledgerRoot']
            assert len(advanced['imports'])==2 and meta['imports'][0] in advanced['imports']
            scene['ledgerRoot']=advanced['ledgerRoot'];write_scene()
            assert request(port,frame_path(),headers=HEADERS)[0]==200
            scene['sensors'][0]['status']='redacted';write_scene()
            assert request(port,frame_path(),headers=HEADERS)[0]==503
            scene['sensors'][0]['status']='available';write_scene()
        with serving(binary,common,path,False) as port:
            assert request(port,frame_path(),headers=HEADERS)[0]==503
            assert json.loads(request(port,'/api/spatial',headers=HEADERS)[2])['framesAuthorized'] is False
    print('PASS: native MJPEG import, real spatial snapshot, approved PNG readback, unchanged deployment bytes, explicit frame denial, integrity refusal, authority advance, exact reapproval and redacted status.')

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--binary',type=Path,default=Path('target/debug/fss-dashboard'))
    p.add_argument('--importer',type=Path,default=Path('target/debug/fss-file'))
    a=p.parse_args();run(a.binary.resolve(),a.importer.resolve())
