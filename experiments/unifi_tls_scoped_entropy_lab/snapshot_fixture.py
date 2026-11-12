#!/usr/bin/env python3
"""Disposable loopback P-256 camera; never uses physical credentials or media."""
import json
import os
from pathlib import Path
import secrets
import socket
import ssl
import subprocess
import sys
import tempfile
import threading


def request(peer):
    data = bytearray()
    while b"\r\n\r\n" not in data:
        part = peer.recv(4096)
        if not part or len(data) + len(part) > 16384:
            raise RuntimeError("invalid request")
        data.extend(part)
    head, body = data.split(b"\r\n\r\n", 1)
    lines = bytes(head).split(b"\r\n")
    headers = dict((a.lower(), b.strip()) for a, b in (line.split(b":", 1) for line in lines[1:]))
    size = int(headers.get(b"content-length", b"0"))
    if size > 4096:
        raise RuntimeError("oversized request")
    while len(body) < size:
        part = peer.recv(size-len(body))
        if not part:
            raise RuntimeError("truncated request")
        body.extend(part)
    return bytes(lines[0]), headers, bytes(body)


def run(binary, jpeg, root, mode):
    profiles = mode in ('profiles', 'profiles-unsupported')
    username, password, token = (secrets.token_hex(16) for _ in range(3))
    cred = root / (mode + '.json')
    fd = os.open(cred, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'w') as output:
        json.dump({'username':username, 'password':password}, output)
    listener = socket.socket(); listener.bind(('127.0.0.1', 0)); listener.listen(1); listener.settimeout(15)
    port = listener.getsockname()[1]
    events, errors = [], []
    def serve():
        try:
            ctx=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); ctx.minimum_version=ssl.TLSVersion.TLSv1_3; ctx.maximum_version=ssl.TLSVersion.TLSv1_3
            ctx.set_ecdh_curve('prime256v1'); ctx.num_tickets=0; ctx.load_cert_chain(root/'peer.pem',root/'peer.key')
            raw,_=listener.accept(); raw.settimeout(10)
            try:
                with ctx.wrap_socket(raw,server_side=True) as peer:
                    line,headers,body=request(peer)
                    if line != b'POST /api/1.1/login HTTP/1.1' or json.loads(body) != {'username':username,'password':password}:
                        raise RuntimeError('login mismatch')
                    events.append('login')
                    peer.sendall(b'HTTP/1.1 200 OK\r\nContent-Length: 2\r\nSet-Cookie: authId='+token.encode()+b'; Path=/; HttpOnly\r\nConnection: keep-alive\r\n\r\n{}')
                    line,headers,body=request(peer)
                    if line != b'GET /api/1.1/status HTTP/1.1' or headers.get(b'cookie') != b'authId='+token.encode() or body:
                        raise RuntimeError('status mismatch')
                    events.append('status')
                    body=b'{"board":{},"fw":{},"controller":{"port":7442}}'
                    peer.sendall(b'HTTP/1.1 200 OK\r\nContent-Length: '+str(len(body)).encode()+b'\r\nConnection: keep-alive\r\n\r\n'+body)
                    if profiles:
                        line,headers,body=request(peer)
                        if line != b'GET /api/1.1/settings HTTP/1.1' or headers.get(b'cookie') != b'authId='+token.encode() or body:
                            raise RuntimeError('settings mismatch')
                        events.append('settings')
                        body = (b'{"av":{"video":{"video1":{"width":2688,"height":1512,"fps":30},"video2":{"width":1280,"height":720,"fps":30},"video3":{"width":640,"height":360,"fps":15},"mjpg":{"width":640,"height":360,"fps":2}}}}' if mode == 'profiles' else b'{"av":{"video":{"video1":{"width":0,"height":"unknown"}}}}')
                        peer.sendall(b'HTTP/1.1 200 OK\r\nContent-Length: '+str(len(body)).encode()+b'\r\nConnection: keep-alive\r\n\r\n'+body)
                    line,headers,body=request(peer)
                    if line != b'GET /snap.jpeg HTTP/1.1' or headers.get(b'cookie') != b'authId='+token.encode() or body:
                        raise RuntimeError('snapshot mismatch')
                    events.append('snapshot')
                    data=jpeg.read_bytes(); sent=data if mode in ('valid','profiles','profiles-unsupported') else data[:len(data)//2]
                    peer.sendall(b'HTTP/1.1 200 OK\r\nContent-Type: image/jpeg\r\nContent-Length: '+str(len(data)).encode()+b'\r\nConnection: close\r\n\r\n'+sent)
                    if mode in ('valid','profiles','profiles-unsupported'):
                        try:
                            if peer.recv(1): raise RuntimeError('unexpected additional request')
                        except (ConnectionError, ssl.SSLError): pass
            except ssl.SSLError:
                if mode != 'wrong-pin': raise
                events.append('pin-rejected')
        except Exception as exc:
            errors.append(type(exc).__name__)
        finally:
            listener.close()
    thread=threading.Thread(target=serve); thread.start()
    pin=root/('wrong.der' if mode=='wrong-pin' else 'peer.der')
    secret = root/'does-not-exist' if mode=='wrong-pin' else cred
    arguments=[binary,f'127.0.0.1:{port}',str(pin),str(secret)]
    if profiles: arguments.append('--observe-profiles')
    arguments.append('--owner-authorized')
    result=subprocess.run(arguments,capture_output=True,text=True,timeout=30)
    thread.join(15)
    if thread.is_alive() or errors: raise RuntimeError(f'fixture error mode={mode}, errors={errors}')
    expected = {'valid':['login','status','snapshot'], 'truncated':['login','status','snapshot'], 'wrong-pin':['pin-rejected'], 'profiles':['login','status','settings','snapshot'], 'profiles-unsupported':['login','status','settings','snapshot']}[mode]
    if events != expected or (result.returncode == 0) != (mode in ('valid','profiles','profiles-unsupported')):
        raise RuntimeError(f'unexpected fixture result mode={mode}, events={events}, rc={result.returncode}, stderr={result.stderr}')
    if mode in ('valid','profiles','profiles-unsupported') and 'snapshot=decoded dimensions=16x16 media_persisted=false' not in result.stdout:
        raise RuntimeError('snapshot was not decoded')
    if mode == 'profiles' and ('profile=video1 width=2688 height=1512 fps=30 provenance=camera_claim' not in result.stdout or 'profile=snapshot width=640 height=360 fps=2 provenance=camera_claim' not in result.stdout):
        raise RuntimeError('reported profiles missing')
    if mode == 'profiles' and 'highest_complete_reported_profile=video1 resource_limits=not_applied provenance=camera_claim' not in result.stdout:
        raise RuntimeError('reported profile selection missing')
    if mode == 'profiles-unsupported' and ('profile=video1 width=unsupported height=unsupported fps=not_reported provenance=camera_claim' not in result.stdout or 'profile=video2 width=not_reported height=not_reported fps=not_reported provenance=camera_claim' not in result.stdout):
        raise RuntimeError('unknown profiles flattened')
    if mode == 'profiles-unsupported' and 'highest_complete_reported_profile=none resource_limits=not_applied provenance=camera_claim' not in result.stdout:
        raise RuntimeError('incomplete profile was selected')
    if mode == 'wrong-pin' and 'private credential' in result.stderr:
        raise RuntimeError('credential reached before pin rejection')
    if any(value in result.stdout or value in result.stderr for value in (username,password,token)):
        raise RuntimeError('synthetic secret in output')
    print(mode+'=pass')


def main():
    if len(sys.argv) != 3: raise SystemExit('usage: snapshot_fixture.py BINARY 16X16_JPEG')
    with tempfile.TemporaryDirectory(prefix='fss-snapshot-fixture-') as d:
        root=Path(d)
        for label in ('peer','wrong'):
            subprocess.run(['openssl','req','-x509','-newkey','ec','-pkeyopt','ec_paramgen_curve:P-256','-nodes','-keyout',str(root/(label+'.key')),'-out',str(root/(label+'.pem')),'-days','1','-subj','/CN=fixture'],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
            subprocess.run(['openssl','x509','-in',str(root/(label+'.pem')),'-outform','DER','-out',str(root/(label+'.der'))],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        for mode in ('valid','wrong-pin','truncated','profiles','profiles-unsupported'): run(sys.argv[1],Path(sys.argv[2]),root,mode)

if __name__=='__main__': main()
