import socket, ssl, os, threading, time
THING="80482c4bcf0b"; D=os.path.expanduser("~/.config/fss-lab/wyze_iot/80482C4BCF0B")
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
def handle(cli):
    try:
        u=up_ctx().wrap_socket(socket.create_connection(UP,timeout=10),server_hostname=SNI)
        print("UP ok",flush=True)
    except Exception as e: print("upstream fail",repr(e),flush=True); cli.close(); return
    threading.Thread(target=pipe,args=(cli,u,"C"),daemon=True).start()
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
