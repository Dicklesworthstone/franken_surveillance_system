import dtlslib as d, struct, time, json
ENR="O7y73ZL+K47xvSPY"
class R:
    def __init__(self):
        self.c=None; self.n=0; self.log=[]
    def conn(self):
        for _ in range(6):
            try:
                c=d.Cam2("192.168.4.24","80482C4BCF0B","S3X2PBBR14M8Y2J6111A",ENR)
                if not c.handshake(): raise RuntimeError("dtls")
                rid=b'\x01\x02\x03\x04'
                c.send(c.encrypt(23,d.av_login1(ENR,rid))); time.sleep(0.01)
                c.send(c.encrypt(23,d.av_login2(d.av_login1(ENR,rid))))
                end=time.time()+5; ok=False
                while time.time()<end and not ok:
                    q=c.recv_dtls(2.0)
                    if not q: break
                    if q[0]==23:
                        pt=c.decrypt(23,int.from_bytes(q[5:11],'big'),q[13:13+int.from_bytes(q[11:13],'big')])
                        if pt[:2]==b'\x00\x21' and pt[4]==0x10: ok=True
                if ok: self.c=c; return True
            except Exception: pass
            time.sleep(4)
        return False
    def alive(self,sec=1.5):
        end=time.time()+sec
        while time.time()<end:
            q=self.c.recv_dtls(0.4)
            if not q: continue
            if q[0]==21: return "ALERT"
            if q[0]==23:
                try: pt=self.c.decrypt(23,int.from_bytes(q[5:11],'big'),q[13:13+int.from_bytes(q[11:13],'big')])
                except Exception: return "DECRYPT-FAIL"
                if pt[:2]==b'\x00\x10': return "live"
        return "stalled"
    def run(self,name,payloads):
        if self.c is None and not self.conn(): print(f"{name:46s} NO-CONN"); return
        try:
            for p in payloads: self.c.send(self.c.encrypt(23,p)); 
        except Exception as e: print(f"{name:46s} SEND-EXC {e}"); self.c=None; return
        st=self.alive()
        print(f"{name:46s} {st}")
        if st!="live":
            self.log.append((name,st)); self.c=None; time.sleep(6)
            if not self.conn(): print("  !! camera unreachable after",name); time.sleep(10); self.conn()
r=R(); print("initial conn:",r.conn())
def hl(c,cmd,payload,sub=0):
    c.avseq+=1; return d.build_ioctrl(c.avseq,sub,d.build_hl(cmd,payload))
# baseline
r.run("baseline K10000",[hl(r.c,10000,json.dumps({"cameraInfo":{"audioEncoderList":[137,138,140]}}).encode())])
# HL payload-length field lies (declared > actual / < actual)
for decl,actual in ((65535,16),(0,16),(16,0),(4096,16),(16,4096),(65535,60000)):
    body=b'X'*actual
    m=bytearray(d.build_hl(10000,body)); struct.pack_into('<H',m,6,decl)
    r.run(f"HL plen decl={decl} actual={actual}",[hl(r.c,10000,b'')[0:0] or d.build_ioctrl(r.c.avseq+1,0,bytes(m))])
    r.c.avseq+=1
# IOCTRL wrapper size field lies
for decl in (0,1,0xFFFF,0x10000&0xFFFF):
    m=bytearray(hl(r.c,10000,b'{"cameraInfo":{}}'))
    r.c.avseq+=1
    struct.pack_into('<I',m,24,decl)
    r.run(f"ioctrl size decl={decl}",[bytes(m)])
# unknown commands / subchannels
for cmd in (0,1,0xFFFF,10001,10002,10004,20000):
    r.run(f"unknown HL cmd {cmd}",[hl(r.c,cmd,b'\x00'*16)])
for sub in (1,2,0xFFFF):
    r.run(f"subchannel {sub}",[hl(r.c,10000,b'{"cameraInfo":{}}',sub)])
# huge total frame
for n in (1400,4000,8000):
    r.run(f"K10000 padded {n}",[hl(r.c,10000,b'{"a":"'+b'A'*(n-10)+b'"}')])
# K10002 malformed
r.run("K10002 short 3B",[hl(r.c,10002,b'\x00\x01\x02')])
r.run("K10002 long 64B",[hl(r.c,10002,b'\x00'*64)])
r.run("K10002 16B only",[hl(r.c,10002,b'\x11'*16)])
print("degradations:",r.log)
