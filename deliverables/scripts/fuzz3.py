import dtlslib as d, struct, time, json
ENR="O7y73ZL+K47xvSPY"
class R:
    def __init__(self): self.c=None; self.log=[]
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
    def emit(self,frame,mtu=8000):
        for i in range(0,len(frame),mtu): self.c.send(self.c.encrypt(23,frame[i:i+mtu]))
    def run(self,name,frame):
        if self.c is None and not self.conn(): print(f"{name:46s} NO-CONN"); return
        try: self.emit(frame)
        except Exception as e: print(f"{name:46s} SEND-EXC {e}"); self.c=None; return
        st=self.alive(); print(f"{name:46s} {st}")
        if st!="live":
            self.log.append((name,st)); self.c=None; time.sleep(6)
            if not self.conn(): print("  !! unreachable"); time.sleep(12); self.conn()
def mk(c,cmd,payload,sub=0):
    c.avseq=(c.avseq+1)&0xFFFFFFFF
    return d.build_ioctrl(c.avseq,sub,d.build_hl(cmd,payload))
r=R(); print("conn:",r.conn())
r.run("baseline",mk(r.c,10000,json.dumps({"cameraInfo":{"audioEncoderList":[137,138,140]}}).encode()))
for decl,actual in ((65535,16),(0,16),(16,0),(4096,16),(16,4096),(65535,40000)):
    m=bytearray(d.build_hl(10000,b'Y'*actual)); struct.pack_into('<H',m,6,decl)
    r.c.avseq+=1; r.run(f"plen decl={decl} actual={actual}",d.build_ioctrl(r.c.avseq,0,bytes(m)))
for decl in (0,1,0xFFFF,0x8000):
    m=bytearray(d.build_ioctrl(r.c.avseq+1,0,d.build_hl(10000,b'{"cameraInfo":{}}')))
    struct.pack_into('<I',m,24,decl); r.c.avseq+=1; r.run(f"ioctrl size={decl}",bytes(m))
for cmd in (0,1,0xFFFF,10001,10004,20000):
    r.run(f"unknown cmd {cmd}",mk(r.c,cmd,b'\x00'*16))
for sub in (1,2,0xFFFF):
    r.run(f"subchannel {sub}",mk(r.c,10000,b'{"cameraInfo":{}}',sub))
r.run("K10002 0B",mk(r.c,10002,b''))
r.run("K10002 16B",mk(r.c,10002,b'\x11'*16))
r.run("K10002 64B",mk(r.c,10002,b'\x00'*64))
r.run("K10010 media 0",mk(r.c,10010,b'\x00\x01'))
r.run("HL lead corrupt",b'XL'+d.build_hl(10000,b'{}')[2:])
r.run("HL plen 65535 empty",d.build_ioctrl(1,0,b'HL\x05\x00\x00\x00\xff\xff'+b'\x00'*8))
print("degradations:",r.log)
