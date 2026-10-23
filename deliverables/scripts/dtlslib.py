import socket, struct, hashlib, hmac, os, time
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
B64=b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
def ak(enr,mac):
    h=hashlib.sha256((enr+mac.upper()).encode()).digest()[:6]; o=bytearray()
    for i in (0,3):
        n=(h[i]<<16)|(h[i+1]<<8)|h[i+2]; o+=bytes([B64[(n>>18)&63],B64[(n>>12)&63],B64[(n>>6)&63],B64[n&63]])
    return bytes({43:90,47:57}.get(c,c) for c in o)
def prf(secret,label,seed,n):
    out=b''; A=label+seed
    while len(out)<n:
        A=hmac.new(secret,A,hashlib.sha256).digest(); out+=hmac.new(secret,A+label+seed,hashlib.sha256).digest()
    return out[:n]
EXTS=struct.pack('>HHHH',0x000A,4,2,0x001D)+struct.pack('>HH',0x000B,2)+bytes([1,0])
class Cam:
    def __init__(self,ip,mac,uid,enr,iface="192.168.4.170",port=32761):
        self.ip=ip; self.key=uid.encode()+ak(enr,mac); self.psk=hashlib.sha256(enr.encode()).digest()
        n=self.psk.find(b'\x00');  self.psk=self.psk[:n] if n>=0 else self.psk
        self.sid=os.urandom(2)+bytes.fromhex('760a9d2488ba'); self.port=port
        self.s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); self.s.bind((iface,0)); self.s.settimeout(3)
        self.cr=os.urandom(32); self.eph=X25519PrivateKey.generate(); self.transcript=b''
        self.cseq=0; self.sseq=0
    def disc(self,seq,t=0):
        b=bytearray(struct.pack('<HHHHHH',0xCC51,0,0x1002,0x28,0,0)); b+=struct.pack('<HH',seq,t)+self.sid+bytes([0,8,3,4,0x1D,0,0,0])
        return bytes(b)+hmac.new(self.key,bytes(b),hashlib.sha1).digest()
    def wrap(self,p):
        h=bytearray(struct.pack('<HHHHHH',0xCC51,0,0x1502,16+len(p)+20,0,0)); h+=struct.pack('<HH',0x0010,self.ticket)+self.sid+struct.pack('<I',1)
        return bytes(h)+p+hmac.new(self.key,bytes(h),hashlib.sha1).digest()
    def send(self,p): self.s.sendto(self.wrap(p),(self.ip,self.port))
    def recv_dtls(self,sec=3.0):
        end=time.time()+sec
        while time.time()<end:
            try: r,_=self.s.recvfrom(70000)
            except socket.timeout: return None
            if len(r)>6 and struct.unpack('<H',r[4:6])[0]==0x1502: return r[28:-20]
        return None
    def open(self):
        for attempt in range(14):
            try:
                self.s.settimeout(2.0)
                self.s.sendto(self.disc(0),(self.ip,self.port)); d,_=self.s.recvfrom(2048)
                self.ticket=struct.unpack('<HHHHHHHH',d[:16])[7]
                self.s.sendto(self.disc(2,self.ticket),(self.ip,self.port)); self.s.recvfrom(2048)
                time.sleep(0.5); return
            except socket.timeout:
                time.sleep(2.5)
        raise RuntimeError("discovery failed")
    def client_hello(self,cookie=b''):
        body=b'\xfe\xfd'+self.cr+b'\x00'+bytes([len(cookie)])+cookie+struct.pack('>HH',2,0xCCAC)+bytes([1,0])+struct.pack('>H',len(EXTS))+EXTS
        m=b'\x01'+len(body).to_bytes(3,'big')+b'\x00\x00'+b'\x00'*3+len(body).to_bytes(3,'big')+body
        return m
    def pack_record(self,ct,epoch,seq,payload):
        return bytes([ct,0xFE,0xFD])+epoch.to_bytes(2,'big')+seq.to_bytes(6,'big')+len(payload).to_bytes(2,'big')+payload
    def handshake(self):
        self.open()
        m=self.client_hello(); self.transcript=m
        self.send(self.pack_record(22,0,self.cseq,m)); self.cseq+=1
        p=self.recv_dtls()
        if not p: raise RuntimeError("no serverhello")
        # parse flight
        off=0; msgs=[]; sh=None; ske=None
        while off+13<=len(p):
            ct=p[off]; ln=int.from_bytes(p[off+11:off+13],'big'); payload=p[off+13:off+13+ln]; off+=13+ln
            if ct!=22: continue
            j=0
            while j+12<=len(payload):
                mt=payload[j]; ml=int.from_bytes(payload[j+1:j+4],'big'); fl=int.from_bytes(payload[j+9:j+12],'big')
                body=payload[j+12:j+12+fl]; j+=12+fl
                msgs.append((mt,ml,body)); self.transcript+=payload[j-12-fl:j] if False else b''
        # reparse transcript properly from raw records
        self.transcript=self.client_hello()
        off=0
        while off+13<=len(p):
            ct=p[off]; ln=int.from_bytes(p[off+11:off+13],'big'); payload=p[off+13:off+13+ln]; off+=13+ln
            if ct==22: self.transcript+=payload
        for mt,ml,body in msgs:
            if mt==2: sh=body
            elif mt==12: ske=body
        if not sh or not ske: raise RuntimeError("missing flight")
        srv_random=sh[2:34]
        # SKE body: psk_identity_hint_len(2) + curve_list_len(2) + curve(2) + pub_len(1) + pub
        hintlen=int.from_bytes(ske[0:2],'big'); base=2+hintlen
        publen=ske[base+3]; pub=ske[base+4:base+4+publen]
        shared=self.eph.exchange(X25519PublicKey.from_public_bytes(pub))
        pm=len(shared).to_bytes(2,'big')+shared+len(self.psk).to_bytes(2,'big')+self.psk
        master=prf(pm,b"master secret",self.cr+srv_random,48)
        kb=prf(master,b"key expansion",srv_random+self.cr,88)
        self.ck,self.sk,self.civ,self.siv=kb[0:32],kb[32:64],kb[64:76],kb[76:88]
        ident=self.identity if getattr(self,"identity",None) else "AUTHPWD_admin"
        if isinstance(ident,str): ident=ident.encode()
        cke_body=len(ident).to_bytes(2,'big')+ident+bytes([32])+self.eph.public_key().public_bytes(Encoding.Raw,PublicFormat.Raw)
        cke=b'\x10'+len(cke_body).to_bytes(3,'big')+b'\x00\x01'+b'\x00'*3+len(cke_body).to_bytes(3,'big')+cke_body
        self.transcript+=cke
        cv=prf(master,b"client finished",hashlib.sha256(self.transcript).digest(),12)
        fin=b'\x14'+len(cv).to_bytes(3,'big')+b'\x00\x02'+b'\x00'*3+len(cv).to_bytes(3,'big')+cv
        self.send(self.pack_record(22,0,self.cseq,cke)); self.cseq+=1
        self.send(self.pack_record(20,0,self.cseq,b'\x01')); self.cseq+=1
        self.cseq=0   # epoch 1 records start at seq 0
        self.send(self.encrypt(22,fin))
        self.transcript+=fin
        self.expected=prf(master,b"server finished",hashlib.sha256(self.transcript).digest(),12)
        self.master=master
        # await server CCS + Finished
        end=time.time()+4
        while time.time()<end:
            q=self.recv_dtls(2.0)
            if not q: break
            off=0
            while off+13<=len(q):
                ct=q[off]; ep=int.from_bytes(q[off+3:off+5],'big'); seq=int.from_bytes(q[off+5:off+11],'big')
                ln=int.from_bytes(q[off+11:off+13],'big'); body=q[off+13:off+13+ln]; off+=13+ln
                if ct==21: raise RuntimeError(f"alert {body.hex()}")
                if ct==22 and ep==1:
                    pt=self.decrypt(22,seq,body)
                    if pt[12:12+12]==self.expected:
                        self.ready=True; return True
                    return False
        return False
    def nonce(self,iv,seq): 
        n=bytearray(iv); x=(1).to_bytes(2,'big')+seq.to_bytes(6,'big')
        for i in range(8): n[4+i]^=x[i]
        return bytes(n)
    def aad(self,ct,seq,l): return (1).to_bytes(2,'big')+seq.to_bytes(6,'big')+bytes([ct,0xFE,0xFD])+l.to_bytes(2,'big')
    def encrypt(self,ct,plain,seq=None):
        seq=self.cseq if seq is None else seq
        sealed=ChaCha20Poly1305(self.ck).encrypt(self.nonce(self.civ,seq),plain,self.aad(ct,seq,len(plain)))
        self.cseq=seq+1
        return not None and self.pack_record(ct,1,seq,sealed)
    def decrypt(self,ct,seq,payload):
        s=seq if isinstance(seq,int) else int.from_bytes(seq,'big')
        pt=ChaCha20Poly1305(self.sk).decrypt(self.nonce(self.siv,s),payload,self.aad(ct,s,len(payload)-16))
        self.sseq=s+1
        return pt
    def appdata(self,data): return self.send(self.encrypt(23,data))
    def recv_app(self,sec=3.0):
        end=time.time()+sec
        while time.time()<end:
            q=self.recv_dtls(sec)
            if not q: return None
            ct=q[0]; ln=int.from_bytes(q[11:13],'big'); ep=int.from_bytes(q[3:5],'big'); seq=int.from_bytes(q[5:11],'big')
            if ct==23 and ep==1: return self.decrypt(23,seq,q[13:13+ln])
        return None

def xt_decrypt(data,key):
    M=0xffffffff
    v=list(struct.unpack('<%dI'%((len(data))//4),data)); k=struct.unpack('<4I',key); n=len(v)
    rounds=6+52//n; sum=(rounds*0x9E3779B9)&M; y=v[0]
    def mx(sum,y,z,p,e):
        a=((z>>5)^((y<<2)&M))&M; b=((y>>3)^((z<<4)&M))&M
        c=((sum^y)+(k[(p&3)^e]^z))&M
        return ((a+b)&M)^c
    while rounds>0:
        e=(sum>>2)&3
        for p in range(n-1,0,-1):
            z=v[p-1]; v[p]=(v[p]-mx(sum,y,z,p,e))&M; y=v[p]
        z=v[n-1]; v[0]=(v[0]-mx(sum,y,z,0,e))&M; y=v[0]
        sum=(sum-0x9E3779B9)&M; rounds-=1
    return struct.pack('<%dI'%n,*v)

def av_login1(enr,rid):
    p=bytearray(570); st=struct
    st.pack_into('<HH',p,0,0x0000,0x000C); st.pack_into('<HH',p,16,0x0222,0x0001)
    p[20:24]=rid; p[24:29]=b"admin"; e=enr.encode(); p[280:280+len(e)]=e
    st.pack_into('<I',p,536,0); st.pack_into('<I',p,540,2); st.pack_into('<I',p,544,0)
    st.pack_into('<I',p,548,0); st.pack_into('<I',p,552,0x001F07FB)
    return bytes(p)
def av_login2(l1):
    p=bytearray(l1); p+=b'\x00\x00'
    struct.pack_into('<HH',p,0,0x2000,0x0224); struct.pack_into('<H',p,18,0)
    p[20]=(p[20]+1)&0xff
    return bytes(p)
def build_hl(cmd,payload):
    return b"HL"+bytes([5,0])+struct.pack('<H',cmd)+struct.pack('<H',len(payload))+b'\x00'*8+payload
def build_ioctrl(avseq,sub,hl):
    p=bytearray(40); struct.pack_into('<HH',p,0,0x000C,0x000C); struct.pack_into('<I',p,4,avseq)
    struct.pack_into('<H',p,16,0x7000); struct.pack_into('<H',p,18,sub); struct.pack_into('<I',p,20,1)
    struct.pack_into('<I',p,24,len(hl)+4); struct.pack_into('<I',p,28,sub); struct.pack_into('<H',p,36,0x0100)
    return bytes(p)+hl
def build_ack(avseq,a,b,flags,ts):
    p=bytearray(24); struct.pack_into('<HHHH',p,0,0x0009,0x000C,avseq&0xffff,(avseq>>16)&0xffff)
    struct.pack_into('<HHH',p,8,a,b,flags); struct.pack_into('<I',p,16,(flags<<16)&0xffffffff)
    struct.pack_into('<H',p,20,ts)
    return bytes(p)

class Cam2(Cam):
    def __init__(self,*a,**kw):
        super().__init__(*a,**kw); self.enr=a[3]; self.avseq=0; self.rx=0
    def hl(self,cmd,payload,sub=0):
        self.avseq+=1
        self.send(self.encrypt(23,build_ioctrl(self.avseq,sub,build_hl(cmd,payload))))
    def k10000(self,encoders=None):
        import json
        enc=encoders or [137,138,140]
        self.hl(10000,json.dumps({"cameraInfo":{"audioEncoderList":enc}}).encode())
    def k10002(self,status,challenge):
        mode={3:'enr',6:'enrd',1:'def'}.get(status,'def')
        if mode=='def': r=xt_decrypt(bytes(challenge),b"FFFFFFFFFFFFFFFF")
        elif mode=='enr': r=xt_decrypt(bytes(challenge),self.enr.encode()[:16])
        else:
            r=xt_decrypt(xt_decrypt(bytes(challenge),self.enr.encode()[:16]),self.enr.encode()[16:32])
        self.hl(10002,r+struct.pack('<I',self.rx)+b'\x01\x01')
        return r
    def login(self,tries=2):
        rid=os.urandom(4); self.send(self.encrypt(23,av_login1(self.enr,rid)))
        time.sleep(0.01)
        self.send(self.encrypt(23,av_login2(av_login1(self.enr,rid))))
        end=time.time()+5
        while time.time()<end:
            q=self.recv_dtls(2.0)
            if not q: continue
            if struct.unpack('<H',q[4:6])[0]==0x1302 and len(q)>=48:
                cnt=struct.unpack('<I',q[16:20])[0]
                self.avseq+=1; self.send(self.encrypt(23,build_ack(self.avseq,cnt&0xffff,cnt&0xffff,0x2000,0)))
                continue
            ep=int.from_bytes(q[3:5],'big'); ln=int.from_bytes(q[11:13],'big')
            if q[0]!=23 or ep!=1: continue
            d=self.decrypt(23,int.from_bytes(q[5:11],'big'),q[13:13+ln])
            off=0
            while off+16<=len(d):
                if d[off:off+2]==b"HL":
                    plen=struct.unpack('<H',d[off+6:off+8])[0]; cmd=struct.unpack('<H',d[off+4:off+6])[0]
                    payload=d[off+16:off+16+plen]
                    if cmd==10001 and len(payload)>=17:
                        st=payload[0]; ch=payload[1:17]; print("  K10001 status",st)
                        r=self.k10002(st,ch); print("  sent K10002 resp",r.hex())
                    if cmd==10003:
                        print("  K10003:",payload[:120]); return True
                    off+=16+plen
                elif len(d)>=40 and d[off+16:off+18]==b'\x00\x70':
                    plen=struct.unpack('<H',d[off+46:off+48])[0]; cmd=struct.unpack('<H',d[off+44:off+46])[0]
                    payload=d[off+56:off+56+plen]
                    if cmd==10001 and len(payload)>=17:
                        st=payload[0]; ch=payload[1:17]; print("  K10001 status",st)
                        r=self.k10002(st,ch); print("  sent K10002 resp",r.hex())
                    if cmd==10003:
                        print("  K10003:",payload[:120]); return True
                    off+=40+16+plen
                else: off+=1
        return False
