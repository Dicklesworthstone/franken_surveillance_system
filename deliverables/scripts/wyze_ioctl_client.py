"""Minimal live K-channel client for the Wyze v4 LAN surface.

Takes `dtlslib.Cam2` and adds the three things the vendors' ioctl layer needs:

  * a monotonically increasing ioctl subchannel (word at +0x12 of the 0x7000 wrapper) — the camera
    silently re-sends K10001 forever if consecutive HL messages reuse sub=0;
  * K10002 as `answer(16) || random(4) || 01 01`;
  * acks that carry the received AV sequence from the frame header at [4:8].

Also raises SO_SNDBUF, without which macOS rejects datagrams above ~9 KiB with EMSGSIZE and the
0x284C overflow (see docs/exploit/wyze-v4-lan-control-plane.md) cannot be driven past ~0x850 bytes.

Import path is resolved relative to this file so it can live in-repo.
"""

import sys, os, time, struct, json
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import wyze_dtls as D

class Cam(D.Cam2):
    def __init__(self, ip, mac, uid, enr):
        super().__init__(ip, mac, uid, enr)
        self.rx=0; self.pending=[]; self.sub=0
    def hl(self, cmd, payload, sub=None):
        if sub is None: sub=self.sub; self.sub=(self.sub+1)&0xffff
        self.avseq+=1
        self.send(self.encrypt(23, D.build_ioctrl(self.avseq, sub, D.build_hl(cmd, payload))))
    def send_ack(self, a, b):
        self.avseq+=1
        self.send(self.encrypt(23, D.build_ack(self.avseq, a&0xffff, b&0xffff, 0x2000, 0)))
    def _frames(self, secs):
        """Yield (cmd,payload) HL messages; auto-ack the AV stream."""
        end=time.time()+secs
        while time.time()<end:
            q=self.recv_dtls(0.7)
            if not q: continue
            if q[0]==21:
                print("dtls alert", q.hex()); continue
            ep=int.from_bytes(q[3:5],'big'); ln=int.from_bytes(q[11:13],'big')
            if q[0]!=23 or ep!=1: continue
            seq=int.from_bytes(q[5:11],'big')
            try: d=self.decrypt(23,seq,q[13:13+ln])
            except Exception as e: print("dec err",e); continue
            if len(d)>=2 and d[0:2]==b'\x00\x21':
                self.send_ack(struct.unpack('<I',d[4:8])[0]&0xffff, struct.unpack('<I',d[4:8])[0]&0xffff)
                yield ('LOGIN', d[:44]); continue
            if d[0:2]==b'\x00\x70':
                i=d.find(b'HL')
                if i>=0 and i+16<=len(d):
                    cmd=struct.unpack('<H',d[i+4:i+6])[0]; plen=struct.unpack('<H',d[i+6:i+8])[0]
                    yield (cmd, d[i+16:i+16+plen])
                self.send_ack(struct.unpack('<I',d[4:8])[0]&0xffff, struct.unpack('<I',d[4:8])[0]&0xffff)
                continue
            off=0
            while off+2<=len(d):
                if d[off:off+2]==b'HL' and off+16<=len(d):
                    plen=struct.unpack('<H',d[off+6:off+8])[0]; cmd=struct.unpack('<H',d[off+4:off+6])[0]
                    pl=d[off+16:off+16+plen]
                    yield (cmd, pl)
                    off+=16+plen
                elif d[off:off+2]==b'\x00\x70' and off+56<=len(d):
                    plen=struct.unpack('<H',d[off+46:off+48])[0]; cmd=struct.unpack('<H',d[off+44:off+46])[0]
                    yield (cmd, d[off+56:off+56+plen]); off+=56+plen
                else: off+=1
            self.send_ack(struct.unpack('<I',d[4:8])[0]&0xffff, struct.unpack('<I',d[4:8])[0]&0xffff)
    def full_login(self, encoders=(137,138,140), verbose=True):
        self.handshake()
        rid=os.urandom(4); l1=self.enr and D.av_login1(self.enr,rid)
        self.send(self.encrypt(23,l1)); time.sleep(0.01)
        self.send(self.encrypt(23,D.av_login2(l1)))
        ok=False
        for cmd,pl in self._frames(5):
            if cmd=='LOGIN':
                if pl[4]==0x10: ok=True; break
                raise RuntimeError("login rejected type %02x"%pl[4])
        if not ok: raise RuntimeError("no login response")
        self.k10000(list(encoders))
        for cmd,pl in self._frames(5):
            if cmd==10001:
                st=pl[0]; ch=pl[1:17]
                r=self._kauth(st,ch); self.hl(10002, r); continue
            if cmd==10003:
                if verbose: print("K10003", pl[:160])
                return pl
        raise RuntimeError("kauth failed")
    def _kauth(self, st, ch):
        if st==3: r=D.xt_decrypt(bytes(ch), self.enr.encode()[:16])
        elif st==6: r=D.xt_decrypt(D.xt_decrypt(bytes(ch), self.enr.encode()[:16]), self.enr.encode()[16:32])
        else: r=D.xt_decrypt(bytes(ch), b"FFFFFFFFFFFFFFFF")
        return r+os.urandom(4)+b'\x01\x01'
