"""One-session laboratory fixture inspection; not a production dependency."""
from pathlib import Path
import re, json, hashlib, subprocess
root = Path(__file__).resolve().parents[1] / 'crates/fss-packet/tests/fixtures/avc'

class Reader:
    def __init__(self, nal):
        rbsp = bytearray()
        i, zeros = 1, 0
        while i < len(nal):
            b = nal[i]; i += 1
            if zeros == 2 and b == 3:
                b = nal[i]; i += 1; zeros = 0
            rbsp.append(b)
            zeros = zeros + 1 if b == 0 else 0
        self.bits = ''.join(f'{x:08b}' for x in rbsp)
        self.at = 0
    def u(self, n):
        s = self.bits[self.at:self.at+n]
        if len(s) != n: raise ValueError('truncated')
        self.at += n
        return int(s or '0', 2)
    def ue(self):
        n = 0
        while self.u(1) == 0: n += 1
        return (1 << n) - 1 + self.u(n)
    def se(self):
        n = self.ue()
        return (n+1)//2 if n&1 else -(n//2)
    def scale(self, n):
        last = nxt = 8
        for _ in range(n):
            if nxt: nxt = (last + self.se() + 256) % 256
            if nxt: last = nxt

def sps(nal):
    b = Reader(nal)
    profile, flags, level, ident = b.u(8), b.u(8), b.u(8), b.ue()
    chroma = 1
    if profile == 100:
        chroma = b.ue(); assert chroma == 1
        assert b.ue() == b.ue() == 0
        b.u(1)
        if b.u(1):
            for i in range(8):
                if b.u(1): b.scale(16 if i < 6 else 64)
    frame_bits = b.ue()+4
    poc = b.ue(); poc_bits = None; always_zero = False
    if poc == 0: poc_bits = b.ue()+4
    if poc == 1:
        always_zero = b.u(1); b.se(); b.se()
        for _ in range(b.ue()): b.se()
    refs = b.ue(); b.u(1)
    wm, hm = b.ue()+1, b.ue()+1
    frame_only = b.u(1); mbaff = 0 if frame_only else b.u(1)
    b.u(1)
    crop = [b.ue() for _ in range(4)] if b.u(1) else [0]*4
    factor = 2-frame_only
    coded = (16*wm, 16*hm*factor)
    visible = (coded[0]-2*(crop[0]+crop[1]), coded[1]-2*factor*(crop[2]+crop[3]))
    return dict(id=ident, profile=profile, flags=flags, level=level, frame_bits=frame_bits, poc=poc,
                poc_bits=poc_bits, always_zero=always_zero, frame_only=frame_only, mbaff=mbaff,
                refs=refs, coded_dimensions=coded, display_dimensions=visible, crop=crop)

def pps(nal):
    b = Reader(nal)
    ident, sid, cabac, bottom = b.ue(), b.ue(), b.u(1), b.u(1)
    assert b.ue() == 0
    b.ue(); b.ue(); b.u(1); b.u(2); b.se(); b.se(); b.se(); b.u(1); b.u(1)
    return dict(id=ident,sps_id=sid,cabac=cabac,bottom=bottom,redundant=b.u(1))

def identity(nal, s, p):
    b = Reader(nal)
    first, kind, pid = b.ue(), b.ue()%5, b.ue()
    assert pid == p['id']
    fn = b.u(s['frame_bits'])
    field = 0 if s['frame_only'] else b.u(1)
    bottom = b.u(1) if field else 0
    idr = b.ue() if nal[0]&31 == 5 else None
    lsb = db = d0 = d1 = 0
    if s['poc'] == 0:
        lsb = b.u(s['poc_bits'])
        if p['bottom'] and not field: db = b.se()
    if s['poc'] == 1 and not s['always_zero']:
        d0 = b.se()
        if p['bottom'] and not field: d1 = b.se()
    redundant = b.ue() if p['redundant'] else 0
    return dict(first_mb=first,slice_type=kind,pps_id=pid,frame_num=fn,field=field,bottom=bottom,
                idr_pic_id=idr,poc_lsb=lsb,delta_bottom=db,delta0=d0,delta1=d1,
                reference=bool(nal[0]&0x60),redundant=redundant,prefix_bits=b.at)

def split(data):
    return [p.rstrip(b'\0') for p in re.split(b'\x00\x00\x00?\x01', data) if p]

out=[]
for path in sorted(root.glob('*.264')):
    data=path.read_bytes(); nals=split(data); sets={}; pictures=[]; ps=None
    for nal in nals:
        if nal[0]&31 == 7: ss=sps(nal); sets[ss['id']]=ss
        elif nal[0]&31 == 8: ps=pps(nal)
        elif nal[0]&31 in (1,5): pictures.append(identity(nal,sets[ps['sps_id']],ps))
    meta=json.loads(subprocess.check_output(['ffprobe','-v','error','-count_frames','-show_entries',
       'stream=profile,width,height,coded_width,coded_height,has_b_frames,nb_read_frames','-of','json',str(path)],timeout=5))['streams'][0]
    ss=list(sets.values())[0]
    assert ss['display_dimensions'] == (meta['width'],meta['height'])
    assert ss['coded_dimensions'] == (meta['coded_width'],meta['coded_height'])
    assert len(pictures) == int(meta['nb_read_frames'])
    assert all(x['first_mb']==0 and x['redundant']==0 for x in pictures)
    out.append(dict(file=path.name,bytes=len(data),sha256=hashlib.sha256(data).hexdigest(),
                    nal_types=[x[0]&31 for x in nals],sps=ss,pps=ps,pictures=pictures,ffprobe=meta))
report=dict(kind='laboratory_fixture_oracle',compiler_tests_executed=False,
            ffmpeg_version=subprocess.check_output(['ffmpeg','-version'],text=True).splitlines()[0], fixtures=out)
# Inspection is read-only: do not silently rewrite the retained oracle.
expected = json.loads((root/'expected.json').read_text())
for actual, retained in zip(report['fixtures'], expected['fixtures'], strict=True):
    assert json.loads(json.dumps(actual)) == retained, actual['file']
print(json.dumps(report,indent=2))
