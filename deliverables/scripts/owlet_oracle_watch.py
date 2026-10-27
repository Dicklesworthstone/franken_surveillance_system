#!/usr/bin/env python3
"""Owlet oracle watch — decode the live capture ring and flag any camera frame that is
not the standard 200B 0x0602 LAN_SEARCH_R or a 3478 keepalive (bead fss-kemuu).

The prize: the app-session grant trace. The Owlet app completes LAN_SEARCH -> grant ->
AV every time it opens live view, so a passive capture bounded to the camera's IP will
eventually hold a real grant. This tool watches the ring produced by a rolling tcpdump
(capture_ring.sh in /tmp/owlet_oracle, filter `host 192.168.4.163 and (udp port 63616
or 3478 or 32761)`, full snaplen, 90s windows, 6-file buffer) and logs every frame with
direction + plaintext type; anything that is not 0x0602/keepalive from the camera is
flagged *** NON-0x0602 ***.

Run alongside the ring:
  sudo sh /tmp/owlet_oracle/capture_ring.sh &
  sudo python3 deliverables/scripts/owlet_oracle_watch.py [--minutes 30]

Decode pipeline (validated live): tcpdump -x per-packet hex -> locate the TUTK frame by
its wire magic 6e4c9d8c -> cp.inv_transcode (the real transcode inverse, NOT xor_frame,
which is only correct for zero plaintext) -> plaintext type at [8:10].
"""

import subprocess, time, os, glob, datetime, sys
DIR = os.environ.get("OWLET_ORACLE_DIR", "/tmp/owlet_oracle")
LOG = os.path.join(DIR, "watch.log")
def log(m):
    line=f"{datetime.datetime.now().isoformat(timespec='seconds')} {m}"
    print(line,flush=True); open(LOG,"a").write(line+"\n")
def decode(b, key=bytes.fromhex("6e2e8d8c40d040ca2d6d280c40e4cad8")):
    return bytes(x^key[i%16] for i,x in enumerate(b))
def read_pkts(path):
    import subprocess, re, sys, os
    sys.path.insert(0, "/Users/jemanuel/fw-lab/owlet/cubo")
    import cuboai_pure_owlet as cp
    r=subprocess.run(["tcpdump","-n","-r",path,"-x"],capture_output=True,text=True)
    out=[]
    # tcpdump -x emits per-packet blocks: header line then 0x hex lines
    pkts=[];cur=[]
    for l in r.stdout.splitlines():
        if "IP " in l:
            if cur: pkts.append(cur); cur=[]
            cur.append(l)
        elif l.strip().startswith("0x") and cur:
            cur.append(l)
    if cur: pkts.append(cur)
    for grp in pkts:
        hx=""
        for l in grp[1:]:
            toks=l.split(":",1)[1].split()
            hx+="".join(t for t in toks if re.fullmatch(r"[0-9a-fA-F]{2,8}", t))
        try: raw=bytes.fromhex(hx)
        except ValueError: continue
        i=raw.find(bytes.fromhex("6e4c9d8c"))
        if i<0: continue
        p=raw[i:i+600]
        try: d=cp.inv_transcode(p[:88]) if len(p)>=88 else cp.inv_transcode(p)
        except Exception: continue
        out.append((grp[0], p, d))
    return out

def main():
    import argparse
    ap=argparse.ArgumentParser()
    ap.add_argument("--minutes", type=int, default=30)
    a=ap.parse_args()
    deadline=time.time()+a.minutes*60
    seen=set()
    log("ring-reader oracle watch started (30 min)")
    while time.time()<deadline:
        for f in sorted(glob.glob(f"{DIR}/oracle_*.pcapng"), key=os.path.getmtime)[-2:]:
            for hdr,p,d in read_pkts(f):
                sig=(f,p[:32].hex(),len(p))
                if sig in seen: continue
                seen.add(sig)
                from_cam = "192.168.4.163." in hdr and ">" in hdr.split("192.168.4.163.")[1]
                is3478="3478" in hdr and from_cam
                typ=f"0x{d[8:10].hex()}" if len(d)>=10 else "?"
                interesting = from_cam and (not is3478) and (typ!="0206" or len(p)!=200)
                tag="*** NON-0x0602 ***" if interesting else ""
                log(f"{os.path.basename(f)} {len(p)}B type={typ} {'from-cam' if from_cam else 'to-cam'} {tag} head={p[:40].hex()}")
        time.sleep(30)
    log("ring-reader done (30 min)")
if __name__=="__main__": main()
