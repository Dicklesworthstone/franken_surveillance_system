#!/usr/bin/env python3
"""fleet_status.py — the liberation control plane's read side.

One command answers "what state is every camera in, right now, and what is
broken" — replacing the per-session ritual of grepping launchctl, pf, ports,
ARP, and six log files (the 2026-11-06 outage took hours because that ritual
was manual and unpracticed).

    fleet_status.py              # status table for every camera in registry.yaml
    fleet_status.py --json       # machine form for other tools
    fleet_status.py --gate       # exit nonzero if any plane is DOWN (pre-session gate)

Planes checked per camera: presence (ARP/ping), vector state (mitm/rooted/fss),
proofs (latest RootProof per vector), waits (open wait from the ledger).
Fleet planes: broker :8883, forge :443/:8443, backup 444-449, tftp :69,
pf rdr count, plist doctor (cached), launchd duplicate labels, rtsp watch,
and every camera-lane watcher job (a dead watcher is invisible otherwise).

Read-only: this NEVER mutates. Convergence (the write side) is a separate
reviewed change; status first, always.
"""
import argparse
import datetime
import glob
import json
import os
import re
import socket
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from registry import load, arp_table, ping_probe, norm_mac  # noqa: E402

PROOFS = os.path.normpath(os.path.join(HERE, "..", "proofs"))
WAITS = "/var/lib/fss-telemetry/waits.jsonl"


# Camera-lane watchers. Each one was running as an unsupervised nohup at some point and
# one (the RTSP watcher) sat four days on an address its fleet did not contain; a plane
# per job is the only way that death is visible.
WATCHERS = (
    "com.jeffreyemanuel.c460-fire",
    "com.jeffreyemanuel.c460-burst-daemon",
    "com.jeffreyemanuel.c660-sweep",
    "com.jeffreyemanuel.c660-tftp",
    "com.jeffreyemanuel.c660-convert",
    "com.jeffreyemanuel.owlet-relay-watch",
    "com.jeffreyemanuel.yi-listener",
    "com.jeffreyemanuel.wyze-rtsp-watch",
)


def sh(cmd, timeout=15):
    try:
        r = subprocess.run(["/bin/zsh", "-c", cmd], capture_output=True, text=True, timeout=timeout)
        return r.returncode, r.stdout
    except (subprocess.TimeoutExpired, OSError):
        return 1, ""


def forge_serving(port, secs=6):
    """A wedged forge still accepts TCP — the :443 one did on 2026-11-09 and every port
    check called it green while nothing was served. Ask for a real response."""
    code = sh(f"curl -sk -o /dev/null -w '%{{http_code}}' --max-time {secs} https://127.0.0.1:{port}/")[1]
    return code.strip() == "200"


def port_open(port, host="127.0.0.1"):
    try:
        with socket.create_connection((host, port), timeout=1.5):
            return True
    except OSError:
        return False


PLANE_DETAILS = {}


def fleet_planes():
    planes = {}
    planes["broker:8883"] = port_open(8883)
    planes["forge:443"] = forge_serving(443)
    planes["forge:8443"] = forge_serving(8443)
    planes["backup:444-449"] = all(port_open(p) for p in range(444, 450))
    # session-lineage quirk (see registry.py): netstat under this harness's
    # python returns 0 lines; port_open sockets are lineage-independent, so
    # every check that CAN be a socket probe IS one; the two netstat-only
    # checks (udp tftp, LISTEN count) use per-port socket probes instead.
    planes["forge:8443"] = forge_serving(8443)
    # UDP has no connect probe; a real RRQ round-trip is the honest check.
    try:
        marker = f"fleet_probe_{int(time.time())}.txt"
        with open(f"/tmp/tftp/{marker}", "w") as f:
            f.write("probe")
        t = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        t.settimeout(3)
        # RRQ: opcode 1, filename, mode netascii
        t.sendto(b"\x00\x01" + marker.encode() + b"\x00netascii\x00", ("192.168.4.160", 69))
        data, _ = t.recvfrom(600)
        t.close()
        planes["tftp:69"] = data[0:1] == b"\x00" and data[1:2] == b"\x03"  # DATA packet
    except (OSError, IndexError):
        planes["tftp:69"] = False
    _, out = sh("sudo -n pfctl -a fss -s nat 2>/dev/null | grep -c rdr")
    planes["pf-rdr"] = int(out.strip()) if out.strip().isdigit() else 0
    # launchd duplicate labels (the outage class)
    dups = []
    _, sysout = sh("sudo -n launchctl list 2>/dev/null | grep jeffreyemanuel | awk '{print $3}'")
    _, guiout = sh("launchctl list 2>/dev/null | grep jeffreyemanuel | awk '{print $3}'")
    sysset = set(filter(None, sysout.split()))
    guiset = set(filter(None, guiout.split()))
    dups = sorted(sysset & guiset)
    planes["launchd-duplicates"] = dups
    # the RTSP watcher is the only thing that re-enables a unit that rebooted
    # without rtspd; dead means a vendor reset silently costs ingest again
    planes["rtsp-watch"] = bool(sh("pgrep -f wyze_rtsp_one_shot.py")[1].strip())
    # the flash chain pins image md5s; if the files drift, the chain dies on the camera
    # *after* a shell was won. Single source of truth is the chain script itself.
    chain = os.path.join(os.path.dirname(os.path.abspath(__file__)), "tapo_flash_chain.sh")
    pins = {}
    try:
        text = open(chain).read()
        for kind, name, val in re.findall(r"(IMG|MD5)_(ROOTFS|KERNEL)=([^;\s]+)", text):
            pins[(kind, name)] = val
    except OSError:
        pins = {}
    okimgs = bool(pins)
    for (kind, name), val in list(pins.items()):
        if kind != "IMG":
            continue
        want = pins.get(("MD5", name), "")
        got = sh(f"md5 -q {os.path.expanduser('~/fss-exploit/fw/' + val)} 2>/dev/null")[1].strip()
        okimgs = okimgs and bool(want) and got == want
    planes["images:tapo"] = okimgs
    for label in WATCHERS:
        key = "watch:" + label.rsplit(".", 1)[-1]
        planes[key] = "state = running" in sh(f"sudo -n launchctl print system/{label} 2>/dev/null")[1]
    # plist doctor as a cached gate check: runs at most once/15min, result cached
    cache = "/tmp/plist_doctor_cache.json"
    try:
        age = time.time() - os.path.getmtime(cache)
    except OSError:
        age = 1e9
    if age > 900:
        here = os.path.dirname(os.path.abspath(__file__))
        sh(f"bash {here}/plist_doctor.sh --json > {cache} 2>/dev/null", timeout=60)
    try:
        doc = json.load(open(cache))
        f_ = doc.get("findings", 1)
        planes["plist-doctor"] = f_ == 0
        PLANE_DETAILS["plist-doctor"] = f"{f_} findings / {doc.get('checked', '?')} plists"
    except (json.JSONDecodeError, OSError):
        planes["plist-doctor"] = "no cache (doctor not yet run)"
    return planes


def latest_proofs(registry_cameras):
    """registry-id -> {vector: (pass, ts)} — keys proofs by registry id."""
    # ip -> id map for artifacts recorded by ip
    ip_to_id = {c.get("last_seen_ip"): c["id"] for c in registry_cameras}
    id_forms = {}
    for c in registry_cameras:
        oct = c["id"].split("-")[-1]
        id_forms[f"192.168.4.{oct}"] = c["id"]
    out = {}
    for f in glob.glob(os.path.join(PROOFS, "*.json")):
        try:
            d = json.load(open(f))
        except (json.JSONDecodeError, OSError):
            continue
        cam, vec = d.get("camera"), d.get("vector")
        if not cam or not vec:
            continue
        rid = cam if cam in {c["id"] for c in registry_cameras} else ip_to_id.get(cam) or id_forms.get(cam)
        if rid is None:
            continue
        cur = out.setdefault(rid, {})
        old = cur.get(vec)
        if old is None or str(d.get("timestamp_utc", "")) > str(old[1]):
            cur[vec] = (bool(d.get("pass")), d.get("timestamp_utc", ""))
    return out


def open_waits():
    out = {}
    try:
        for line in open(WAITS):
            line = line.strip()
            if not line:
                continue
            try:
                r = json.loads(line)
            except json.JSONDecodeError:
                continue
            out[(r.get("cam"), r.get("expectation"))] = r  # last wins
    except OSError:
        pass
    return out


def camera_state(cam, table, proofs, waits):
    mac = norm_mac(cam["mac"])
    ip = table.get(mac)
    present = bool(ip) or (ip is None and cam.get("last_seen_ip") and ping_probe(cam["last_seen_ip"]))
    vector = cam.get("vector", "none")
    cam_proofs = proofs.get(cam["id"], {})
    # rtsp-enable is served by the VENDOR rtspd — passing it does not mean root,
    # so only a shell/installer beacon may upgrade the state to ROOTED.
    ROOT_VECTORS = ("telnet9999", "dropbear22", "beacon-uid0")
    rooted = any(ok and vec in ROOT_VECTORS for vec, (ok, _) in cam_proofs.items())
    # derive state from evidence, not aspiration
    if vector == "fss":
        state = "INGESTING"
    elif rooted:
        state = "ROOTED"
    elif vector == "mitm-ota":
        state = "ARMED"
    elif present:
        state = "PRESENT"
    else:
        state = "OFFLINE"
    # open wait referencing this camera
    open_wait = None
    for (wcam, wexp), r in waits.items():
        if cam["id"] in wcam and r.get("event") == "open":
            open_wait = wexp
            break
    return {
        "id": cam["id"], "mac": cam["mac"], "ip": ip or cam.get("last_seen_ip"),
        "present": bool(present), "vector": vector, "state": state,
        "proofs": cam_proofs,
        "open_wait": open_wait,
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--gate", action="store_true", help="exit 2 if any fleet plane is DOWN")
    a = ap.parse_args()

    reg = load()
    table = arp_table()
    proofs = latest_proofs(reg["cameras"])
    waits = open_waits()
    planes = fleet_planes()

    cams = [camera_state(c, table, proofs, waits) for c in reg["cameras"]]

    if a.json:
        print(json.dumps({"generated": datetime.datetime.now().astimezone().isoformat(timespec="seconds"),
                          "planes": planes, "cameras": cams}, indent=1))
    else:
        print("=== fleet planes ===")
        for name, val in planes.items():
            mark = "✅" if (val is True or (isinstance(val, int) and val > 0) or (isinstance(val, list) and not val)) else "❌"
            detail = PLANE_DETAILS.get(name, "")
            print(f"  {mark} {name}: {val}{'  (' + detail + ')' if detail else ''}")
        print("=== cameras ===")
        print("| camera | state | ip | vector | proofs | open wait |")
        print("|---|---|---|---|---|---|")
        for c in cams:
            p = " ".join(f"{v}{'✅' if ok else '❌'}" for v, (ok, _) in sorted(c["proofs"].items())) or "—"
            print(f"| {c['id']} | {c['state']} | {c['ip'] or '—'} | {c['vector']} | {p} | {c['open_wait'] or '—'} |")

    if a.gate:
        bad = [n for n, v in planes.items()
               if v is False or (isinstance(v, int) and v == 0 and n != "launchd-duplicates")
               or (n == "launchd-duplicates" and v)]
        if bad:
            print(f"GATE FAILED: {', '.join(bad)}", file=sys.stderr)
            return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
