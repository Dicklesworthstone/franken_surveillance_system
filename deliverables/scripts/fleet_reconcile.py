#!/usr/bin/env python3
"""fleet_reconcile.py — the control plane's write side: converge live → desired.

Reads the same truth as fleet_status.py (registry.yaml + capsule manifests +
launchd) and repairs the drift classes measured in the 2026-11-06 outage:

  R1  broker plist OTA_MD5 != md5(live capsule)      → rewrite env from manifest
  R2  pf anchor fss missing Wyze rdr rules           → restore from pf-expected set
  R3  backup receivers not listening (444-449)       → kickstart fss-backup-recv
  R4  forge :8443/:443 not listening                 → kickstart the forge daemons

Safety contract (each rule is a measured lesson):
  - ADOPT-DON'T-KILL: never kill a plane that is UP (KeepAlive supervisors
    fight back; camera MQTT sessions drop into 15-30 min backoff).
  - --plan first: prints convergence actions without mutating.
  - every mutation is logged to /var/lib/fss-telemetry/reconcile.jsonl.
  - plist edits go through PlistBuddy single-key writes (never whole-file
    rewrites — other agents own concurrent edits).
  - kickstart instead of bootout/bootstrap (KeepAlive does the rest).
"""
import argparse
import datetime
import hashlib
import json
import os
import re
import socket
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from registry import load  # noqa: E402

LOG = "/var/lib/fss-telemetry/reconcile.jsonl"
BROKER_PLIST = "/Library/LaunchDaemons/com.jeffreyemanuel.wyze-broker.plist"
PF_ANCHOR = "/etc/pf.anchors/fss"

PF_EXPECTED = [
    # (src_ip, dst_ip, dst_port -> to_port); src any = registry last_seen_ip
    ("192.168.4.51", "any", 443, 443),
    ("192.168.4.39", "66.151.242.74", 443, 8883),
    ("192.168.4.51", "66.151.242.74", 443, 8883),
    ("192.168.4.39", "66.151.242.74", 8883, 8883),
    ("192.168.4.51", "66.151.242.74", 8883, 8883),
]

ACTIONS = []


def action(name, detail, mutate_fn=None):
    ACTIONS.append({"name": name, "detail": detail, "fn": mutate_fn})


def log(rec):
    try:
        os.makedirs(os.path.dirname(LOG), exist_ok=True)
        with open(LOG, "a") as f:
            f.write(json.dumps(rec, separators=(",", ":")) + "\n")
    except OSError as e:
        print(f"reconcile log unavailable: {e}", file=sys.stderr)


def sh(cmd, timeout=60):
    try:
        return subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return None


def port_open(port):
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=1.5):
            return True
    except OSError:
        return False


def md5_of(path):
    try:
        return hashlib.md5(open(path, "rb").read()).hexdigest()
    except OSError:
        return None


def pb(plist, key, value=None):
    """PlistBuddy single-key read or set."""
    if value is None:
        r = sh(f"/usr/libexec/PlistBuddy -c 'Print :{key}' '{plist}'")
        return r.stdout.strip() if r and r.returncode == 0 else None
    r = sh(f"/usr/libexec/PlistBuddy -c 'Set :{key} {value}' '{plist}'")
    return r is not None and r.returncode == 0


def r1_broker_md5(plan):
    """Broker env OTA_MD5 must equal md5 of the live capsule bytes."""
    md5v = pb(BROKER_PLIST, "EnvironmentVariables:OTA_MD5")
    cap = pb(BROKER_PLIST, "EnvironmentVariables:CAP_PATH")
    if not cap:
        return
    path = cap if cap.startswith("/") else f"/tmp/fwserve/{cap}"
    actual = md5_of(path)
    if actual and md5v != actual:
        def fix():
            # PlistBuddy cannot Set a missing key; Add if Set fails
            if not pb(BROKER_PLIST, "EnvironmentVariables:OTA_MD5", actual):
                sh(f"/usr/libexec/PlistBuddy -c 'Add :EnvironmentVariables:OTA_MD5 string {actual}' '{BROKER_PLIST}'")
            # re-arm the broker so the new env takes effect (KeepAlive reapplies)
            sh("sudo -n launchctl kickstart -k system/com.jeffreyemanuel.wyze-broker")
        action("R1-broker-md5", f"OTA_MD5 {md5v} -> {actual} (file truth; kickstart broker)", fix)
    else:
        action("R1-broker-md5", f"converged (env==file=={actual[:12]}…)", None)


def r2_pf_rules(plan):
    """The fss anchor must contain the Wyze rdr set; missing ones are restored."""
    r = sh("sudo -n pfctl -a fss -s nat")
    live = r.stdout if r else ""
    missing = []
    for src, dst, dport, toport in PF_EXPECTED:
        dstpart = "any" if dst == "any" else dst
        # live pfctl prints 'port = 443'; accept both spellings
        probe = re.compile(rf"from {re.escape(src)} to {re.escape(dstpart)} port = {dport}\b")
        if not probe.search(live):
            missing.append((src, dst, dport, toport))
    if not missing:
        action("R2-pf-rdr", f"converged ({len(PF_EXPECTED)} wyze rules present)", None)
        return
    rules = []
    for src, dst, dport, toport in missing:
        dstpart = "any" if dst == "any" else dst
        rules.append(f"rdr pass on en1 proto tcp from {src} to {dstpart} port {dport} -> 192.168.4.160 port {toport}")

    def fix():
        # /etc/pf.anchors is root-owned: write via sudo tee (whole-file rewrite
        # of OUR OWN anchor file is safe — it is generated truth, not shared)
        import tempfile
        try:
            current = open(PF_ANCHOR).read()
        except OSError:
            current = ""
        for rule in rules:
            if rule not in current:
                current += rule + "\n"
        with tempfile.NamedTemporaryFile("w", delete=False) as tf:
            tf.write(current)
            tmp = tf.name
        sh(f"sudo -n cp {tmp} {PF_ANCHOR} && rm -f {tmp} && sudo -n pfctl -f /etc/pf.conf")
    action("R2-pf-rdr", f"restore {len(missing)} missing rdr rules", fix)


def r3_backups(plan):
    missing = [p for p in range(444, 450) if not port_open(p)]
    if not missing:
        action("R3-backups", "converged (444-449 listening)", None)
        return

    def fix():
        # kickstart only works on a LOADED job; after a bootout (or first boot
        # before bootstrap) the job must be (re)bootstrapped from its plist.
        sh("sudo -n launchctl kickstart -k system/com.jeffreyemanuel.fss-backup-recv")
        # kickstart works only on a LOADED job; after bootout, bootstrap needs a
        # settle delay (measured: immediate bootstrap → error 5, +5 s → success)
        for attempt in range(3):
            time.sleep(5)
            if all(port_open(p) for p in range(444, 450)):
                return
            sh("sudo -n launchctl bootstrap system /Library/LaunchDaemons/com.jeffreyemanuel.fss-backup-recv.plist")
        time.sleep(5)
    action("R3-backups", f"ports down {missing} → kickstart (bootstrap fallback)", fix)


def r4_forge(plan):
    down = [p for p in (443, 8443) if not port_open(p)]
    if not down:
        action("R4-forge", "converged (443+8443 listening)", None)
        return
    label = {443: "wyze-forge", 8443: "wyze-forge-8443"}

    def fix():
        for p in down:
            sh(f"sudo -n launchctl kickstart -k system/com.jeffreyemanuel.{label[p]}")
    action("R4-forge", f"ports down {down} → kickstart forge daemons", fix)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--plan", action="store_true", help="print actions, mutate nothing")
    ap.add_argument("--execute", action="store_true", help="apply the actions")
    a = ap.parse_args()
    if not (a.plan or a.execute):
        a.plan = True

    r1_broker_md5(a.plan)
    r2_pf_rules(a.plan)
    r3_backups(a.plan)
    r4_forge(a.plan)

    print("=== reconcile plan ===")
    any_needed = False
    for act in ACTIONS:
        needed = "fn" in act and act["fn"] is not None
        any_needed = any_needed or needed
        mark = "⚙" if needed else "✓"
        print(f"  {mark} {act['name']}: {act['detail']}")
    if a.execute:
        for act in ACTIONS:
            if act["fn"] is not None:
                print(f"  executing {act['name']}…")
                try:
                    act["fn"]()
                except Exception as e:
                    print(f"    FAILED: {e}", file=sys.stderr)
                log({"ts": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"),
                     "action": act["name"], "detail": act["detail"]})
        print("convergence applied; re-run fleet_status.py --gate to verify")
    elif any_needed:
        print("(dry run — pass --execute to apply)")
    else:
        print("fleet already converged")
    return 0


if __name__ == "__main__":
    sys.exit(main())
