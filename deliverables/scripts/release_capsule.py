#!/usr/bin/env python3
"""release_capsule.py — point the fleet at a capsule manifest (single source).

The manifest (deliverables/capsules/<family>/<version>.manifest.json) is the
only artifact that may define CAP_PATH / OTA_MD5 / OTA_URL. This tool:

    release_capsule.py <family> <version> --plan     # show every file it would touch
    release_capsule.py <family> <version> --apply    # write plists + verify

writes the broker plist env (CAP_PATH, OTA_MD5, OTA_URL) from the manifest via
single-key PlistBuddy edits, verifies md5 against the served bytes, runs
plist_doctor, and prints the diff for review. Never rewrites a whole plist
(concurrent agents), never deletes anything.
"""
import argparse
import hashlib
import json
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
CAPSULES = os.path.normpath(os.path.join(HERE, "..", "capsules"))
BROKER_PLIST = "/Library/LaunchDaemons/com.jeffreyemanuel.wyze-broker.plist"


def pb(plist, key, value=None):
    if value is None:
        r = subprocess.run(["/usr/libexec/PlistBuddy", "-c", f"Print :{key}", plist],
                           capture_output=True, text=True)
        return r.stdout.strip() if r.returncode == 0 else None
    # Set, falling back to Add (PlistBuddy cannot Set a missing key)
    r = subprocess.run(["/usr/libexec/PlistBuddy", "-c", f"Set :{key} {value}", plist],
                       capture_output=True, text=True)
    if r.returncode != 0:
        r = subprocess.run(["/usr/libexec/PlistBuddy", "-c", f"Add :{key} string {value}", plist],
                           capture_output=True, text=True)
    return r.returncode == 0


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("family")
    ap.add_argument("version")
    ap.add_argument("--apply", action="store_true")
    ap.add_argument("--serve-root", default="/tmp/fwserve")
    a = ap.parse_args()

    mpath = os.path.join(CAPSULES, a.family, f"{a.version}.manifest.json")
    if not os.path.exists(mpath):
        print(f"no manifest: {mpath}", file=sys.stderr)
        return 2
    m = json.load(open(mpath))
    cap = m["capsule"]
    url = m["delivery"]["url"]
    # CAP_PATH is the served-tree-relative path from the URL
    cap_path = url.split("amazonaws.com/")[-1] if "amazonaws.com/" in url else cap["path"]
    full = f"{a.serve_root}/{cap_path}"

    print(f"manifest: {mpath}")
    print(f"  version   : {a.version}")
    print(f"  CAP_PATH  : {cap_path}")
    print(f"  OTA_MD5   : {cap['md5']}")
    print(f"  OTA_URL   : {url}")

    # verify served bytes match the manifest BEFORE touching anything
    actual = None
    if os.path.exists(full):
        actual = hashlib.md5(open(full, "rb").read()).hexdigest()
    ok = actual == cap["md5"]
    print(f"  served md5: {actual} {'✅' if ok else '❌ (MISMATCH — fix the served file first)'}")
    if not ok:
        return 1

    changes = []
    for key, val in (("EnvironmentVariables:CAP_PATH", cap_path),
                     ("EnvironmentVariables:OTA_MD5", cap["md5"]),
                     ("EnvironmentVariables:OTA_URL", url)):
        cur = pb(BROKER_PLIST, key)
        if cur != val:
            changes.append((key, cur, val))
    if not changes:
        print("plist already converged — nothing to do")
        return 0

    for key, cur, val in changes:
        print(f"  would set {key}: {cur!r} -> {val!r}")

    if not a.apply:
        print("(dry run — pass --apply)")
        return 0

    for key, _, val in changes:
        if not pb(BROKER_PLIST, key, val):
            print(f"FAILED to set {key}", file=sys.stderr)
            return 1
    print("plist updated; kickstarting broker for the new env…")
    subprocess.run(["sudo", "-n", "launchctl", "kickstart", "-k",
                    "system/com.jeffreyemanuel.wyze-broker"], timeout=30)
    # verify with the doctor
    r = subprocess.run(["bash", os.path.join(HERE, "plist_doctor.sh"), "--json"],
                       capture_output=True, text=True)
    if r.returncode == 0:
        print("plist_doctor: 0 findings ✅")
        return 0
    doc = json.loads(r.stdout)
    for it in doc.get("items", []):
        print(f"  doctor finding: {it['check']}: {it['detail']}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
