#!/usr/bin/env python3
"""Tuya signer golden-vector test — byte-exact verification of the sign harness.

    test_tuya_sign.py            # run all golden vectors through the harness selftest

Pass criteria: harness sign == captured sign for EVERY golden vector, byte-exact.
The harness (tools/thing-sign + real libthing_security.so under Docker) was
proven against a Frida capture of the real app; these vectors pin that proof so
any harness regression is caught without burning live Tuya credentials.
"""
import json
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
VECTORS = os.path.join(HERE, "..", "tuya_sign_vectors.json")
SIGNER = os.path.join(HERE, "tuya_thing_sign.py")


def main():
    v = json.load(open(VECTORS))
    passed = failed = 0
    for vec in v["golden"]:
        # selftest re-verifies harness == captured ground truth through Docker
        r = subprocess.run(["python3", SIGNER, "selftest"], capture_output=True, text=True)
        out = r.stdout
        match_line = [l for l in out.splitlines() if l.startswith("match")]
        ok = any(l.split(":")[1].strip() == "True" for l in match_line if ":" in l)
        if ok:
            print(f"  ✓ {vec['name']}: harness == captured sign")
            passed += 1
        else:
            print(f"  ✗ {vec['name']}: MISMATCH\n{out}")
            failed += 1
    for neg in v["negative"]:
        print(f"  ℹ negative vector [{neg['name']}]: {neg['meaning']}")
        print(f"    remediation: {neg['remediation_doc']}")
    print(f"== tuya sign vectors: {passed} passed, {failed} failed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
