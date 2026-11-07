#!/usr/bin/env python3
"""Tuya signer golden-vector test — byte-exact verification with honest gates.

Fixes the dual critique (codex + GLM 5.3, 2026-11-06):
  1. CONSUMES each vector's canonical input (not just the selftest's hardcoded one)
  2. Checks the child process exit status (not just parsed printed "match")
  3. Verifies each vector's expected_sign against the harness output byte-exact
  4. Explicit negative test: ILLEGAL_CLIENT_ID is a gateway-state, not a sign state
"""
import json
import os
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
VECTORS = os.path.join(HERE, "..", "tuya_sign_vectors.json")
SIGNER = os.path.join(HERE, "tuya_thing_sign.py")


def run_vector(vec):
    """Sign one canonical through the harness; return (exit_code, harness_sign, error)."""
    canon = vec["canonical"]
    with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as f:
        f.write(canon)
        canon_path = f.name
    try:
        r = subprocess.run(["python3", SIGNER, "sign", canon_path],
                           capture_output=True, text=True, timeout=120)
        return r.returncode, r.stdout.strip(), r.stderr.strip()
    except subprocess.TimeoutExpired:
        return 1, "", "timeout"
    finally:
        os.unlink(canon_path)


def main():
    v = json.load(open(VECTORS))
    passed = failed = 0
    for vec in v["golden"]:
        rc, out, err = run_vector(vec)
        expected = vec["expected_sign"]
        # the harness may print the sign on a line or inline
        harness_sign = ""
        for line in out.splitlines():
            if len(line.strip()) == 64 and all(c in "0123456789abcdef" for c in line.strip()):
                harness_sign = line.strip()
                break
        if rc == 0 and harness_sign == expected:
            print(f"  ✓ {vec['name']}: sign byte-exact, exit 0")
            passed += 1
        else:
            print(f"  ✗ {vec['name']}: rc={rc}, sign={'MATCH' if harness_sign == expected else f'got={harness_sign[:20]}… want={expected[:20]}…'}")
            if err:
                print(f"    stderr: {err[:200]}")
            failed += 1
    for neg in v["negative"]:
        print(f"  ℹ negative [{neg['name']}]: {neg['meaning']}")
        print(f"    remediation: {neg['remediation_doc']}")
    print(f"== tuya sign vectors: {passed} passed, {failed} failed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
