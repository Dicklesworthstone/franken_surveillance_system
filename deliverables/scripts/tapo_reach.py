#!/usr/bin/env python3
"""Wake a Tapo and prove the DS answers with a login — the "can it execute" gate.

The vendor apps do exactly this and it is why a sleeping unit is still reachable: a WoWLAN
magic packet brings the SoC up, then the DS login succeeds. The previous gate sent a login with
no `device_confirm`/RSA step and never saw a `stok` on 1.2.2 firmware, so 143k fires were
refused as "DS closed" while the camera was in fact reachable.

  tapo_reach.py <ip> [--wake-mac MAC] [--tries N] [--wait S]

Exit 0 ready (prints READY), 1 not ready. Never fires anything.
"""
import argparse
import os
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)


def wake(mac: str, ip: str, wait: float = 45.0) -> bool:
    r = subprocess.run([sys.executable, os.path.join(HERE, "tapo_wake.py"), mac,
                        "--ip", ip, "--wait", str(wait), "--port", "443"],
                       capture_output=True, text=True)
    return r.returncode == 0


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("ip")
    ap.add_argument("--wake-mac")
    ap.add_argument("--tries", type=int, default=6)
    ap.add_argument("--wake-tries", type=int, default=3, help="full wake rounds before giving up")
    ap.add_argument("--wait", type=float, default=45.0)
    a = ap.parse_args()

    if a.wake_mac:
        woke = False
        for _ in range(a.wake_tries):
            if wake(a.wake_mac, a.ip, a.wait):
                woke = True
                break
            time.sleep(1)
        if not woke:
            print("WAKE-FAILED")
            return 1
    import tapo_connectap_sc as ds
    try:
        sess = ds.login(a.ip, tries=a.tries)
    except BaseException as e:
        print(f"LOGIN-FAILED {type(e).__name__}: {e}")
        return 1
    print(f"READY stok={sess['stok'][:8]}…")
    return 0


if __name__ == "__main__":
    sys.exit(main())
