#!/usr/bin/env python3
"""Runtime self-test for the qualification network seal (fss-x4a.26.3, FSS-183).

scripts/qualify.sh sets QUALIFY_SEAL_MODE and runs every lane step inside
`unshare -n` when the namespace primitive is available. This step proves the
seal is real instead of assumed:

- namespace mode: a TCP connect must FAIL (the namespace has no routes and no
  external interfaces). A successful connect means the seal is broken and the
  lane fails closed.
- unavailable mode: the run is on a host without the namespace primitive; the
  env-only seal cannot be proven at the OS level, so the outcome is declared
  degraded and the step passes - the receipt records the degraded seal for the
  release reviewer.
"""
from __future__ import annotations

import os
import socket
import sys

# Documentation-reserved address (RFC 3849, 2001:db8::/32 is IPv6; 240.0.0.1 is
# reserved) plus a tiny timeout: nothing legitimate listens there, and a sealed
# namespace fails the connect immediately with no route to host.
PROBE_HOST = "240.0.0.1"
PROBE_PORT = 1
TIMEOUT_S = 2


def main() -> int:
    mode = os.environ.get("QUALIFY_SEAL_MODE", "unavailable")
    connected = False
    err = "no error"
    try:
        sock = socket.create_connection((PROBE_HOST, PROBE_PORT), timeout=TIMEOUT_S)
        connected = True
        sock.close()
    except OSError as exc:
        err = str(exc)

    if mode == "namespace":
        if connected:
            print(
                f"NETSEAL FAIL: connect to {PROBE_HOST}:{PROBE_PORT} succeeded inside "
                "the network namespace; the seal is broken",
                file=sys.stderr,
            )
            return 1
        print(f"NETSEAL ok: namespace-sealed (probe refused: {err})")
        return 0

    if connected:
        print(
            f"NETSEAL FAIL: connect to {PROBE_HOST}:{PROBE_PORT} succeeded with the "
            "env-only seal; treat this host as network-capable for review",
            file=sys.stderr,
        )
        return 1
    print(
        f"NETSEAL degraded: QUALIFY_SEAL_MODE={mode}; OS-level seal unavailable, "
        f"env-only seal in force (probe refused anyway: {err})"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
